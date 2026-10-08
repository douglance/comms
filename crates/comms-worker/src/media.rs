use std::collections::HashMap;
use std::convert::TryInto;

use axum::http::{Method, StatusCode, header};
use js_sys::{Function, Reflect, Uint8Array};
use serde::Deserialize;
use serde_json::{Value, json};
use wasm_bindgen::{JsCast, JsValue};
use worker::d1::D1PreparedStatement;
use worker::send::IntoSendFuture;
use worker::{Env, HttpRequest, HttpResponse, Response};

use crate::auth::Agent;

const BLOB_PREFIX: &str = "blobs/";
const UPLOAD_TABLE: &str = "_comms_multipart_uploads";

#[derive(Clone, Debug)]
pub(crate) struct BlobDescriptor {
    pub id: String,
    pub mime_type: String,
    pub bytes: usize,
    pub sha256: Option<String>,
    pub etag: Option<String>,
    pub created_by: String,
    pub name: Option<String>,
}

impl BlobDescriptor {
    pub fn value(&self, ticket: Option<String>, base_url: &str) -> Value {
        let mut value = json!({
            "id": self.id,
            "mime_type": self.mime_type,
            "bytes": self.bytes,
            "sha256": self.sha256,
            "etag": self.etag,
            "created_by": self.created_by,
            "name": self.name.as_deref().unwrap_or(self.id.as_str()),
        });
        if let Some(ticket) = ticket {
            value["download_url"] = Value::String(format!(
                "{}/media/{}?ticket={}",
                base_url.trim_end_matches('/'),
                self.id,
                ticket
            ));
        }
        value
    }
}

pub async fn handle(
    request: HttpRequest,
    env: Env,
    agent: Agent,
    base_url: String,
) -> worker::Result<HttpResponse> {
    match handle_inner(request, env, agent, base_url).await {
        Ok(response) => Ok(response),
        Err(error) => media_error_response(error),
    }
}

async fn handle_inner(
    request: HttpRequest,
    env: Env,
    agent: Agent,
    base_url: String,
) -> worker::Result<HttpResponse> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let mime_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();
    let name = request
        .headers()
        .get("x-comms-name")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    if method == Method::POST && path == "/media" {
        let bytes = request_bytes(request).await?;
        let descriptor = put_bytes(&env, &agent, bytes, mime_type, name).await?;
        return json_response(StatusCode::CREATED, descriptor.value(None, &base_url));
    }

    if let Some(id) = path.strip_prefix("/media/").filter(|id| !id.is_empty()) {
        let id = decode_path_segment(id)?;
        return match method {
            Method::GET => get_media(&env, &id).await,
            Method::DELETE => {
                let deleted = delete_blob(&env, &id).await?;
                json_response(StatusCode::OK, json!({"id": id, "deleted": deleted}))
            }
            _ => json_error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "METHOD_NOT_ALLOWED",
                "method is not allowed for this media resource",
            ),
        };
    }

    if path == "/uploads" && method == Method::POST {
        let input = request_optional_json(request).await?;
        return create_upload(&env, &agent, input, mime_type, name).await;
    }

    if let Some(rest) = path.strip_prefix("/uploads/") {
        let parts = rest
            .split('/')
            .map(decode_path_segment)
            .collect::<worker::Result<Vec<_>>>()?;
        if parts.len() == 2 && method == Method::DELETE {
            return abort_upload(&env, &agent, &parts[0], &parts[1]).await;
        }
        if parts.len() == 3 && method == Method::PUT {
            let part_number = parts[2]
                .parse::<u16>()
                .map_err(|_| worker::Error::RustError("malformed part number".into()))?;
            if part_number == 0 {
                return json_error_response(
                    StatusCode::BAD_REQUEST,
                    "INPUT_ERROR",
                    "part number must be greater than zero",
                );
            }
            let bytes = request_bytes(request).await?;
            return upload_part(&env, &agent, &parts[0], &parts[1], part_number, bytes).await;
        }
        if parts.len() == 3 && parts[2] == "complete" && method == Method::POST {
            let input = request_json(request).await?;
            return complete_upload(&env, &agent, &parts[0], &parts[1], input, &base_url).await;
        }
    }

    json_error_response(StatusCode::NOT_FOUND, "NOT_FOUND", "media route not found")
}

pub(crate) async fn put_bytes(
    env: &Env,
    agent: &Agent,
    bytes: Vec<u8>,
    mime_type: String,
    name: Option<String>,
) -> worker::Result<BlobDescriptor> {
    let id = format!("blb_{}", random_hex(16)?);
    let sha256 = crate::data::sha256_hex(&bytes);
    let descriptor = BlobDescriptor {
        id: id.clone(),
        mime_type,
        bytes: bytes.len(),
        sha256: Some(sha256),
        etag: None,
        created_by: agent.id.clone(),
        name,
    };
    let metadata = descriptor_metadata(&descriptor);
    let bucket = env.bucket("MEDIA")?;
    async move {
        bucket
            .put(blob_key(&id), bytes)
            .custom_metadata(metadata)
            .execute()
            .await
    }
    .into_send()
    .await?;
    Ok(descriptor)
}

pub(crate) async fn put_stream(
    env: &Env,
    agent: &Agent,
    stream: web_sys::ReadableStream,
    mime_type: String,
    name: Option<String>,
) -> worker::Result<BlobDescriptor> {
    let id = format!("blb_{}", random_hex(16)?);
    let mut descriptor = BlobDescriptor {
        id: id.clone(),
        mime_type,
        bytes: 0,
        sha256: None,
        etag: None,
        created_by: agent.id.clone(),
        name,
    };
    let metadata = descriptor_metadata(&descriptor);
    let bucket = env.bucket("MEDIA")?;
    let object = async move {
        bucket
            .put(blob_key(&id), stream)
            .custom_metadata(metadata)
            .execute()
            .await
    }
    .into_send()
    .await?;
    let object = object.ok_or_else(|| {
        worker::Error::RustError("binary response storage returned no object".into())
    })?;
    descriptor.bytes = object.size() as usize;
    descriptor.etag = Some(object.etag());
    Ok(descriptor)
}

pub(crate) async fn open_blob(
    env: &Env,
    id: &str,
) -> worker::Result<(BlobDescriptor, worker::ResponseBody)> {
    let bucket = env.bucket("MEDIA")?;
    let object = async move { bucket.get(blob_key(id)).execute().await }
        .into_send()
        .await?
        .ok_or_else(|| worker::Error::RustError("blob not found".into()))?;
    let descriptor =
        descriptor_from_metadata(id, object.size() as usize, object.custom_metadata()?)?;
    let body = object
        .body()
        .ok_or_else(|| worker::Error::RustError("blob has no body".into()))?
        .response_body()?;
    Ok((descriptor, body))
}

pub(crate) async fn head_blob(env: &Env, id: &str) -> worker::Result<BlobDescriptor> {
    let bucket = env.bucket("MEDIA")?;
    let object = async move { bucket.head(blob_key(id)).await }
        .into_send()
        .await?
        .ok_or_else(|| worker::Error::RustError("blob not found".into()))?;
    descriptor_from_metadata(id, object.size() as usize, object.custom_metadata()?)
}

pub(crate) async fn get_bytes(env: &Env, id: &str) -> worker::Result<(BlobDescriptor, Vec<u8>)> {
    let bucket = env.bucket("MEDIA")?;
    let object = async move { bucket.get(blob_key(id)).execute().await }
        .into_send()
        .await?
        .ok_or_else(|| worker::Error::RustError("blob not found".into()))?;
    let metadata = object.custom_metadata()?;
    let body = object
        .body()
        .ok_or_else(|| worker::Error::RustError("blob has no body".into()))?;
    let bytes = async move { body.bytes().await }.into_send().await?;
    let mut descriptor = descriptor_from_metadata(id, bytes.len(), metadata)?;
    descriptor.bytes = bytes.len();
    descriptor.sha256 = Some(crate::data::sha256_hex(&bytes));
    Ok((descriptor, bytes))
}

pub(crate) async fn delete_blob(env: &Env, id: &str) -> worker::Result<bool> {
    let existed = head_blob(env, id).await.is_ok();
    let bucket = env.bucket("MEDIA")?;
    let key = blob_key(id);
    async move { bucket.delete(key).await }.into_send().await?;
    Ok(existed)
}

async fn get_media(env: &Env, id: &str) -> worker::Result<HttpResponse> {
    let bucket = env.bucket("MEDIA")?;
    let object = async move { bucket.get(blob_key(id)).execute().await }
        .into_send()
        .await?
        .ok_or_else(|| worker::Error::RustError("blob not found".into()))?;
    let metadata = object.custom_metadata()?;
    let descriptor = descriptor_from_metadata(id, object.size() as usize, metadata)?;
    let body = object
        .body()
        .ok_or_else(|| worker::Error::RustError("blob has no body".into()))?
        .response_body()?;
    let response = Response::from_body(body)?.with_status(StatusCode::OK.as_u16());
    let mut response: HttpResponse = response.try_into()?;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        descriptor
            .mime_type
            .parse()
            .unwrap_or_else(|_| "application/octet-stream".parse().unwrap()),
    );
    response
        .headers_mut()
        .insert(header::CONTENT_DISPOSITION, "attachment".parse().unwrap());
    harden(&mut response);
    Ok(response)
}

async fn create_upload(
    env: &Env,
    agent: &Agent,
    input: Value,
    header_mime_type: String,
    header_name: Option<String>,
) -> worker::Result<HttpResponse> {
    ensure_upload_table(env).await?;
    let id = format!("blb_{}", random_hex(16)?);
    let mime_type = input
        .get("mime_type")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or(header_mime_type);
    let name = input
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or(header_name);
    let descriptor = BlobDescriptor {
        id: id.clone(),
        mime_type,
        bytes: 0,
        sha256: None,
        etag: None,
        created_by: agent.id.clone(),
        name,
    };
    let metadata = descriptor_metadata(&descriptor);
    let bucket = env.bucket("MEDIA")?;
    let upload_key = blob_key(&id);
    let upload = async move {
        bucket
            .create_multipart_upload(upload_key)
            .custom_metadata(metadata)
            .execute()
            .await
    }
    .into_send()
    .await?;
    let upload_id = upload.upload_id().await;
    control_exec(
        env,
        &format!(
            "INSERT INTO {UPLOAD_TABLE} (id, upload_id, agent_id, mime_type, name, created_at, status) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'open')"
        ),
        vec![
            JsValue::from_str(&id),
            JsValue::from_str(&upload_id),
            JsValue::from_str(&agent.id),
            JsValue::from_str(&descriptor.mime_type),
            descriptor
                .name
                .as_deref()
                .map(JsValue::from_str)
                .unwrap_or(JsValue::NULL),
            JsValue::from_f64(js_sys::Date::now()),
        ],
    )
    .await?;
    json_response(
        StatusCode::CREATED,
        json!({"id": id, "upload_id": upload_id, "mime_type": descriptor.mime_type, "name": descriptor.name}),
    )
}

async fn upload_part(
    env: &Env,
    agent: &Agent,
    id: &str,
    upload_id: &str,
    part_number: u16,
    bytes: Vec<u8>,
) -> worker::Result<HttpResponse> {
    load_upload(env, agent, id, upload_id).await?;
    let bucket = env.bucket("MEDIA")?;
    let upload = bucket.resume_multipart_upload(blob_key(id), upload_id)?;
    let part = async move { upload.upload_part(part_number, bytes).await }
        .into_send()
        .await?;
    json_response(
        StatusCode::OK,
        json!({"part_number": part.part_number(), "etag": part.etag()}),
    )
}

async fn complete_upload(
    env: &Env,
    agent: &Agent,
    id: &str,
    upload_id: &str,
    input: CompleteUpload,
    base_url: &str,
) -> worker::Result<HttpResponse> {
    let upload_row = load_upload(env, agent, id, upload_id).await?;
    let bucket = env.bucket("MEDIA")?;
    let upload = bucket.resume_multipart_upload(blob_key(id), upload_id)?;
    let uploaded_parts = input
        .parts
        .into_iter()
        .map(|part| worker::UploadedPart::new(part.part_number, part.etag));
    let object = async move { upload.complete(uploaded_parts).await }
        .into_send()
        .await?;
    let object_size = object.size() as usize;
    let object_etag = object.etag();
    let descriptor = BlobDescriptor {
        id: id.to_owned(),
        mime_type: upload_row.mime_type,
        bytes: object_size,
        sha256: None,
        etag: Some(object_etag),
        created_by: agent.id.clone(),
        name: upload_row.name,
    };
    control_exec(
        env,
        &format!("UPDATE {UPLOAD_TABLE} SET status = 'complete' WHERE id = ?1 AND upload_id = ?2"),
        vec![JsValue::from_str(id), JsValue::from_str(upload_id)],
    )
    .await?;
    json_response(StatusCode::OK, descriptor.value(None, base_url))
}

async fn abort_upload(
    env: &Env,
    agent: &Agent,
    id: &str,
    upload_id: &str,
) -> worker::Result<HttpResponse> {
    load_upload(env, agent, id, upload_id).await?;
    let bucket = env.bucket("MEDIA")?;
    let upload = bucket.resume_multipart_upload(blob_key(id), upload_id)?;
    async move { upload.abort().await }.into_send().await?;
    control_exec(
        env,
        &format!("UPDATE {UPLOAD_TABLE} SET status = 'aborted' WHERE id = ?1 AND upload_id = ?2"),
        vec![JsValue::from_str(id), JsValue::from_str(upload_id)],
    )
    .await?;
    json_response(
        StatusCode::OK,
        json!({"id": id, "upload_id": upload_id, "aborted": true}),
    )
}

#[derive(Deserialize)]
struct CompleteUpload {
    parts: Vec<CompletePart>,
}

#[derive(Deserialize)]
struct CompletePart {
    part_number: u16,
    etag: String,
}

struct UploadRow {
    mime_type: String,
    name: Option<String>,
}

async fn ensure_upload_table(env: &Env) -> worker::Result<()> {
    control_exec(
        env,
        &format!(
            "CREATE TABLE IF NOT EXISTS {UPLOAD_TABLE} (id TEXT NOT NULL, upload_id TEXT NOT NULL, agent_id TEXT NOT NULL, mime_type TEXT NOT NULL, name TEXT, created_at REAL NOT NULL, status TEXT NOT NULL, PRIMARY KEY (id, upload_id))"
        ),
        Vec::new(),
    )
    .await
}

async fn load_upload(
    env: &Env,
    agent: &Agent,
    id: &str,
    upload_id: &str,
) -> worker::Result<UploadRow> {
    ensure_upload_table(env).await?;
    let db = env.d1("CONTROL")?;
    let statement = bind(
        db.prepare(format!(
            "SELECT mime_type, name FROM {UPLOAD_TABLE} WHERE id = ?1 AND upload_id = ?2 AND agent_id = ?3 AND status = 'open'"
        )),
        vec![
            JsValue::from_str(id),
            JsValue::from_str(upload_id),
            JsValue::from_str(&agent.id),
        ],
    )?;
    let row = async move { statement.first::<HashMap<String, Value>>(None).await }
        .into_send()
        .await?
        .ok_or_else(|| worker::Error::RustError("upload not found for this agent".into()))?;
    Ok(UploadRow {
        mime_type: row
            .get("mime_type")
            .and_then(Value::as_str)
            .unwrap_or("application/octet-stream")
            .to_owned(),
        name: row.get("name").and_then(Value::as_str).map(str::to_owned),
    })
}

async fn control_exec(env: &Env, sql: &str, params: Vec<JsValue>) -> worker::Result<()> {
    let db = env.d1("CONTROL")?;
    let statement = bind(db.prepare(sql), params)?;
    async move { statement.run().await }.into_send().await?;
    Ok(())
}

fn bind(
    statement: D1PreparedStatement,
    params: Vec<JsValue>,
) -> worker::Result<D1PreparedStatement> {
    if params.is_empty() {
        Ok(statement)
    } else {
        statement.bind(&params)
    }
}

async fn request_bytes(request: HttpRequest) -> worker::Result<Vec<u8>> {
    let request = worker::request_to_wasm(request)?;
    let mut request = worker::Request::from(request);
    request.bytes().await
}

async fn request_json<T: for<'de> Deserialize<'de>>(request: HttpRequest) -> worker::Result<T> {
    let bytes = request_bytes(request).await?;
    parse_json_bytes(&bytes)
}

async fn request_optional_json(request: HttpRequest) -> worker::Result<Value> {
    let bytes = request_bytes(request).await?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        Ok(Value::Null)
    } else {
        parse_json_bytes(&bytes)
    }
}

fn parse_json_bytes<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> worker::Result<T> {
    serde_json::from_slice(bytes)
        .map_err(|_| worker::Error::RustError("malformed JSON body".into()))
}

fn media_error_response(error: worker::Error) -> worker::Result<HttpResponse> {
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("blob not found") || message.contains("upload not found") {
        return json_error_response(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "media resource not found",
        );
    }
    if message.contains("malformed") || message.contains("part number") {
        return json_error_response(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "malformed media request",
        );
    }
    json_error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_ERROR",
        "media operation failed",
    )
}

fn decode_path_segment(segment: &str) -> worker::Result<String> {
    let bytes = segment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(worker::Error::RustError("malformed path encoding".into()));
            }
            let high = hex_value(bytes[index + 1])?;
            let low = hex_value(bytes[index + 2])?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded)
        .map_err(|_| worker::Error::RustError("malformed path encoding".into()))
}

fn hex_value(byte: u8) -> worker::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(worker::Error::RustError("malformed path encoding".into())),
    }
}

fn json_response(status: StatusCode, value: Value) -> worker::Result<HttpResponse> {
    json_body(status, json!({"ok": true, "data": value}))
}

fn json_error_response(
    status: StatusCode,
    code: &str,
    message: &str,
) -> worker::Result<HttpResponse> {
    json_body(
        status,
        json!({"ok": false, "error": {"code": code, "message": message}}),
    )
}

fn json_body(status: StatusCode, value: Value) -> worker::Result<HttpResponse> {
    let response = Response::from_json(&value)?.with_status(status.as_u16());
    let mut response: HttpResponse = response.try_into()?;
    harden(&mut response);
    Ok(response)
}

fn harden(response: &mut HttpResponse) {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
}

fn descriptor_metadata(descriptor: &BlobDescriptor) -> HashMap<String, String> {
    let mut metadata = HashMap::from([
        ("id".to_string(), descriptor.id.clone()),
        ("mime_type".to_string(), descriptor.mime_type.clone()),
        ("bytes".to_string(), descriptor.bytes.to_string()),
        ("created_by".to_string(), descriptor.created_by.clone()),
    ]);
    if let Some(sha256) = &descriptor.sha256 {
        metadata.insert("sha256".into(), sha256.clone());
    }
    if let Some(etag) = &descriptor.etag {
        metadata.insert("etag".into(), etag.clone());
    }
    if let Some(name) = &descriptor.name {
        metadata.insert("name".into(), name.clone());
    }
    metadata
}

fn descriptor_from_metadata(
    id: &str,
    size: usize,
    metadata: HashMap<String, String>,
) -> worker::Result<BlobDescriptor> {
    Ok(BlobDescriptor {
        id: metadata.get("id").cloned().unwrap_or_else(|| id.to_owned()),
        mime_type: metadata
            .get("mime_type")
            .cloned()
            .unwrap_or_else(|| "application/octet-stream".into()),
        bytes: size,
        sha256: metadata.get("sha256").cloned(),
        etag: metadata.get("etag").cloned(),
        created_by: metadata.get("created_by").cloned().unwrap_or_default(),
        name: metadata.get("name").cloned(),
    })
}

fn blob_key(id: &str) -> String {
    format!("{BLOB_PREFIX}{id}")
}

fn random_hex(len: usize) -> worker::Result<String> {
    let global = js_sys::global();
    let crypto = Reflect::get(&global, &JsValue::from_str("crypto"))?;
    let get_random_values =
        Reflect::get(&crypto, &JsValue::from_str("getRandomValues"))?.dyn_into::<Function>()?;
    let array = Uint8Array::new_with_length(len as u32);
    get_random_values.call1(&crypto, &array)?;
    let mut bytes = vec![0; len];
    array.copy_to(&mut bytes);
    Ok(crate::data::hex_bytes(&bytes))
}
