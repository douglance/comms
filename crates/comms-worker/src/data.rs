use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use js_sys::Uint8Array;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wasm_bindgen::JsValue;
use worker::Env;
use worker::d1::{D1PreparedStatement, D1Result};
use worker::send::{IntoSendFuture, SendWrapper};

use crate::auth::Agent;

#[derive(Clone, Copy, PartialEq, Eq)]
enum RetentionMode {
    Direct,
    Durable,
    Ephemeral,
}

pub struct DataBackend {
    env: SendWrapper<Env>,
    agent: Agent,
    base_url: String,
    retention_mode: RetentionMode,
}

impl DataBackend {
    pub fn new(env: Env, agent: Agent, base_url: String) -> Self {
        Self {
            env: SendWrapper::new(env),
            agent,
            base_url,
            retention_mode: RetentionMode::Direct,
        }
    }

    pub fn new_durable(env: Env, agent: Agent, base_url: String) -> Self {
        let mut backend = Self::new(env, agent, base_url);
        backend.retention_mode = RetentionMode::Durable;
        backend
    }

    pub fn new_ephemeral(env: Env, agent: Agent, base_url: String) -> Self {
        let mut backend = Self::new(env, agent, base_url);
        backend.retention_mode = RetentionMode::Ephemeral;
        backend
    }

    fn data_db(&self) -> Result<worker::d1::D1Database, String> {
        self.env.d1("DATA").map_err(|error| error.to_string())
    }

    async fn sql(&self, input: Value) -> Result<Value, String> {
        let sql = string_field(&input, "sql")?;
        let params = input.get("params").cloned().unwrap_or(Value::Null);
        let bookmark = input
            .get("bookmark")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let db = self.data_db()?;
        let session = match bookmark.as_deref() {
            Some(bookmark) if !bookmark.is_empty() => db
                .with_session(Some(bookmark))
                .map_err(|error| error.to_string())?,
            _ => db
                .with_session_constraint(worker::d1::D1SessionConstraint::FirstPrimary)
                .map_err(|error| error.to_string())?,
        };
        let statement = bind_statement(session.prepare(sql), &params)?;
        let result = async move { statement.all().await }
            .into_send()
            .await
            .map_err(|error| error.to_string())?;
        let bookmark = session.get_bookmark().map_err(|error| error.to_string())?;
        result_value(&result, bookmark, &self.agent.id)
    }

    async fn batch(&self, input: Value) -> Result<Value, String> {
        let bookmark = input
            .get("bookmark")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let statements = input
            .get("statements")
            .and_then(Value::as_array)
            .ok_or_else(|| "statements must be an array".to_string())?;
        let db = self.data_db()?;
        let session = match bookmark.as_deref() {
            Some(bookmark) if !bookmark.is_empty() => db
                .with_session(Some(bookmark))
                .map_err(|error| error.to_string())?,
            _ => db
                .with_session_constraint(worker::d1::D1SessionConstraint::FirstPrimary)
                .map_err(|error| error.to_string())?,
        };
        let mut prepared = Vec::with_capacity(statements.len());
        for (index, statement) in statements.iter().enumerate() {
            let sql = statement
                .get("sql")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("statements[{index}].sql must be a string"))?;
            let params = statement.get("params").cloned().unwrap_or(Value::Null);
            prepared.push(bind_statement(session.prepare(sql), &params)?);
        }
        let results = async { session.batch(prepared).await }
            .into_send()
            .await
            .map_err(|error| error.to_string())?;
        let bookmark = session.get_bookmark().map_err(|error| error.to_string())?;
        let results = results
            .iter()
            .map(result_payload)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(json!({
            "results": results,
            "bookmark": bookmark,
            "agent_id": self.agent.id,
        }))
    }

    async fn schema(&self) -> Result<Value, String> {
        let input = json!({
            "sql": "SELECT type, name, tbl_name, rootpage, sql FROM sqlite_schema WHERE type IN ('table','index','view') ORDER BY type, name",
            "params": [],
        });
        self.sql(input).await
    }

    async fn blob_put(&self, input: Value) -> Result<Value, String> {
        if input.get("file").and_then(Value::as_str).is_some() {
            return Err("file uploads are only available in native clients; Worker blob.put accepts data base64".into());
        }
        let data = input
            .get("data")
            .and_then(Value::as_str)
            .ok_or_else(|| "data must be base64".to_string())?;
        let bytes = BASE64.decode(data).map_err(|error| error.to_string())?;
        let mime_type = input
            .get("mime_type")
            .and_then(Value::as_str)
            .unwrap_or("application/octet-stream")
            .to_owned();
        let name = input.get("name").and_then(Value::as_str).map(str::to_owned);
        let env = self.env.0.clone();
        let descriptor = crate::media::put_bytes(&env, &self.agent, bytes, mime_type, name)
            .await
            .map_err(|error| error.to_string())?;
        Ok(descriptor.value(None, &self.base_url))
    }

    async fn blob_get(&self, input: Value) -> Result<Value, String> {
        if input.get("output").and_then(Value::as_str).is_some() {
            return Err("output paths are only available in native clients; Worker blob.get returns data when inline is true".into());
        }
        let id = string_field(&input, "id")?;
        let inline = input
            .get("inline")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let env = self.env.0.clone();
        let ticket = crate::auth::download_ticket(&env, &self.agent, id)
            .into_send()
            .await
            .map_err(|error| error.to_string())?;
        let mut value = if inline {
            let (descriptor, bytes) = crate::media::get_bytes(&env, id)
                .await
                .map_err(|error| error.to_string())?;
            let mut value = descriptor.value(Some(ticket), &self.base_url);
            value["data"] = Value::String(BASE64.encode(&bytes));
            if descriptor.mime_type.starts_with("image/") {
                value["image_data"] = Value::String(BASE64.encode(&bytes));
            }
            if descriptor.mime_type.starts_with("audio/") {
                value["audio_data"] = Value::String(BASE64.encode(&bytes));
            }
            value
        } else {
            let descriptor = crate::media::head_blob(&env, id)
                .await
                .map_err(|error| error.to_string())?;
            descriptor.value(Some(ticket), &self.base_url)
        };
        value["agent_id"] = Value::String(self.agent.id.clone());
        Ok(value)
    }

    async fn blob_delete(&self, input: Value) -> Result<Value, String> {
        let id = string_field(&input, "id")?;
        let env = self.env.0.clone();
        let deleted = crate::media::delete_blob(&env, id)
            .await
            .map_err(|error| error.to_string())?;
        Ok(json!({"id": id, "deleted": deleted, "agent_id": self.agent.id}))
    }
}

#[async_trait]
impl comms_core::Backend for DataBackend {
    async fn call(&self, operation: &str, input: Value) -> Result<Value, String> {
        crate::auth::ensure_agent_active(&self.env, &self.agent)
            .into_send()
            .await
            .map_err(|error| error.to_string())?;
        if self.retention_mode == RetentionMode::Ephemeral
            && matches!(
                operation,
                "sql"
                    | "batch"
                    | "blob_put"
                    | "blob_delete"
                    | "question_create"
                    | "question_cancel"
                    | "question_wait"
            )
        {
            return Err("Zero-retention executions cannot write to shared durable storage".into());
        }
        match operation {
            "linear_me" | "linear_query" | "linear_inbox" => {
                if self.retention_mode == RetentionMode::Ephemeral {
                    return Err("Linear calls require direct or durable execution".into());
                }
                let env: Env = (*self.env).clone();
                let agent = self.agent.clone();
                let operation = operation.to_owned();
                async move { crate::linear::agent_call(&env, &agent, &operation, input).await }
                    .into_send()
                    .await
            }
            "slack_call" => {
                let method = string_field(&input, "method")?.to_owned();
                if self.retention_mode == RetentionMode::Durable
                    && comms_slack_runtime::is_zero_retention_method(&method)
                {
                    return Err("Slack search requires zero-retention execution; its results cannot enter a durable journal".into());
                }
                if self.retention_mode == RetentionMode::Ephemeral
                    && !comms_slack_runtime::is_zero_retention_method(&method)
                {
                    return Err("Zero-retention execution permits Slack search only; other Slack calls require direct or durable execution".into());
                }
                let params = input.get("params").cloned().unwrap_or_else(|| json!({}));
                let env: Env = (*self.env).clone();
                let agent = self.agent.clone();
                async move {
                    let backend = crate::slack::WorkerSlackBackend::from_env(env, agent)
                        .await
                        .map_err(|error| error.to_string())?;
                    backend.invoke(&method, params).await
                }
                .into_send()
                .await
            }
            "sql" => self.sql(input).await,
            "batch" => self.batch(input).await,
            "schema" => self.schema().await,
            "blob_put" => self.blob_put(input).await,
            "blob_get" => self.blob_get(input).await,
            "blob_delete" => self.blob_delete(input).await,
            other => Err(format!("unknown operation: {other}")),
        }
    }
}

fn string_field<'a>(input: &'a Value, field: &str) -> Result<&'a str, String> {
    input
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{field} must be a non-empty string"))
}

fn bind_statement(
    statement: D1PreparedStatement,
    params: &Value,
) -> Result<D1PreparedStatement, String> {
    let params = match params {
        Value::Null => return Ok(statement),
        Value::Array(params) => params,
        _ => return Err("params must be an array or null".into()),
    };
    let mut values = Vec::with_capacity(params.len());
    for (index, param) in params.iter().enumerate() {
        values.push(bind_value(param).map_err(|error| format!("params[{index}]: {error}"))?);
    }
    statement.bind(&values).map_err(|error| error.to_string())
}

fn bind_value(value: &Value) -> Result<JsValue, String> {
    match value {
        Value::Null => Ok(JsValue::NULL),
        Value::Bool(value) => Ok(JsValue::from_f64(if *value { 1.0 } else { 0.0 })),
        Value::Number(value) => value
            .as_f64()
            .map(JsValue::from_f64)
            .ok_or_else(|| "number is outside JavaScript numeric range".to_string()),
        Value::String(value) => Ok(JsValue::from_str(value)),
        Value::Object(value) => {
            let encoding = value.get("encoding").and_then(Value::as_str);
            let data = value.get("data").and_then(Value::as_str);
            match (encoding, data) {
                (Some("base64"), Some(data)) => {
                    let bytes = BASE64.decode(data).map_err(|error| error.to_string())?;
                    let array = Uint8Array::new_with_length(bytes.len() as u32);
                    array.copy_from(&bytes);
                    Ok(array.into())
                }
                _ => Err("object params must be {\"encoding\":\"base64\",\"data\":\"...\"}".into()),
            }
        }
        _ => Err(
            "params may contain only string, number, boolean, null, or base64 binary objects"
                .into(),
        ),
    }
}

fn result_value(
    result: &D1Result,
    bookmark: Option<String>,
    agent_id: &str,
) -> Result<Value, String> {
    let mut value = result_payload(result)?;
    value["bookmark"] = bookmark.map(Value::String).unwrap_or(Value::Null);
    value["agent_id"] = Value::String(agent_id.to_owned());
    Ok(value)
}

fn result_payload(result: &D1Result) -> Result<Value, String> {
    if !result.success() {
        return Err(result
            .error()
            .unwrap_or_else(|| "D1 statement failed without an error message".into()));
    }
    let rows = result
        .results::<Value>()
        .map_err(|error| error.to_string())?;
    Ok(json!({
        "success": true,
        "error": Value::Null,
        "results": rows,
        "meta": result.meta().map_err(|error| error.to_string())?.map(|meta| json!({
            "changed_db": meta.changed_db,
            "changes": meta.changes,
            "duration": meta.duration,
            "last_row_id": meta.last_row_id,
            "rows_read": meta.rows_read,
            "rows_written": meta.rows_written,
            "size_after": meta.size_after,
        })),
    }))
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex_bytes(&Sha256::digest(bytes))
}

pub(crate) fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
