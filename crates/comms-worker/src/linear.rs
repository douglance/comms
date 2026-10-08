//! Hosted Linear OAuth, encrypted per-agent credentials, and durable webhook inbox.
use axum::http::Method;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wasm_bindgen::JsValue;
use worker::{Env, Fetch, HttpRequest, HttpResponse, Request, RequestInit};

#[derive(Deserialize)]
struct AppRow {
    agent_id: String,
    profile_name: String,
    role: String,
    workspace_slug: String,
    organization_id: String,
    app_user_id: String,
    client_id: String,
    sealed_json: String,
}
#[derive(Deserialize)]
struct StateRow {
    agent_id: String,
    client_id: String,
}
#[derive(Deserialize)]
struct Register {
    agent_id: String,
    role: String,
    workspace_slug: String,
    client_id: String,
    client_secret: String,
    webhook_secret: Option<String>,
}
#[derive(Deserialize)]
struct Transfer {
    from_agent_id: String,
    to_agent_id: String,
}
#[derive(Deserialize)]
struct ProfileRow {
    profile_name: String,
}

fn err(code: &str) -> worker::Error {
    worker::Error::RustError(code.into())
}
fn endpoints(env: &Env) -> worker::Result<(String, String)> {
    comms_linear::endpoints(&env.var("COMMS_PUBLIC_URL")?.to_string()).map_err(err)
}
fn seal_key(env: &Env) -> worker::Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(env.secret("LINEAR_SEAL_KEY")?.to_string())
        .map_err(|_| err("LINEAR_SEAL_KEY_INVALID"))
}
fn encrypt(env: &Env, agent: &str, value: &Value) -> worker::Result<String> {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|_| err("RANDOM_FAILED"))?;
    comms_linear::seal(&seal_key(env)?, &nonce, agent, value).map_err(err)
}
fn decrypt(env: &Env, app: &AppRow) -> worker::Result<Value> {
    comms_linear::unseal(&seal_key(env)?, &app.agent_id, &app.sealed_json).map_err(err)
}
async fn app(env: &Env, agent: &str) -> worker::Result<AppRow> {
    crate::auth::control_db(env)?
        .prepare("SELECT * FROM linear_apps WHERE agent_id=?1")
        .bind(&[JsValue::from_str(agent)])?
        .first(None)
        .await?
        .ok_or_else(|| err("LINEAR_APP_NOT_INSTALLED"))
}
fn metadata(env: &Env, app: &AppRow) -> worker::Result<Value> {
    let (callback, events) = endpoints(env)?;
    Ok(json!({
        "agent_id": app.agent_id, "profile_name": app.profile_name,
        "role": app.role, "workspace_slug": app.workspace_slug,
        "organization_id": app.organization_id, "app_user_id": app.app_user_id,
        "client_id": app.client_id, "callback_url": callback,
        "webhook_url": format!("{events}?agent_id={}", encode(&app.agent_id)),
    }))
}
async fn body(request: HttpRequest) -> worker::Result<Vec<u8>> {
    http_body_util::Limited::new(request.into_body(), 1024 * 1024)
        .collect()
        .await
        .map(|value| value.to_bytes().to_vec())
        .map_err(|_| err("LINEAR_REQUEST_TOO_LARGE"))
}
fn parameter(request: &HttpRequest, key: &str) -> Option<String> {
    url::form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes())
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}
fn encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
fn hash(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
async fn post(
    url: &str,
    content_type: &str,
    body: String,
    token: Option<&str>,
) -> worker::Result<Value> {
    let headers = worker::Headers::new();
    headers.set("content-type", content_type)?;
    if let Some(token) = token {
        headers.set("authorization", &format!("Bearer {token}"))?;
    }
    let mut init = RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(&body)));
    let mut response = Fetch::Request(Request::new_with_init(url, &init)?)
        .send()
        .await?;
    if !(200..300).contains(&response.status_code()) {
        return Err(err("LINEAR_PROVIDER_FAILED"));
    }
    response
        .json::<Value>()
        .await
        .map_err(|_| err("LINEAR_PROVIDER_FAILED"))
}
async fn token(credentials: &Value) -> worker::Result<String> {
    let client = credentials["client_id"]
        .as_str()
        .ok_or_else(|| err("LINEAR_CREDENTIAL_INVALID"))?;
    let secret = credentials["client_secret"]
        .as_str()
        .ok_or_else(|| err("LINEAR_CREDENTIAL_INVALID"))?;
    let form = format!(
        "grant_type=client_credentials&client_id={}&client_secret={}&scope={}",
        encode(client),
        encode(secret),
        encode("read,write,app:assignable,app:mentionable")
    );
    let value = post(
        "https://api.linear.app/oauth/token",
        "application/x-www-form-urlencoded",
        form,
        None,
    )
    .await?;
    value["access_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| err("LINEAR_TOKEN_FAILED"))
}
async fn revoke(token: &str) -> worker::Result<()> {
    let headers = worker::Headers::new();
    headers.set("content-type", "application/x-www-form-urlencoded")?;
    let mut init = RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(&format!(
            "token={}&token_type_hint=access_token",
            encode(token),
        ))));
    let response = Fetch::Request(Request::new_with_init(
        "https://api.linear.app/oauth/revoke",
        &init,
    )?)
    .send()
    .await?;
    if response.status_code() != 200 {
        return Err(err("LINEAR_TOKEN_REVOKE_FAILED"));
    }
    Ok(())
}

async fn graphql(token: &str, input: Value) -> worker::Result<Value> {
    let (mut result, cleanup) = comms_linear::use_and_revoke(
        token.to_owned(),
        |token| async move {
            post(
                "https://api.linear.app/graphql",
                "application/json",
                input.to_string(),
                Some(&token),
            )
            .await
        },
        |token| async move { revoke(&token).await },
    )
    .await;
    if cleanup.is_err() {
        worker::console_error!("LINEAR_TOKEN_REVOKE_FAILED");
        if let Ok(value) = &mut result {
            let extensions = value
                .as_object_mut()
                .ok_or_else(|| err("LINEAR_PROVIDER_FAILED"))?
                .entry("extensions")
                .or_insert_with(|| json!({}));
            if let Some(extensions) = extensions.as_object_mut() {
                extensions.insert(
                    "comms_token_cleanup".into(),
                    json!({
                        "ok": false,
                        "code": "LINEAR_TOKEN_REVOKE_FAILED",
                        "operation_must_not_be_replayed": true,
                    }),
                );
            }
        }
    }
    result
}
async fn identity(token: &str, role: &str, workspace: &str) -> worker::Result<Value> {
    let provider = graphql(
        token,
        json!({"query":"{ viewer { id name } organization { id urlKey } }"}),
    )
    .await?;
    comms_linear::verify_identity(&provider, role, workspace).map_err(err)
}

pub async fn owner(request: HttpRequest, env: Env, base: String) -> worker::Result<HttpResponse> {
    crate::auth::authenticate_owner(&env, &request, &base).await?;
    match (request.method().as_str(), request.uri().path()) {
        ("POST", "/owner/linear/apps") => {
            let input: Register = serde_json::from_slice(&body(request).await?)
                .map_err(|_| err("LINEAR_REQUEST_INVALID"))?;
            if input.role.is_empty() || input.role.len() > 80 || input.workspace_slug.is_empty() {
                return Err(err("LINEAR_REQUEST_INVALID"));
            }
            let profile: ProfileRow = crate::auth::control_db(&env)?
                .prepare("SELECT profile_name FROM agents WHERE id=?1 AND revoked_at IS NULL AND expires_at>?2 AND profile_name IS NOT NULL")
                .bind(&[JsValue::from_str(&input.agent_id), JsValue::from_f64(crate::auth::now_seconds() as f64)])?
                .first(None).await?.ok_or_else(|| err("LINEAR_AGENT_NOT_FOUND"))?;
            let credentials = json!({
                "client_id": input.client_id, "client_secret": input.client_secret,
                "webhook_secret": input.webhook_secret,
            });
            let bearer = token(&credentials).await?;
            let verified = identity(&bearer, &input.role, &input.workspace_slug).await?;
            let sealed = encrypt(&env, &input.agent_id, &credentials)?;
            crate::auth::control_db(&env)?
                .prepare("INSERT INTO linear_apps(agent_id,profile_name,role,workspace_slug,organization_id,app_user_id,client_id,sealed_json,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(agent_id) DO UPDATE SET profile_name=excluded.profile_name,role=excluded.role,workspace_slug=excluded.workspace_slug,organization_id=excluded.organization_id,app_user_id=excluded.app_user_id,client_id=excluded.client_id,sealed_json=excluded.sealed_json,updated_at=excluded.updated_at")
                .bind(&[
                    JsValue::from_str(&input.agent_id), JsValue::from_str(&profile.profile_name),
                    JsValue::from_str(&input.role), JsValue::from_str(&input.workspace_slug),
                    JsValue::from_str(verified["organization_id"].as_str().unwrap()),
                    JsValue::from_str(verified["app_user_id"].as_str().unwrap()),
                    JsValue::from_str(&input.client_id), JsValue::from_str(&sealed),
                    JsValue::from_f64(crate::auth::now_seconds() as f64),
                ])?.run().await?;
            crate::auth::json_response(
                200,
                json!({"ok":true,"data":metadata(&env, &app(&env, &input.agent_id).await?)?}),
            )
        }
        ("POST", "/owner/linear/apps/transfer") => {
            let input: Transfer = serde_json::from_slice(&body(request).await?)
                .map_err(|_| err("LINEAR_REQUEST_INVALID"))?;
            if input.from_agent_id == input.to_agent_id {
                return crate::auth::json_response(
                    400,
                    json!({
                        "ok": false,
                        "error": {"code": "LINEAR_TRANSFER_INVALID"},
                    }),
                );
            }
            let previous = app(&env, &input.from_agent_id).await?;
            let sealed = encrypt(&env, &input.to_agent_id, &decrypt(&env, &previous)?)?;
            let db = crate::auth::control_db(&env)?;
            let transfer = db.prepare(comms_linear::TRANSFER_APP_SQL).bind(&[
                JsValue::from_str(&input.to_agent_id),
                JsValue::from_str(&sealed),
                JsValue::from_f64(crate::auth::now_seconds() as f64),
                JsValue::from_str(&input.from_agent_id),
                JsValue::from_str(&previous.profile_name),
            ])?;
            let discard_states = db
                .prepare("DELETE FROM linear_oauth_states WHERE agent_id=?1 AND client_id=?2")
                .bind(&[
                    JsValue::from_str(&input.to_agent_id),
                    JsValue::from_str(&previous.client_id),
                ])?;
            let results = db.batch(vec![transfer, discard_states]).await?;
            let changed = results
                .first()
                .ok_or_else(|| err("LINEAR_TRANSFER_FAILED"))?
                .results::<Value>()?;
            if changed.first().and_then(|v| v["agent_id"].as_str())
                != Some(input.to_agent_id.as_str())
            {
                return crate::auth::json_response(
                    409,
                    json!({
                        "ok": false,
                        "error": {"code": "LINEAR_TRANSFER_TARGET_INVALID"},
                    }),
                );
            }
            crate::auth::json_response(
                200,
                json!({
                    "ok": true,
                    "data": metadata(&env, &app(&env, &input.to_agent_id).await?)?,
                }),
            )
        }
        ("GET", "/owner/linear/apps") => {
            let rows = crate::auth::control_db(&env)?
                .prepare("SELECT * FROM linear_apps ORDER BY role")
                .all()
                .await?
                .results::<AppRow>()?;
            let apps = rows
                .iter()
                .map(|row| metadata(&env, row))
                .collect::<worker::Result<Vec<_>>>()?;
            crate::auth::json_response(200, json!({"ok":true,"data":{"apps":apps}}))
        }
        ("GET", "/owner/linear/install") => {
            let agent =
                parameter(&request, "agent_id").ok_or_else(|| err("LINEAR_REQUEST_INVALID"))?;
            let app = app(&env, &agent).await?;
            let state = crate::auth::random_token(32)?;
            crate::auth::control_db(&env)?
                .prepare("INSERT INTO linear_oauth_states(state_hash,agent_id,client_id,expires_at) VALUES (?1,?2,?3,?4)")
                .bind(&[JsValue::from_str(&hash(&state)),JsValue::from_str(&agent),JsValue::from_str(&app.client_id),JsValue::from_f64((crate::auth::now_seconds()+600) as f64)])?.run().await?;
            let callback = endpoints(&env)?.0;
            let location = format!(
                "https://linear.app/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&actor=app&scope={}&state={}",
                encode(&app.client_id),
                encode(&callback),
                encode("read,write,app:assignable,app:mentionable"),
                encode(&state)
            );
            axum::http::Response::builder()
                .status(302)
                .header("location", location)
                .body(worker::Body::empty())
                .map_err(|_| err("LINEAR_REDIRECT_FAILED"))
        }
        _ => crate::auth::json_response(
            405,
            json!({"ok":false,"error":{"code":"METHOD_NOT_ALLOWED"}}),
        ),
    }
}

pub async fn callback(request: HttpRequest, env: Env) -> worker::Result<HttpResponse> {
    if request.method() != Method::GET {
        return crate::auth::json_response(405, json!({"ok":false}));
    }
    let state = parameter(&request, "state").ok_or_else(|| err("LINEAR_STATE_INVALID"))?;
    let code = parameter(&request, "code").ok_or_else(|| err("LINEAR_REQUEST_INVALID"))?;
    let state:StateRow=crate::auth::control_db(&env)?
        .prepare("DELETE FROM linear_oauth_states WHERE state_hash=?1 AND expires_at>?2 RETURNING agent_id,client_id")
        .bind(&[JsValue::from_str(&hash(&state)),JsValue::from_f64(crate::auth::now_seconds() as f64)])?
        .first(None).await?.ok_or_else(||err("LINEAR_STATE_INVALID"))?;
    let app = app(&env, &state.agent_id).await?;
    if app.client_id != state.client_id {
        return Err(err("LINEAR_STATE_INVALID"));
    }
    let credentials = decrypt(&env, &app)?;
    let form = format!(
        "grant_type=authorization_code&client_id={}&client_secret={}&code={}&redirect_uri={}",
        encode(&app.client_id),
        encode(
            credentials["client_secret"]
                .as_str()
                .ok_or_else(|| err("LINEAR_CREDENTIAL_INVALID"))?
        ),
        encode(&code),
        encode(&endpoints(&env)?.0)
    );
    let tokens = post(
        "https://api.linear.app/oauth/token",
        "application/x-www-form-urlencoded",
        form,
        None,
    )
    .await?;
    let bearer = tokens["access_token"]
        .as_str()
        .ok_or_else(|| err("LINEAR_TOKEN_FAILED"))?;
    let verified = identity(bearer, &app.role, &app.workspace_slug).await?;
    if verified["app_user_id"].as_str() != Some(&app.app_user_id) {
        return Err(err("LINEAR_IDENTITY_MISMATCH"));
    }
    // The verification call has already revoked this temporary callback token.
    crate::auth::json_response(
        200,
        json!({"ok":true,"data":{"installed":true,"identity":verified}}),
    )
}

pub async fn events(request: HttpRequest, env: Env) -> worker::Result<HttpResponse> {
    if request.method() != Method::POST {
        return crate::auth::json_response(405, json!({"ok":false}));
    }
    let agent = parameter(&request, "agent_id").ok_or_else(|| err("LINEAR_REQUEST_INVALID"))?;
    let app = app(&env, &agent).await?;
    let signature = request
        .headers()
        .get("linear-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let raw = body(request).await?;
    let credentials = decrypt(&env, &app)?;
    let secret = credentials["webhook_secret"]
        .as_str()
        .ok_or_else(|| err("LINEAR_WEBHOOK_NOT_CONFIGURED"))?;
    let payload = comms_linear::verify_webhook(
        secret.as_bytes(),
        &signature,
        &raw,
        (js_sys::Date::now()) as i64,
        &app.organization_id,
    )
    .map_err(err)?;
    // Deduplicate the verified event even if a retry has a new signed timestamp.
    let digest = comms_linear::event_key(&payload).map_err(err)?;
    crate::auth::control_db(&env)?
        .prepare("INSERT OR IGNORE INTO linear_events(agent_id,event_hash,payload_json,received_at) VALUES (?1,?2,?3,?4)")
        .bind(&[JsValue::from_str(&agent),JsValue::from_str(&digest),JsValue::from_str(&payload.to_string()),JsValue::from_f64(crate::auth::now_seconds() as f64)])?
        .run().await?;
    crate::auth::json_response(200, json!({"ok":true}))
}

pub async fn agent_call(
    env: &Env,
    agent: &crate::auth::Agent,
    method: &str,
    input: Value,
) -> Result<Value, String> {
    crate::auth::ensure_agent_active(env, agent)
        .await
        .map_err(|_| "UNAUTHORIZED".to_owned())?;
    let app = app(env, &agent.id).await.map_err(|e| e.to_string())?;
    match method {
        "linear_me" => metadata(env, &app).map_err(|e| e.to_string()),
        "linear_query" => {
            let query = input["query"]
                .as_str()
                .filter(|q| !q.trim().is_empty())
                .ok_or("LINEAR_QUERY_REQUIRED")?;
            if query.len() > 64 * 1024 {
                return Err("LINEAR_REQUEST_TOO_LARGE".into());
            }
            let credentials = decrypt(env, &app).map_err(|e| e.to_string())?;
            let bearer = token(&credentials).await.map_err(|e| e.to_string())?;
            graphql(&bearer,json!({"query":query,"variables":input.get("variables").cloned().unwrap_or(json!({}))})).await.map_err(|e|e.to_string())
        }
        "linear_inbox" => {
            let cursor = input.get("cursor").and_then(Value::as_u64).unwrap_or(0);
            if cursor > i64::MAX as u64 {
                return Err("LINEAR_CURSOR_INVALID".into());
            }
            let limit = input
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(20)
                .clamp(1, 100);
            let rows=crate::auth::control_db(env).map_err(|e|e.to_string())?
                .prepare("SELECT sequence,payload_json,received_at FROM linear_events WHERE agent_id=?1 AND sequence>?2 ORDER BY sequence LIMIT ?3")
                .bind(&[JsValue::from_str(&agent.id),JsValue::from_f64(cursor as f64),JsValue::from_f64(limit as f64)]).map_err(|e|e.to_string())?
                .all().await.map_err(|e|e.to_string())?.results::<Value>().map_err(|e|e.to_string())?;
            let mut next = cursor;
            let mut events = Vec::new();
            for row in rows {
                next = row["sequence"].as_u64().ok_or("LINEAR_EVENT_INVALID")?;
                let payload: Value = serde_json::from_str(
                    row["payload_json"].as_str().ok_or("LINEAR_EVENT_INVALID")?,
                )
                .map_err(|_| "LINEAR_EVENT_INVALID")?;
                events.push(
                    json!({"cursor":next,"received_at":row["received_at"],"payload":payload}),
                );
            }
            Ok(json!({"events":events,"cursor":next}))
        }
        _ => Err("LINEAR_METHOD_INVALID".into()),
    }
}
