//! Owner-only Slack OAuth and encrypted installation credentials.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use js_sys::{Array, Function, Object, Promise, Reflect, Uint8Array};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use worker::{Env, HttpRequest, HttpResponse};

const TEAM: &str = "TEXAMPLE";
const OWNER: &str = "UEXAMPLE";
#[derive(Deserialize)]
struct StateRow {
    state_hash: String,
}
#[derive(Deserialize)]
struct InstallationRow {
    sealed_json: String,
}

pub async fn handle(request: HttpRequest, env: Env, base: String) -> worker::Result<HttpResponse> {
    crate::auth::authenticate_owner_browser(&env, &request).await?;
    if request.method() != axum::http::Method::GET {
        return crate::auth::json_response(
            405,
            json!({"ok":false,"error":{"code":"METHOD_NOT_ALLOWED"}}),
        );
    }
    let callback = format!("{base}/owner/slack/callback");
    if request.uri().path() == "/owner/slack/install" {
        let state = crate::auth::random_token(32)?;
        let digest = hash(&state);
        let expiry = crate::auth::now_seconds() + 600;
        crate::auth::control_db(&env)?
            .prepare("INSERT INTO slack_oauth_states(state_hash, expires_at) VALUES (?1, ?2)")
            .bind(&[JsValue::from_str(&digest), JsValue::from_f64(expiry as f64)])?
            .run()
            .await?;
        let bot = include_str!("../../../slack-app-bootstrap-manifest.json");
        let manifest: Value =
            serde_json::from_str(bot).map_err(|_| error("SLACK_MANIFEST_INVALID"))?;
        let scopes = manifest
            .pointer("/oauth_config/scopes/bot")
            .and_then(Value::as_array)
            .ok_or(error("SLACK_MANIFEST_INVALID"))?
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(",");
        let user_scopes = manifest
            .pointer("/oauth_config/scopes/user")
            .and_then(Value::as_array)
            .ok_or(error("SLACK_MANIFEST_INVALID"))?
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(",");
        let client = env.var("SLACK_CLIENT_ID")?.to_string();
        let url = format!(
            "https://slack.com/oauth/v2/authorize?client_id={}&scope={}&user_scope={}&redirect_uri={}&state={}&team={}",
            encode(&client),
            encode(&scopes),
            encode(&user_scopes),
            encode(&callback),
            encode(&state),
            TEAM
        );
        return redirect(&url);
    }
    let query = request.uri().query().unwrap_or("");
    let state = parameter(query, "state").ok_or(error("SLACK_OAUTH_STATE_REQUIRED"))?;
    let code = parameter(query, "code").ok_or(error("SLACK_OAUTH_CODE_REQUIRED"))?;
    let consumed: Option<StateRow> = crate::auth::control_db(&env)?
        .prepare("DELETE FROM slack_oauth_states WHERE state_hash = ?1 AND expires_at > ?2 RETURNING state_hash")
        .bind(&[JsValue::from_str(&hash(&state)), JsValue::from_f64(crate::auth::now_seconds() as f64)])?.first(None).await?;
    if !consumed.is_some_and(|row| row.state_hash == hash(&state)) {
        return Err(error("SLACK_OAUTH_STATE_INVALID"));
    }
    let secret = env.secret("SLACK_CLIENT_SECRET")?.to_string();
    let client = env.var("SLACK_CLIENT_ID")?.to_string();
    let body = format!(
        "client_id={}&client_secret={}&code={}&redirect_uri={}",
        encode(&client),
        encode(&secret),
        encode(&code),
        encode(&callback)
    );
    let value = fetch_form(&env, &body).await?;
    if value.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(error("SLACK_OAUTH_EXCHANGE_FAILED"));
    }
    if value.pointer("/team/id").and_then(Value::as_str) != Some(TEAM)
        || value.pointer("/authed_user/id").and_then(Value::as_str) != Some(OWNER)
    {
        return Err(error("SLACK_OAUTH_INSTALLATION_MISMATCH"));
    }
    if value.get("access_token").and_then(Value::as_str).is_none()
        || value
            .pointer("/authed_user/access_token")
            .and_then(Value::as_str)
            .is_none()
    {
        return Err(error("SLACK_OAUTH_TOKENS_MISSING"));
    }
    let credentials = json!({"bot_token":value["access_token"],"user_token":value["authed_user"]["access_token"],"bot_scopes":value["scope"],"user_scopes":value["authed_user"]["scope"],"team_id":TEAM,"owner_id":OWNER});
    let sealed = seal(&env, &credentials).await?;
    crate::auth::control_db(&env)?.prepare("INSERT INTO slack_installations(team_id, owner_id, sealed_json, updated_at) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(team_id) DO UPDATE SET owner_id=excluded.owner_id, sealed_json=excluded.sealed_json, updated_at=excluded.updated_at")
        .bind(&[JsValue::from_str(TEAM), JsValue::from_str(OWNER), JsValue::from_str(&sealed), JsValue::from_f64(crate::auth::now_seconds() as f64)])?.run().await?;
    crate::auth::json_response(
        200,
        json!({"ok":true,"data":{"installed":true,"team_id":TEAM,"owner_id":OWNER}}),
    )
}

pub async fn installation(env: &Env) -> worker::Result<Value> {
    let row: Option<InstallationRow> = crate::auth::control_db(env)?
        .prepare("SELECT sealed_json FROM slack_installations WHERE team_id=?1 AND owner_id=?2")
        .bind(&[JsValue::from_str(TEAM), JsValue::from_str(OWNER)])?
        .first(None)
        .await?;
    let row = row.ok_or(error("SLACK_NOT_INSTALLED"))?;
    let sealed: Value =
        serde_json::from_str(&row.sealed_json).map_err(|_| error("SLACK_CREDENTIAL_INVALID"))?;
    let nonce = decode(
        sealed["nonce"]
            .as_str()
            .ok_or(error("SLACK_CREDENTIAL_INVALID"))?,
    )?;
    let data = decode(
        sealed["data"]
            .as_str()
            .ok_or(error("SLACK_CREDENTIAL_INVALID"))?,
    )?;
    let plaintext = crypt(env, "decrypt", &nonce, &data).await?;
    serde_json::from_slice(&plaintext).map_err(|_| error("SLACK_CREDENTIAL_INVALID"))
}
async fn seal(env: &Env, value: &Value) -> worker::Result<String> {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|_| error("RANDOM_FAILED"))?;
    let plain = serde_json::to_vec(value).map_err(|_| error("SLACK_CREDENTIAL_INVALID"))?;
    let cipher = crypt(env, "encrypt", &nonce, &plain).await?;
    Ok(json!({"version":1,"nonce":URL_SAFE_NO_PAD.encode(nonce),"data":URL_SAFE_NO_PAD.encode(cipher)}).to_string())
}
async fn crypt(env: &Env, operation: &str, nonce: &[u8], data: &[u8]) -> worker::Result<Vec<u8>> {
    if nonce.len() != 12 {
        return Err(error("SLACK_CREDENTIAL_INVALID"));
    }
    let raw = decode(&env.secret("SLACK_SEAL_KEY")?.to_string())?;
    if raw.len() != 32 {
        return Err(error("SLACK_SEAL_KEY_INVALID"));
    }
    let crypto = Reflect::get(&js_sys::global(), &JsValue::from_str("crypto"))
        .map_err(|_| error("CRYPTO_UNAVAILABLE"))?;
    let subtle = Reflect::get(&crypto, &JsValue::from_str("subtle"))
        .map_err(|_| error("CRYPTO_UNAVAILABLE"))?;
    let usages = Array::new();
    usages.push(&JsValue::from_str(operation));
    let import = function(&subtle, "importKey")?;
    let key = await_value(
        import
            .call5(
                &subtle,
                &JsValue::from_str("raw"),
                &Uint8Array::from(raw.as_slice()),
                &JsValue::from_str("AES-GCM"),
                &JsValue::FALSE,
                &usages,
            )
            .map_err(|_| error("CRYPTO_FAILED"))?,
    )
    .await?;
    let algorithm = Object::new();
    Reflect::set(
        &algorithm,
        &JsValue::from_str("name"),
        &JsValue::from_str("AES-GCM"),
    )
    .map_err(|_| error("CRYPTO_FAILED"))?;
    Reflect::set(
        &algorithm,
        &JsValue::from_str("iv"),
        &Uint8Array::from(nonce),
    )
    .map_err(|_| error("CRYPTO_FAILED"))?;
    Reflect::set(
        &algorithm,
        &JsValue::from_str("additionalData"),
        &Uint8Array::from(format!("comms/slack/v1/{TEAM}/{OWNER}").as_bytes()),
    )
    .map_err(|_| error("CRYPTO_FAILED"))?;
    let result = await_value(
        function(&subtle, operation)?
            .call3(&subtle, &algorithm, &key, &Uint8Array::from(data))
            .map_err(|_| error("CRYPTO_FAILED"))?,
    )
    .await?;
    Ok(Uint8Array::new(&result).to_vec())
}
async fn fetch_form(env: &Env, body: &str) -> worker::Result<Value> {
    let global = js_sys::global();
    let headers = Object::new();
    Reflect::set(
        &headers,
        &JsValue::from_str("content-type"),
        &JsValue::from_str("application/x-www-form-urlencoded"),
    )
    .map_err(|_| error("SLACK_OAUTH_EXCHANGE_FAILED"))?;
    let init = Object::new();
    for (name, value) in [
        ("method", JsValue::from_str("POST")),
        ("headers", headers.into()),
        ("body", JsValue::from_str(body)),
        ("redirect", JsValue::from_str("manual")),
    ] {
        Reflect::set(&init, &JsValue::from_str(name), &value)
            .map_err(|_| error("SLACK_OAUTH_EXCHANGE_FAILED"))?;
    }
    let response = await_value(
        function(&global, "fetch")?
            .call2(
                &global,
                &JsValue::from_str(&api_url(env, "oauth.v2.access")?),
                &init,
            )
            .map_err(|_| error("SLACK_OAUTH_EXCHANGE_FAILED"))?,
    )
    .await?
    .dyn_into::<web_sys::Response>()
    .map_err(|_| error("SLACK_OAUTH_EXCHANGE_FAILED"))?;
    if !response.ok() {
        return Err(error("SLACK_OAUTH_EXCHANGE_FAILED"));
    }
    let text = JsFuture::from(response.text()?)
        .await
        .map_err(|_| error("SLACK_OAUTH_EXCHANGE_FAILED"))?
        .as_string()
        .ok_or(error("SLACK_OAUTH_EXCHANGE_FAILED"))?;
    serde_json::from_str(&text).map_err(|_| error("SLACK_OAUTH_EXCHANGE_FAILED"))
}
fn function(target: &JsValue, name: &str) -> worker::Result<Function> {
    Reflect::get(target, &JsValue::from_str(name))
        .map_err(|_| error("CRYPTO_UNAVAILABLE"))?
        .dyn_into::<Function>()
        .map_err(|_| error("CRYPTO_UNAVAILABLE"))
}
async fn await_value(value: JsValue) -> worker::Result<JsValue> {
    JsFuture::from(Promise::resolve(&value))
        .await
        .map_err(|_| error("SLACK_SECRET_OPERATION_FAILED"))
}
fn hash(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn decode(value: &str) -> worker::Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| error("SLACK_CREDENTIAL_INVALID"))
}
fn error(code: &str) -> worker::Error {
    worker::Error::RustError(code.into())
}
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
fn parameter(query: &str, key: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| *k == key)
        .and_then(|(_, v)| {
            let bytes = v.as_bytes();
            let mut out = Vec::new();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'%' {
                    if i + 2 >= bytes.len() {
                        return None;
                    }
                    out.push(
                        u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).ok()?, 16)
                            .ok()?,
                    );
                    i += 3;
                } else {
                    out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
                    i += 1;
                }
            }
            String::from_utf8(out).ok()
        })
}
fn redirect(url: &str) -> worker::Result<HttpResponse> {
    let mut r = axum::http::Response::builder()
        .status(302)
        .header("location", url)
        .header("cache-control", "no-store")
        .header("referrer-policy", "no-referrer")
        .body(worker::Body::empty())
        .map_err(|_| error("REDIRECT_FAILED"))?;
    r.headers_mut()
        .insert("x-content-type-options", "nosniff".parse().unwrap());
    Ok(r)
}

pub fn api_url(env: &Env, method: &str) -> worker::Result<String> {
    if !method
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._".contains(&b))
    {
        return Err(error("SLACK_METHOD_INVALID"));
    }
    if env
        .var("SLACK_FIXTURE_MODE")
        .map(|v| v.to_string() == "1")
        .unwrap_or(false)
    {
        let origin = env.var("SLACK_API_ORIGIN")?.to_string();
        let uri: axum::http::Uri = origin
            .parse()
            .map_err(|_| error("SLACK_FIXTURE_ORIGIN_INVALID"))?;
        if uri.scheme_str() != Some("http")
            || !matches!(uri.host(), Some("127.0.0.1" | "localhost"))
            || uri.query().is_some()
            || uri.path() != "/"
        {
            return Err(error("SLACK_FIXTURE_ORIGIN_INVALID"));
        }
        return Ok(format!("{}/api/{method}", origin.trim_end_matches('/')));
    }
    Ok(format!("https://slack.com/api/{method}"))
}
