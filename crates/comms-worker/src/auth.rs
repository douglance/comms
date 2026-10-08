use std::convert::TryInto;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::{BigUint, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::Response as WebResponse;

use worker::{Env, HttpRequest, HttpResponse};

const CONTROL_BINDING: &str = "CONTROL";
const OWNER_TOKEN_SECONDS: i64 = 30 * 24 * 60 * 60;
const DEVICE_SECONDS: i64 = 10 * 60;
const INVITE_SECONDS: i64 = 10 * 60;
const DEFAULT_AGENT_SECONDS: i64 = 24 * 60 * 60;
const DOWNLOAD_TICKET_SECONDS: i64 = 5 * 60;

#[derive(Clone, Debug, Serialize)]
pub struct Agent {
    pub id: String,
    pub label: Option<String>,
    pub expires_at: i64,
}

#[derive(Deserialize)]
struct AgentRow {
    id: String,
    label: Option<String>,
    expires_at: i64,
}

#[derive(Deserialize)]
struct DownloadAgentRow {
    id: String,
    label: Option<String>,
    expires_at: i64,
}

#[derive(Deserialize)]
struct DevicePoll {
    device_code: String,
}

#[derive(Deserialize)]
struct InviteRequest {
    label: Option<String>,
    ttl_seconds: Option<i64>,
}

#[derive(Deserialize)]
struct JoinRequest {
    invitation: Option<String>,
    enrollment: Option<String>,
    label: Option<String>,
    profile_name: Option<String>,
}

#[derive(Deserialize)]
struct RevokeRequest {
    id: String,
}

#[derive(Deserialize)]
struct AgentJoinRow {
    id: String,
    label: Option<String>,
    expires_at: i64,
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    kid: String,
}

#[derive(Deserialize)]
struct AccessClaims {
    aud: Value,
    iss: String,
    exp: i64,
    nbf: Option<i64>,
    email: String,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    n: String,
    e: String,
    alg: Option<String>,
}

pub async fn authenticate_agent(env: &Env, request: &HttpRequest) -> worker::Result<Agent> {
    let token = bearer_token(request).ok_or_else(|| err("UNAUTHORIZED"))?;
    let token_hash = sha256_hex(token.as_bytes());
    let now = now_seconds();
    let db = control_db(env)?;
    let row: Option<AgentRow> = db
        .prepare("SELECT id, label, expires_at FROM agents WHERE token_hash = ?1 AND expires_at > ?2 AND revoked_at IS NULL")
        .bind(&[JsValue::from_str(&token_hash), JsValue::from_f64(now as f64)])?
        .first(None)
        .await?;
    row.map(|row| Agent {
        id: row.id,
        label: row.label,
        expires_at: row.expires_at,
    })
    .ok_or_else(|| err("UNAUTHORIZED"))
}

pub async fn ensure_agent_active(env: &Env, agent: &Agent) -> worker::Result<()> {
    let now = now_seconds();
    let db = control_db(env)?;
    let row: Option<AgentRow> = db
        .prepare("SELECT id, label, expires_at FROM agents WHERE id = ?1 AND expires_at > ?2 AND revoked_at IS NULL")
        .bind(&[JsValue::from_str(&agent.id), JsValue::from_f64(now as f64)])?
        .first(None)
        .await?;

    match row {
        Some(_) => Ok(()),
        None => Err(err("UNAUTHORIZED")),
    }
}

pub async fn authenticate_download_request(
    env: &Env,
    request: &HttpRequest,
) -> worker::Result<Agent> {
    let ticket = query_param(request.uri().query(), "ticket").ok_or_else(|| err("UNAUTHORIZED"))?;
    let blob_id = request
        .uri()
        .path()
        .strip_prefix("/media/")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| err("INVALID_BLOB_ROUTE"))?;
    let now = now_seconds();
    let row: Option<DownloadAgentRow> = control_db(env)?
        .prepare(
            "SELECT agents.id, agents.label, agents.expires_at \
             FROM downloads JOIN agents ON agents.id = downloads.agent_id \
             WHERE downloads.token_hash = ?1 AND downloads.blob_id = ?2 AND downloads.expires_at > ?3 \
             AND agents.expires_at > ?3 AND agents.revoked_at IS NULL",
        )
        .bind(&[
            JsValue::from_str(&sha256_hex(ticket.as_bytes())),
            JsValue::from_str(blob_id),
            JsValue::from_f64(now as f64),
        ])?
        .first(None)
        .await?;
    row.map(|row| Agent {
        id: row.id,
        label: row.label,
        expires_at: row.expires_at,
    })
    .ok_or_else(|| err("UNAUTHORIZED"))
}

pub async fn download_ticket(env: &Env, agent: &Agent, blob_id: &str) -> worker::Result<String> {
    let ticket = random_token(32)?;
    let token_hash = sha256_hex(ticket.as_bytes());
    let expires_at = now_seconds() + DOWNLOAD_TICKET_SECONDS;
    let result = control_db(env)?
        .prepare("INSERT INTO downloads(token_hash, agent_id, blob_id, expires_at) VALUES (?1, ?2, ?3, ?4)")
        .bind(&[
            JsValue::from_str(&token_hash),
            JsValue::from_str(&agent.id),
            JsValue::from_str(blob_id),
            JsValue::from_f64(expires_at as f64),
        ])?
        .run()
        .await?;
    if result.success() {
        Ok(ticket)
    } else {
        Err(err("TICKET_CREATE_FAILED"))
    }
}

pub fn is_auth_route(path: &str) -> bool {
    path.starts_with("/auth/")
        || path.starts_with("/owner/")
        || path == "/agent/join"
        || path == "/agent/renew"
}

pub(crate) async fn authenticate_owner_browser(
    env: &Env,
    request: &HttpRequest,
) -> worker::Result<()> {
    let base = request_base(request);
    verify_access_request(env, request, &base).await
}

pub async fn handle(request: HttpRequest, env: Env, base: String) -> worker::Result<HttpResponse> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let result = match (method.as_str(), path.as_str()) {
        ("POST", "/auth/start") => auth_start(&env, &base).await,
        ("GET", "/owner/login") => owner_login(request, env, base).await,
        ("POST", "/owner/approve") => owner_approve(request, env, base).await,
        ("POST", "/auth/poll") => auth_poll(request, env).await,
        ("POST", "/owner/invite") => owner_invite(request, env, base).await,
        ("POST", "/owner/enrollments") => {
            authenticate_owner(&env, &request, &base).await?;
            crate::enrollment::owner_create(request, env).await
        }
        ("POST", "/agent/join") => agent_join(request, env).await,
        ("POST", "/agent/renew") => crate::enrollment::renew(request, env).await,
        ("POST", "/owner/revoke") => owner_revoke(request, env, base).await,
        _ => json_response(404, json!({"ok":false,"error":{"code":"NOT_FOUND"}})),
    };
    match result {
        Ok(response) => Ok(response),
        Err(error) => error_response_for(error),
    }
}

async fn auth_start(env: &Env, base: &str) -> worker::Result<HttpResponse> {
    let device_code = random_token(32)?;
    let user_code = random_code(8)?;
    let expires_at = now_seconds() + DEVICE_SECONDS;
    let result = control_db(env)?
        .prepare("INSERT INTO devices(device_hash, user_code, expires_at, approved, consumed) VALUES (?1, ?2, ?3, 0, 0)")
        .bind(&[
            JsValue::from_str(&sha256_hex(device_code.as_bytes())),
            JsValue::from_str(&user_code),
            JsValue::from_f64(expires_at as f64),
        ])?
        .run()
        .await?;
    if !result.success() {
        return json_response(
            500,
            json!({"ok":false,"error":{"code":"DEVICE_CREATE_FAILED"}}),
        );
    }
    success_response(
        200,
        json!({
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": format!("{base}/owner/login?code={user_code}"),
            "expires_at": expires_at
        }),
    )
}

async fn owner_login(request: HttpRequest, env: Env, base: String) -> worker::Result<HttpResponse> {
    verify_access_request(&env, &request, &base).await?;
    let code = query_param(request.uri().query(), "code").ok_or_else(|| err("MISSING_CODE"))?;
    let now = now_seconds();
    let exists: Option<Value> = control_db(&env)?
        .prepare("SELECT user_code FROM devices WHERE user_code = ?1 AND expires_at > ?2 AND consumed = 0")
        .bind(&[JsValue::from_str(&code), JsValue::from_f64(now as f64)])?
        .first(None)
        .await?;
    if exists.is_none() {
        return json_response(404, json!({"ok":false,"error":{"code":"DEVICE_NOT_FOUND"}}));
    }
    html_response(
        200,
        &format!(
            r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Approve device · comms</title></head><body style="font-family:system-ui,sans-serif;line-height:1.5;margin:0;color:#172020;background:#f6f8f7"><main style="max-width:32rem;margin:12vh auto;padding:2rem"><h1>Approve this device</h1><p>This lets the device enroll agents in your shared comms database and media store.</p><p>Check that this matches the code in your terminal:</p><p style="font-family:monospace;font-size:1.75rem;letter-spacing:.15em"><strong>{}</strong></p><form method="post" action="/owner/approve"><input type="hidden" name="code" value="{}"><button type="submit" style="min-height:44px;padding:.65rem 1rem;font:inherit;background:#174d3e;color:white;border:0;border-radius:6px">Approve device</button></form><p>If you did not start this login, close this page.</p></main></body></html>"#,
            html_escape(&code),
            html_escape(&code),
        ),
    )
}

async fn owner_approve(
    request: HttpRequest,
    env: Env,
    base: String,
) -> worker::Result<HttpResponse> {
    let is_form = request
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/x-www-form-urlencoded"));
    verify_same_origin(&request, &base)?;
    verify_access_request(&env, &request, &base).await?;
    let body = body_text(request).await?;
    let user_code = form_value(&body, "user_code")
        .or_else(|| form_value(&body, "code"))
        .or_else(|| json_field(&body, "user_code"))
        .or_else(|| json_field(&body, "code"))
        .ok_or_else(|| err("MISSING_USER_CODE"))?;
    let now = now_seconds();
    let result = control_db(&env)?
        .prepare("UPDATE devices SET approved = 1 WHERE user_code = ?1 AND expires_at > ?2 AND consumed = 0")
        .bind(&[JsValue::from_str(&user_code), JsValue::from_f64(now as f64)])?
        .run()
        .await?;
    if result.meta()?.and_then(|meta| meta.changes).unwrap_or(0) == 0 {
        return json_response(404, json!({"ok":false,"error":{"code":"DEVICE_NOT_FOUND"}}));
    }
    if is_form {
        return html_response(
            200,
            r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Device approved · comms</title></head><body style="font-family:system-ui,sans-serif;line-height:1.5;margin:0;color:#172020;background:#f6f8f7"><main style="max-width:32rem;margin:12vh auto;padding:2rem"><h1>Device approved</h1><p>Return to your terminal and finish the login with the device code from <code>comms auth login</code>.</p><p>You can close this page.</p></main></body></html>"#,
        );
    }
    success_response(200, json!({"user_code": user_code}))
}

async fn auth_poll(request: HttpRequest, env: Env) -> worker::Result<HttpResponse> {
    let input: DevicePoll = json_body(request).await?;
    let device_hash = sha256_hex(input.device_code.as_bytes());
    let now = now_seconds();
    let owner_token = random_token(32)?;
    let owner_hash = sha256_hex(owner_token.as_bytes());
    let expires_at = now
        .checked_add(OWNER_TOKEN_SECONDS)
        .ok_or_else(|| err("OWNER_TOKEN_EXPIRY_OVERFLOW"))?;
    let db = control_db(&env)?;
    let insert = db
        .prepare(
            "INSERT INTO owners(token_hash, expires_at) \
             SELECT ?1, ?2 WHERE EXISTS (\
               SELECT 1 FROM devices WHERE device_hash = ?3 AND approved = 1 AND consumed = 0 AND expires_at > ?4\
             ) RETURNING token_hash",
        )
        .bind(&[
            JsValue::from_str(&owner_hash),
            JsValue::from_f64(expires_at as f64),
            JsValue::from_str(&device_hash),
            JsValue::from_f64(now as f64),
        ])?;
    let consume = db
        .prepare(
            "UPDATE devices SET consumed = 1 \
             WHERE device_hash = ?1 AND approved = 1 AND consumed = 0 AND expires_at > ?2 \
             AND EXISTS (SELECT 1 FROM owners WHERE token_hash = ?3)",
        )
        .bind(&[
            JsValue::from_str(&device_hash),
            JsValue::from_f64(now as f64),
            JsValue::from_str(&owner_hash),
        ])?;
    let results = db.batch(vec![insert, consume]).await?;
    let inserted = results
        .first()
        .ok_or_else(|| err("OWNER_TOKEN_CREATE_FAILED"))?
        .results::<Value>()?;
    if inserted.is_empty() {
        return pending_response();
    }
    success_response(
        200,
        json!({"owner_token": owner_token, "expires_at": expires_at}),
    )
}

async fn owner_invite(
    request: HttpRequest,
    env: Env,
    base: String,
) -> worker::Result<HttpResponse> {
    authenticate_owner(&env, &request, &base).await?;
    let input: InviteRequest = json_body(request).await?;
    let now = now_seconds();
    let ttl_seconds = input.ttl_seconds.unwrap_or(DEFAULT_AGENT_SECONDS);
    if ttl_seconds <= 0 || now.checked_add(ttl_seconds).is_none() {
        return Err(err("INVALID_TTL_SECONDS"));
    }
    let invitation = random_token(32)?;
    let expires_at = now
        .checked_add(INVITE_SECONDS)
        .ok_or_else(|| err("INVITE_EXPIRY_OVERFLOW"))?;
    let result = control_db(&env)?
        .prepare("INSERT INTO invitations(token_hash, label, expires_at, ttl_seconds) VALUES (?1, ?2, ?3, ?4)")
        .bind(&[
            JsValue::from_str(&sha256_hex(invitation.as_bytes())),
            optional_js_string(input.label.as_deref()),
            JsValue::from_f64(expires_at as f64),
            JsValue::from_f64(ttl_seconds as f64),
        ])?
        .run()
        .await?;
    if !result.success() {
        return Err(err("INVITE_CREATE_FAILED"));
    }
    success_response(
        200,
        json!({"invitation": invitation, "expires_at": expires_at, "ttl_seconds": ttl_seconds}),
    )
}

async fn agent_join(request: HttpRequest, env: Env) -> worker::Result<HttpResponse> {
    let input: JoinRequest = json_body(request).await?;
    let Some(invitation) = input.invitation else {
        let Some(enrollment) = input.enrollment else {
            return json_response(
                400,
                json!({"ok":false,"error":{"code":"MISSING_INVITATION"}}),
            );
        };
        return crate::enrollment::join(&env, enrollment, input.label, input.profile_name).await;
    };
    let invite_hash = sha256_hex(invitation.as_bytes());
    let now = now_seconds();
    let agent_id = format!("agent_{}", random_hex(16)?);
    let token = random_token(32)?;
    let token_hash = sha256_hex(token.as_bytes());
    let db = control_db(&env)?;
    let insert = db
        .prepare(
            "INSERT INTO agents(id, token_hash, label, expires_at, revoked_at) \
             SELECT ?1, ?2, COALESCE(?3, label), ?4 + ttl_seconds, NULL \
             FROM invitations WHERE token_hash = ?5 AND expires_at > ?4 \
             RETURNING id, label, expires_at",
        )
        .bind(&[
            JsValue::from_str(&agent_id),
            JsValue::from_str(&token_hash),
            optional_js_string(input.label.as_deref()),
            JsValue::from_f64(now as f64),
            JsValue::from_str(&invite_hash),
        ])?;
    let consume = db
        .prepare("DELETE FROM invitations WHERE token_hash = ?1 AND EXISTS (SELECT 1 FROM agents WHERE id = ?2)")
        .bind(&[JsValue::from_str(&invite_hash), JsValue::from_str(&agent_id)])?;
    let results = db.batch(vec![insert, consume]).await?;
    let rows = results
        .first()
        .ok_or_else(|| err("AGENT_CREATE_FAILED"))?
        .results::<AgentJoinRow>()?;
    let row = match rows.into_iter().next() {
        Some(row) => row,
        None => {
            return json_response(
                401,
                json!({"ok":false,"error":{"code":"INVITATION_INVALID"}}),
            );
        }
    };
    success_response(
        200,
        json!({"agent_id": row.id, "label": row.label, "token": token, "expires_at": row.expires_at}),
    )
}

async fn owner_revoke(
    request: HttpRequest,
    env: Env,
    base: String,
) -> worker::Result<HttpResponse> {
    authenticate_owner(&env, &request, &base).await?;
    let input: RevokeRequest = json_body(request).await?;
    let now = now_seconds();
    let result = control_db(&env)?
        .prepare("UPDATE agents SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL")
        .bind(&[JsValue::from_f64(now as f64), JsValue::from_str(&input.id)])?
        .run()
        .await?;
    let agent_revoked = result.meta()?.and_then(|meta| meta.changes).unwrap_or(0) > 0;
    let cascade = crate::enrollment::revoke_descendants(&env, &input.id, now).await?;
    let revoked = agent_revoked || cascade.enrollment_revoked || cascade.descendants_revoked > 0;
    success_response(
        200,
        json!({
            "id": input.id,
            "revoked": revoked,
            "agent_revoked": agent_revoked,
            "enrollment_revoked": cascade.enrollment_revoked,
            "descendants_revoked": cascade.descendants_revoked,
        }),
    )
}

pub(crate) async fn authenticate_owner(
    env: &Env,
    request: &HttpRequest,
    base: &str,
) -> worker::Result<()> {
    if let Some(token) = bearer_token(request) {
        let row: Option<Value> = control_db(env)?
            .prepare("SELECT expires_at FROM owners WHERE token_hash = ?1 AND expires_at > ?2")
            .bind(&[
                JsValue::from_str(&sha256_hex(token.as_bytes())),
                JsValue::from_f64(now_seconds() as f64),
            ])?
            .first(None)
            .await?;
        if row.is_some() {
            return Ok(());
        }
    }
    verify_access_request(env, request, base).await
}

async fn verify_access_request(env: &Env, request: &HttpRequest, base: &str) -> worker::Result<()> {
    let token = access_jwt(request).ok_or_else(|| err("ACCESS_TOKEN_REQUIRED"))?;
    verify_access_jwt(env, base, &token).await
}

async fn verify_access_jwt(env: &Env, base: &str, token: &str) -> worker::Result<()> {
    let owner_email = required_var(env, "OWNER_EMAIL")?;
    let team_domain = required_var(env, "ACCESS_TEAM_DOMAIN")?
        .trim_end_matches('/')
        .to_owned();
    let audience = required_var(env, "ACCESS_AUD")?;
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(err("ACCESS_JWT_MALFORMED"));
    }
    let header: JwtHeader = serde_json::from_slice(&base64url_decode(parts[0])?)
        .map_err(|_| err("ACCESS_JWT_HEADER"))?;
    if header.alg != "RS256" {
        return Err(err("ACCESS_JWT_ALG"));
    }
    let claims: AccessClaims = serde_json::from_slice(&base64url_decode(parts[1])?)
        .map_err(|_| err("ACCESS_JWT_CLAIMS"))?;
    let now = now_seconds();
    if claims.exp <= now || claims.nbf.unwrap_or(0) > now {
        return Err(err("ACCESS_JWT_TIME"));
    }
    if claims.iss != format!("https://{team_domain}") {
        return Err(err("ACCESS_JWT_ISSUER"));
    }
    if !audience_matches(&claims.aud, &audience) {
        return Err(err("ACCESS_JWT_AUDIENCE"));
    }
    if !claims.email.eq_ignore_ascii_case(owner_email.trim()) {
        return Err(err("ACCESS_JWT_EMAIL"));
    }
    let jwks_url = jwks_url(env, base, &team_domain)?;
    let jwks: Jwks = fetch_json(&jwks_url).await?;
    let jwk = jwks
        .keys
        .iter()
        .find(|key| {
            key.kid == header.kid
                && key.kty == "RSA"
                && key.alg.as_deref().unwrap_or("RS256") == "RS256"
        })
        .ok_or_else(|| err("ACCESS_JWK_NOT_FOUND"))?;
    let key = rsa_key_from_jwk(jwk)?;
    let signature = RsaSignature::try_from(base64url_decode(parts[2])?.as_slice())
        .map_err(|_| err("ACCESS_JWT_SIGNATURE"))?;
    let signed = format!("{}.{}", parts[0], parts[1]);
    VerifyingKey::<Sha256>::new(key)
        .verify(signed.as_bytes(), &signature)
        .map_err(|_| err("ACCESS_JWT_SIGNATURE"))
}

fn jwks_url(env: &Env, base: &str, team_domain: &str) -> worker::Result<String> {
    match env.var("ACCESS_JWKS_URL") {
        Ok(value) => {
            let url = value.to_string();
            if is_loopback_url(base) && is_loopback_url(&url) {
                Ok(url)
            } else {
                Err(err("JWKS_OVERRIDE_FORBIDDEN"))
            }
        }
        Err(_) => Ok(format!("https://{team_domain}/cdn-cgi/access/certs")),
    }
}

async fn fetch_json<T: for<'de> Deserialize<'de>>(url: &str) -> worker::Result<T> {
    let global = js_sys::global();
    let fetch = js_sys::Reflect::get(&global, &JsValue::from_str("fetch"))
        .map_err(|_| err("JWKS_FETCH_UNAVAILABLE"))?
        .dyn_into::<js_sys::Function>()
        .map_err(|_| err("JWKS_FETCH_UNAVAILABLE"))?;
    let promise = fetch
        .call1(&global, &JsValue::from_str(url))
        .map_err(|_| err("JWKS_FETCH_FAILED"))?
        .dyn_into::<js_sys::Promise>()
        .map_err(|_| err("JWKS_FETCH_FAILED"))?;
    let response = JsFuture::from(promise)
        .await
        .map_err(|_| err("JWKS_FETCH_FAILED"))?
        .dyn_into::<WebResponse>()
        .map_err(|_| err("JWKS_FETCH_FAILED"))?;
    if !response.ok() {
        return Err(err("JWKS_FETCH_FAILED"));
    }
    let text = JsFuture::from(response.text().map_err(|_| err("JWKS_FETCH_FAILED"))?)
        .await
        .map_err(|_| err("JWKS_FETCH_FAILED"))?
        .as_string()
        .ok_or_else(|| err("JWKS_FETCH_FAILED"))?;
    serde_json::from_str(&text).map_err(|_| err("JWKS_PARSE_FAILED"))
}

fn rsa_key_from_jwk(jwk: &Jwk) -> worker::Result<RsaPublicKey> {
    let n = BigUint::from_bytes_be(&base64url_decode(&jwk.n)?);
    let e = BigUint::from_bytes_be(&base64url_decode(&jwk.e)?);
    RsaPublicKey::new(n, e).map_err(|_| err("ACCESS_JWK_INVALID"))
}

pub(crate) async fn json_body<T: for<'de> Deserialize<'de>>(
    request: HttpRequest,
) -> worker::Result<T> {
    let text = body_text(request).await?;
    serde_json::from_str(&text).map_err(|_| err("INVALID_JSON"))
}

async fn body_text(request: HttpRequest) -> worker::Result<String> {
    let bytes = request
        .into_body()
        .collect()
        .await
        .map_err(|_| err("BODY_READ_FAILED"))?
        .to_bytes();
    if bytes.len() > 64 * 1024 {
        return Err(err("BODY_TOO_LARGE"));
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| err("BODY_UTF8_REQUIRED"))
}

pub(crate) fn success_response(status: u16, data: Value) -> worker::Result<HttpResponse> {
    json_response(status, json!({"ok": true, "data": data}))
}

fn pending_response() -> worker::Result<HttpResponse> {
    json_response(
        202,
        json!({"ok": false, "status": "pending", "error": {"code": "AUTH_PENDING"}}),
    )
}

fn error_response_for(error: worker::Error) -> worker::Result<HttpResponse> {
    match error {
        worker::Error::RustError(code) => error_response(error_status(&code), &code),
        _ => error_response(500, "INTERNAL_ERROR"),
    }
}

fn error_response(status: u16, code: &str) -> worker::Result<HttpResponse> {
    json_response(status, json!({"ok": false, "error": {"code": code}}))
}

fn error_status(code: &str) -> u16 {
    match code {
        "UNAUTHORIZED"
        | "ACCESS_TOKEN_REQUIRED"
        | "INVITATION_INVALID"
        | "ENROLLMENT_INVALID"
        | "RENEWAL_INVALID" => 401,
        "ORIGIN_REJECTED"
        | "ACCESS_JWT_ALG"
        | "ACCESS_JWT_AUDIENCE"
        | "ACCESS_JWT_EMAIL"
        | "ACCESS_JWT_ISSUER"
        | "ACCESS_JWT_SIGNATURE"
        | "ACCESS_JWT_TIME"
        | "ACCESS_JWK_NOT_FOUND"
        | "JWKS_OVERRIDE_FORBIDDEN" => 403,
        "CONFIG_MISSING"
        | "CONTROL_DB_UNAVAILABLE"
        | "JWKS_FETCH_FAILED"
        | "JWKS_FETCH_UNAVAILABLE"
        | "JWKS_PARSE_FAILED" => 503,
        "BASE64URL_INVALID"
        | "BODY_READ_FAILED"
        | "BODY_TOO_LARGE"
        | "BODY_UTF8_REQUIRED"
        | "INVALID_BLOB_ROUTE"
        | "INVALID_JSON"
        | "INVALID_TTL_SECONDS"
        | "INVALID_ENROLLMENT_TTL"
        | "MISSING_INVITATION"
        | "MISSING_CODE"
        | "MISSING_USER_CODE"
        | "ACCESS_JWT_CLAIMS"
        | "ACCESS_JWT_HEADER"
        | "ACCESS_JWT_MALFORMED" => 400,
        _ => 500,
    }
}

pub(crate) fn json_response(status: u16, body: Value) -> worker::Result<HttpResponse> {
    let mut response: HttpResponse = worker::Response::builder()
        .with_status(status)
        .from_json(&body)?
        .try_into()?;
    secure_headers(&mut response);
    Ok(response)
}

fn html_response(status: u16, html: &str) -> worker::Result<HttpResponse> {
    let mut response: HttpResponse = worker::Response::builder()
        .with_status(status)
        .from_html(html)?
        .try_into()?;
    secure_headers(&mut response);
    Ok(response)
}

fn secure_headers(response: &mut HttpResponse) {
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert("x-content-type-options", "nosniff".parse().unwrap());
}

fn verify_same_origin(request: &HttpRequest, base: &str) -> worker::Result<()> {
    match request
        .headers()
        .get("origin")
        .and_then(|value| value.to_str().ok())
    {
        Some(origin) if origin == base => Ok(()),
        _ => Err(err("ORIGIN_REJECTED")),
    }
}

pub(crate) fn control_db(env: &Env) -> worker::Result<worker::D1Database> {
    env.d1(CONTROL_BINDING)
        .map_err(|_| err("CONTROL_DB_UNAVAILABLE"))
}

fn required_var(env: &Env, name: &str) -> worker::Result<String> {
    env.var(name)
        .map(|value| value.to_string())
        .map_err(|_| err("CONFIG_MISSING"))
}

fn bearer_token(request: &HttpRequest) -> Option<String> {
    request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn access_jwt(request: &HttpRequest) -> Option<String> {
    if let Some(value) = request
        .headers()
        .get("cf-access-jwt-assertion")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
    {
        return Some(value.to_owned());
    }
    request
        .headers()
        .get("cookie")
        .and_then(|value| value.to_str().ok())
        .and_then(|cookie| {
            cookie.split(';').find_map(|part| {
                let mut split = part.trim().splitn(2, '=');
                match (split.next(), split.next()) {
                    (Some("CF_Authorization"), Some(value)) if !value.is_empty() => {
                        Some(value.to_owned())
                    }
                    _ => None,
                }
            })
        })
}

fn query_param(query: Option<&str>, key: &str) -> Option<String> {
    query?.split('&').find_map(|part| {
        let mut split = part.splitn(2, '=');
        let name = split.next()?;
        let value = split.next().unwrap_or_default();
        (name == key).then(|| percent_decode(value))
    })
}

fn form_value(body: &str, key: &str) -> Option<String> {
    body.split('&').find_map(|part| {
        let mut split = part.splitn(2, '=');
        let name = split.next()?;
        let value = split.next().unwrap_or_default();
        (percent_decode(name) == key).then(|| percent_decode(value))
    })
}

fn json_field(body: &str, key: &str) -> Option<String> {
    serde_json::from_str::<Value>(body)
        .ok()?
        .get(key)?
        .as_str()
        .map(str::to_owned)
}

fn percent_decode(value: &str) -> String {
    let mut output = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                if let (Some(a), Some(b)) =
                    (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
                {
                    output.push((a << 4) | b);
                    index += 3;
                } else {
                    output.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn optional_js_string(value: Option<&str>) -> JsValue {
    value.map(JsValue::from_str).unwrap_or_else(JsValue::null)
}

fn audience_matches(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(aud) => aud == expected,
        Value::Array(items) => items.iter().any(|item| item.as_str() == Some(expected)),
        _ => false,
    }
}

pub(crate) fn random_token(bytes: usize) -> worker::Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(random_bytes(bytes)?))
}

pub(crate) fn random_hex(bytes: usize) -> worker::Result<String> {
    Ok(hex(&random_bytes(bytes)?))
}

fn random_code(len: usize) -> worker::Result<String> {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let bytes = random_bytes(len)?;
    Ok(bytes
        .into_iter()
        .map(|byte| ALPHABET[(byte as usize) % ALPHABET.len()] as char)
        .collect())
}

fn random_bytes(len: usize) -> worker::Result<Vec<u8>> {
    let global = js_sys::global();
    let crypto = js_sys::Reflect::get(&global, &JsValue::from_str("crypto"))
        .map_err(|_| err("RANDOM_UNAVAILABLE"))?;
    let get_random_values = js_sys::Reflect::get(&crypto, &JsValue::from_str("getRandomValues"))
        .map_err(|_| err("RANDOM_UNAVAILABLE"))?
        .dyn_into::<js_sys::Function>()
        .map_err(|_| err("RANDOM_UNAVAILABLE"))?;
    let array = js_sys::Uint8Array::new_with_length(len as u32);
    get_random_values
        .call1(&crypto, &array)
        .map_err(|_| err("RANDOM_UNAVAILABLE"))?;
    let mut bytes = vec![0; len];
    array.copy_to(&mut bytes);
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn base64url_decode(value: &str) -> worker::Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| err("BASE64URL_INVALID"))
}

pub(crate) fn now_seconds() -> i64 {
    (js_sys::Date::now() / 1000.0).floor() as i64
}

fn request_base(request: &HttpRequest) -> String {
    format!(
        "{}://{}",
        request.uri().scheme_str().unwrap_or("https"),
        request.uri().authority().map(|a| a.as_str()).unwrap_or("")
    )
}

fn is_loopback_url(value: &str) -> bool {
    value.starts_with("http://127.0.0.1")
        || value.starts_with("http://localhost")
        || value.starts_with("http://[::1]")
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub(crate) fn err(code: &str) -> worker::Error {
    worker::Error::RustError(code.to_owned())
}
