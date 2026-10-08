use serde::{Deserialize, Serialize};
use serde_json::json;
use wasm_bindgen::JsValue;
use worker::{Env, HttpRequest, HttpResponse};

const ENROLLMENT_SECONDS: i64 = comms_identity::ENROLLMENT_TTL_SECONDS;
const ACCESS_SECONDS: i64 = comms_identity::ACCESS_TTL_SECONDS;
const RENEWAL_SECONDS: i64 = comms_identity::RENEWAL_TTL_SECONDS;

#[derive(Deserialize)]
pub(crate) struct EnrollmentCreateRequest {
    pub label: Option<String>,
    pub profile_name: Option<String>,
    pub ttl_seconds: Option<i64>,
}

#[derive(Deserialize)]
struct EnrollmentRenewRequest {
    agent_id: String,
    renewal: String,
}

#[derive(Deserialize)]
struct EnrollmentRow {
    id: String,
    root_id: String,
    label: Option<String>,
    profile_name: Option<String>,
    expires_at: i64,
    revoked_at: Option<i64>,
}

#[derive(Deserialize)]
struct RenewAgentRow {
    id: String,
    label: Option<String>,
    profile_name: Option<String>,
    expires_at: i64,
    renewal_expires_at: i64,
    revoked_at: Option<i64>,
    root_revoked_at: Option<i64>,
}

#[derive(Serialize)]
pub(crate) struct RevokeCascade {
    pub enrollment_revoked: bool,
    pub descendants_revoked: u64,
}

pub(crate) async fn owner_create(request: HttpRequest, env: Env) -> worker::Result<HttpResponse> {
    let input: EnrollmentCreateRequest = crate::auth::json_body(request).await?;
    let ttl_seconds = input.ttl_seconds.unwrap_or(ENROLLMENT_SECONDS);
    if ttl_seconds <= 0 || ttl_seconds > ENROLLMENT_SECONDS {
        return Err(crate::auth::err("INVALID_ENROLLMENT_TTL"));
    }
    let now = crate::auth::now_seconds();
    let expires_at = now
        .checked_add(ttl_seconds)
        .ok_or_else(|| crate::auth::err("ENROLLMENT_EXPIRY_OVERFLOW"))?;
    let id = format!("enr_{}", crate::auth::random_hex(16)?);
    let enrollment = crate::auth::random_token(32)?;
    let hash = comms_identity::hash_secret(&enrollment);
    let result = crate::auth::control_db(&env)?
        .prepare(
            "INSERT INTO enrollments(id, root_id, parent_id, secret_hash, label, profile_name, created_at, expires_at, revoked_at, revoked_by) \
             VALUES (?1, ?1, NULL, ?2, ?3, ?4, ?5, ?6, NULL, NULL)",
        )
        .bind(&[
            JsValue::from_str(&id),
            JsValue::from_str(&hash),
            crate::auth::optional_js_string(input.label.as_deref()),
            crate::auth::optional_js_string(input.profile_name.as_deref()),
            JsValue::from_f64(now as f64),
            JsValue::from_f64(expires_at as f64),
        ])?
        .run()
        .await?;
    if !result.success() {
        return Err(crate::auth::err("ENROLLMENT_CREATE_FAILED"));
    }
    crate::auth::success_response(
        200,
        json!({
            "enrollment_id": id,
            "enrollment": enrollment,
            "expires_at": expires_at,
            "reusable": true,
        }),
    )
}

pub(crate) async fn join(
    env: &Env,
    enrollment_secret: String,
    label: Option<String>,
    profile_name: Option<String>,
) -> worker::Result<HttpResponse> {
    let now = crate::auth::now_seconds();
    let row: Option<EnrollmentRow> = crate::auth::control_db(env)?
        .prepare(
            "SELECT id, root_id, label, profile_name, expires_at, revoked_at \
             FROM enrollments WHERE secret_hash = ?1 AND expires_at > ?2 AND revoked_at IS NULL",
        )
        .bind(&[
            JsValue::from_str(&comms_identity::hash_secret(&enrollment_secret)),
            JsValue::from_f64(now as f64),
        ])?
        .first(None)
        .await?;
    let row = match row {
        Some(row) => row,
        None => {
            return crate::auth::json_response(
                401,
                json!({"ok":false,"error":{"code":"ENROLLMENT_INVALID"}}),
            );
        }
    };
    if row.revoked_at.is_some() || row.expires_at <= now {
        return crate::auth::json_response(
            401,
            json!({"ok":false,"error":{"code":"ENROLLMENT_INVALID"}}),
        );
    }

    let agent_id = format!("agent_{}", crate::auth::random_hex(16)?);
    let token = crate::auth::random_token(32)?;
    let renewal = crate::auth::random_token(32)?;
    let expires_at = now
        .checked_add(ACCESS_SECONDS)
        .ok_or_else(|| crate::auth::err("AGENT_EXPIRY_OVERFLOW"))?;
    let renewal_expires_at = now
        .checked_add(RENEWAL_SECONDS)
        .ok_or_else(|| crate::auth::err("RENEWAL_EXPIRY_OVERFLOW"))?;
    let label = label.or(row.label);
    let profile_name = profile_name.or(row.profile_name);
    let result = crate::auth::control_db(env)?
        .prepare(
            "INSERT INTO agents(id, token_hash, label, expires_at, revoked_at, enrollment_id, root_enrollment_id, profile_name, renewal_hash, renewal_expires_at) \
             VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(&[
            JsValue::from_str(&agent_id),
            JsValue::from_str(&comms_identity::hash_secret(&token)),
            crate::auth::optional_js_string(label.as_deref()),
            JsValue::from_f64(expires_at as f64),
            JsValue::from_str(&row.id),
            JsValue::from_str(&row.root_id),
            crate::auth::optional_js_string(profile_name.as_deref()),
            JsValue::from_str(&comms_identity::hash_secret(&renewal)),
            JsValue::from_f64(renewal_expires_at as f64),
        ])?
        .run()
        .await?;
    if !result.success() {
        return Err(crate::auth::err("AGENT_CREATE_FAILED"));
    }
    crate::auth::success_response(
        200,
        json!({
            "agent_id": agent_id,
            "label": label,
            "profile_name": profile_name,
            "token": token,
            "renewal": renewal,
            "expires_at": expires_at,
            "renewal_expires_at": renewal_expires_at,
            "enrollment_id": row.id,
            "root_enrollment_id": row.root_id,
        }),
    )
}

pub(crate) async fn renew(request: HttpRequest, env: Env) -> worker::Result<HttpResponse> {
    let input: EnrollmentRenewRequest = crate::auth::json_body(request).await?;
    let now = crate::auth::now_seconds();
    let renewal_hash = comms_identity::hash_secret(&input.renewal);
    let row: Option<RenewAgentRow> = crate::auth::control_db(&env)?
        .prepare(
            "SELECT agents.id, agents.label, agents.profile_name, agents.expires_at, agents.renewal_expires_at, agents.revoked_at, enrollments.revoked_at AS root_revoked_at \
             FROM agents LEFT JOIN enrollments ON enrollments.id = agents.root_enrollment_id \
             WHERE agents.id = ?1 AND agents.renewal_hash = ?2 AND agents.renewal_expires_at > ?3",
        )
        .bind(&[
            JsValue::from_str(&input.agent_id),
            JsValue::from_str(&renewal_hash),
            JsValue::from_f64(now as f64),
        ])?
        .first(None)
        .await?;
    let row = match row {
        Some(row) if row.revoked_at.is_none() && row.root_revoked_at.is_none() => row,
        _ => {
            return crate::auth::json_response(
                401,
                json!({"ok":false,"error":{"code":"RENEWAL_INVALID"}}),
            );
        }
    };
    let token = crate::auth::random_token(32)?;
    let renewal = crate::auth::random_token(32)?;
    let token_hash = comms_identity::hash_secret(&token);
    let next_renewal_hash = comms_identity::hash_secret(&renewal);
    let expires_at = now
        .checked_add(ACCESS_SECONDS)
        .ok_or_else(|| crate::auth::err("AGENT_EXPIRY_OVERFLOW"))?;
    let renewal_expires_at = now
        .checked_add(RENEWAL_SECONDS)
        .ok_or_else(|| crate::auth::err("RENEWAL_EXPIRY_OVERFLOW"))?;
    let result = crate::auth::control_db(&env)?
        .prepare(
            "UPDATE agents SET token_hash = ?1, renewal_hash = ?2, expires_at = ?3, renewal_expires_at = ?4 \
             WHERE id = ?5 AND renewal_hash = ?6 AND revoked_at IS NULL",
        )
        .bind(&[
            JsValue::from_str(&token_hash),
            JsValue::from_str(&next_renewal_hash),
            JsValue::from_f64(expires_at as f64),
            JsValue::from_f64(renewal_expires_at as f64),
            JsValue::from_str(&input.agent_id),
            JsValue::from_str(&renewal_hash),
        ])?
        .run()
        .await?;
    if result.meta()?.and_then(|meta| meta.changes).unwrap_or(0) == 0 {
        return crate::auth::json_response(
            401,
            json!({"ok":false,"error":{"code":"RENEWAL_INVALID"}}),
        );
    }
    crate::auth::success_response(
        200,
        json!({
            "agent_id": row.id,
            "label": row.label,
            "profile_name": row.profile_name,
            "token": token,
            "renewal": renewal,
            "previous_expires_at": row.expires_at,
            "previous_renewal_expires_at": row.renewal_expires_at,
            "expires_at": expires_at,
            "renewal_expires_at": renewal_expires_at,
        }),
    )
}

pub(crate) async fn revoke_descendants(
    env: &Env,
    id: &str,
    now: i64,
) -> worker::Result<RevokeCascade> {
    let enrollment = crate::auth::control_db(env)?
        .prepare("UPDATE enrollments SET revoked_at = ?1, revoked_by = 'owner' WHERE id = ?2 AND revoked_at IS NULL")
        .bind(&[JsValue::from_f64(now as f64), JsValue::from_str(id)])?
        .run()
        .await?;
    let enrollment_revoked = enrollment
        .meta()?
        .and_then(|meta| meta.changes)
        .unwrap_or(0)
        > 0;
    let descendants = crate::auth::control_db(env)?
        .prepare(
            "UPDATE agents SET revoked_at = ?1 \
             WHERE revoked_at IS NULL AND (enrollment_id = ?2 OR root_enrollment_id = ?2)",
        )
        .bind(&[JsValue::from_f64(now as f64), JsValue::from_str(id)])?
        .run()
        .await?;
    let descendants_revoked = descendants
        .meta()?
        .and_then(|meta| meta.changes)
        .unwrap_or(0) as u64;
    Ok(RevokeCascade {
        enrollment_revoked,
        descendants_revoked,
    })
}
