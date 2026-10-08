//! Portable security contracts for Comms' Linear credential broker.
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

pub fn endpoints(origin: &str) -> Result<(String, String), &'static str> {
    let url = url::Url::parse(origin).map_err(|_| "LINEAR_ORIGIN_INVALID")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("LINEAR_ORIGIN_INVALID");
    }
    let origin = origin.trim_end_matches('/');
    Ok((
        format!("{origin}/linear/oauth/callback"),
        format!("{origin}/linear/events"),
    ))
}

pub fn seal(
    key: &[u8],
    nonce: &[u8; 12],
    binding: &str,
    value: &Value,
) -> Result<String, &'static str> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "LINEAR_SEAL_KEY_INVALID")?;
    let plaintext = serde_json::to_vec(value).map_err(|_| "LINEAR_CREDENTIAL_INVALID")?;
    let aad = format!("comms/linear/v1/{binding}");
    let encrypted = cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: &plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| "LINEAR_CREDENTIAL_INVALID")?;
    Ok(json!({
        "version": 1,
        "nonce": URL_SAFE_NO_PAD.encode(nonce),
        "data": URL_SAFE_NO_PAD.encode(encrypted),
    })
    .to_string())
}

pub fn unseal(key: &[u8], binding: &str, sealed: &str) -> Result<Value, &'static str> {
    let value: Value = serde_json::from_str(sealed).map_err(|_| "LINEAR_CREDENTIAL_INVALID")?;
    if value["version"] != 1 {
        return Err("LINEAR_CREDENTIAL_INVALID");
    }
    let decode = |name| {
        URL_SAFE_NO_PAD
            .decode(value[name].as_str().ok_or("LINEAR_CREDENTIAL_INVALID")?)
            .map_err(|_| "LINEAR_CREDENTIAL_INVALID")
    };
    let nonce = decode("nonce")?;
    let nonce: &[u8; 12] = nonce
        .as_slice()
        .try_into()
        .map_err(|_| "LINEAR_CREDENTIAL_INVALID")?;
    let encrypted = decode("data")?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "LINEAR_SEAL_KEY_INVALID")?;
    let aad = format!("comms/linear/v1/{binding}");
    let plaintext = cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: &encrypted,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| "LINEAR_CREDENTIAL_INVALID")?;
    serde_json::from_slice(&plaintext).map_err(|_| "LINEAR_CREDENTIAL_INVALID")
}

pub fn verify_identity(value: &Value, role: &str, workspace: &str) -> Result<Value, &'static str> {
    let data = value.get("data").ok_or("LINEAR_IDENTITY_MISMATCH")?;
    let user = data["viewer"]["id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .ok_or("LINEAR_IDENTITY_MISMATCH")?;
    let organization = data["organization"]["id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .ok_or("LINEAR_IDENTITY_MISMATCH")?;
    if value.get("errors").is_some()
        || data["viewer"]["name"].as_str() != Some(role)
        || data["organization"]["urlKey"].as_str() != Some(workspace)
    {
        return Err("LINEAR_IDENTITY_MISMATCH");
    }
    Ok(json!({
        "app_user_id": user,
        "role": role,
        "organization_id": organization,
        "workspace_slug": workspace,
    }))
}

pub fn verify_webhook(
    secret: &[u8],
    signature: &str,
    body: &[u8],
    now_ms: i64,
    organization: &str,
) -> Result<Value, &'static str> {
    if signature.len() != 64 || secret.is_empty() {
        return Err("LINEAR_SIGNATURE_INVALID");
    }
    let mut digest = [0u8; 32];
    for (index, pair) in signature.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|_| "LINEAR_SIGNATURE_INVALID")?;
        digest[index] = u8::from_str_radix(pair, 16).map_err(|_| "LINEAR_SIGNATURE_INVALID")?;
    }
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(secret).map_err(|_| "LINEAR_SIGNATURE_INVALID")?;
    mac.update(body);
    mac.verify_slice(&digest)
        .map_err(|_| "LINEAR_SIGNATURE_INVALID")?;
    let payload: Value = serde_json::from_slice(body).map_err(|_| "LINEAR_EVENT_INVALID")?;
    let timestamp = payload["webhookTimestamp"]
        .as_i64()
        .ok_or("LINEAR_EVENT_INVALID")?;
    let age = now_ms
        .checked_sub(timestamp)
        .ok_or("LINEAR_EVENT_INVALID")?;
    if !(-5_000..=60_000).contains(&age) || payload["organizationId"].as_str() != Some(organization)
    {
        return Err("LINEAR_EVENT_INVALID");
    }
    Ok(payload)
}

pub fn event_key(payload: &Value) -> Result<String, &'static str> {
    use sha2::Digest;
    let mut event = payload.clone();
    event
        .as_object_mut()
        .ok_or("LINEAR_EVENT_INVALID")?
        .remove("webhookTimestamp");
    let body = serde_json::to_vec(&event).map_err(|_| "LINEAR_EVENT_INVALID")?;
    Ok(Sha256::digest(body)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub async fn use_and_revoke<T, E, Operation, OperationFuture, Revoke, RevokeFuture>(
    token: String,
    operation: Operation,
    revoke: Revoke,
) -> (Result<T, E>, Result<(), E>)
where
    Operation: FnOnce(String) -> OperationFuture,
    OperationFuture: std::future::Future<Output = Result<T, E>>,
    Revoke: FnOnce(String) -> RevokeFuture,
    RevokeFuture: std::future::Future<Output = Result<(), E>>,
{
    let result = operation(token.clone()).await;
    let cleanup = revoke(token).await;
    (result, cleanup)
}

pub const TRANSFER_APP_SQL: &str = "UPDATE linear_apps SET agent_id=?1,sealed_json=?2,updated_at=?3 WHERE agent_id=?4 AND profile_name=?5 AND EXISTS (SELECT 1 FROM agents WHERE id=?1 AND profile_name=?5 AND revoked_at IS NULL AND expires_at>?3) RETURNING agent_id";
