mod code;
mod credential_profiles;
pub mod credentials;
use std::sync::Arc;

use comms_core::Backend;
use incurs::cli::Cli;
use incurs::command::{CommandDef, TypedResult};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

const DEFAULT_MIME_TYPE: &str = "application/octet-stream";
const DEFAULT_BASE_URL: &str = "https://comms.example.com";
const MULTIPART_UPLOAD_THRESHOLD_BYTES: u64 = 8 * 1024 * 1024;
const MULTIPART_UPLOAD_PART_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub struct HttpBackend {
    client: reqwest::Client,
    base_url: Url,
    token: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AuthClient {
    client: reqwest::Client,
    base_url: Url,
}

#[derive(Debug, Deserialize)]
struct Envelope {
    ok: bool,
    #[serde(default)]
    data: Option<Value>,
    #[serde(default)]
    error: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct MultipartUploadStart {
    id: String,
    upload_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct MultipartUploadPart {
    part_number: u16,
    etag: String,
}

#[derive(Debug, Deserialize, incurs::Env)]
struct CommsEnv {
    /// Base URL for the comms Worker, for example https://comms.example.workers.dev.
    #[incurs(env = "COMMS_URL")]
    url: Option<String>,
    /// Agent bearer token used by shared data and agent self commands.
    #[incurs(env = "COMMS_TOKEN")]
    token: Option<String>,
    /// Owner bearer token used by owner enrollment commands.
    #[incurs(env = "COMMS_OWNER_TOKEN")]
    owner_token: Option<String>,
    /// Reusable enrollment secret injected by the swarm's secret manager.
    #[incurs(env = "COMMS_ENROLLMENT_SECRET")]
    enrollment: Option<String>,
    /// Select a saved agent or owner credential profile.
    #[incurs(env = "COMMS_PROFILE")]
    profile: Option<String>,
}

#[derive(Debug, Deserialize, incurs::Options)]
struct EndpointOptions {
    /// Override COMMS_URL for this command.
    url: Option<String>,
}

#[derive(Debug, Deserialize, incurs::Options)]
struct FinishOptions {
    /// Override COMMS_URL for this command.
    url: Option<String>,
    /// Device code returned by auth login.
    device_code: String,
    /// Save the owner credential under this profile.
    profile: Option<String>,
}

#[derive(Debug, Deserialize, incurs::Options)]
struct InviteOptions {
    /// Override COMMS_URL for this command.
    url: Option<String>,
    /// Human label for the invited agent.
    label: Option<String>,
    /// Invite lifetime in seconds.
    ttl_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, incurs::Options)]
struct JoinOptions {
    /// Override COMMS_URL for this command.
    url: Option<String>,
    /// One-time invitation code or URL.
    invitation: String,
}

#[derive(Debug, Deserialize, incurs::Options)]
struct RevokeOptions {
    /// Override COMMS_URL for this command.
    url: Option<String>,
    /// Agent id to revoke.
    id: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeviceLoginOutput {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_at: i64,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct OwnerTokenOutput {
    pub owner_token: String,
    pub expires_at: i64,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct InvitationOutput {
    pub invitation: String,
    pub expires_at: i64,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AgentJoinOutput {
    pub agent_id: String,
    pub token: String,
    pub expires_at: i64,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AgentMeOutput {
    pub agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RevokeOutput {
    pub revoked: bool,
}

impl HttpBackend {
    pub fn remote_code_mode(&self) -> Result<comms_codemode::RemoteCodeModeService, String> {
        let token = self
            .token
            .clone()
            .ok_or("An active Comms credential is required for Code Mode")?;
        comms_codemode::RemoteCodeModeService::new(self.base_url.as_str(), token)?
            .retention_from_env()
    }

    pub fn new(base_url: impl AsRef<str>, token: Option<String>) -> Result<Self, String> {
        Ok(Self {
            client: no_redirect_client()?,
            base_url: parse_base_url(base_url.as_ref())?,
            token,
        })
    }

    pub fn from_env() -> Result<Self, String> {
        let base_url = std::env::var("COMMS_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_string());
        let mut token = std::env::var("COMMS_TOKEN")
            .ok()
            .filter(|value| !value.is_empty());
        if token.is_none()
            && let Ok(name) = std::env::var("COMMS_PROFILE")
        {
            let profile = credentials::CredentialProfile::new(base_url.clone(), Some(name));
            let store = credentials::default_credential_store();
            let manager = credentials::CredentialProfileManager::new(store.as_ref());
            token = manager
                .load_agent(&profile)
                .map_err(|error| error.to_string())?
                .map(|agent| agent.access.into_inner());
        }
        Self::new(&base_url, token)
    }

    async fn post_json(&self, path: &str, body: Value) -> Result<Value, String> {
        let body = without_top_level_nulls(body);
        let mut request = self
            .client
            .post(endpoint(&self.base_url, path)?)
            .json(&body);
        request = with_bearer(request, self.token.as_deref())?;
        send_json_envelope(request).await
    }

    async fn put_media(&self, input: Value) -> Result<Value, String> {
        let Some(path) = input.get("file").and_then(Value::as_str) else {
            return self.post_json("/api/blob/put", input).await;
        };
        let metadata = tokio::fs::metadata(path)
            .await
            .map_err(|error| format!("failed to read blob file metadata: {error}"))?;
        if metadata.len() > MULTIPART_UPLOAD_THRESHOLD_BYTES {
            return self.put_multipart_media(path, &input).await;
        }
        let bytes = tokio::fs::read(path)
            .await
            .map_err(|error| format!("failed to read blob file: {error}"))?;
        let mime_type = input
            .get("mime_type")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_MIME_TYPE);
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str(mime_type).map_err(|_| "invalid MIME type".to_string())?,
        );
        if let Some(name) = input.get("name").and_then(Value::as_str) {
            headers.insert(
                "x-comms-name",
                HeaderValue::from_str(name).map_err(|_| "invalid media name".to_string())?,
            );
        }
        let mut request = self
            .client
            .post(endpoint(&self.base_url, "/media")?)
            .headers(headers)
            .body(bytes);
        request = with_bearer(request, self.token.as_deref())?;
        send_json_envelope(request).await
    }

    async fn put_multipart_media(&self, path: &str, input: &Value) -> Result<Value, String> {
        let mime_type = input
            .get("mime_type")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_MIME_TYPE);
        let name = input.get("name").and_then(Value::as_str);
        let start = self
            .post_json("/uploads", json!({"mime_type": mime_type, "name": name}))
            .await?;
        let start: MultipartUploadStart = decode(start)?;
        let mut file = tokio::fs::File::open(path)
            .await
            .map_err(|error| format!("failed to open blob file: {error}"))?;
        let mut buffer = vec![0_u8; MULTIPART_UPLOAD_PART_BYTES];
        let mut part_number = 1_u16;
        let mut parts = Vec::new();
        loop {
            let read = read_upload_part(&mut file, &mut buffer).await?;
            if read == 0 {
                break;
            }
            let request = self
                .client
                .put(endpoint_segments(
                    &self.base_url,
                    "/uploads",
                    &[&start.id, &start.upload_id, &part_number.to_string()],
                )?)
                .body(buffer[..read].to_vec());
            let request = with_bearer(request, self.token.as_deref())?;
            match send_json_envelope(request).await {
                Ok(value) => parts.push(decode::<MultipartUploadPart>(value)?),
                Err(error) => {
                    let abort_error = self.abort_multipart_upload(&start).await.err();
                    return Err(match abort_error {
                        Some(abort_error) => {
                            format!("{error}; upload abort failed: {abort_error}")
                        }
                        None => error,
                    });
                }
            }
            part_number = part_number
                .checked_add(1)
                .ok_or_else(|| "blob has too many multipart upload parts".to_string())?;
        }
        let request = self
            .client
            .post(endpoint_segments(
                &self.base_url,
                "/uploads",
                &[&start.id, &start.upload_id, "complete"],
            )?)
            .json(&json!({"parts": parts}));
        let request = with_bearer(request, self.token.as_deref())?;
        send_json_envelope(request).await
    }

    async fn abort_multipart_upload(&self, upload: &MultipartUploadStart) -> Result<(), String> {
        let request = self.client.delete(endpoint_segments(
            &self.base_url,
            "/uploads",
            &[&upload.id, &upload.upload_id],
        )?);
        let request = with_bearer(request, self.token.as_deref())?;
        send_json_envelope(request).await.map(|_| ())
    }

    async fn get_media(&self, input: Value) -> Result<Value, String> {
        let Some(output) = input.get("output").and_then(Value::as_str) else {
            return self.post_json("/api/blob/get", input).await;
        };
        let id = required_string(&input, "id")?;
        let mut request = self
            .client
            .get(endpoint_segments(&self.base_url, "/media", &[id])?);
        request = with_bearer(request, self.token.as_deref())?;
        let response = request
            .send()
            .await
            .map_err(|error| format!("request failed: {error}"))?;
        if response.status().is_redirection() {
            return Err("redirects are not followed".to_string());
        }
        if !response.status().is_success() {
            return Err(format!(
                "request failed with HTTP {}",
                response.status().as_u16()
            ));
        }
        let mut file = tokio::fs::File::create(output)
            .await
            .map_err(|error| format!("failed to create blob output: {error}"))?;
        let mut bytes = 0_usize;
        let mut response = response;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| format!("failed to read response body: {error}"))?
        {
            file.write_all(&chunk)
                .await
                .map_err(|error| format!("failed to write blob output: {error}"))?;
            bytes += chunk.len();
        }
        file.flush()
            .await
            .map_err(|error| format!("failed to flush blob output: {error}"))?;
        Ok(json!({"id": id, "output": output, "bytes": bytes}))
    }
}

#[async_trait::async_trait]
impl Backend for HttpBackend {
    async fn call(&self, operation: &str, input: Value) -> Result<Value, String> {
        match operation {
            "linear_me" => self.post_json("/api/linear/me", input).await,
            "linear_query" => self.post_json("/api/linear/query", input).await,
            "linear_inbox" => self.post_json("/api/linear/inbox", input).await,
            "slack_call" => self.post_json("/api/slack/invoke", input).await,
            "question_create" => {
                let blocking = input
                    .get("blocking")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let result = self.post_json("/api/question/create", input).await?;
                if blocking {
                    let id = result
                        .pointer("/question/id")
                        .and_then(Value::as_str)
                        .ok_or("Question response omitted id")?;
                    self.call("question_wait", json!({"id": id})).await
                } else {
                    Ok(result)
                }
            }
            "question_status" => self.post_json("/api/question/status", input).await,
            "question_wait" => loop {
                let result = self
                    .post_json("/api/question/status", input.clone())
                    .await?;
                match result.pointer("/question/state").and_then(Value::as_str) {
                    Some("answered" | "expired" | "cancelled") => return Ok(result),
                    Some("pending_delivery" | "waiting") => {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await
                    }
                    _ => return Err("Question status response omitted a valid state".into()),
                }
            },
            "question_cancel" => self.post_json("/api/question/cancel", input).await,
            "sql" => self.post_json("/api/sql", input).await,
            "batch" => self.post_json("/api/batch", input).await,
            "schema" => self.post_json("/api/schema", input).await,
            "blob_put" => self.put_media(input).await,
            "blob_get" => self.get_media(input).await,
            "blob_delete" => self.post_json("/api/blob/delete", input).await,
            other => Err(format!("unsupported operation: {other}")),
        }
    }
}

impl AuthClient {
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, String> {
        Ok(Self {
            client: no_redirect_client()?,
            base_url: parse_base_url(base_url.as_ref())?,
        })
    }

    pub async fn start_login(&self) -> Result<DeviceLoginOutput, String> {
        decode(
            send_json_envelope(self.client.post(endpoint(&self.base_url, "/auth/start")?)).await?,
        )
    }

    pub async fn finish_login(&self, device_code: &str) -> Result<OwnerTokenOutput, String> {
        decode(
            send_json_envelope(
                self.client
                    .post(endpoint(&self.base_url, "/auth/poll")?)
                    .json(&json!({"device_code": device_code})),
            )
            .await?,
        )
    }

    pub async fn invite(
        &self,
        owner_token: &str,
        label: Option<String>,
        ttl_seconds: Option<u64>,
    ) -> Result<InvitationOutput, String> {
        let request = with_bearer(
            self.client
                .post(endpoint(&self.base_url, "/owner/invite")?)
                .json(&json!({"label": label, "ttl_seconds": ttl_seconds})),
            Some(owner_token),
        )?;
        decode(send_json_envelope(request).await?)
    }

    pub async fn join(&self, invitation: &str) -> Result<AgentJoinOutput, String> {
        decode(
            send_json_envelope(
                self.client
                    .post(endpoint(&self.base_url, "/agent/join")?)
                    .json(&json!({"invitation": invitation})),
            )
            .await?,
        )
    }

    pub async fn me(&self, token: &str) -> Result<AgentMeOutput, String> {
        let request = with_bearer(
            self.client.get(endpoint(&self.base_url, "/agent/me")?),
            Some(token),
        )?;
        decode(send_json_envelope(request).await?)
    }

    pub async fn revoke(&self, owner_token: &str, id: &str) -> Result<RevokeOutput, String> {
        let request = with_bearer(
            self.client
                .post(endpoint(&self.base_url, "/owner/revoke")?)
                .json(&json!({"id": id})),
            Some(owner_token),
        )?;
        decode(send_json_envelope(request).await?)
    }
}

pub fn build_cli(backend: HttpBackend) -> Cli {
    build_cli_with_store(backend, credentials::default_credential_store())
}

pub fn build_cli_with_store(
    backend: HttpBackend,
    store: credentials::SharedCredentialStore,
) -> Cli {
    let code = code::cli(backend.clone());
    let shared = comms_core::cli(Arc::new(backend));
    shared
        .group(auth_cli(store.clone()))
        .group(agent_cli(store.clone()))
        .group(code)
        .group(credential_profiles::credential_cli(store))
}

fn auth_cli(store: credentials::SharedCredentialStore) -> Cli {
    Cli::create("auth")
        .description("Owner email-code authentication")
        .command(
            "login",
            CommandDef::typed::<(), EndpointOptions, CommsEnv, DeviceLoginOutput, _, _>(
                "login",
                |ctx| async move {
                    match auth_client(ctx.env.url.as_deref(), ctx.options.url.as_deref()) {
                        Ok(client) => match client.start_login().await {
                            Ok(output) => TypedResult::ok(output),
                            Err(error) => TypedResult::error("AUTH_START_FAILED", error),
                        },
                        Err(error) => TypedResult::error("CONFIG_ERROR", error),
                    }
                },
            )
            .description("Start an owner email-code login and print the user code")
            .done(),
        )
        .command(
            "finish",
            CommandDef::typed::<(), FinishOptions, CommsEnv, credential_profiles::SavedOutput, _, _>(
                "finish",
                move |ctx| {
                    let store = store.clone();
                    async move {
                        match auth_client(ctx.env.url.as_deref(), ctx.options.url.as_deref()) {
                            Ok(client) => match client.finish_login(&ctx.options.device_code).await {
                                Ok(output) => match credential_profiles::store_owner_token(store.as_ref(), client.base_url.as_str(), ctx.options.profile.or(ctx.env.profile), &output.owner_token) {
                                    Ok(saved) => TypedResult::ok(saved),
                                    Err(error) => TypedResult::error("CREDENTIAL_SAVE_FAILED", error),
                                },
                                Err(error) => TypedResult::error("AUTH_POLL_FAILED", error),
                            },
                            Err(error) => TypedResult::error("CONFIG_ERROR", error),
                        }
                    }
                },
            )
            .description("Complete owner login and save its credential in the vault")
            .done(),
        )
}

fn agent_cli(store: credentials::SharedCredentialStore) -> Cli {
    Cli::create("agent")
        .description("Agent enrollment and identity")
        .command(
            "invite",
            CommandDef::typed::<(), InviteOptions, CommsEnv, InvitationOutput, _, _>(
                "invite",
                |ctx| async move {
                    let Some(owner_token) = ctx.env.owner_token.as_deref() else {
                        return TypedResult::error("CONFIG_ERROR", "COMMS_OWNER_TOKEN is required");
                    };
                    match auth_client(ctx.env.url.as_deref(), ctx.options.url.as_deref()) {
                        Ok(client) => match client
                            .invite(owner_token, ctx.options.label, ctx.options.ttl_seconds)
                            .await
                        {
                            Ok(output) => TypedResult::ok(output),
                            Err(error) => TypedResult::error("INVITE_FAILED", error),
                        },
                        Err(error) => TypedResult::error("CONFIG_ERROR", error),
                    }
                },
            )
            .description("Create a one-time invitation for a uniquely identified agent")
            .done(),
        )
        .command(
            "join",
            CommandDef::typed::<(), JoinOptions, CommsEnv, AgentJoinOutput, _, _>(
                "join",
                |ctx| async move {
                    match auth_client(ctx.env.url.as_deref(), ctx.options.url.as_deref()) {
                        Ok(client) => match client.join(&ctx.options.invitation).await {
                            Ok(output) => TypedResult::ok(output),
                            Err(error) => TypedResult::error("JOIN_FAILED", error),
                        },
                        Err(error) => TypedResult::error("CONFIG_ERROR", error),
                    }
                },
            )
            .description("Redeem an invitation for an ephemeral agent id and token")
            .done(),
        )
        .command(
            "whoami",
            CommandDef::typed::<(), EndpointOptions, CommsEnv, AgentMeOutput, _, _>(
                "whoami",
                move |ctx| {
                    let store = store.clone();
                    async move {
                        let profile = credential_profiles::profile_from_parts(
                            ctx.env.url.as_deref(),
                            ctx.options.url.as_deref(),
                            ctx.env.profile.as_deref(),
                            None,
                        );
                        let token = match ctx.env.token {
                            Some(token) => credentials::CredentialSecret::new(token),
                            None => credentials::CredentialProfileManager::new(store.as_ref())
                                .load_agent(&profile)
                                .and_then(|agent| {
                                    agent
                                        .map(|agent| agent.access)
                                        .ok_or(credentials::CredentialError::EmptySecret)
                                }),
                        };
                        let token = match token {
                            Ok(token) => token,
                            Err(error) => {
                                return TypedResult::error("CONFIG_ERROR", error.to_string());
                            }
                        };
                        match auth_client(ctx.env.url.as_deref(), ctx.options.url.as_deref()) {
                            Ok(client) => match client.me(token.expose()).await {
                                Ok(output) => TypedResult::ok(output),
                                Err(error) => TypedResult::error("WHOAMI_FAILED", error),
                            },
                            Err(error) => TypedResult::error("CONFIG_ERROR", error),
                        }
                    }
                },
            )
            .description("Show the authenticated agent identity")
            .done(),
        )
        .command(
            "revoke",
            CommandDef::typed::<(), RevokeOptions, CommsEnv, RevokeOutput, _, _>(
                "revoke",
                |ctx| async move {
                    let Some(owner_token) = ctx.env.owner_token.as_deref() else {
                        return TypedResult::error("CONFIG_ERROR", "COMMS_OWNER_TOKEN is required");
                    };
                    match auth_client(ctx.env.url.as_deref(), ctx.options.url.as_deref()) {
                        Ok(client) => match client.revoke(owner_token, &ctx.options.id).await {
                            Ok(output) => TypedResult::ok(output),
                            Err(error) => TypedResult::error("REVOKE_FAILED", error),
                        },
                        Err(error) => TypedResult::error("CONFIG_ERROR", error),
                    }
                },
            )
            .description("Revoke an agent token by id")
            .done(),
        )
}

fn auth_client(env_url: Option<&str>, option_url: Option<&str>) -> Result<AuthClient, String> {
    let url = option_url.or(env_url).unwrap_or(DEFAULT_BASE_URL);
    AuthClient::new(url)
}

fn no_redirect_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| format!("failed to create HTTP client: {error}"))
}

fn parse_base_url(raw: &str) -> Result<Url, String> {
    let url = Url::parse(raw).map_err(|_| "COMMS_URL must be an absolute URL".to_string())?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("COMMS_URL must not contain credentials".to_string());
    }
    match url.scheme() {
        "https" => Ok(url),
        "http" if is_localhost(&url) => Ok(url),
        _ => Err("COMMS_URL must use HTTPS unless it points at localhost".to_string()),
    }
}

fn is_localhost(url: &Url) -> bool {
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"))
}

fn endpoint(base: &Url, path: &str) -> Result<Url, String> {
    let mut url = base.clone();
    let base_path = url.path().trim_end_matches('/');
    let suffix = path.trim_start_matches('/');
    url.set_path(&format!("{base_path}/{suffix}"));
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn endpoint_segments(base: &Url, path: &str, segments: &[&str]) -> Result<Url, String> {
    let mut url = endpoint(base, path)?;
    {
        let mut path = url
            .path_segments_mut()
            .map_err(|_| "COMMS_URL cannot be a base URL".to_string())?;
        for segment in segments {
            path.push(segment);
        }
    }
    Ok(url)
}

fn with_bearer(
    request: reqwest::RequestBuilder,
    token: Option<&str>,
) -> Result<reqwest::RequestBuilder, String> {
    let Some(token) = token else {
        return Ok(request);
    };
    let value = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| "invalid bearer token".to_string())?;
    Ok(request.header(AUTHORIZATION, value))
}

async fn send_json_envelope(request: reqwest::RequestBuilder) -> Result<Value, String> {
    let response = request
        .send()
        .await
        .map_err(|error| format!("request failed: {error}"))?;
    if response.status().is_redirection() {
        return Err("redirects are not followed".to_string());
    }
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|error| format!("failed to read response body: {error}"))?;
    let envelope: Result<Envelope, _> = serde_json::from_str(&text);
    match envelope {
        Ok(envelope) if envelope.ok && status.is_success() => {
            Ok(envelope.data.unwrap_or(Value::Null))
        }
        Ok(envelope) => Err(envelope_error(status.as_u16(), envelope.error.as_ref())),
        Err(_) => Err(format!("request failed with HTTP {}", status.as_u16())),
    }
}

fn envelope_error(status: u16, error: Option<&Value>) -> String {
    let message = error
        .and_then(|value| value.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("request failed");
    let code = error
        .and_then(|value| value.get("code"))
        .and_then(Value::as_str);
    match code {
        Some(code) => format!("{code}: {message} (HTTP {status})"),
        None => format!("{message} (HTTP {status})"),
    }
}

fn decode<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T, String> {
    serde_json::from_value(value).map_err(|error| format!("invalid server response: {error}"))
}

fn without_top_level_nulls(value: Value) -> Value {
    match value {
        Value::Object(mut map) => {
            map.retain(|_, value| !value.is_null());
            Value::Object(map)
        }
        value => value,
    }
}

async fn read_upload_part(file: &mut tokio::fs::File, buffer: &mut [u8]) -> Result<usize, String> {
    let mut filled = 0;
    while filled < buffer.len() {
        let read = file
            .read(&mut buffer[filled..])
            .await
            .map_err(|error| format!("failed to read blob file: {error}"))?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    Ok(filled)
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} is required"))
}

impl std::fmt::Debug for HttpBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpBackend")
            .field("base_url", &self.base_url)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}
