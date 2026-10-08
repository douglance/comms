#![cfg(target_arch = "wasm32")]

mod sessions;
mod upload;

use async_trait::async_trait;
use comms_slack_api::Registry;
use comms_slack_runtime::{
    Credential, CredentialProvider, DeliveryRecord, DeliveryState, Invocation, InvocationPolicy,
    InvocationResult, RuntimeError, SlackRuntime, SlackSecret, SlackTransport, TokenClass,
    TransportError, TransportRequest, TransportResponse, mark_delivery_result,
    private_channel_owner_invite, redacted_error,
};
use js_sys::{Function, Object, Promise, Reflect};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::Response as WebResponse;
use worker::Env;

use crate::auth::Agent;

#[derive(Clone)]
pub struct WorkerSlackCredentials {
    pub team_id: String,
    pub owner_user_id: String,
    pub bot_token: Option<String>,
    pub app_token: Option<String>,
    pub user_token: Option<String>,
    pub admin_token: Option<String>,
    pub appconfig_token: Option<String>,
    pub scim_token: Option<String>,
    pub audit_token: Option<String>,
}

impl WorkerSlackCredentials {
    pub fn from_installation_value(value: &Value) -> Result<Self, String> {
        Ok(Self {
            team_id: string_field(value, "team_id")?.to_owned(),
            owner_user_id: string_field(value, "owner_id")?.to_owned(),
            bot_token: optional_string(value, "bot_token"),
            app_token: optional_string(value, "app_token"),
            user_token: optional_string(value, "user_token"),
            admin_token: optional_string(value, "admin_token"),
            appconfig_token: optional_string(value, "appconfig_token"),
            scim_token: optional_string(value, "scim_token"),
            audit_token: optional_string(value, "audit_token"),
        })
    }

    fn from_env_tokens(env: &Env) -> worker::Result<Self> {
        Ok(Self {
            team_id: env
                .var("SLACK_WORKSPACE_ID")
                .or_else(|_| env.var("SLACK_TEAM_ID"))?
                .to_string(),
            owner_user_id: env
                .var("SLACK_OWNER_USER_ID")
                .or_else(|_| env.var("OWNER_SLACK_ID"))?
                .to_string(),
            bot_token: env
                .secret("SLACK_BOT_TOKEN")
                .ok()
                .map(|secret| secret.to_string()),
            app_token: env
                .secret("SLACK_APP_TOKEN")
                .ok()
                .map(|secret| secret.to_string()),
            user_token: env
                .secret("SLACK_USER_TOKEN")
                .ok()
                .map(|secret| secret.to_string()),
            admin_token: env
                .secret("SLACK_ADMIN_TOKEN")
                .ok()
                .map(|secret| secret.to_string()),
            appconfig_token: env
                .secret("SLACK_APPCONFIG_TOKEN")
                .ok()
                .map(|secret| secret.to_string()),
            scim_token: env
                .secret("SLACK_SCIM_TOKEN")
                .ok()
                .map(|secret| secret.to_string()),
            audit_token: env
                .secret("SLACK_AUDIT_TOKEN")
                .ok()
                .map(|secret| secret.to_string()),
        })
    }

    fn token(&self, token_class: TokenClass) -> Option<&str> {
        match token_class {
            TokenClass::Bot => self.bot_token.as_deref(),
            TokenClass::App => self.app_token.as_deref(),
            TokenClass::User => self.user_token.as_deref(),
            TokenClass::Admin => self.admin_token.as_deref(),
            TokenClass::AppConfig => self.appconfig_token.as_deref(),
            TokenClass::Scim => self.scim_token.as_deref(),
            TokenClass::Audit => self.audit_token.as_deref(),
            TokenClass::Public => None,
        }
    }
}

#[async_trait(?Send)]
impl CredentialProvider for WorkerSlackCredentials {
    async fn credential(&self, token_class: TokenClass) -> Result<Credential, RuntimeError> {
        let token = self
            .token(token_class)
            .ok_or(RuntimeError::MissingCredential(token_class))?;
        Ok(Credential {
            workspace_id: self.team_id.clone(),
            token_class,
            token: SlackSecret::new(token.to_owned()),
        })
    }
}

#[derive(Clone)]
struct WorkerSlackTransport {
    api_origin: String,
    env: Env,
    agent: Agent,
}

#[async_trait(?Send)]
impl SlackTransport for WorkerSlackTransport {
    async fn send(
        &self,
        mut request: TransportRequest,
    ) -> Result<TransportResponse, TransportError> {
        let suffix = comms_slack_runtime::fixture_route_suffix(&request.url)
            .ok_or_else(|| transport_error("Slack endpoint rejected", false))?;
        if self.api_origin != "https://slack.com/api/" {
            request.url = format!("{}{suffix}", self.api_origin);
        }
        fetch_runtime_request(&self.env, &self.agent, request).await
    }
}

pub struct WorkerSlackBackend {
    env: Env,
    agent: Agent,
    credentials: WorkerSlackCredentials,
    runtime: SlackRuntime<WorkerSlackCredentials, WorkerSlackTransport>,
}

impl WorkerSlackBackend {
    pub async fn from_env(env: Env, agent: Agent) -> worker::Result<Self> {
        let allow_admin = env
            .var("SLACK_ALLOW_ADMIN")
            .map(|value| value.to_string() == "1" || value.to_string().eq_ignore_ascii_case("true"))
            .unwrap_or(true);
        let mut credentials = match crate::slack_oauth::installation(&env).await {
            Ok(value) => {
                WorkerSlackCredentials::from_installation_value(&value).map_err(worker_error)?
            }
            Err(error) if error.to_string().contains("SLACK_NOT_INSTALLED") => {
                WorkerSlackCredentials::from_env_tokens(&env)?
            }
            Err(error) => return Err(error),
        };
        let injected = |name: &str| env.secret(name).ok().map(|value| value.to_string());
        credentials.app_token = credentials
            .app_token
            .or_else(|| injected("SLACK_APP_TOKEN"));
        credentials.user_token = credentials
            .user_token
            .or_else(|| injected("SLACK_USER_TOKEN"));
        credentials.admin_token = credentials
            .admin_token
            .or_else(|| injected("SLACK_ADMIN_TOKEN"));
        credentials.appconfig_token = credentials
            .appconfig_token
            .or_else(|| injected("SLACK_APPCONFIG_TOKEN"));
        credentials.scim_token = credentials
            .scim_token
            .or_else(|| injected("SLACK_SCIM_TOKEN"));
        credentials.audit_token = credentials
            .audit_token
            .or_else(|| injected("SLACK_AUDIT_TOKEN"));
        Self::from_credentials(env, agent, credentials, allow_admin)
    }

    pub fn from_credentials(
        env: Env,
        agent: Agent,
        credentials: WorkerSlackCredentials,
        allow_admin: bool,
    ) -> worker::Result<Self> {
        let registry = Registry::embedded().map_err(|error| worker_error(error.to_string()))?;
        let policy = InvocationPolicy {
            workspace_id: credentials.team_id.clone(),
            owner_user_id: credentials.owner_user_id.clone(),
            allow_admin,
        };
        let runtime = SlackRuntime::new(
            registry,
            credentials.clone(),
            WorkerSlackTransport {
                api_origin: crate::slack_oauth::api_url(&env, "")?,
                env: env.clone(),
                agent: agent.clone(),
            },
            policy,
        );
        Ok(Self {
            env,
            agent,
            credentials,
            runtime,
        })
    }

    pub async fn invoke(&self, method: &str, arguments: Value) -> Result<Value, String> {
        if method == "files.uploadExternal" {
            return self.upload_blob(arguments).await;
        }
        match method {
            "comms.sessions.start" => return self.session_start(arguments).await,
            "comms.sessions.send" => return self.session_send(arguments).await,
            "comms.sessions.status" => return self.session_status(arguments).await,
            _ => {}
        }
        self.invoke_provider(method, arguments).await
    }

    async fn invoke_provider(&self, method: &str, arguments: Value) -> Result<Value, String> {
        let (arguments, delivery_key) = extract_delivery_key(arguments)?;
        if delivery_key.is_some() && comms_slack_runtime::is_zero_retention_method(method) {
            return Err("zero-retention search cannot use a durable delivery key".into());
        }
        let delivery_key = delivery_key.map(|key| format!("{}:{key}", self.agent.id));
        if let Some(retry_after_ms) = self.method_retry_after(method).await? {
            return Ok(json!({
                "ok": false,
                "method": method,
                "error": "rate_limited",
                "retry_after_ms": retry_after_ms,
                "agent_id": self.agent.id,
                "workspace_id": self.credentials.team_id,
            }));
        }

        let mut delivery = if let Some(key) = delivery_key.as_deref() {
            Some(
                self.load_or_enqueue_delivery(key, method, &arguments)
                    .await?,
            )
        } else {
            None
        };
        if let Some(record) = &delivery
            && matches!(record.state, DeliveryState::Sent)
        {
            let owner_invite = self
                .invite_owner_to_created_channel(
                    method,
                    &arguments,
                    record.result.as_ref().unwrap_or(&Value::Null),
                )
                .await?;
            return Ok(json!({
                "ok": true,
                "method": record.method,
                "delivery_key": record.key,
                "body": record.result,
                "agent_id": self.agent.id,
                "workspace_id": self.credentials.team_id,
                "replayed": true,
                "owner_invite": owner_invite,
            }));
        }

        if let Some(record) = delivery.as_mut() {
            let claim = crate::auth::control_db(&self.env).map_err(|e| e.to_string())?
                .prepare("UPDATE slack_outbox SET state='sending', updated_at=?3 WHERE workspace_id=?1 AND delivery_key=?2 AND state='pending' AND next_attempt_at<=?3")
                .bind(&[JsValue::from_str(&record.workspace_id), JsValue::from_str(&record.key), JsValue::from_f64(now_ms() as f64)])
                .map_err(|e| e.to_string())?.run().await.map_err(|e| e.to_string())?;
            if claim
                .meta()
                .map_err(|e| e.to_string())?
                .and_then(|m| m.changes)
                .unwrap_or(0)
                != 1
            {
                return Ok(
                    json!({"ok":false,"method":method,"delivery_key":record.key,"error":"delivery_requires_reconciliation","state":delivery_state_name(record.state.clone())}),
                );
            }
            record.state = DeliveryState::Sending;
        }

        let result = match self
            .runtime
            .invoke(Invocation {
                agent_id: self.agent.id.clone(),
                method: method.to_owned(),
                arguments: arguments.clone(),
                idempotency_key: delivery_key.clone(),
            })
            .await
        {
            Ok(result) => result,
            Err(error) => {
                if let Some(record) = delivery.as_mut() {
                    self.save_delivery_error(record, method, &error).await?;
                }
                return Err(error.to_string());
            }
        };

        self.save_method_clock(&result).await?;
        if let Some(record) = delivery.as_mut() {
            mark_delivery_result(record, &result, now_ms());
            self.save_delivery_record(record).await?;
        }

        let owner_invite = self
            .owner_invite_if_private_channel(method, &arguments, &result)
            .await?;
        Ok(result_value(
            &self.agent,
            &self.credentials,
            &result,
            delivery_key,
            owner_invite,
        ))
    }

    async fn owner_invite_if_private_channel(
        &self,
        method: &str,
        arguments: &Value,
        result: &InvocationResult,
    ) -> Result<Option<Value>, String> {
        if !result.ok
            || private_channel_owner_invite(method, arguments, &self.credentials.owner_user_id)
                .is_none()
        {
            return Ok(None);
        }
        self.invite_owner_to_created_channel(method, arguments, &result.body)
            .await
    }

    async fn invite_owner_to_created_channel(
        &self,
        method: &str,
        arguments: &Value,
        body: &Value,
    ) -> Result<Option<Value>, String> {
        if private_channel_owner_invite(method, arguments, &self.credentials.owner_user_id)
            .is_none()
        {
            return Ok(None);
        }
        let channel = created_channel_id(body).ok_or_else(|| {
            "Slack private channel create response did not include a channel id".to_string()
        })?;
        let invite = self
            .runtime
            .invoke(Invocation {
                agent_id: self.agent.id.clone(),
                method: "conversations.invite".into(),
                arguments: json!({"channel": channel, "users": self.credentials.owner_user_id}),
                idempotency_key: None,
            })
            .await
            .map_err(|error| error.to_string())?;
        if !invite.ok
            && invite.body.get("error").and_then(Value::as_str) != Some("already_in_channel")
        {
            return Err(format!(
                "Slack private channel owner invite failed: {}",
                invite
                    .body
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
            ));
        }
        Ok(Some(json!({
            "ok": true,
            "method": invite.method,
            "status": invite.status,
        })))
    }

    async fn method_retry_after(&self, method: &str) -> Result<Option<u64>, String> {
        let row: Option<ClockRow> = crate::auth::control_db(&self.env)
            .map_err(|error| error.to_string())?
            .prepare(
                "SELECT next_at FROM slack_method_clock WHERE workspace_id = ?1 AND method = ?2",
            )
            .bind(&[
                JsValue::from_str(&self.credentials.team_id),
                JsValue::from_str(method),
            ])
            .map_err(|error| error.to_string())?
            .first(None)
            .await
            .map_err(|error| error.to_string())?;
        let Some(row) = row else {
            return Ok(None);
        };
        let now = now_ms();
        if row.next_at <= now {
            Ok(None)
        } else {
            Ok(Some(row.next_at - now))
        }
    }

    async fn save_method_clock(&self, result: &InvocationResult) -> Result<(), String> {
        let Some(retry_after_ms) = result.retry_after_ms else {
            return Ok(());
        };
        let next_at = now_ms().saturating_add(retry_after_ms);
        crate::auth::control_db(&self.env)
            .map_err(|error| error.to_string())?
            .prepare("INSERT INTO slack_method_clock(workspace_id, method, next_at) VALUES (?1, ?2, ?3) ON CONFLICT(workspace_id, method) DO UPDATE SET next_at = excluded.next_at")
            .bind(&[
                JsValue::from_str(&self.credentials.team_id),
                JsValue::from_str(&result.method),
                JsValue::from_f64(next_at as f64),
            ])
            .map_err(|error| error.to_string())?
            .run()
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    async fn load_or_enqueue_delivery(
        &self,
        key: &str,
        method: &str,
        arguments: &Value,
    ) -> Result<DeliveryRecord, String> {
        let body = arguments.to_string();
        let now = now_ms();
        let db = crate::auth::control_db(&self.env).map_err(|e| e.to_string())?;
        db.prepare("INSERT OR IGNORE INTO slack_outbox(workspace_id, delivery_key, agent_id, method, body, state, attempts, next_attempt_at, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, 'pending', 0, ?6, ?6, ?6)")
            .bind(&[JsValue::from_str(&self.credentials.team_id), JsValue::from_str(key), JsValue::from_str(&self.agent.id), JsValue::from_str(method), JsValue::from_str(&body), JsValue::from_f64(now as f64)])
            .map_err(|e| e.to_string())?.run().await.map_err(|e| e.to_string())?;
        let row: OutboxRow = db.prepare("SELECT delivery_key, method, body, state, attempts, result, error, next_attempt_at FROM slack_outbox WHERE workspace_id=?1 AND delivery_key=?2 AND agent_id=?3")
            .bind(&[JsValue::from_str(&self.credentials.team_id), JsValue::from_str(key), JsValue::from_str(&self.agent.id)])
            .map_err(|e| e.to_string())?.first(None).await.map_err(|e| e.to_string())?
            .ok_or_else(|| "Slack delivery unavailable".to_string())?;
        if row.method != method || row.body != body {
            return Err("Slack delivery idempotency conflict".into());
        }
        row.into_record(&self.credentials.team_id)
    }

    async fn save_delivery_record(&self, record: &DeliveryRecord) -> Result<(), String> {
        let now = now_ms();
        let stored_result = stored_delivery_result(record);
        crate::auth::control_db(&self.env)
            .map_err(|error| error.to_string())?
            .prepare("UPDATE slack_outbox SET state = ?3, attempts = ?4, result = ?5, error = ?6, next_attempt_at = ?7, updated_at = ?8 WHERE workspace_id = ?1 AND delivery_key = ?2")
            .bind(&[
                JsValue::from_str(&record.workspace_id),
                JsValue::from_str(&record.key),
                JsValue::from_str(delivery_state_name(record.state.clone())),
                JsValue::from_f64(record.attempts as f64),
                optional_js_string(stored_result.as_deref()),
                optional_js_string(record.error.as_deref()),
                JsValue::from_f64(record.next_attempt_at_ms as f64),
                JsValue::from_f64(now as f64),
            ])
            .map_err(|error| error.to_string())?
            .run()
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    async fn save_delivery_error(
        &self,
        record: &mut DeliveryRecord,
        method: &str,
        error: &RuntimeError,
    ) -> Result<(), String> {
        record.attempts = record.attempts.saturating_add(1);
        if error.to_string().contains("ambiguous Slack write") {
            record.state = DeliveryState::Ambiguous;
            record.next_attempt_at_ms = now_ms().saturating_add(30_000);
            record.error = Some("ambiguous_write".into());
        } else {
            record.state = DeliveryState::Failed;
            record.error = Some(error.to_string());
        }
        if comms_slack_runtime::is_zero_retention_method(method) {
            record.result = None;
        }
        self.save_delivery_record(record).await
    }
}

#[derive(Deserialize)]
struct ClockRow {
    next_at: u64,
}

#[derive(Deserialize)]
struct OutboxRow {
    delivery_key: String,
    method: String,
    body: String,
    state: String,
    attempts: u32,
    result: Option<String>,
    error: Option<String>,
    next_attempt_at: u64,
}

impl OutboxRow {
    fn into_record(self, workspace_id: &str) -> Result<DeliveryRecord, String> {
        Ok(DeliveryRecord {
            key: self.delivery_key,
            workspace_id: workspace_id.to_owned(),
            method: self.method,
            body: serde_json::from_str(&self.body).map_err(|error| error.to_string())?,
            state: parse_delivery_state(&self.state),
            attempts: self.attempts,
            result: self
                .result
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(|error| error.to_string())?,
            error: self.error,
            next_attempt_at_ms: self.next_attempt_at,
        })
    }
}

async fn fetch_runtime_request(
    env: &Env,
    agent: &Agent,
    request: TransportRequest,
) -> Result<TransportResponse, TransportError> {
    let mut url = request.url.clone();
    let method = if request.http_method.is_empty() {
        "POST"
    } else {
        request.http_method.as_str()
    };
    let body = String::from_utf8(request.body.clone()).map_err(|error| TransportError {
        message: error.to_string(),
        ambiguous_write: false,
    })?;
    let global = js_sys::global();
    let fetch = Reflect::get(&global, &JsValue::from_str("fetch"))
        .map_err(|_| transport_error("fetch unavailable", false))?
        .dyn_into::<Function>()
        .map_err(|_| transport_error("fetch unavailable", false))?;
    let headers = Object::new();
    if !request.authorization.is_empty() {
        Reflect::set(
            &headers,
            &JsValue::from_str("authorization"),
            &JsValue::from_str(&request.authorization),
        )
        .ok();
    }
    let init = Object::new();
    Reflect::set(
        &init,
        &JsValue::from_str("redirect"),
        &JsValue::from_str("manual"),
    )
    .ok();
    Reflect::set(
        &init,
        &JsValue::from_str("method"),
        &JsValue::from_str(method),
    )
    .ok();
    if method.eq_ignore_ascii_case("GET") {
        if !body.is_empty() {
            url.push(if url.contains('?') { '&' } else { '?' });
            url.push_str(&body);
        }
    } else {
        Reflect::set(
            &headers,
            &JsValue::from_str("content-type"),
            &JsValue::from_str(&request.content_type),
        )
        .ok();
        Reflect::set(&init, &JsValue::from_str("body"), &JsValue::from_str(&body)).ok();
    }
    Reflect::set(&init, &JsValue::from_str("headers"), &headers).ok();
    let promise = fetch
        .call2(&global, &JsValue::from_str(&url), &init)
        .map_err(|_| transport_error("Slack fetch failed", true))?
        .dyn_into::<Promise>()
        .map_err(|_| transport_error("Slack fetch failed", true))?;
    let response = JsFuture::from(promise)
        .await
        .map_err(|_| transport_error("Slack fetch failed", true))?
        .dyn_into::<WebResponse>()
        .map_err(|_| transport_error("Slack fetch response invalid", true))?;
    let status = response.status();
    if (300..400).contains(&status) {
        return Err(transport_error("Slack redirect rejected", false));
    }
    let retry_after = response_header(&response, "retry-after").unwrap_or_default();
    let content_type = response_header(&response, "content-type").unwrap_or_default();
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let mut headers = BTreeMap::new();
    if !retry_after.is_empty() {
        headers.insert("retry-after".to_string(), retry_after);
    }
    if !content_type.is_empty() {
        headers.insert("content-type".to_string(), content_type.clone());
    }
    if (200..300).contains(&status)
        && status != 204
        && !media_type.is_empty()
        && media_type != "application/json"
        && !media_type.ends_with("+json")
    {
        if comms_slack_runtime::is_zero_retention_method(&request.method) {
            return Err(transport_error(
                "zero-retention search requires a JSON response",
                false,
            ));
        }
        let stream = response
            .body()
            .ok_or_else(|| transport_error("Slack binary response has no body", false))?;
        let name = response_header(&response, "content-disposition").and_then(|header| {
            header.split(';').find_map(|part| {
                let (key, value) = part.trim().split_once('=')?;
                key.eq_ignore_ascii_case("filename")
                    .then(|| value.trim_matches('"').to_owned())
            })
        });
        let descriptor = crate::media::put_stream(env, agent, stream, content_type, name)
            .await
            .map_err(|_| transport_error("Slack binary response storage failed", false))?;
        return Ok(TransportResponse {
            status,
            headers,
            body: json!({"artifact": descriptor.value(None, ""), "download_path": format!("/media/{}", descriptor.id)}),
        });
    }
    let text = JsFuture::from(
        response
            .text()
            .map_err(|_| transport_error("Slack fetch body failed", true))?,
    )
    .await
    .map_err(|_| transport_error("Slack fetch body failed", true))?
    .as_string()
    .ok_or_else(|| transport_error("Slack fetch body was not text", true))?;
    let body = if status == 204 && text.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text)
            .map_err(|_| transport_error("Slack response was not JSON", false))?
    };
    Ok(TransportResponse {
        status,
        headers,
        body,
    })
}

fn response_header(response: &WebResponse, name: &str) -> Option<String> {
    let headers = Reflect::get(response.as_ref(), &JsValue::from_str("headers")).ok()?;
    let get = Reflect::get(&headers, &JsValue::from_str("get"))
        .ok()?
        .dyn_into::<Function>()
        .ok()?;
    get.call1(&headers, &JsValue::from_str(name))
        .ok()?
        .as_string()
}

fn result_value(
    agent: &Agent,
    credentials: &WorkerSlackCredentials,
    result: &InvocationResult,
    delivery_key: Option<String>,
    owner_invite: Option<Value>,
) -> Value {
    json!({
        "ok": result.ok,
        "method": result.method,
        "token_class": result.token_class.as_str(),
        "status": result.status,
        "body": redacted_error(&result.body),
        "retry_after_ms": result.retry_after_ms,
        "ambiguous_write": result.ambiguous_write,
        "delivery_key": delivery_key,
        "owner_invite": owner_invite,
        "agent_id": agent.id,
        "workspace_id": credentials.team_id,
    })
}

fn extract_delivery_key(mut arguments: Value) -> Result<(Value, Option<String>), String> {
    let Some(object) = arguments.as_object_mut() else {
        return Ok((arguments, None));
    };
    let key = object
        .remove("idempotency_key")
        .or_else(|| object.remove("delivery_key"))
        .or_else(|| object.remove("_delivery_key"))
        .and_then(|value| value.as_str().map(str::to_owned));
    Ok((arguments, key))
}

fn stored_delivery_result(record: &DeliveryRecord) -> Option<String> {
    if comms_slack_runtime::is_zero_retention_method(&record.method) {
        return None;
    }
    record
        .result
        .as_ref()
        .map(|value| redacted_error(value).to_string())
}

fn delivery_state_name(state: DeliveryState) -> &'static str {
    match state {
        DeliveryState::Pending => "pending",
        DeliveryState::Sending => "sending",
        DeliveryState::Sent => "sent",
        DeliveryState::Failed => "failed",
        DeliveryState::Ambiguous => "ambiguous",
    }
}

fn parse_delivery_state(value: &str) -> DeliveryState {
    match value {
        "sent" => DeliveryState::Sent,
        "failed" => DeliveryState::Failed,
        "ambiguous" => DeliveryState::Ambiguous,
        "sending" => DeliveryState::Sending,
        _ => DeliveryState::Pending,
    }
}

fn created_channel_id(value: &Value) -> Option<&str> {
    value
        .pointer("/channel/id")
        .and_then(Value::as_str)
        .or_else(|| value.get("channel").and_then(Value::as_str))
}

fn string_field<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{field} must be a non-empty string"))
}

fn optional_string(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn optional_js_string(value: Option<&str>) -> JsValue {
    value.map(JsValue::from_str).unwrap_or(JsValue::NULL)
}

fn now_ms() -> u64 {
    js_sys::Date::now().floor() as u64
}

fn transport_error(message: &str, ambiguous_write: bool) -> TransportError {
    TransportError {
        message: message.to_string(),
        ambiguous_write,
    }
}

fn worker_error(message: String) -> worker::Error {
    worker::Error::RustError(message)
}
