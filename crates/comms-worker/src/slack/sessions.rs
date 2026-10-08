//! Agent-owned Slack sessions backed by the existing durable delivery journal.
use super::*;
use serde::Serialize;

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct AgentSession {
    pub session_id: String,
    pub channel_id: String,
    pub thread_ts: String,
    pub name: String,
    pub icon_emoji: Option<String>,
    pub icon_url: Option<String>,
}

#[derive(Deserialize)]
struct SessionRow {
    delivery_key: String,
    body: String,
    result: String,
}

impl WorkerSlackBackend {
    pub(super) async fn session_start(&self, arguments: Value) -> Result<Value, String> {
        let id = session_id(&arguments)?;
        let name = string_field(&arguments, "name")?;
        if name.trim().is_empty() || name.chars().count() > 200 {
            return Err("name must contain 1 to 200 characters".into());
        }
        let title = optional_string(&arguments, "title").unwrap_or_else(|| name.to_owned());
        if title.chars().count() > 200 {
            return Err("title must contain at most 200 characters".into());
        }
        let emoji = optional_string(&arguments, "icon_emoji");
        let url = optional_string(&arguments, "icon_url");
        if emoji.is_some() == url.is_some() {
            return Err("choose exactly one icon_emoji or icon_url".into());
        }
        if let Some(url) = &url {
            let parsed = worker::Url::parse(url).map_err(|_| "icon_url must be an HTTPS URL")?;
            if parsed.scheme() != "https"
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
            {
                return Err("icon_url must be an HTTPS URL without credentials".into());
            }
        }
        let dm = self
            .invoke_provider(
                "conversations.open",
                json!({"users": self.credentials.owner_user_id}),
            )
            .await?;
        require_ok(&dm)?;
        let channel = dm
            .pointer("/body/channel/id")
            .and_then(Value::as_str)
            .ok_or("owner DM response missing channel")?;
        let mut root = json!({"channel":channel, "text":title, "username":name,
            "idempotency_key":format!("session:{id}:root")});
        set_icon(&mut root, emoji.as_deref(), url.as_deref());
        let posted = self.invoke_provider("chat.postMessage", root).await?;
        require_ok(&posted)?;
        let thread = posted
            .pointer("/body/ts")
            .and_then(Value::as_str)
            .ok_or("session root response missing timestamp")?;
        let session = AgentSession {
            session_id: id.to_owned(),
            channel_id: channel.to_owned(),
            thread_ts: thread.to_owned(),
            name: name.to_owned(),
            icon_emoji: emoji,
            icon_url: url,
        };
        let mut params = json!({"channel_id":channel,"thread_ts":thread,"title":title,"status":"processing",
            "username":session.name,"initiator_user_id":self.credentials.owner_user_id,
            "idempotency_key":format!("session:{id}:start")});
        set_icon(
            &mut params,
            session.icon_emoji.as_deref(),
            session.icon_url.as_deref(),
        );
        let status = self
            .invoke_provider("agents.sessions.setStatus", params)
            .await?;
        require_ok(&status)?;
        Ok(
            json!({"ok":true,"session":session,"agent_id":self.agent.id,"workspace_id":self.credentials.team_id}),
        )
    }

    pub(super) async fn session_send(&self, arguments: Value) -> Result<Value, String> {
        let session = self
            .load_session(Some(session_id(&arguments)?))
            .await?
            .ok_or("session not found for this agent")?;
        let key = string_field(&arguments, "idempotency_key")?;
        let text = optional_string(&arguments, "text");
        let blocks = arguments.get("blocks").filter(|v| !v.is_null());
        if text.is_none() && blocks.is_none() {
            return Err("text or blocks is required".into());
        }
        if let Some(blocks) = blocks {
            comms_slack_api::validate_blocks_value(blocks)?;
        }
        let channel = optional_string(&arguments, "channel");
        let thread = optional_string(&arguments, "thread_ts");
        if let Some(channel) = &channel {
            if channel.is_empty()
                || !channel
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err("channel must be a Slack channel ID".into());
            }
        } else if thread.is_some() {
            return Err("channel is required when thread_ts is supplied".into());
        }
        if let Some(thread) = &thread {
            let valid = thread.split_once('.').is_some_and(|(seconds, fraction)| {
                !seconds.is_empty()
                    && !fraction.is_empty()
                    && seconds.bytes().all(|b| b.is_ascii_digit())
                    && fraction.bytes().all(|b| b.is_ascii_digit())
            });
            if !valid {
                return Err("thread_ts must be a Slack message timestamp".into());
            }
        }
        let thread = thread.or_else(|| channel.is_none().then(|| session.thread_ts.clone()));
        let mut params = json!({"channel":channel.unwrap_or(session.channel_id),
            "username":session.name,"idempotency_key":format!("session:{}:send:{key}",session.session_id)});
        if let Some(thread) = thread {
            params["thread_ts"] = json!(thread);
        }
        if let Some(text) = text {
            params["text"] = json!(text);
        }
        if let Some(blocks) = blocks {
            params["blocks"] = blocks.clone();
        }
        set_icon(
            &mut params,
            session.icon_emoji.as_deref(),
            session.icon_url.as_deref(),
        );
        self.invoke_provider("chat.postMessage", params).await
    }

    pub(super) async fn session_status(&self, arguments: Value) -> Result<Value, String> {
        let session = self
            .load_session(Some(session_id(&arguments)?))
            .await?
            .ok_or("session not found for this agent")?;
        let status = string_field(&arguments, "status")?;
        if !matches!(status, "processing" | "active" | "suspended" | "closed") {
            return Err("invalid session status".into());
        }
        let key = string_field(&arguments, "idempotency_key")?;
        self.invoke_provider(
            "agents.sessions.setStatus",
            json!({"channel_id":session.channel_id,
            "thread_ts":session.thread_ts,"status":status,
            "idempotency_key":format!("session:{}:status:{key}",session.session_id)}),
        )
        .await
    }

    pub(crate) async fn load_session(
        &self,
        id: Option<&str>,
    ) -> Result<Option<AgentSession>, String> {
        if let Some(id) = id {
            validate_session_id(id)?;
        }
        let key = id.map(|id| format!("{}:session:{id}:root", self.agent.id));
        let row: Option<SessionRow> = crate::auth::control_db(&self.env).map_err(|e|e.to_string())?
            .prepare("SELECT delivery_key, body, result FROM slack_outbox WHERE workspace_id=?1 AND agent_id=?2 AND method='chat.postMessage' AND state='sent' AND (?3 IS NULL OR delivery_key=?3) AND json_extract(body,'$.thread_ts') IS NULL AND substr(delivery_key,1,length(?4))=?4 AND substr(delivery_key,-5)=':root' ORDER BY created_at DESC, delivery_key DESC LIMIT 1")
            .bind(&[JsValue::from_str(&self.credentials.team_id),JsValue::from_str(&self.agent.id),
                optional_js_string(key.as_deref()),JsValue::from_str(&format!("{}:session:",self.agent.id))])
            .map_err(|e|e.to_string())?.first(None).await.map_err(|e|e.to_string())?;
        row.map(|row| {
            let body: Value = serde_json::from_str(&row.body).map_err(|e| e.to_string())?;
            let result: Value = serde_json::from_str(&row.result).map_err(|e| e.to_string())?;
            let prefix = format!("{}:session:", self.agent.id);
            Ok(AgentSession {
                session_id: row
                    .delivery_key
                    .strip_prefix(&prefix)
                    .and_then(|s| s.strip_suffix(":root"))
                    .ok_or("invalid stored session")?
                    .to_owned(),
                channel_id: string_field(&body, "channel")?.to_owned(),
                thread_ts: string_field(&result, "ts")?.to_owned(),
                name: string_field(&body, "username")?.to_owned(),
                icon_emoji: optional_string(&body, "icon_emoji"),
                icon_url: optional_string(&body, "icon_url"),
            })
        })
        .transpose()
    }
}
fn session_id(value: &Value) -> Result<&str, String> {
    let id = string_field(value, "session_id")?;
    validate_session_id(id)?;
    Ok(id)
}
fn validate_session_id(id: &str) -> Result<(), String> {
    if id.is_empty()
        || id.len() > 100
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(
            "session_id must contain 1 to 100 letters, digits, hyphens, or underscores".into(),
        );
    }
    Ok(())
}
fn set_icon(params: &mut Value, emoji: Option<&str>, url: Option<&str>) {
    if let Some(emoji) = emoji {
        params["icon_emoji"] = json!(emoji);
    }
    if let Some(url) = url {
        params["icon_url"] = json!(url);
    }
}
fn require_ok(value: &Value) -> Result<(), String> {
    if value.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(format!(
            "Slack session operation failed: {}",
            value.get("body").unwrap_or(value)
        ))
    }
}
