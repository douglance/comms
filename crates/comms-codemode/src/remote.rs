use std::fmt;

use async_trait::async_trait;
use incurs_codemode::{CodeModeRunOptions, CodeModeService, ExecutionState, SearchOutput};
use reqwest::Url;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

const DEFAULT_BASE_URL: &str = "https://comms.example.com";

#[derive(Clone)]
pub struct RemoteCodeModeService {
    client: reqwest::Client,
    base_url: Url,
    zero_retention: bool,
    token: String,
}

impl RemoteCodeModeService {
    pub fn new(base_url: impl AsRef<str>, token: impl Into<String>) -> Result<Self, String> {
        let token = token.into();
        if token.trim().is_empty() {
            return Err("COMMS_TOKEN is required for hosted Code Mode".to_string());
        }
        let mut base_url = Url::parse(base_url.as_ref()).map_err(|error| error.to_string())?;
        if !base_url.username().is_empty() || base_url.password().is_some() {
            return Err("hosted Code Mode URL must not contain credentials".to_string());
        }
        let loopback = matches!(
            base_url.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
        );
        if base_url.scheme() != "https" && !(base_url.scheme() == "http" && loopback) {
            return Err("hosted Code Mode requires https or localhost".to_string());
        }
        base_url.set_query(None);
        base_url.set_fragment(None);
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| error.to_string())?;
        Ok(Self {
            client,
            base_url,
            zero_retention: false,
            token,
        })
    }

    pub fn with_zero_retention(mut self, enabled: bool) -> Self {
        self.zero_retention = enabled;
        self
    }

    pub fn retention_from_env(self) -> Result<Self, String> {
        match std::env::var("COMMS_CODEMODE_RETENTION").ok().as_deref() {
            None | Some("durable") => Ok(self.with_zero_retention(false)),
            Some("memory") => Ok(self.with_zero_retention(true)),
            _ => Err("COMMS_CODEMODE_RETENTION must be durable or memory".into()),
        }
    }

    pub fn from_env() -> Result<Self, String> {
        let base_url = std::env::var("COMMS_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_string());
        let token = std::env::var("COMMS_TOKEN")
            .map_err(|_| "COMMS_TOKEN is required for hosted Code Mode".to_string())?;
        Self::new(base_url, token)?.retention_from_env()
    }

    async fn post<T: DeserializeOwned>(&self, path: &str, body: Value) -> Result<T, String> {
        let data = self.post_value(path, body).await?;
        serde_json::from_value(data).map_err(|error| error.to_string())
    }

    async fn post_execution(&self, path: &str, body: Value) -> Result<ExecutionState, String> {
        decode_execution_data(self.post_value(path, body).await?)
    }

    async fn post_value(&self, path: &str, body: Value) -> Result<Value, String> {
        let response = self
            .client
            .post(endpoint(&self.base_url, path)?)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|error| error.to_string())?;
        let status = response.status();
        let value = response
            .json::<Value>()
            .await
            .map_err(|error| format!("invalid Code Mode response: {error}"))?;
        if !status.is_success() {
            return Err(format!(
                "Code Mode HTTP {status}: {}",
                compact_error(&value)
            ));
        }
        if value.get("ok").and_then(Value::as_bool) == Some(false) {
            return Err(compact_error(&value));
        }
        Ok(value.get("data").cloned().unwrap_or(value))
    }
}

impl fmt::Debug for RemoteCodeModeService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteCodeModeService")
            .field("base_url", &self.base_url.as_str())
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl CodeModeService for RemoteCodeModeService {
    async fn search(&self, query: String) -> Result<SearchOutput, String> {
        self.post("/api/codemode/search", json!({ "query": query }))
            .await
    }

    async fn execute(
        &self,
        code: String,
        _options: CodeModeRunOptions,
    ) -> Result<ExecutionState, String> {
        let path = if self.zero_retention {
            "/api/codemode/zero-retention/execute"
        } else {
            "/api/codemode/execute"
        };
        self.post_execution(path, json!({ "code": code })).await
    }

    async fn execution(&self, execution_id: String) -> Result<ExecutionState, String> {
        if self.zero_retention {
            return Err("Memory-only executions return their terminal state directly and cannot be retrieved later".into());
        }
        self.post_execution(
            "/api/codemode/execution",
            json!({ "execution_id": execution_id }),
        )
        .await
    }

    async fn artifact(&self, execution_id: String, artifact_id: String) -> Result<Value, String> {
        if self.zero_retention {
            return Err("Memory-only executions do not retain artifacts".into());
        }
        self.post(
            "/api/codemode/execution",
            json!({ "execution_id": execution_id, "artifact_id": artifact_id }),
        )
        .await
    }

    async fn approve(
        &self,
        execution_id: String,
        seq: u64,
        _options: CodeModeRunOptions,
    ) -> Result<ExecutionState, String> {
        if self.zero_retention {
            return Err(
                "Memory-only executions finish synchronously and have no durable lifecycle actions"
                    .into(),
            );
        }
        self.post_execution(
            "/api/codemode/decide",
            json!({ "execution_id": execution_id, "seq": seq, "decision": "approve" }),
        )
        .await
    }

    async fn reject(&self, execution_id: String, seq: u64) -> Result<ExecutionState, String> {
        if self.zero_retention {
            return Err(
                "Memory-only executions finish synchronously and have no durable lifecycle actions"
                    .into(),
            );
        }
        self.post_execution(
            "/api/codemode/decide",
            json!({ "execution_id": execution_id, "seq": seq, "decision": "reject" }),
        )
        .await
    }

    async fn cancel(&self, execution_id: String) -> Result<ExecutionState, String> {
        if self.zero_retention {
            return Err(
                "Memory-only executions finish synchronously and have no durable lifecycle actions"
                    .into(),
            );
        }
        self.post_execution(
            "/api/codemode/cancel",
            json!({ "execution_id": execution_id }),
        )
        .await
    }
}

fn decode_execution_data(data: Value) -> Result<ExecutionState, String> {
    let execution = data.get("execution").cloned().unwrap_or(data);
    serde_json::from_value(execution).map_err(|error| error.to_string())
}

fn endpoint(base_url: &Url, path: &str) -> Result<Url, String> {
    let path = path.trim_start_matches('/');
    base_url.join(path).map_err(|error| error.to_string())
}

fn compact_error(value: &Value) -> String {
    if let Some(error) = value.get("error") {
        if let Some(message) = error.get("message").and_then(Value::as_str) {
            return message.to_string();
        }
        if let Some(code) = error.get("code").and_then(Value::as_str) {
            return code.to_string();
        }
        return error.to_string();
    }
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_bearer_token() {
        let error = RemoteCodeModeService::new("https://example.com", "").unwrap_err();
        assert_eq!(error, "COMMS_TOKEN is required for hosted Code Mode");
    }

    #[test]
    fn rejects_plain_http_remote_hosts() {
        let error = RemoteCodeModeService::new("http://example.com", "token").unwrap_err();
        assert_eq!(error, "hosted Code Mode requires https or localhost");
    }

    #[test]
    fn debug_redacts_bearer_token() {
        let service = RemoteCodeModeService::new("https://example.com", "secret-token").unwrap();
        let debug = format!("{service:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret-token"));
    }
    #[test]
    fn local_transport_accepts_only_http_loopback() {
        for url in [
            "http://127.0.0.1:9411",
            "http://localhost:9411",
            "http://[::1]:9411",
        ] {
            assert!(RemoteCodeModeService::new(url, "fixture").is_ok());
        }
        for url in [
            "ftp://localhost",
            "http://example.com",
            "https://user:secret@example.com",
        ] {
            assert!(RemoteCodeModeService::new(url, "fixture").is_err());
        }
    }
}
