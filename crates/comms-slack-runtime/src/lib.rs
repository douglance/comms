//! Runtime policy, transport, and durable delivery primitives for Slack access.

use async_trait::async_trait;
use comms_slack_api::{Method, Registry};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenClass {
    Bot,
    App,
    User,
    Admin,
    AppConfig,
    Scim,
    Audit,
    Public,
}

impl TokenClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bot => "bot",
            Self::App => "app",
            Self::User => "user",
            Self::Admin => "admin",
            Self::AppConfig => "app_config",
            Self::Scim => "scim",
            Self::Audit => "audit",
            Self::Public => "public",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SlackSecret(String);

impl SlackSecret {
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SlackSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SlackSecret(REDACTED)")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credential {
    pub workspace_id: String,
    pub token_class: TokenClass,
    pub token: SlackSecret,
}

#[async_trait(?Send)]
pub trait CredentialProvider: Send + Sync {
    async fn credential(&self, token_class: TokenClass) -> Result<Credential, RuntimeError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportRequest {
    pub method: String,
    pub url: String,
    pub http_method: String,
    pub token_class: TokenClass,
    pub authorization: String,
    pub content_type: String,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TransportResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportError {
    pub message: String,
    pub ambiguous_write: bool,
}

#[async_trait(?Send)]
pub trait SlackTransport: Send + Sync {
    async fn send(&self, request: TransportRequest) -> Result<TransportResponse, TransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Invocation {
    pub agent_id: String,
    pub method: String,
    pub arguments: Value,
    pub idempotency_key: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InvocationResult {
    pub ok: bool,
    pub method: String,
    pub token_class: TokenClass,
    pub status: u16,
    pub body: Value,
    pub retry_after_ms: Option<u64>,
    pub ambiguous_write: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    UnknownMethod(String),
    PolicyDenied(String),
    MissingCredential(TokenClass),
    WorkspaceMismatch { expected: String, actual: String },
    Transport(String),
    InvalidResponse(String),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownMethod(method) => write!(formatter, "unknown Slack method {method}"),
            Self::PolicyDenied(message) => formatter.write_str(message),
            Self::MissingCredential(class) => {
                write!(formatter, "missing {} Slack credential", class.as_str())
            }
            Self::WorkspaceMismatch { expected, actual } => write!(
                formatter,
                "Slack credential workspace {actual} does not match {expected}"
            ),
            Self::Transport(message) => formatter.write_str(message),
            Self::InvalidResponse(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for RuntimeError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvocationPolicy {
    pub workspace_id: String,
    pub owner_user_id: String,
    pub allow_admin: bool,
}

pub fn is_zero_retention_method(method: &str) -> bool {
    method.starts_with("search.") || method.starts_with("assistant.search.")
}

fn requires_owner_visibility(method: &str) -> bool {
    is_zero_retention_method(method)
        || matches!(
            method,
            "conversations.list"
                | "conversations.history"
                | "conversations.replies"
                | "conversations.info"
                | "conversations.members"
        )
}

impl InvocationPolicy {
    pub fn authorize(
        &self,
        method: &Method,
        arguments: &Value,
    ) -> Result<TokenClass, RuntimeError> {
        reject_caller_supplied_authority(arguments)?;
        for key in ["team_id", "workspace_id"] {
            if let Some(target) = arguments.get(key).and_then(Value::as_str)
                && target != self.workspace_id
            {
                return Err(RuntimeError::WorkspaceMismatch {
                    expected: self.workspace_id.clone(),
                    actual: target.to_owned(),
                });
            }
        }
        let owner_scim_write = method.name.starts_with("scim.")
            && !method.http_method.eq_ignore_ascii_case("GET")
            && arguments.get("id").and_then(Value::as_str) == Some(self.owner_user_id.as_str());
        if owner_scim_write
            || (!is_admin_read_method(&method.name)
                && is_owner_affecting(method.name.as_str(), arguments, &self.owner_user_id))
        {
            return Err(RuntimeError::PolicyDenied(
                "Slack owner access, role, membership, and recovery controls are protected".into(),
            ));
        }
        if is_zero_retention_method(&method.name) && contains_persistence_hint(arguments) {
            return Err(RuntimeError::PolicyDenied(
                "Slack real-time search results are zero-retention and cannot be requested with caching or logging".into(),
            ));
        }
        if method.name.starts_with("admin.") {
            if !self.allow_admin {
                return Err(RuntimeError::PolicyDenied(
                    "Slack admin methods require an injected admin credential".into(),
                ));
            }
            if !allowed_admin_method(&method.name) {
                return Err(RuntimeError::PolicyDenied(format!(
                    "Slack admin method {} is not classified as safe for agent use",
                    method.name
                )));
            }
            return Ok(TokenClass::Admin);
        }
        if matches!(
            method.name.as_str(),
            "apps.connections.open" | "apps.event.authorizations.list"
        ) || token_types_include(&method.token_types, "app-level")
        {
            return Ok(TokenClass::App);
        }
        if method.name == "api.test" {
            return Ok(TokenClass::Public);
        }
        if method.name.starts_with("apps.manifest.") {
            return Ok(TokenClass::AppConfig);
        }
        if method.name.starts_with("scim.") {
            return Ok(TokenClass::Scim);
        }
        if matches!(
            method.name.as_str(),
            "audit.actions.list" | "audit.schemas.list" | "status.current" | "status.history"
        ) {
            return Ok(TokenClass::Public);
        }
        if method.name.starts_with("audit.") {
            return Ok(TokenClass::Audit);
        }
        if requires_owner_visibility(&method.name) {
            Ok(TokenClass::User)
        } else if token_types_include(&method.token_types, "bot") {
            Ok(TokenClass::Bot)
        } else if token_types_include(&method.token_types, "user") {
            Ok(TokenClass::User)
        } else if defaults_to_bot_token(&method.name) {
            Ok(TokenClass::Bot)
        } else if method.name == "search.query" || method.name.starts_with("search.") {
            Ok(TokenClass::User)
        } else {
            Err(RuntimeError::PolicyDenied(format!(
                "Slack method {} has no supported token class",
                method.name
            )))
        }
    }
}

pub struct SlackRuntime<C, T> {
    registry: Registry,
    credentials: C,
    transport: T,
    policy: InvocationPolicy,
}

impl<C, T> SlackRuntime<C, T> {
    pub fn new(registry: Registry, credentials: C, transport: T, policy: InvocationPolicy) -> Self {
        Self {
            registry,
            credentials,
            transport,
            policy,
        }
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}

impl<C, T> SlackRuntime<C, T>
where
    C: CredentialProvider,
    T: SlackTransport,
{
    pub async fn invoke(&self, invocation: Invocation) -> Result<InvocationResult, RuntimeError> {
        let method = self
            .registry
            .get(&invocation.method)
            .ok_or_else(|| RuntimeError::UnknownMethod(invocation.method.clone()))?;
        let mut token_class = self.policy.authorize(method, &invocation.arguments)?;
        validate_input_schema(method, &invocation.arguments)?;
        let credential = if token_class == TokenClass::Public {
            Credential {
                workspace_id: self.policy.workspace_id.clone(),
                token_class,
                token: SlackSecret::new(""),
            }
        } else {
            match self.credentials.credential(token_class).await {
                Err(RuntimeError::MissingCredential(TokenClass::User))
                    if !is_zero_retention_method(&method.name)
                        && token_types_include(&method.token_types, "bot") =>
                {
                    token_class = TokenClass::Bot;
                    self.credentials.credential(token_class).await?
                }
                result => result?,
            }
        };
        if credential.workspace_id != self.policy.workspace_id {
            return Err(RuntimeError::WorkspaceMismatch {
                expected: self.policy.workspace_id.clone(),
                actual: credential.workspace_id,
            });
        }
        let request = transport_request(
            method,
            token_class,
            &credential.token,
            &invocation.arguments,
        )?;
        let response = self.transport.send(request).await.map_err(|error| {
            if error.ambiguous_write {
                RuntimeError::Transport(format!("ambiguous Slack write: {}", error.message))
            } else {
                RuntimeError::Transport(error.message)
            }
        })?;
        let retry_after_ms = retry_after_ms(&response.headers);
        let ok = response
            .body
            .get("ok")
            .and_then(Value::as_bool)
            .unwrap_or(response.status < 400);
        Ok(InvocationResult {
            ok,
            method: method.name.clone(),
            token_class,
            status: response.status,
            body: response.body,
            retry_after_ms,
            ambiguous_write: false,
        })
    }
}

fn validate_input_schema(method: &Method, arguments: &Value) -> Result<(), RuntimeError> {
    let schema = &method.input_schema;
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for field in required.iter().filter_map(Value::as_str) {
            if arguments.get(field).is_none_or(Value::is_null) {
                return Err(RuntimeError::PolicyDenied(format!(
                    "Slack method {} missing required argument `{field}`",
                    method.name
                )));
            }
        }
    }
    if schema_accepts(schema, schema, arguments, 0) {
        Ok(())
    } else {
        Err(RuntimeError::PolicyDenied(format!(
            "Slack method {} arguments do not match its schema",
            method.name
        )))
    }
}

fn schema_accepts(root: &Value, schema: &Value, value: &Value, depth: usize) -> bool {
    if depth > 64 {
        return false;
    }
    if let Some(allowed) = schema.as_bool() {
        return allowed;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let Some(target) = reference
            .strip_prefix('#')
            .and_then(|path| root.pointer(path))
        else {
            return false;
        };
        if !schema_accepts(root, target, value, depth + 1) {
            return false;
        }
    }
    if schema
        .get("const")
        .is_some_and(|expected| expected != value)
        || schema
            .get("enum")
            .and_then(Value::as_array)
            .is_some_and(|values| !values.contains(value))
    {
        return false;
    }
    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(branches) = schema.get(keyword).and_then(Value::as_array) {
            let accepted = branches
                .iter()
                .filter(|branch| schema_accepts(root, branch, value, depth + 1))
                .count();
            let valid = match keyword {
                "allOf" => accepted == branches.len(),
                "anyOf" => accepted > 0,
                _ => accepted == 1,
            };
            if !valid {
                return false;
            }
        }
    }
    if schema
        .get("not")
        .is_some_and(|denied| schema_accepts(root, denied, value, depth + 1))
    {
        return false;
    }
    let accepts_type = |name: &str| match name {
        "null" => value.is_null(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        _ => false,
    };
    match schema.get("type") {
        Some(Value::String(name)) if !accepts_type(name) => return false,
        Some(Value::Array(names)) if !names.iter().filter_map(Value::as_str).any(accepts_type) => {
            return false;
        }
        _ => {}
    }
    if let Some(object) = value.as_object() {
        if schema
            .get("required")
            .and_then(Value::as_array)
            .is_some_and(|required| {
                required
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|name| !object.contains_key(name))
            })
        {
            return false;
        }
        let properties = schema.get("properties").and_then(Value::as_object);
        for (name, item) in object {
            let property = properties.and_then(|properties| properties.get(name));
            if let Some(property) = property {
                if !schema_accepts(root, property, item, depth + 1) {
                    return false;
                }
            } else if let Some(additional) = schema.get("additionalProperties")
                && !schema_accepts(root, additional, item, depth + 1)
            {
                return false;
            }
        }
    }
    if let Some(items) = value.as_array() {
        if schema
            .get("minItems")
            .and_then(Value::as_u64)
            .is_some_and(|min| items.len() < min as usize)
            || schema
                .get("maxItems")
                .and_then(Value::as_u64)
                .is_some_and(|max| items.len() > max as usize)
        {
            return false;
        }
        let prefix = schema.get("prefixItems").and_then(Value::as_array);
        for (index, item) in items.iter().enumerate() {
            let constraint = prefix
                .and_then(|prefix| prefix.get(index))
                .or_else(|| schema.get("items"));
            if constraint
                .is_some_and(|constraint| !schema_accepts(root, constraint, item, depth + 1))
            {
                return false;
            }
        }
    }
    if let Some(text) = value.as_str() {
        let length = text.chars().count() as u64;
        if schema
            .get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|min| length < min)
            || schema
                .get("maxLength")
                .and_then(Value::as_u64)
                .is_some_and(|max| length > max)
        {
            return false;
        }
    }
    if let Some(number) = value.as_f64()
        && (schema
            .get("minimum")
            .and_then(Value::as_f64)
            .is_some_and(|min| number < min)
            || schema
                .get("maximum")
                .and_then(Value::as_f64)
                .is_some_and(|max| number > max)
            || schema
                .get("exclusiveMinimum")
                .and_then(Value::as_f64)
                .is_some_and(|min| number <= min)
            || schema
                .get("exclusiveMaximum")
                .and_then(Value::as_f64)
                .is_some_and(|max| number >= max))
    {
        return false;
    }
    true
}

fn transport_request(
    method: &Method,
    token_class: TokenClass,
    token: &SlackSecret,
    arguments: &Value,
) -> Result<TransportRequest, RuntimeError> {
    let (url, wire_arguments) = rest_route(method, arguments)?;
    let content_type = if !method.http_method.eq_ignore_ascii_case("GET")
        && method
            .content_types
            .iter()
            .any(|value| value == "application/json")
    {
        "application/json".to_string()
    } else {
        "application/x-www-form-urlencoded".to_string()
    };
    let body = if method.http_method.eq_ignore_ascii_case("DELETE") {
        Vec::new()
    } else if content_type == "application/json" {
        serde_json::to_vec(&wire_arguments)
            .map_err(|error| RuntimeError::InvalidResponse(error.to_string()))?
    } else {
        form_encode(&wire_arguments)?.into_bytes()
    };
    Ok(TransportRequest {
        method: method.name.clone(),
        url,
        http_method: method.http_method.clone(),
        token_class,
        authorization: if token_class == TokenClass::Public {
            String::new()
        } else {
            format!("Bearer {}", token.expose())
        },
        content_type,
        body,
    })
}

fn rest_route(method: &Method, arguments: &Value) -> Result<(String, Value), RuntimeError> {
    if method.name.starts_with("status.") {
        let path = match method.name.as_str() {
            "status.current" => "/api/v2.0.0/current",
            "status.history" => "/api/v2.0.0/history",
            _ => {
                return Err(RuntimeError::PolicyDenied(
                    "invalid Slack Status catalog route".into(),
                ));
            }
        };
        if method.path != path || method.http_method != "GET" {
            return Err(RuntimeError::PolicyDenied(
                "invalid Slack Status catalog route".into(),
            ));
        }
        return Ok((format!("https://slack-status.com{path}"), arguments.clone()));
    }
    if method.name.starts_with("scim.") {
        if !method.path.starts_with("/scim/v1/") && !method.path.starts_with("/scim/v2/") {
            return Err(RuntimeError::PolicyDenied(
                "invalid SCIM catalog route".into(),
            ));
        }
        let mut path = method.path.clone();
        let mut query = arguments.clone();
        if path.contains("{id}") {
            let id = arguments
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| {
                    !id.is_empty()
                        && id
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                })
                .ok_or_else(|| {
                    RuntimeError::PolicyDenied("SCIM id must be an opaque Slack resource ID".into())
                })?;
            path = path.replace("{id}", id);
            query
                .as_object_mut()
                .ok_or_else(|| {
                    RuntimeError::PolicyDenied("SCIM arguments must be an object".into())
                })?
                .remove("id");
        }
        let wire = if matches!(method.http_method.as_str(), "POST" | "PATCH" | "PUT") {
            arguments
                .get("body")
                .filter(|body| body.is_object())
                .cloned()
                .ok_or_else(|| RuntimeError::PolicyDenied("SCIM body must be an object".into()))?
        } else {
            query
        };
        return Ok((format!("https://api.slack.com{path}"), wire));
    }
    if method.name.starts_with("audit.") {
        if !matches!(
            method.path.as_str(),
            "/audit/v1/actions" | "/audit/v1/schemas" | "/audit/v1/logs"
        ) {
            return Err(RuntimeError::PolicyDenied(
                "invalid Audit Logs catalog route".into(),
            ));
        }
        return Ok((
            format!("https://api.slack.com{}", method.path),
            arguments.clone(),
        ));
    }
    Ok((
        format!("https://slack.com/api/{}", method.name),
        arguments.clone(),
    ))
}

/// Maps only canonical Slack API origins into the loopback fixture transport.
pub fn fixture_route_suffix(url: &str) -> Option<String> {
    for path in ["current", "history"] {
        if url == format!("https://slack-status.com/api/v2.0.0/{path}") {
            return Some(format!("status/v2.0.0/{path}"));
        }
    }
    if let Some(path) = url.strip_prefix("https://slack.com/api/") {
        return Some(path.to_owned());
    }
    for prefix in ["scim/v1/", "scim/v2/", "audit/v1/"] {
        if let Some(path) = url.strip_prefix(&format!("https://api.slack.com/{prefix}")) {
            return Some(format!("{prefix}{path}"));
        }
    }
    None
}

fn form_encode(value: &Value) -> Result<String, RuntimeError> {
    let object = value.as_object().ok_or_else(|| {
        RuntimeError::PolicyDenied("Slack arguments must be a JSON object".into())
    })?;
    let mut pairs = Vec::new();
    for (key, value) in object {
        let rendered = match value {
            Value::Null => continue,
            Value::String(value) => value.clone(),
            Value::Bool(value) => value.to_string(),
            Value::Number(value) => value.to_string(),
            other => serde_json::to_string(other)
                .map_err(|error| RuntimeError::InvalidResponse(error.to_string()))?,
        };
        pairs.push(format!(
            "{}={}",
            percent_encode(key),
            percent_encode(&rendered)
        ));
    }
    Ok(pairs.join("&"))
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char)
            }
            b' ' => encoded.push('+'),
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }
    encoded
}

fn retry_after_ms(headers: &BTreeMap<String, String>) -> Option<u64> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("retry-after"))
        .and_then(|(_, value)| value.parse::<u64>().ok())
        .map(|seconds| seconds.saturating_mul(1000))
}

fn reject_caller_supplied_authority(value: &Value) -> Result<(), RuntimeError> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let normalized = key.to_ascii_lowercase();
                if matches!(
                    normalized.as_str(),
                    "token"
                        | "auth"
                        | "authorization"
                        | "headers"
                        | "api_url"
                        | "base_url"
                        | "endpoint"
                        | "server_url"
                ) {
                    return Err(RuntimeError::PolicyDenied(format!(
                        "Slack caller-supplied authority field `{key}` is not allowed"
                    )));
                }
                reject_caller_supplied_authority(value)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for value in values {
                reject_caller_supplied_authority(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn contains_persistence_hint(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "cache" | "cache_results" | "retain" | "log_results"
            ) || contains_persistence_hint(value)
        }),
        Value::Array(values) => values.iter().any(contains_persistence_hint),
        _ => false,
    }
}

fn token_types_include(token_types: &[String], required: &str) -> bool {
    token_types.iter().any(|token| {
        let normalized = token.to_ascii_lowercase().replace([' ', '-', '_'], "");
        normalized == required || normalized.contains(required)
    })
}

fn defaults_to_bot_token(name: &str) -> bool {
    [
        "apps.",
        "assistant.",
        "bookmarks.",
        "canvases.",
        "chat.",
        "conversations.",
        "dialog.",
        "dnd.",
        "emoji.",
        "files.",
        "lists.",
        "pins.",
        "reactions.",
        "reminders.",
        "stars.",
        "team.",
        "usergroups.",
        "users.",
        "views.",
        "workflows.",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

fn is_admin_read_method(name: &str) -> bool {
    name.starts_with("admin.")
        && matches!(
            name.rsplit('.').next().unwrap_or(""),
            "getFile"
                | "activity"
                | "metadata"
                | "list"
                | "lookup"
                | "getItem"
                | "getEntities"
                | "listOriginalConnectedChannelInfo"
                | "getConversationPrefs"
                | "getCustomRetention"
                | "getTeams"
                | "listGroups"
                | "search"
                | "listAssignments"
                | "info"
                | "fetch"
                | "listChannels"
                | "getExpiration"
                | "getSettings"
                | "export"
        )
}

fn allowed_admin_method(name: &str) -> bool {
    matches!(
        name,
        "admin.legalHold.policies.activate"
            | "admin.legalHold.policies.create"
            | "admin.legalHold.policies.info"
            | "admin.legalHold.policies.list"
            | "admin.legalHold.policies.release"
            | "admin.legalHold.policies.set"
            | "admin.legalHold.entities.add"
            | "admin.legalHold.entities.list"
            | "admin.legalHold.entities.remove"
    ) || is_admin_read_method(name)
        || name.starts_with("admin.emoji.")
        || name == "admin.conversations.create"
        || name == "admin.conversations.invite"
        || name == "admin.apps.approve"
        || name == "admin.apps.requests.list"
        || name == "admin.apps.mcp.servers.list"
        || name == "admin.apps.mcp.servers.permissions.set"
}

fn is_owner_affecting(method: &str, arguments: &Value, owner_user_id: &str) -> bool {
    let destructive = method.contains("remove")
        || method.contains("delete")
        || method.contains("setOwner")
        || method.contains("setRegular")
        || method.contains("setAdmin")
        || method.contains("assign")
        || method.contains("kick")
        || method.contains("restrictAccess")
        || method.contains("roles.")
        || method.contains("permissions.set")
        || method.contains(".permissions.");
    destructive && contains_string(arguments, owner_user_id)
}

fn contains_string(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(value) => {
            value == needle || value.split(',').any(|part| part.trim() == needle)
        }
        Value::Array(values) => values.iter().any(|value| contains_string(value, needle)),
        Value::Object(object) => object.values().any(|value| contains_string(value, needle)),
        _ => false,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DeliveryState {
    Pending,
    Sending,
    Sent,
    Failed,
    Ambiguous,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeliveryRecord {
    pub key: String,
    pub workspace_id: String,
    pub method: String,
    pub body: Value,
    pub state: DeliveryState,
    pub attempts: u32,
    pub result: Option<Value>,
    pub error: Option<String>,
    pub next_attempt_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryError {
    IdempotencyConflict,
    Store(String),
}

pub trait DeliveryStore: Send + Sync {
    fn enqueue(&self, record: DeliveryRecord) -> Result<DeliveryRecord, DeliveryError>;
    fn next_ready(
        &self,
        workspace_id: &str,
        now_ms: u64,
    ) -> Result<Option<DeliveryRecord>, DeliveryError>;
    fn save(&self, record: DeliveryRecord) -> Result<(), DeliveryError>;
}

#[derive(Clone, Default)]
pub struct MemoryDeliveryStore {
    inner: Arc<Mutex<HashMap<(String, String), DeliveryRecord>>>,
}

impl DeliveryStore for MemoryDeliveryStore {
    fn enqueue(&self, record: DeliveryRecord) -> Result<DeliveryRecord, DeliveryError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|error| DeliveryError::Store(error.to_string()))?;
        let key = (record.workspace_id.clone(), record.key.clone());
        if let Some(existing) = inner.get(&key) {
            if existing.method != record.method || existing.body != record.body {
                return Err(DeliveryError::IdempotencyConflict);
            }
            return Ok(existing.clone());
        }
        inner.insert(key, record.clone());
        Ok(record)
    }

    fn next_ready(
        &self,
        workspace_id: &str,
        now_ms: u64,
    ) -> Result<Option<DeliveryRecord>, DeliveryError> {
        let inner = self
            .inner
            .lock()
            .map_err(|error| DeliveryError::Store(error.to_string()))?;
        Ok(inner
            .values()
            .filter(|record| record.workspace_id == workspace_id)
            .filter(|record| {
                matches!(
                    record.state,
                    DeliveryState::Pending | DeliveryState::Ambiguous
                )
            })
            .filter(|record| record.next_attempt_at_ms <= now_ms)
            .min_by(|left, right| left.key.cmp(&right.key))
            .cloned())
    }

    fn save(&self, record: DeliveryRecord) -> Result<(), DeliveryError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|error| DeliveryError::Store(error.to_string()))?;
        inner.insert((record.workspace_id.clone(), record.key.clone()), record);
        Ok(())
    }
}

pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_ms(&self) -> u64 {
        self.0
    }
}

pub fn enqueue_delivery<S: DeliveryStore>(
    store: &S,
    workspace_id: &str,
    key: &str,
    method: &str,
    body: Value,
    now_ms: u64,
) -> Result<DeliveryRecord, DeliveryError> {
    store.enqueue(DeliveryRecord {
        key: key.to_string(),
        workspace_id: workspace_id.to_string(),
        method: method.to_string(),
        body,
        state: DeliveryState::Pending,
        attempts: 0,
        result: None,
        error: None,
        next_attempt_at_ms: now_ms,
    })
}

pub fn mark_delivery_result(record: &mut DeliveryRecord, result: &InvocationResult, now_ms: u64) {
    record.attempts = record.attempts.saturating_add(1);
    if result.ok {
        record.state = DeliveryState::Sent;
        record.result = Some(result.body.clone());
        record.error = None;
    } else if let Some(retry_after_ms) = result.retry_after_ms {
        record.state = DeliveryState::Pending;
        record.next_attempt_at_ms = now_ms.saturating_add(retry_after_ms);
        record.error = Some("rate_limited".to_string());
    } else if result.status >= 500 {
        record.state = DeliveryState::Ambiguous;
        record.next_attempt_at_ms = now_ms.saturating_add(30_000);
        record.error = Some("ambiguous_write".to_string());
    } else {
        record.state = DeliveryState::Failed;
        record.error = result
            .body
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_owned);
    }
}

pub fn redacted_error(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut redacted = MapRedactor::default();
            for (key, value) in object {
                redacted.insert(key, value);
            }
            Value::Object(redacted.output)
        }
        Value::Array(values) => Value::Array(values.iter().map(redacted_error).collect()),
        other => other.clone(),
    }
}

#[derive(Default)]
struct MapRedactor {
    output: serde_json::Map<String, Value>,
}

impl MapRedactor {
    fn insert(&mut self, key: &str, value: &Value) {
        let normalized = key.to_ascii_lowercase();
        if normalized.contains("token")
            || normalized.contains("secret")
            || normalized == "authorization"
        {
            self.output
                .insert(key.to_string(), Value::String("REDACTED".to_string()));
        } else {
            self.output.insert(key.to_string(), redacted_error(value));
        }
    }
}

pub fn private_channel_owner_invite(
    method: &str,
    arguments: &Value,
    owner_user_id: &str,
) -> Option<Value> {
    if method != "conversations.create" {
        return None;
    }
    let is_private = arguments
        .get("is_private")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !is_private {
        return None;
    }
    Some(json!({"method":"conversations.invite","arguments":{"users":owner_user_id}}))
}

#[cfg(test)]
mod schema_tests {
    use super::*;
    #[test]
    fn validates_nested_blocks_unions_and_local_refs() {
        let schema = json!({
            "type":"object", "required":["channel","blocks"],
            "properties":{"channel":{"type":"string"},"blocks":{"type":"array","items":{"$ref":"#/$defs/block"}}},
            "$defs":{"block":{"anyOf":[
                {"type":"object","required":["type","text"],"properties":{"type":{"const":"section"},"text":{"type":"object","required":["text"],"properties":{"text":{"type":"string"}}}}},
                {"type":"object","required":["type"],"properties":{"type":{"const":"divider"}}}
            ]}}
        });
        assert!(schema_accepts(
            &schema,
            &schema,
            &json!({"channel":"C1","blocks":[{"type":"section","text":{"text":"hello"}},{"type":"divider"}]}),
            0
        ));
        assert!(!schema_accepts(
            &schema,
            &schema,
            &json!({"channel":"C1","blocks":[{"type":"section","text":{"text":false}}]}),
            0
        ));
        assert!(!schema_accepts(
            &schema,
            &schema,
            &json!({"channel":"C1","blocks":"serialized"}),
            0
        ));
        assert!(!schema_accepts(
            &schema,
            &schema,
            &json!({"channel":"C1","blocks":[{"type":"unknown"}]}),
            0
        ));
    }
    #[test]
    fn rejects_missing_null_and_never_fields() {
        let schema = json!({"type":"object","required":["channel"],"properties":{"channel":{"type":"string"},"token":false},"additionalProperties":false});
        assert!(schema_accepts(
            &schema,
            &schema,
            &json!({"channel":"C1"}),
            0
        ));
        for value in [
            json!({}),
            json!({"channel":null}),
            json!({"channel":"C1","token":"caller"}),
            json!({"channel":"C1","extra":true}),
        ] {
            assert!(!schema_accepts(&schema, &schema, &value, 0));
        }
        let remote = json!({"$ref":"https://example.com/schema"});
        assert!(!schema_accepts(&remote, &remote, &json!({}), 0));
    }
}
