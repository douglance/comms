//! Slack API catalog, docs search, and Incurs command construction.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{error::Error as StdError, fmt, sync::Arc};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Method {
    pub name: String,
    pub summary: String,
    pub input_schema: Value,
    pub docs_url: String,
    pub http_method: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub content_types: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub token_types: Vec<String>,
    #[serde(default)]
    pub rate_limit: String,
    #[serde(default)]
    pub deprecated: bool,
    #[serde(default)]
    pub source_refs: Vec<String>,
    #[serde(default)]
    pub coverage: Coverage,
    #[serde(default)]
    pub sdk_argument_type: Option<String>,
    #[serde(default)]
    pub canonical_key: String,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Eq, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Coverage {
    SdkSchema,
    #[serde(alias = "schema")]
    OpenapiSchema,
    #[default]
    DocsOnly,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct DocEntry {
    pub title: String,
    pub url: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub method: Option<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct CoverageReport {
    pub generated_at: String,
    pub method_count: usize,
    pub schema_methods: usize,
    #[serde(default)]
    pub sdk_schema_methods: usize,
    #[serde(default)]
    pub openapi_schema_methods: usize,
    pub docs_only_methods: usize,
    pub docs_index_entries: usize,
    #[serde(default)]
    pub sources: Vec<SourceReceipt>,
    #[serde(default)]
    pub unresolved: Vec<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct SourceReceipt {
    pub name: String,
    pub kind: String,
    pub url: String,
    #[serde(default)]
    pub final_url: String,
    pub fetched_at: String,
    #[serde(default)]
    pub bytes: usize,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub etag: Option<String>,
    #[serde(default)]
    pub last_modified: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
struct CatalogFile {
    generated_at: String,
    methods: Vec<Method>,
    coverage: CoverageReport,
}
#[derive(Debug, Clone)]
pub struct Registry {
    generated_at: String,
    methods: Vec<Method>,
    docs: Vec<DocEntry>,
    coverage: CoverageReport,
}
impl Registry {
    pub fn embedded() -> Result<Self, CatalogError> {
        let mut catalog: CatalogFile = serde_json::from_str(include_str!("../data/catalog.json"))?;
        let rest: Vec<Method> = serde_json::from_str(include_str!("../data/rest_catalog.json"))?;
        catalog.coverage.method_count += rest.len();
        catalog.coverage.docs_only_methods += rest.len();
        catalog
            .coverage
            .unresolved
            .extend(rest.iter().map(|method| method.name.clone()));
        catalog.methods.extend(rest);
        catalog.methods.sort_by(|a, b| a.name.cmp(&b.name));
        let docs: Vec<DocEntry> = serde_json::from_str(include_str!("../data/docs_index.json"))?;
        Ok(Self {
            generated_at: catalog.generated_at,
            methods: catalog.methods,
            docs,
            coverage: catalog.coverage,
        })
    }
    pub fn generated_at(&self) -> &str {
        &self.generated_at
    }
    pub fn methods(&self) -> &[Method] {
        &self.methods
    }
    pub fn get(&self, name: &str) -> Option<&Method> {
        self.methods.iter().find(|m| m.name == name)
    }
    pub fn docs(&self) -> &[DocEntry] {
        &self.docs
    }
    pub fn coverage(&self) -> &CoverageReport {
        &self.coverage
    }
    pub fn search(&self, query: &str, limit: usize, max_bytes: usize) -> Vec<SearchHit> {
        let terms: Vec<String> = query
            .split_whitespace()
            .map(|s| s.to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        if terms.is_empty() || limit == 0 || max_bytes == 0 {
            return vec![];
        }
        let mut hits = Vec::new();
        for method in &self.methods {
            let hay = format!("{} {} {}", method.name, method.summary, method.docs_url)
                .to_ascii_lowercase();
            if terms.iter().all(|term| hay.contains(term)) {
                hits.push(SearchHit::method(method, max_bytes));
            }
            if hits.len() >= limit {
                return hits;
            }
        }
        for doc in &self.docs {
            let hay = format!("{} {} {} {}", doc.title, doc.summary, doc.url, doc.body)
                .to_ascii_lowercase();
            if terms.iter().all(|term| hay.contains(term)) {
                hits.push(SearchHit::doc(doc, max_bytes));
            }
            if hits.len() >= limit {
                return hits;
            }
        }
        hits
    }
}
#[derive(Debug)]
pub struct CatalogError(serde_json::Error);
impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "generated Slack catalog is invalid: {}", self.0)
    }
}
impl StdError for CatalogError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.0)
    }
}
impl From<serde_json::Error> for CatalogError {
    fn from(value: serde_json::Error) -> Self {
        Self(value)
    }
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct SearchHit {
    pub title: String,
    pub url: String,
    pub summary: String,
    pub kind: SearchKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SearchKind {
    Method,
    Documentation,
}
impl SearchHit {
    fn method(m: &Method, max: usize) -> Self {
        Self {
            title: m.name.clone(),
            url: m.docs_url.clone(),
            summary: truncate(&m.summary, max),
            kind: SearchKind::Method,
            method: Some(m.name.clone()),
        }
    }
    fn doc(d: &DocEntry, max: usize) -> Self {
        let s = if d.summary.is_empty() {
            &d.body
        } else {
            &d.summary
        };
        Self {
            title: d.title.clone(),
            url: d.url.clone(),
            summary: truncate(s, max),
            kind: SearchKind::Documentation,
            method: d.method.clone(),
        }
    }
}
fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}
#[async_trait::async_trait]
pub trait Invocation: Send + Sync {
    async fn invoke(&self, method: &str, params: Value) -> Result<Value, String>;
}
#[derive(Deserialize, Serialize, incurs::Options)]
struct SearchOptions {
    query: String,
    limit: Option<usize>,
    max_bytes: Option<usize>,
}
#[derive(Deserialize, Serialize, incurs::Options)]
struct InspectOptions {
    method: String,
}
#[derive(Deserialize, Serialize, incurs::Options)]
struct InvokeOptions {
    method: String,
    params: Value,
}
#[derive(Deserialize, Serialize, incurs::Options)]
struct SessionStartOptions {
    session_id: String,
    name: String,
    icon_emoji: Option<String>,
    icon_url: Option<String>,
    title: Option<String>,
}
#[derive(Deserialize, Serialize, incurs::Options)]
struct SessionSendOptions {
    session_id: String,
    /// Shared channel destination; omitted sends to your owner session thread.
    channel: Option<String>,
    /// Reply to this Slack message in the selected channel.
    thread_ts: Option<String>,
    text: Option<String>,
    blocks: Option<Value>,
    idempotency_key: String,
}
#[derive(Deserialize, Serialize, incurs::Options)]
struct SessionStatusOptions {
    session_id: String,
    status: String,
    idempotency_key: String,
}
#[derive(Deserialize, Serialize, incurs::Options)]
struct UploadOptions {
    blob_id: String,
    filename: Option<String>,
    get_params: Option<Value>,
    complete_params: Option<Value>,
    idempotency_key: String,
}

pub fn cli(invocation: Arc<dyn Invocation>) -> incurs::cli::Cli {
    let registry = Arc::new(
        Registry::embedded()
            .expect("embedded Slack catalog should be generated from checked fixtures"),
    );
    let search_registry = registry.clone();
    let inspect_registry = registry.clone();
    let invoke_registry = registry;
    let search = incurs::command::CommandDef::typed::<(), SearchOptions, (), Value, _, _>(
        "search",
        move |ctx: incurs::command::TypedContext<(), SearchOptions, ()>| {
            let registry = search_registry.clone();
            async move {
                let limit = ctx.options.limit.unwrap_or(20).min(100);
                let max = ctx.options.max_bytes.unwrap_or(8192).min(32768);
                match serde_json::to_value(registry.search(&ctx.options.query, limit, max)) {
                    Ok(v) => incurs::command::TypedResult::ok(v),
                    Err(e) => incurs::command::TypedResult::error("CATALOG_ERROR", e.to_string()),
                }
            }
        },
    )
    .description("Search bounded Slack method and documentation excerpts")
    .done();
    let inspect = incurs::command::CommandDef::typed::<(), InspectOptions, (), Value, _, _>(
        "inspect",
        move |ctx: incurs::command::TypedContext<(), InspectOptions, ()>| {
            let registry = inspect_registry.clone();
            async move {
                match registry.get(&ctx.options.method) {
                    Some(method) => incurs::command::TypedResult::ok(
                        serde_json::to_value(method).unwrap_or(Value::Null),
                    ),
                    None => incurs::command::TypedResult::error(
                        "NOT_FOUND",
                        format!("unknown Slack method {}", ctx.options.method),
                    ),
                }
            }
        },
    )
    .description("Inspect one Slack method schema and provenance")
    .done();
    let session_start_invoker = invocation.clone();
    let session_start = incurs::command::CommandDef::typed::<(), SessionStartOptions, (), Value, _, _>(
        "start", move |ctx: incurs::command::TypedContext<(), SessionStartOptions, ()>| {
            let invoker = session_start_invoker.clone();
            async move {
                let params = serde_json::to_value(ctx.options).unwrap_or(Value::Null);

                match invoker.invoke("comms.sessions.start", params).await {
                    Ok(value) => incurs::command::TypedResult::ok(value),
                    Err(error) => incurs::command::TypedResult::error("SLACK_ERROR", error),
                }
            }
        }).description("Start your own Slack session with a custom name and icon; reuse session_id to resume safely").done();
    let session_send_invoker = invocation.clone();
    let mut session_send =
        incurs::command::CommandDef::typed::<(), SessionSendOptions, (), Value, _, _>(
            "send",
            move |ctx: incurs::command::TypedContext<(), SessionSendOptions, ()>| {
                let invoker = session_send_invoker.clone();
                async move {
                    let mut params = serde_json::to_value(ctx.options).unwrap_or(Value::Null);
                    if let Some(Value::String(raw)) = params.get("blocks") {
                        match serde_json::from_str::<Value>(raw) {
                            Ok(value) => params["blocks"] = value,
                            Err(_) => {
                                return incurs::command::TypedResult::error(
                                    "INPUT_ERROR",
                                    "blocks must be a JSON array",
                                );
                            }
                        }
                    }
                    match invoker.invoke("comms.sessions.send", params).await {
                        Ok(value) => incurs::command::TypedResult::ok(value),
                        Err(error) => incurs::command::TypedResult::error("SLACK_ERROR", error),
                    }
                }
            },
        )
        .description("Send text or rich blocks to your session or a shared channel using your saved name and icon")
        .done();
    for field in &mut session_send.options_fields {
        if field.name == "blocks" {
            field.field_type = incurs::schema::FieldType::Value;
        }
    }
    let session_status_invoker = invocation.clone();
    let session_status =
        incurs::command::CommandDef::typed::<(), SessionStatusOptions, (), Value, _, _>(
            "status",
            move |ctx: incurs::command::TypedContext<(), SessionStatusOptions, ()>| {
                let invoker = session_status_invoker.clone();
                async move {
                    let params = serde_json::to_value(ctx.options).unwrap_or(Value::Null);

                    match invoker.invoke("comms.sessions.status", params).await {
                        Ok(value) => incurs::command::TypedResult::ok(value),
                        Err(error) => incurs::command::TypedResult::error("SLACK_ERROR", error),
                    }
                }
            },
        )
        .description("Set your session to processing, active, suspended, or closed")
        .done();
    let upload_invoker = invocation.clone();
    let mut upload = incurs::command::CommandDef::typed::<(), UploadOptions, (), Value, _, _>(
        "upload",
        move |ctx: incurs::command::TypedContext<(), UploadOptions, ()>| {
            let invoker = upload_invoker.clone();
            async move {
                let mut params = serde_json::to_value(ctx.options).unwrap_or(Value::Null);
                for field in ["get_params", "complete_params"] {
                    if let Some(Value::String(raw)) = params.get(field) {
                        match serde_json::from_str::<Value>(raw) {
                            Ok(value) if value.is_object() => params[field] = value,
                            _ => return incurs::command::TypedResult::error("INPUT_ERROR", format!("{field} must be a JSON object")),
                        }
                    }
                }
                match invoker.invoke("files.uploadExternal", params).await {
                    Ok(value) => incurs::command::TypedResult::ok(value),
                    Err(error) => incurs::command::TypedResult::error("SLACK_ERROR", error),
                }
            }
        },
    ).description("Upload a media blob to Slack with URL allocation, byte transfer, and completion; reuse an idempotency key for safe replay").done();
    for field in &mut upload.options_fields {
        if matches!(field.name, "get_params" | "complete_params") {
            field.field_type = incurs::schema::FieldType::Value;
        }
    }
    let invoker = invocation;
    let mut invoke = incurs::command::CommandDef::typed::<(), InvokeOptions, (), Value, _, _>(
        "invoke",
        move |ctx: incurs::command::TypedContext<(), InvokeOptions, ()>| {
            let registry = invoke_registry.clone();
            let invoker = invoker.clone();
            async move {
                if registry.get(&ctx.options.method).is_none() {
                    return incurs::command::TypedResult::error(
                        "NOT_FOUND",
                        format!("unknown Slack method {}", ctx.options.method),
                    );
                }
                let params = match ctx.options.params {
                    Value::String(raw) => match serde_json::from_str::<Value>(&raw) {
                        Ok(value) => value,
                        Err(_) => {
                            return incurs::command::TypedResult::error(
                                "INPUT_ERROR",
                                "params must be a JSON object",
                            );
                        }
                    },
                    value => value,
                };
                if !params.is_object() {
                    return incurs::command::TypedResult::error(
                        "INPUT_ERROR",
                        "params must be a JSON object",
                    );
                }
                match invoker.invoke(&ctx.options.method, params).await {
                    Ok(v) => incurs::command::TypedResult::ok(v),
                    Err(e) => incurs::command::TypedResult::error("SLACK_ERROR", e),
                }
            }
        },
    )
    .description("Invoke one Slack method through the host runtime and policy layer")
    .done();
    for field in &mut invoke.options_fields {
        if field.name == "params" {
            field.field_type = incurs::schema::FieldType::Value;
        }
    }
    incurs::cli::Cli::create("slack")
        .description("Slack API discovery and policy-checked invocation")
        .command("search", search)
        .command("inspect", inspect)
        .command("invoke", invoke)
        .command("upload", upload)
        .group(
            incurs::cli::Cli::create("session")
                .description("Start and use your own named Slack agent session")
                .command("start", session_start)
                .command("send", session_send)
                .command("status", session_status),
        )
}
pub fn schema_properties(method: &Method) -> Option<&Map<String, Value>> {
    method
        .input_schema
        .get("properties")
        .and_then(Value::as_object)
}
/// Performs a compact Block Kit structural check for generated schemas and callers.
pub fn validate_blocks_value(value: &Value) -> Result<(), String> {
    let Some(blocks) = value.as_array() else {
        return Err("blocks must be an array".to_owned());
    };
    for (index, block) in blocks.iter().enumerate() {
        let Some(object) = block.as_object() else {
            return Err(format!("blocks[{index}] must be an object"));
        };
        match object.get("type").and_then(Value::as_str) {
            Some(value) if !value.is_empty() => {}
            _ => return Err(format!("blocks[{index}].type is required")),
        }
    }
    Ok(())
}
