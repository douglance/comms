//! Shared SQL and media command contracts, used by native and Worker transports.
use incurs::cli::Cli;
use incurs::command::{CommandDef, McpCommandOptions, McpResultContent, TypedContext, TypedResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

/// Executes an operation using the identity authenticated by the host.
#[async_trait::async_trait]
pub trait Backend: Send + Sync {
    /// Executes one operation with structured input.
    async fn call(&self, operation: &str, input: Value) -> Result<Value, String>;
}

#[derive(Deserialize, Serialize, incurs::Options)]
struct Sql {
    /// One D1-supported statement, including reads, writes, or schema changes.
    sql: String,
    /// Bound SQL values as a JSON array.
    params: Option<Value>,
    /// A D1 bookmark to read at least the state previously observed.
    bookmark: Option<String>,
}
#[derive(Deserialize, Serialize, incurs::Options)]
struct Batch {
    /// Ordered JSON array of objects containing sql and optional params.
    statements: Value,
    /// A D1 bookmark from a previous request.
    bookmark: Option<String>,
}
#[derive(Deserialize, Serialize, incurs::Options)]
struct Schema {}
#[derive(Deserialize, Serialize, incurs::Options)]
struct BlobPut {
    /// Base64 bytes for inline uploads through CLI or MCP.
    data: Option<String>,
    /// Local file to upload from the native CLI.
    file: Option<String>,
    /// MIME type, defaulting to application/octet-stream.
    mime_type: Option<String>,
    /// Optional display filename.
    name: Option<String>,
}
#[derive(Deserialize, Serialize, incurs::Options)]
struct BlobGet {
    /// Stable blob ID returned by put.
    id: String,
    /// Include base64 bytes and supported rich MCP content.
    inline: Option<bool>,
    /// Write original bytes to this path on the native CLI.
    output: Option<String>,
}
#[derive(Deserialize, Serialize, incurs::Options)]
struct BlobDelete {
    /// Blob ID to delete.
    id: String,
}

#[derive(Deserialize, Serialize, incurs::Options)]
struct QuestionCreate {
    /// Question shown to the owner.
    text: String,
    /// Destination channel; defaults to the configured agent channel.
    channel: Option<String>,
    /// Agent session; defaults to your most recently created session.
    session_id: Option<String>,
    /// Rich Slack Block Kit blocks as a JSON array.
    blocks: Option<Value>,
    /// Answer choices as a JSON array.
    choices: Option<Value>,
    /// Wait for the answer instead of returning the question receipt.
    blocking: Option<bool>,
    /// Deadline after this many seconds; defaults to one day.
    timeout_seconds: Option<u64>,
    /// Enable the deadline; use --no-deadline to wait indefinitely.
    deadline: Option<bool>,
    /// Disable the deadline for API callers.
    no_deadline: Option<bool>,
    /// Stable key for retrying the same question creation.
    idempotency_key: String,
}
#[derive(Deserialize, Serialize, incurs::Options)]
struct QuestionReference {
    /// Durable question identifier.
    id: String,
}

#[derive(Deserialize, Serialize, incurs::Options)]
struct LinearQuery {
    /// GraphQL query or mutation; select only the fields needed.
    query: String,
    /// GraphQL variables as a JSON object.
    variables: Option<Value>,
}
#[derive(Deserialize, Serialize, incurs::Options)]
struct LinearInbox {
    /// Resume after this event cursor; defaults to zero.
    cursor: Option<u64>,
    /// Maximum events, between one and 100; defaults to 20.
    limit: Option<u64>,
}

struct SlackInvocation(Arc<dyn Backend>);
#[async_trait::async_trait]
impl comms_slack_api::Invocation for SlackInvocation {
    async fn invoke(&self, method: &str, params: Value) -> Result<Value, String> {
        self.0
            .call(
                "slack_call",
                serde_json::json!({"method": method, "params": params}),
            )
            .await
    }
}

fn command<T>(
    name: &'static str,
    operation: &'static str,
    description: &'static str,
    backend: Arc<dyn Backend>,
) -> CommandDef
where
    T: incurs::schema::IncurSchema + Serialize + Send + Sync + 'static,
{
    let mut def =
        CommandDef::typed::<(), T, (), Value, _, _>(name, move |ctx: TypedContext<(), T, ()>| {
            let backend = backend.clone();
            async move {
                match serde_json::to_value(ctx.options) {
                    Ok(mut input) => {
                        if operation == "question_create"
                            && let Some(deadline) = input
                                .as_object_mut()
                                .and_then(|fields| fields.remove("deadline"))
                                .and_then(|value| value.as_bool())
                        {
                            input["no_deadline"] = Value::Bool(!deadline);
                        }
                        for key in ["params", "statements", "blocks", "choices", "variables"] {
                            if let Some(text) =
                                input.get(key).and_then(Value::as_str).map(str::to_owned)
                            {
                                match serde_json::from_str::<Value>(&text) {
                                    Ok(value) => input[key] = value,
                                    Err(error) => {
                                        return TypedResult::error(
                                            "INPUT_ERROR",
                                            format!("{key}: {error}"),
                                        );
                                    }
                                }
                            }
                        }
                        match backend.call(operation, input).await {
                            Ok(value) => TypedResult::ok(value),
                            Err(error) => TypedResult::error("SERVICE_ERROR", error),
                        }
                    }
                    Err(error) => TypedResult::error("INPUT_ERROR", error.to_string()),
                }
            }
        })
        .description(description)
        .mcp(McpCommandOptions {
            result_content: if operation == "blob_get" {
                vec![
                    McpResultContent::Image {
                        data_pointer: "/image_data".into(),
                        mime_type_pointer: "/mime_type".into(),
                    },
                    McpResultContent::Audio {
                        data_pointer: "/audio_data".into(),
                        mime_type_pointer: "/mime_type".into(),
                    },
                    McpResultContent::ResourceLink {
                        uri_pointer: "/download_url".into(),
                        name_pointer: "/name".into(),
                        mime_type_pointer: "/mime_type".into(),
                    },
                ]
            } else {
                vec![]
            },
            ..Default::default()
        })
        .done();
    for field in &mut def.options_fields {
        if matches!(field.name, "params" | "statements") {
            field.field_type = incurs::schema::FieldType::Value;
        }
    }
    def
}

/// Builds the canonical catalog. Authorization belongs to the transport host.
pub fn cli(backend: Arc<dyn Backend>) -> Cli {
    let slack = comms_slack_api::cli(Arc::new(SlackInvocation(backend.clone())));
    let linear = Cli::create("linear")
        .command(
            "me",
            command::<Schema>(
                "me",
                "linear_me",
                "Read your installed Linear identity",
                backend.clone(),
            ),
        )
        .command(
            "query",
            command::<LinearQuery>(
                "query",
                "linear_query",
                "Run GraphQL using your own Linear app identity",
                backend.clone(),
            ),
        )
        .command(
            "inbox",
            command::<LinearInbox>(
                "inbox",
                "linear_inbox",
                "Read bounded Linear events using a durable cursor",
                backend.clone(),
            ),
        );
    let questions = Cli::create("question")
        .command(
            "create",
            command::<QuestionCreate>(
                "create",
                "question_create",
                "Send a rich question to the owner",
                backend.clone(),
            ),
        )
        .command(
            "status",
            command::<QuestionReference>(
                "status",
                "question_status",
                "Read a question and its answer",
                backend.clone(),
            ),
        )
        .command(
            "wait",
            command::<QuestionReference>(
                "wait",
                "question_wait",
                "Wait for a question answer",
                backend.clone(),
            ),
        )
        .command(
            "cancel",
            command::<QuestionReference>(
                "cancel",
                "question_cancel",
                "Cancel an unanswered question",
                backend.clone(),
            ),
        );
    let get = command::<BlobGet>(
        "get",
        "blob_get",
        "Read a blob as bytes, a link, or rich content",
        backend.clone(),
    );
    let blobs = Cli::create("blob")
        .command(
            "put",
            command::<BlobPut>(
                "put",
                "blob_put",
                "Store arbitrary media bytes",
                backend.clone(),
            ),
        )
        .command("get", get)
        .command(
            "delete",
            command::<BlobDelete>(
                "delete",
                "blob_delete",
                "Delete a shared blob",
                backend.clone(),
            ),
        );
    Cli::create("comms")
        .version(env!("CARGO_PKG_VERSION"))
        .description("Shared SQL and media for uniquely identified agents")
        .group(linear)
        .command(
            "sql",
            command::<Sql>(
                "sql",
                "sql",
                "Execute agent-chosen SQL with bound values",
                backend.clone(),
            ),
        )
        .command(
            "batch",
            command::<Batch>(
                "batch",
                "batch",
                "Execute an atomic ordered SQL batch",
                backend.clone(),
            ),
        )
        .command(
            "schema",
            command::<Schema>(
                "schema",
                "schema",
                "Inspect the live shared database",
                backend,
            ),
        )
        .group(blobs)
        .group(slack)
        .group(questions)
}
