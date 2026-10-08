use crate::HttpBackend;
use incurs::cli::Cli;
use incurs::command::{CommandDef, TypedResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

#[derive(Debug, Deserialize, Serialize, incurs::Options)]
struct Search {
    query: String,
}
#[derive(Debug, Deserialize, Serialize, incurs::Options)]
struct Run {
    code: String,
    #[serde(default)]
    zero_retention: bool,
}
#[derive(Debug, Deserialize, Serialize, incurs::Options)]
struct Execution {
    execution_id: String,
}
#[derive(Debug, Deserialize, Serialize, incurs::Options)]
struct Decision {
    execution_id: String,
    seq: u64,
    decision: String,
}

pub fn cli(backend: HttpBackend) -> Cli {
    let backend = Arc::new(backend);
    let search = backend.clone();
    let run = backend.clone();
    let status = backend.clone();
    let cancel = backend.clone();
    let decide = backend;
    Cli::create("code")
        .description("Search tools and compose durable hosted JavaScript")
        .command(
            "search",
            CommandDef::typed::<(), Search, (), Value, _, _>("search", move |ctx| {
                let backend = search.clone();
                async move {
                    result(
                        backend
                            .post_json(
                                "/api/codemode/search",
                                serde_json::to_value(ctx.options).unwrap(),
                            )
                            .await,
                    )
                }
            })
            .description("Find only the tools and schemas needed for a task")
            .done(),
        )
        .command(
            "run",
            CommandDef::typed::<(), Run, (), Value, _, _>("run", move |ctx| {
                let backend = run.clone();
                async move {
                    let path = if ctx.options.zero_retention {
                        "/api/codemode/zero-retention/execute"
                    } else {
                        "/api/codemode/execute"
                    };
                    result(
                        backend
                            .post_json(path, serde_json::to_value(ctx.options).unwrap())
                            .await,
                    )
                }
            })
            .description("Execute a JavaScript composition with durable status")
            .done(),
        )
        .command(
            "status",
            CommandDef::typed::<(), Execution, (), Value, _, _>("status", move |ctx| {
                let backend = status.clone();
                async move {
                    result(
                        backend
                            .post_json(
                                "/api/codemode/execution",
                                serde_json::to_value(ctx.options).unwrap(),
                            )
                            .await,
                    )
                }
            })
            .description("Read one execution, including pending human questions")
            .done(),
        )
        .command(
            "cancel",
            CommandDef::typed::<(), Execution, (), Value, _, _>("cancel", move |ctx| {
                let backend = cancel.clone();
                async move {
                    result(
                        backend
                            .post_json(
                                "/api/codemode/cancel",
                                serde_json::to_value(ctx.options).unwrap(),
                            )
                            .await,
                    )
                }
            })
            .description("Cancel one owned execution")
            .done(),
        )
        .command(
            "decide",
            CommandDef::typed::<(), Decision, (), Value, _, _>("decide", move |ctx| {
                let backend = decide.clone();
                async move {
                    result(
                        backend
                            .post_json(
                                "/api/codemode/decide",
                                serde_json::to_value(ctx.options).unwrap(),
                            )
                            .await,
                    )
                }
            })
            .description("Approve or reject one pending tool decision")
            .done(),
        )
}
fn result(value: Result<Value, String>) -> TypedResult<Value> {
    match value {
        Ok(value) => TypedResult::ok(value),
        Err(error) => TypedResult::error("CODE_MODE_FAILED", error),
    }
}
