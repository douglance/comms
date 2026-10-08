use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use incurs_codemode::{
    Connector, ConnectorDescription, ConnectorExample, ConnectorTool, ExecutionState,
    LogEntryState, ReplayPolicy, ToolAnnotations, ToolContext, ToolPolicy,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QuestionAnswer {
    pub answer: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub answered_by: Option<String>,
    pub answered_at: u64,
}

impl QuestionAnswer {
    pub fn new(answer: Value, answered_by: Option<String>, answered_at: u64) -> Self {
        Self {
            answer,
            answered_by,
            answered_at,
        }
    }
}

#[async_trait::async_trait]
pub trait QuestionAnswerStore: Send + Sync {
    async fn answer(
        &self,
        execution_id: &str,
        question_key: &str,
    ) -> Result<Option<QuestionAnswer>, String>;
}

#[derive(Default)]
pub struct MemoryQuestionAnswerStore {
    answers: Mutex<HashMap<(String, String), QuestionAnswer>>,
}

impl MemoryQuestionAnswerStore {
    pub fn put_answer(&self, execution_id: &str, question_key: &str, answer: QuestionAnswer) {
        self.answers
            .lock()
            .expect("question answer store lock poisoned")
            .insert((execution_id.to_string(), question_key.to_string()), answer);
    }
}

#[async_trait::async_trait]
impl QuestionAnswerStore for MemoryQuestionAnswerStore {
    async fn answer(
        &self,
        execution_id: &str,
        question_key: &str,
    ) -> Result<Option<QuestionAnswer>, String> {
        Ok(self
            .answers
            .lock()
            .map_err(|_| "question answer store lock poisoned".to_string())?
            .get(&(execution_id.to_string(), question_key.to_string()))
            .cloned())
    }
}

pub struct HumanQuestionConnector<S> {
    name: String,
    answers: Arc<S>,
}

impl<S> HumanQuestionConnector<S> {
    pub fn new(answers: Arc<S>) -> Self {
        Self {
            name: "human".to_string(),
            answers,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }
}

#[async_trait::async_trait]
impl<S> Connector for HumanQuestionConnector<S>
where
    S: QuestionAnswerStore + 'static,
{
    fn name(&self) -> &str {
        &self.name
    }

    async fn describe(&self) -> Result<ConnectorDescription, String> {
        Ok(ConnectorDescription {
            name: self.name.clone(),
            instructions: Some(
                "Use human.ask only when the execution is blocked on a human answer. Provide a stable key and a concise prompt. The host will pause before the question is sent; after Slack records the answer it approves the pending action and this call returns the stored answer."
                    .to_string(),
            ),
            tools: vec![ConnectorTool {
                name: "ask".to_string(),
                description: Some("Ask the authenticated human a blocking question through Slack.".to_string()),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "key": {"type": "string", "minLength": 1},
                        "prompt": {"type": "string", "minLength": 1},
                        "blocks": {"type": "array", "items": {"type": "object"}},
                        "choices": {"type": "array", "items": {"type": "string"}},
                        "channel": {"type": "string"},
                        "thread_ts": {"type": "string"}
                    },
                    "required": ["key", "prompt"],
                    "additionalProperties": true
                }),
                output_schema: Some(json!({
                    "type": "object",
                    "properties": {
                        "key": {"type": "string"},
                        "answer": {},
                        "answered_by": {"type": ["string", "null"]},
                        "answered_at": {"type": "integer"}
                    },
                    "required": ["key", "answer", "answered_at"],
                    "additionalProperties": false
                })),
                instructions: Some(
                    "Use a deterministic key per logical question so replay cannot create duplicates."
                        .to_string(),
                ),
                examples: vec![ConnectorExample {
                    command: "await human.ask({ key: 'deploy-prod', prompt: 'Deploy to production?' })"
                        .to_string(),
                    description: Some("Pause until the Slack reply is available.".to_string()),
                }],
                annotations: ToolAnnotations {
                    read_only: Some(false),
                    destructive: Some(false),
                    idempotent: Some(true),
                    open_world: Some(true),
                },
                policy: ToolPolicy {
                    requires_approval: true,
                    replay: ReplayPolicy::Log,
                },
            }],
        })
    }

    async fn execute(
        &self,
        method: &str,
        arguments: Value,
        context: &ToolContext,
    ) -> Result<Value, String> {
        if method != "ask" {
            return Err(format!("unknown human question method {method:?}"));
        }
        let key = question_key(&arguments)?;
        let answer = self
            .answers
            .answer(&context.execution_id, &key)
            .await?
            .ok_or_else(|| {
                format!(
                    "human answer for execution {} question {} was not stored before approval",
                    context.execution_id, key
                )
            })?;
        Ok(json!({
            "key": key,
            "answer": answer.answer,
            "answered_by": answer.answered_by,
            "answered_at": answer.answered_at
        }))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PendingHumanQuestion {
    pub execution_id: String,
    pub seq: u64,
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    pub arguments: Value,
}

pub fn pending_human_questions(
    execution: &ExecutionState,
    connector_name: &str,
) -> Vec<PendingHumanQuestion> {
    execution
        .log
        .iter()
        .filter(|entry| {
            entry.state == LogEntryState::Pending
                && entry.connector == connector_name
                && entry.method == "ask"
        })
        .filter_map(|entry| {
            let key = entry.arguments.get("key")?.as_str()?.to_string();
            let prompt = entry
                .arguments
                .get("prompt")
                .and_then(Value::as_str)
                .map(str::to_string);
            Some(PendingHumanQuestion {
                execution_id: execution.id.clone(),
                seq: entry.seq,
                key,
                prompt,
                arguments: entry.arguments.clone(),
            })
        })
        .collect()
}

fn question_key(arguments: &Value) -> Result<String, String> {
    let Some(key) = arguments.get("key").and_then(Value::as_str) else {
        return Err("human.ask requires a string key".to_string());
    };
    let key = key.trim();
    if key.is_empty() {
        return Err("human.ask key must not be empty".to_string());
    }
    Ok(key.to_string())
}
