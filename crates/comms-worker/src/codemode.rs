use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;
use std::sync::Arc;

use axum::http::{StatusCode, header};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use comms_codemode::{
    AgentCodeModeBuilder, AgentIdentity, HumanQuestionConnector, MemoryQuestionAnswerStore,
    PendingHumanQuestion, QuestionAnswer, QuestionAnswerStore, pending_human_questions,
    zero_retention_snapshot,
};
use comms_interactions::{
    QuestionRecord, QuestionState, ResumeSignal, SLACK_REPLAY_WINDOW_SECONDS, slack_signature,
};
use http_body_util::BodyExt;
use incurs_codemode::{
    ArtifactStore, CodeMode, CodeModeRunOptions, DispatchRequest, ExecutionState, ExecutionStatus,
    LogEntryState, MemoryArtifactStore, MemoryStore, RuntimeStore, SearchOutput,
};
use incurs_codemode_cloudflare::{
    CloudflareClock, DurableSqlStore, DynamicWorkerExecutor, DynamicWorkerOptions, McpHttpOptions,
    McpHttpRequest, WorkerCodeModeService, WorkerLoader, handle_mcp_request,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wasm_bindgen::JsValue;
use worker::d1::{D1Database, D1PreparedStatement};
use worker::send::{IntoSendFuture, SendWrapper};
use worker::{
    DurableObject, Env, Headers, HttpRequest, HttpResponse, Method, Request, RequestInit, Response,
    State, durable_object,
};

use crate::auth::Agent;

const CODEMODE_OBJECT_BINDING: &str = "CODEMODE";
const CODEMODE_LOADER_BINDING: &str = "CODEMODE_WORKER_LOADER";
const CODEMODE_CONTROL_BINDING: &str = "CONTROL";
const HUMAN_CONNECTOR: &str = "human";
const INTERNAL_TIMESTAMP_HEADER: &str = "x-comms-internal-timestamp";
const INTERNAL_SIGNATURE_HEADER: &str = "x-comms-internal-signature";
const INTERNAL_CONTEXT_HEADER: &str = "x-comms-internal-context";
const INTERNAL_PAYLOAD_DIGEST_HEADER: &str = "x-comms-internal-payload-sha256";
const INTERNAL_SIGNATURE_KEY_PREFIX: &str = "comms-codemode-do-v1";

type ActiveExecutions = Rc<RefCell<HashMap<String, Rc<CodeMode>>>>;

#[derive(Debug, Deserialize, Serialize)]
struct InternalRequestContext {
    path: String,
    agent_id: String,
    agent_label: Option<String>,
    agent_expires_at: String,
    base_url: String,
    body_sha256: String,
}

impl InternalRequestContext {
    fn agent(&self) -> Agent {
        Agent {
            id: self.agent_id.clone(),
            label: self.agent_label.clone(),
            expires_at: self.agent_expires_at.parse().unwrap_or_default(),
        }
    }
}

pub fn is_route(path: &str) -> bool {
    path == "/api/mcp" || path.starts_with("/api/codemode/")
}

pub async fn handle(
    request: HttpRequest,
    env: Env,
    agent: Agent,
    base_url: String,
) -> worker::Result<HttpResponse> {
    let namespace = env.durable_object(CODEMODE_OBJECT_BINDING)?;
    let stub = namespace.get_by_name(&format!("agent:{}", agent.id))?;
    let request = forward_request(request, &env, &agent, &base_url).await?;
    let response = async move { stub.fetch_with_request(request).await }
        .into_send()
        .await?;
    let mut response: HttpResponse = response.try_into()?;
    harden(&mut response);
    Ok(response)
}
pub async fn resume_from_slack(env: &Env, signal: &ResumeSignal) -> worker::Result<Response> {
    let record = match validated_answered_record(env, signal).await? {
        Some(record) => record,
        None => {
            return Response::from_json(&json!({
                "ok": true,
                "data": {"ignored": true, "reason": "question_not_answered_for_codemode"}
            }));
        }
    };
    let agent = Agent {
        id: signal.agent_id.clone(),
        label: record.agent.label.clone(),
        expires_at: 0,
    };
    crate::auth::ensure_agent_active(env, &agent).await?;
    let question_store =
        DurableQuestionStore::new(env.d1(CODEMODE_CONTROL_BINDING)?, signal.agent_id.clone());
    question_store.ensure().await?;
    if question_store
        .link_for_question(&signal.question_id)
        .await?
        .is_none()
    {
        return Response::from_json(&json!({
            "ok": true,
            "data": {"ignored": true, "reason": "question_not_linked_to_codemode"}
        }));
    }

    let namespace = env.durable_object(CODEMODE_OBJECT_BINDING)?;
    let stub = namespace.get_by_name(&format!("agent:{}", signal.agent_id))?;
    let body = serde_json::to_vec(signal).map_err(worker_error)?;
    let mut headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set("x-comms-agent-id", &signal.agent_id)?;
    if let Some(label) = record.agent.label.as_deref() {
        headers.set("x-comms-agent-label", label)?;
    }
    headers.set("x-comms-agent-expires-at", "0")?;
    headers.set("x-comms-base-url", "https://comms.example.com")?;
    let uri = "https://codemode.internal/__comms_codemode_resume_question";
    let path = internal_request_path(uri)?;
    sign_internal_request(env, &path, &mut headers, &body).await?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_headers(headers);
    init.with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
    let request = Request::new_with_init(uri, &init)?;
    async move { stub.fetch_with_request(request).await }
        .into_send()
        .await
}

#[durable_object]
pub struct CodeModeObject {
    state: State,
    env: Env,
    active: ActiveExecutions,
}

impl DurableObject for CodeModeObject {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            active: Rc::new(RefCell::new(HashMap::new())),
        }
    }

    async fn fetch(&self, mut request: Request) -> worker::Result<Response> {
        let path = request.path();
        let method = request.method();

        if path == "/__incurs_codemode_dispatch" && method == Method::Post {
            let dispatch = request.json::<DispatchRequest>().await?;
            let execution_id = dispatch_execution_id(&dispatch).to_string();
            let codemode = self
                .active
                .borrow()
                .get(&execution_id)
                .cloned()
                .ok_or_else(|| {
                    worker::Error::RustError("Code Mode execution is not active".into())
                })?;
            let value = codemode.dispatch(dispatch).await.map_err(worker_error)?;
            return Response::from_json(&value);
        }

        let body_bytes = request.bytes().await?;
        let internal =
            verify_internal_request(&self.env, &path, request.headers(), &body_bytes).await?;
        let agent = internal.agent();
        crate::auth::ensure_agent_active(&self.env, &agent).await?;
        let base_url = internal.base_url.clone();

        if path == "/__comms_codemode_resume_question" && method == Method::Post {
            let signal: ResumeSignal = serde_json::from_slice(&body_bytes)
                .map_err(|_| worker::Error::RustError("malformed JSON body".to_string()))?;
            if signal.agent_id != agent.id {
                return json_error(
                    StatusCode::FORBIDDEN,
                    "AGENT_MISMATCH",
                    "Slack resume signal does not belong to this agent",
                );
            }
            let service = self.service(agent, base_url).await?;
            let state = service
                .resume_from_slack(signal)
                .await
                .map_err(worker_error)?;
            return match state {
                Some(state) => json_ok(state_with_pending_questions(state)),
                None => {
                    json_ok(json!({"ignored": true, "reason": "question_not_linked_to_codemode"}))
                }
            };
        }

        if path == "/api/mcp" {
            let mut headers = headers_to_map(request.headers())?;
            headers
                .entry("accept".to_string())
                .or_insert_with(|| "application/json, text/event-stream".to_string());
            let body = String::from_utf8(body_bytes.clone()).ok();
            let mcp_request = McpHttpRequest {
                method: method.as_ref().to_string(),
                path,
                headers,
                body,
            };
            let service = self.service(agent, base_url.clone()).await?;
            let response = handle_mcp_request(
                &service,
                mcp_request,
                &McpHttpOptions {
                    allowed_origins: vec![base_url],
                    ..McpHttpOptions::default()
                },
            )
            .await;
            return mcp_response(response.status, response.headers, response.body);
        }

        let body = request_optional_json_from_bytes(&body_bytes)?;
        if method == Method::Post && path == "/api/codemode/zero-retention/execute" {
            let code = required_string(&body, "code")?;
            return match self
                .execute_zero_retention(agent, base_url, code, CodeModeRunOptions::default())
                .await
            {
                Ok(state) => json_ok(state),
                Err(error) => json_ok(json!({
                    "status": "failed",
                    "error": error.to_string(),
                })),
            };
        }
        let service = self.service(agent, base_url).await?;
        match (method.clone(), path.as_str()) {
            (Method::Post, "/api/codemode/search") => {
                let query = body
                    .get("query")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                json_ok(service.search(query).await.map_err(worker_error)?)
            }
            (Method::Post, "/api/codemode/execute") => {
                let code = required_string(&body, "code")?;
                let state = service
                    .execute(code, CodeModeRunOptions::default())
                    .await
                    .map_err(worker_error)?;
                json_ok(state_with_pending_questions(state))
            }
            (Method::Post, "/api/codemode/execution") => {
                let execution_id = required_string_any(&body, &["execution_id", "id"])?;
                if let Some(artifact_id) = body.get("artifact_id").and_then(Value::as_str) {
                    json_ok(
                        service
                            .artifact(execution_id, artifact_id.to_string())
                            .await
                            .map_err(worker_error)?,
                    )
                } else {
                    let state = service
                        .execution(execution_id)
                        .await
                        .map_err(worker_error)?;
                    json_ok(state_with_pending_questions(state))
                }
            }
            (Method::Post, "/api/codemode/decide") => {
                let execution_id = required_string_any(&body, &["execution_id", "id"])?;
                let seq = body
                    .get("seq")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| worker::Error::RustError("seq is required".to_string()))?;
                match body.get("decision").and_then(Value::as_str) {
                    Some("approve") => {
                        let state = service
                            .approve(execution_id, seq, CodeModeRunOptions::default())
                            .await
                            .map_err(worker_error)?;
                        json_ok(state_with_pending_questions(state))
                    }
                    Some("reject") => {
                        let state = service
                            .reject(execution_id, seq)
                            .await
                            .map_err(worker_error)?;
                        json_ok(state_with_pending_questions(state))
                    }
                    _ => json_error(
                        StatusCode::BAD_REQUEST,
                        "BAD_REQUEST",
                        "decision must be approve or reject",
                    ),
                }
            }
            (Method::Post, "/api/codemode/cancel") => {
                let execution_id = required_string_any(&body, &["execution_id", "id"])?;
                let state = service.cancel(execution_id).await.map_err(worker_error)?;
                json_ok(state_with_pending_questions(state))
            }
            _ => json_error(
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                &format!("Code Mode route not found: {} {}", method.as_ref(), path),
            ),
        }
    }
}

struct HostedCodeModeService {
    codemode: Rc<CodeMode>,
    active: ActiveExecutions,
    env: Env,
    agent: Agent,
    question_store: DurableQuestionStore,
}

impl HostedCodeModeService {
    async fn ensure_slack_questions(&self, state: &ExecutionState) -> Result<(), String> {
        for question in pending_human_questions(state, HUMAN_CONNECTOR) {
            if self
                .question_store
                .link_for_execution(&question.execution_id, &question.key)
                .await?
                .is_some()
            {
                continue;
            }
            let question_id = self.create_slack_question(&question).await?;
            self.question_store
                .put_link(&question, &question_id)
                .await
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    async fn reconcile_slack_questions(
        &self,
        mut state: ExecutionState,
    ) -> Result<ExecutionState, String> {
        self.ensure_slack_questions(&state).await?;
        loop {
            if state.status != ExecutionStatus::Paused {
                return Ok(state);
            }
            let mut progressed = false;
            for question in pending_human_questions(&state, HUMAN_CONNECTOR) {
                let Some(question_id) = self
                    .question_store
                    .link_for_execution(&question.execution_id, &question.key)
                    .await?
                else {
                    continue;
                };
                let Some(record) = load_question_record(&self.env, &question_id)
                    .await
                    .map_err(|error| error.to_string())?
                else {
                    continue;
                };
                match record.state {
                    QuestionState::Answered => {
                        let Some(answer) = record.answer.clone() else {
                            continue;
                        };
                        let signal = ResumeSignal {
                            agent_id: record.agent.agent_id.clone(),
                            question_id: record.id.clone(),
                            answer,
                        };
                        if validated_answered_record(&self.env, &signal)
                            .await
                            .map_err(|error| error.to_string())?
                            .is_none()
                        {
                            continue;
                        }
                        self.question_store
                            .put_answer(
                                &question.execution_id,
                                &question.key,
                                QuestionAnswer::new(
                                    signal.answer.value,
                                    Some(signal.answer.owner_user_id),
                                    signal.answer.answered_at as u64,
                                ),
                            )
                            .await
                            .map_err(|error| error.to_string())?;
                        state = self
                            .approve(
                                question.execution_id,
                                question.seq,
                                CodeModeRunOptions::default(),
                            )
                            .await?;
                        progressed = true;
                        break;
                    }
                    QuestionState::Cancelled | QuestionState::Expired => {
                        state = self.reject(question.execution_id, question.seq).await?;
                        progressed = true;
                        break;
                    }
                    QuestionState::PendingDelivery | QuestionState::Waiting => {}
                }
            }
            if !progressed {
                return Ok(state);
            }
        }
    }

    async fn create_slack_question(
        &self,
        question: &PendingHumanQuestion,
    ) -> Result<String, String> {
        let mut request = json!({
            "idempotency_key": format!("codemode:{}:{}:{}", question.execution_id, question.seq, question.key),
            "text": question.prompt.clone().unwrap_or_else(|| question.key.clone()),
            "no_deadline": true,
        });
        if let Some(blocks) = question.arguments.get("blocks") {
            request["blocks"] = blocks.clone();
        }
        if let Some(choices) = question.arguments.get("choices") {
            request["choices"] = choices.clone();
        }
        if let Some(channel) = question.arguments.get("channel").and_then(Value::as_str) {
            request["channel"] = Value::String(channel.to_string());
        }
        if let Some(thread_ts) = question.arguments.get("thread_ts").and_then(Value::as_str) {
            request["thread_ts"] = Value::String(thread_ts.to_string());
        }
        let config = crate::questions::SlackQuestionConfig::from_env(&self.env)
            .await
            .map_err(|error| error.to_string())?;
        let http_request = internal_post_request("/api/question/create", &request)
            .map_err(|error| error.to_string())?;
        let response = crate::questions::handle_agent_question(
            http_request,
            self.env.clone(),
            self.agent.clone(),
            config,
        )
        .await
        .map_err(|error| error.to_string())?;
        let value = axum_response_json(response).await?;
        value
            .pointer("/data/question/id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "Slack question response missing question id".to_string())
    }

    async fn resume_from_slack(
        &self,
        signal: ResumeSignal,
    ) -> Result<Option<ExecutionState>, String> {
        validated_answered_record(&self.env, &signal)
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| {
                "Slack resume signal does not match an answered owner question".to_string()
            })?;
        let Some(link) = self
            .question_store
            .link_for_question(&signal.question_id)
            .await
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        let current = self.codemode.execution_snapshot(&link.execution_id).await?;
        if current.status != ExecutionStatus::Paused {
            return Ok(Some(current));
        }
        self.question_store
            .put_answer(
                &link.execution_id,
                &link.question_key,
                QuestionAnswer::new(
                    signal.answer.value,
                    Some(signal.answer.owner_user_id),
                    signal.answer.answered_at as u64,
                ),
            )
            .await
            .map_err(|error| error.to_string())?;
        self.approve(link.execution_id, link.seq, CodeModeRunOptions::default())
            .await
            .map(Some)
    }
}

#[async_trait::async_trait(?Send)]
impl WorkerCodeModeService for HostedCodeModeService {
    async fn search(&self, query: String) -> Result<SearchOutput, String> {
        self.codemode.search(&query).await
    }

    async fn execute(
        &self,
        code: String,
        options: CodeModeRunOptions,
    ) -> Result<ExecutionState, String> {
        let state = self.codemode.start(&code).await?;
        let execution_id = state.id.clone();
        self.active
            .borrow_mut()
            .insert(execution_id.clone(), Rc::clone(&self.codemode));
        let mut state = self
            .codemode
            .drive_with(&execution_id, options.clone())
            .await?;
        while let Some(seq) = CodeModeObject::zero_retention_auto_approval_seq(&state) {
            state = self
                .codemode
                .approve_with(&execution_id, seq, options.clone())
                .await?;
        }
        self.active.borrow_mut().remove(&execution_id);
        self.ensure_slack_questions(&state).await?;
        Ok(state)
    }

    async fn execution(&self, execution_id: String) -> Result<ExecutionState, String> {
        let state = self.codemode.execution_snapshot(&execution_id).await?;
        self.reconcile_slack_questions(state).await
    }

    async fn artifact(&self, execution_id: String, artifact_id: String) -> Result<Value, String> {
        self.codemode.artifact(&execution_id, &artifact_id).await
    }

    async fn approve(
        &self,
        execution_id: String,
        seq: u64,
        options: CodeModeRunOptions,
    ) -> Result<ExecutionState, String> {
        self.active
            .borrow_mut()
            .insert(execution_id.clone(), Rc::clone(&self.codemode));
        let result = self
            .codemode
            .approve_with(&execution_id, seq, options)
            .await;
        self.active.borrow_mut().remove(&execution_id);
        let state = result?;
        self.ensure_slack_questions(&state).await?;
        Ok(state)
    }

    async fn reject(&self, execution_id: String, seq: u64) -> Result<ExecutionState, String> {
        self.codemode.reject(&execution_id, seq).await
    }

    async fn cancel(&self, execution_id: String) -> Result<ExecutionState, String> {
        self.codemode.cancel(&execution_id).await
    }
}

impl CodeModeObject {
    async fn execute_zero_retention(
        &self,
        agent: Agent,
        base_url: String,
        code: String,
        options: CodeModeRunOptions,
    ) -> worker::Result<Value> {
        let runtime_memory = Arc::new(MemoryStore::default());
        let artifact_memory = Arc::new(MemoryArtifactStore::default());
        let runtime_store: Arc<dyn RuntimeStore> = runtime_memory.clone();
        let artifact_store: Arc<dyn ArtifactStore> = artifact_memory.clone();
        let loader = self
            .env
            .get_binding::<WorkerLoader>(CODEMODE_LOADER_BINDING)?;
        let dispatcher = self
            .env
            .durable_object(CODEMODE_OBJECT_BINDING)?
            .get_by_name(&format!("agent:{}", agent.id))?;
        let executor =
            DynamicWorkerExecutor::new(loader, dispatcher, DynamicWorkerOptions::default());
        let mut identity = AgentIdentity::new(agent.id.clone()).map_err(worker_error)?;
        if let Some(label) = agent.label.clone() {
            identity = identity.with_label(label);
        }
        let cli = comms_core::cli(Arc::new(crate::data::DataBackend::new_ephemeral(
            self.env.clone(),
            agent,
            base_url,
        )));
        let human = Arc::new(HumanQuestionConnector::new(Arc::new(
            MemoryQuestionAnswerStore::default(),
        )));
        let codemode = AgentCodeModeBuilder::new(identity, cli)
            .with_connector(human)
            .build_with_clock_and_artifact_store(
                runtime_store,
                artifact_store,
                executor,
                CloudflareClock,
            )
            .map_err(worker_error)?;
        let codemode = Rc::new(codemode);
        let state = codemode.start(&code).await.map_err(worker_error)?;
        let execution_id = state.id.clone();
        self.active
            .borrow_mut()
            .insert(execution_id.clone(), Rc::clone(&codemode));
        let mut result = codemode.drive_with(&execution_id, options.clone()).await;
        let response = loop {
            match result {
                Ok(state) if state.status == ExecutionStatus::Paused => {
                    if let Some(seq) = Self::zero_retention_auto_approval_seq(&state) {
                        result = codemode
                            .approve_with(&execution_id, seq, options.clone())
                            .await;
                        continue;
                    }
                    break Self::zero_retention_failed(
                        &execution_id,
                        "zero-retention Code Mode cannot suspend; use durable Code Mode for blocking human questions",
                    );
                }
                Ok(state) => {
                    let mut snapshot = serde_json::to_value(zero_retention_snapshot(state))
                        .map_err(worker_error)?;
                    if snapshot.get("status") == Some(&json!("error"))
                        && let Some(object) = snapshot.as_object_mut()
                    {
                        object.insert("status".to_string(), json!("failed"));
                    }
                    break snapshot;
                }
                Err(error) => break Self::zero_retention_failed(&execution_id, error),
            }
        };
        self.active.borrow_mut().remove(&execution_id);
        RuntimeStore::delete_execution(runtime_memory.as_ref(), &execution_id)
            .await
            .map_err(worker_error)?;
        ArtifactStore::delete_execution(artifact_memory.as_ref(), &execution_id)
            .await
            .map_err(worker_error)?;
        Ok(response)
    }

    fn zero_retention_auto_approval_seq(state: &ExecutionState) -> Option<u64> {
        let mut pending = state
            .log
            .iter()
            .filter(|entry| entry.state == LogEntryState::Pending && entry.requires_approval);
        let entry = pending.next()?;
        if pending.next().is_some() {
            return None;
        }
        if entry.connector != "comms" || entry.method != "slack_invoke" {
            return None;
        }
        let method = entry.arguments.get("method")?.as_str()?;
        comms_slack_runtime::is_zero_retention_method(method).then_some(entry.seq)
    }

    fn zero_retention_failed(execution_id: &str, error: impl ToString) -> Value {
        json!({
            "id": execution_id,
            "execution_id": execution_id,
            "status": "failed",
            "error": error.to_string(),
        })
    }
    async fn service(
        &self,
        agent: Agent,
        base_url: String,
    ) -> worker::Result<HostedCodeModeService> {
        let store = Arc::new(DurableSqlStore::new(self.state.storage().sql())?);
        let runtime_store: Arc<dyn RuntimeStore> = store.clone();
        let artifact_store: Arc<dyn ArtifactStore> = store.clone();
        let question_store =
            DurableQuestionStore::new(self.env.d1(CODEMODE_CONTROL_BINDING)?, agent.id.clone());
        question_store.ensure().await?;
        let loader = self
            .env
            .get_binding::<WorkerLoader>(CODEMODE_LOADER_BINDING)?;
        let dispatcher = self
            .env
            .durable_object(CODEMODE_OBJECT_BINDING)?
            .get_by_name(&format!("agent:{}", agent.id))?;
        let executor =
            DynamicWorkerExecutor::new(loader, dispatcher, DynamicWorkerOptions::default());
        let mut identity = AgentIdentity::new(agent.id.clone()).map_err(worker_error)?;
        if let Some(label) = agent.label.clone() {
            identity = identity.with_label(label);
        }
        let cli = comms_core::cli(Arc::new(crate::data::DataBackend::new_durable(
            self.env.clone(),
            agent.clone(),
            base_url,
        )));
        let human = Arc::new(HumanQuestionConnector::new(Arc::new(
            question_store.clone(),
        )));
        let codemode = AgentCodeModeBuilder::new(identity, cli)
            .with_connector(human)
            .build_with_clock_and_artifact_store(
                runtime_store,
                artifact_store,
                executor,
                CloudflareClock,
            )
            .map_err(worker_error)?;
        Ok(HostedCodeModeService {
            codemode: Rc::new(codemode),
            active: Rc::clone(&self.active),
            env: self.env.clone(),
            agent,
            question_store,
        })
    }
}

#[derive(Clone)]
struct DurableQuestionStore {
    db: SendWrapper<Rc<D1Database>>,
    agent_id: String,
}

#[derive(Deserialize)]
struct JsonRow {
    json: String,
}
#[derive(Deserialize)]
struct QuestionLinkRow {
    execution_id: String,
    question_key: String,
    seq: u64,
}

impl DurableQuestionStore {
    fn new(db: D1Database, agent_id: String) -> Self {
        Self {
            db: SendWrapper::new(Rc::new(db)),
            agent_id,
        }
    }

    async fn ensure(&self) -> worker::Result<()> {
        let statement = self.db.prepare(
            "CREATE TABLE IF NOT EXISTS comms_codemode_answers (
                agent_id TEXT NOT NULL,
                execution_id TEXT NOT NULL,
                question_key TEXT NOT NULL,
                json TEXT NOT NULL,
                PRIMARY KEY (agent_id, execution_id, question_key)
            )",
        );
        async move { statement.run().await }.into_send().await?;
        let statement = self.db.prepare(
            "CREATE TABLE IF NOT EXISTS comms_codemode_question_links (
                agent_id TEXT NOT NULL,
                question_id TEXT NOT NULL,
                execution_id TEXT NOT NULL,
                question_key TEXT NOT NULL,
                seq INTEGER NOT NULL,
                PRIMARY KEY (agent_id, question_id),
                UNIQUE (agent_id, execution_id, question_key)
            )",
        );
        async move { statement.run().await }.into_send().await?;
        Ok(())
    }

    async fn put_answer(
        &self,
        execution_id: &str,
        question_key: &str,
        answer: QuestionAnswer,
    ) -> worker::Result<()> {
        self.ensure().await?;
        let json = serde_json::to_string(&answer).map_err(worker_error)?;
        let statement = bind(
            self.db.prepare(
                "INSERT OR REPLACE INTO comms_codemode_answers (agent_id, execution_id, question_key, json)
                 VALUES (?, ?, ?, ?)",
            ),
            vec![
                self.agent_id.clone().into(),
                execution_id.into(),
                question_key.into(),
                json.into(),
            ],
        )?;
        async move { statement.run().await }.into_send().await?;
        Ok(())
    }
    async fn put_link(
        &self,
        question: &PendingHumanQuestion,
        question_id: &str,
    ) -> worker::Result<()> {
        self.ensure().await?;
        let statement = bind(
            self.db.prepare(
                "INSERT OR REPLACE INTO comms_codemode_question_links
                 (agent_id, question_id, execution_id, question_key, seq)
                 VALUES (?, ?, ?, ?, ?)",
            ),
            vec![
                self.agent_id.clone().into(),
                question_id.into(),
                question.execution_id.clone().into(),
                question.key.clone().into(),
                JsValue::from_f64(question.seq as f64),
            ],
        )?;
        async move { statement.run().await }.into_send().await?;
        Ok(())
    }

    async fn link_for_execution(
        &self,
        execution_id: &str,
        question_key: &str,
    ) -> Result<Option<String>, String> {
        self.ensure().await.map_err(|error| error.to_string())?;
        let statement = bind(
            self.db.prepare(
                "SELECT question_id AS json FROM comms_codemode_question_links
                 WHERE agent_id = ? AND execution_id = ? AND question_key = ?",
            ),
            vec![
                self.agent_id.clone().into(),
                execution_id.into(),
                question_key.into(),
            ],
        )
        .map_err(|error| error.to_string())?;
        let row = async move { statement.first::<JsonRow>(None).await }
            .into_send()
            .await
            .map_err(|error| error.to_string())?;
        Ok(row.map(|row| row.json))
    }

    async fn link_for_question(
        &self,
        question_id: &str,
    ) -> worker::Result<Option<QuestionLinkRow>> {
        self.ensure().await?;
        let statement = bind(
            self.db.prepare(
                "SELECT execution_id, question_key, seq FROM comms_codemode_question_links
                 WHERE agent_id = ? AND question_id = ?",
            ),
            vec![self.agent_id.clone().into(), question_id.into()],
        )?;
        async move { statement.first::<QuestionLinkRow>(None).await }
            .into_send()
            .await
    }
}

#[async_trait::async_trait]
impl QuestionAnswerStore for DurableQuestionStore {
    async fn answer(
        &self,
        execution_id: &str,
        question_key: &str,
    ) -> Result<Option<QuestionAnswer>, String> {
        let statement = bind(
            self.db.prepare(
                "SELECT json FROM comms_codemode_answers
                 WHERE agent_id = ? AND execution_id = ? AND question_key = ?",
            ),
            vec![
                self.agent_id.clone().into(),
                execution_id.into(),
                question_key.into(),
            ],
        )
        .map_err(|error| error.to_string())?;
        let row = async move { statement.first::<JsonRow>(None).await }
            .into_send()
            .await
            .map_err(|error| error.to_string())?;
        row.map(|row| serde_json::from_str(&row.json).map_err(|error| error.to_string()))
            .transpose()
    }
}

fn dispatch_execution_id(request: &DispatchRequest) -> &str {
    match request {
        DispatchRequest::Call { execution_id, .. }
        | DispatchRequest::BeginStep { execution_id, .. }
        | DispatchRequest::RecordStep { execution_id, .. } => execution_id,
    }
}

fn state_with_pending_questions(state: ExecutionState) -> Value {
    let id = state.id.clone();
    let questions = pending_human_questions(&state, HUMAN_CONNECTOR);
    json!({
        "id": id,
        "execution_id": id,
        "execution": state,
        "pending_questions": questions,
    })
}

async fn validated_answered_record(
    env: &Env,
    signal: &ResumeSignal,
) -> worker::Result<Option<QuestionRecord>> {
    let Some(record) = load_question_record(env, &signal.question_id).await? else {
        return Ok(None);
    };
    let owner = env.var("OWNER_SLACK_ID")?.to_string();
    let Some(answer) = record.answer.as_ref() else {
        return Ok(None);
    };
    if record.id != signal.question_id
        || record.agent.agent_id != signal.agent_id
        || record.state != QuestionState::Answered
        || answer != &signal.answer
        || answer.question_id != signal.question_id
        || answer.owner_user_id != owner
    {
        return Ok(None);
    }
    Ok(Some(record))
}

async fn load_question_record(
    env: &Env,
    question_id: &str,
) -> worker::Result<Option<QuestionRecord>> {
    let statement = bind(
        env.d1(CODEMODE_CONTROL_BINDING)?
            .prepare("SELECT record_json AS json FROM questions WHERE id = ?1"),
        vec![question_id.into()],
    )?;
    let row = async move { statement.first::<JsonRow>(None).await }
        .into_send()
        .await?;
    row.map(|row| serde_json::from_str(&row.json).map_err(worker_error))
        .transpose()
}

async fn forward_request(
    request: HttpRequest,
    env: &Env,
    agent: &Agent,
    base_url: &str,
) -> worker::Result<Request> {
    let method = request.method().as_str().to_string();
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| request.uri().path());
    let uri = format!("https://codemode.internal{path_and_query}");
    let path = internal_request_path(&uri)?;
    let mut headers = Headers::new();
    for (name, value) in request.headers() {
        if is_forwarded_user_header(name.as_str())
            && let Ok(value) = value.to_str()
        {
            headers.set(name.as_str(), value)?;
        }
    }
    headers.set("x-comms-agent-id", &agent.id)?;
    if let Some(label) = &agent.label {
        headers.set("x-comms-agent-label", label)?;
    }
    headers.set("x-comms-agent-expires-at", &agent.expires_at.to_string())?;
    headers.set("x-comms-base-url", base_url)?;
    if path == "/api/mcp" && headers.get("accept")?.is_none() {
        headers.set("accept", "application/json, text/event-stream")?;
    }
    let bytes = request_bytes(request).await?;
    sign_internal_request(env, &path, &mut headers, &bytes).await?;
    let mut init = RequestInit::new();
    init.with_method(Method::from(method));
    init.with_headers(headers);
    if !bytes.is_empty() {
        init.with_body(Some(js_sys::Uint8Array::from(bytes.as_slice()).into()));
    }
    Request::new_with_init(&uri, &init)
}

async fn request_bytes(request: HttpRequest) -> worker::Result<Vec<u8>> {
    let request = worker::request_to_wasm(request)?;
    let mut request = worker::Request::from(request);
    request.bytes().await
}

async fn sign_internal_request(
    env: &Env,
    path: &str,
    headers: &mut Headers,
    body: &[u8],
) -> worker::Result<()> {
    let timestamp = crate::auth::now_seconds().to_string();
    let context = context_from_headers(path, headers, body)?;
    let context = encode_internal_context(&context)?;
    let payload = internal_signature_payload(&context, &timestamp);
    let payload_digest = hex_lower(&Sha256::digest(&payload));
    let signature = internal_signature(env, &timestamp, &payload).await?;
    headers.set(INTERNAL_CONTEXT_HEADER, &context)?;
    headers.set(INTERNAL_PAYLOAD_DIGEST_HEADER, &payload_digest)?;
    headers.set(INTERNAL_TIMESTAMP_HEADER, &timestamp)?;
    headers.set(INTERNAL_SIGNATURE_HEADER, &signature)?;
    Ok(())
}

async fn verify_internal_request(
    env: &Env,
    path: &str,
    headers: &Headers,
    body: &[u8],
) -> worker::Result<InternalRequestContext> {
    let context = required_internal_header(headers, INTERNAL_CONTEXT_HEADER)?;
    let timestamp = required_internal_header(headers, INTERNAL_TIMESTAMP_HEADER)?;
    let signature = required_internal_header(headers, INTERNAL_SIGNATURE_HEADER)?;
    let ts = timestamp
        .parse::<i64>()
        .map_err(|_| worker::Error::RustError("invalid internal timestamp".to_string()))?;
    if (crate::auth::now_seconds() - ts).abs() > SLACK_REPLAY_WINDOW_SECONDS {
        return Err(worker::Error::RustError(
            "internal timestamp outside replay window".to_string(),
        ));
    }
    let payload = internal_signature_payload(&context, &timestamp);
    let payload_digest = hex_lower(&Sha256::digest(&payload));
    let expected = internal_signature(env, &timestamp, &payload).await?;
    if !constant_time_eq(expected.as_bytes(), signature.as_bytes()) {
        let signed_payload_digest =
            optional_internal_header(headers, INTERNAL_PAYLOAD_DIGEST_HEADER)?
                .unwrap_or_else(|| "missing".to_string());
        return Err(worker::Error::RustError(format!(
            "invalid internal signature path={path} signed_payload_sha256={signed_payload_digest} verify_payload_sha256={payload_digest} signed_sig_sha256={} verify_sig_sha256={}",
            hex_lower(&Sha256::digest(signature.as_bytes())),
            hex_lower(&Sha256::digest(expected.as_bytes())),
        )));
    }
    let context = decode_internal_context(&context)?;
    if context.path != path {
        return Err(worker::Error::RustError(
            "internal context path mismatch".to_string(),
        ));
    }
    let body_sha256 = hex_lower(&Sha256::digest(body));
    if context.body_sha256 != body_sha256 {
        return Err(worker::Error::RustError(
            "internal body digest mismatch".to_string(),
        ));
    }
    Ok(context)
}

async fn internal_signature(env: &Env, timestamp: &str, payload: &[u8]) -> worker::Result<String> {
    let signing_secret = env.secret("SLACK_SIGNING_SECRET")?.to_string();
    let secret = format!("{INTERNAL_SIGNATURE_KEY_PREFIX}:{signing_secret}");
    Ok(slack_signature(&secret, timestamp, payload))
}

fn internal_signature_payload(context: &str, timestamp: &str) -> Vec<u8> {
    format!("{INTERNAL_SIGNATURE_KEY_PREFIX}\ncontext:{context}\ntimestamp:{timestamp}\n")
        .into_bytes()
}

fn internal_request_path(uri: &str) -> worker::Result<String> {
    let init = RequestInit::new();
    let request = Request::new_with_init(uri, &init)?;
    Ok(request.path())
}

fn context_from_headers(
    path: &str,
    headers: &Headers,
    body: &[u8],
) -> worker::Result<InternalRequestContext> {
    Ok(InternalRequestContext {
        path: path.to_string(),
        agent_id: required_internal_header(headers, "x-comms-agent-id")?,
        agent_label: optional_internal_header(headers, "x-comms-agent-label")?,
        agent_expires_at: required_internal_header(headers, "x-comms-agent-expires-at")?,
        base_url: required_internal_header(headers, "x-comms-base-url")?,
        body_sha256: hex_lower(&Sha256::digest(body)),
    })
}

fn encode_internal_context(context: &InternalRequestContext) -> worker::Result<String> {
    let bytes = serde_json::to_vec(context).map_err(worker_error)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_internal_context(value: &str) -> worker::Result<InternalRequestContext> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| worker::Error::RustError("invalid internal context".to_string()))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| worker::Error::RustError("invalid internal context".to_string()))
}

fn required_internal_header(headers: &Headers, name: &str) -> worker::Result<String> {
    optional_internal_header(headers, name)?
        .ok_or_else(|| worker::Error::RustError(format!("missing internal header {name}")))
}

fn optional_internal_header(headers: &Headers, name: &str) -> worker::Result<Option<String>> {
    headers.get(name)
}

fn is_forwarded_user_header(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "x-comms-agent-id"
            | "x-comms-agent-label"
            | "x-comms-agent-expires-at"
            | "x-comms-base-url"
            | "x-comms-internal-timestamp"
            | "x-comms-internal-signature"
            | "x-comms-internal-context"
            | "x-comms-internal-payload-sha256"
    )
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    for i in 0..left.len().max(right.len()) {
        diff |= (left.get(i).copied().unwrap_or(0) ^ right.get(i).copied().unwrap_or(0)) as usize;
    }
    diff == 0
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
fn internal_post_request(path: &str, body: &Value) -> worker::Result<HttpRequest> {
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_headers(headers);
    init.with_body(Some(JsValue::from_str(&body.to_string())));
    let request = Request::new_with_init(&format!("https://codemode.internal{path}"), &init)?;
    request.try_into()
}

async fn axum_response_json(response: axum::response::Response) -> Result<Value, String> {
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|_| "question response body read failed".to_string())?
        .to_bytes();
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if !status.is_success() || value.get("ok").and_then(Value::as_bool) == Some(false) {
        return Err(value.to_string());
    }
    Ok(value)
}

fn request_optional_json_from_bytes(bytes: &[u8]) -> worker::Result<Value> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        Ok(Value::Null)
    } else {
        serde_json::from_slice(bytes)
            .map_err(|_| worker::Error::RustError("malformed JSON body".to_string()))
    }
}

fn headers_to_map(headers: &Headers) -> worker::Result<BTreeMap<String, String>> {
    Ok(headers
        .entries()
        .map(|(name, value)| (name.to_ascii_lowercase(), value))
        .collect())
}

fn required_string(value: &Value, key: &str) -> worker::Result<String> {
    required_string_any(value, &[key])
}

fn required_string_any(value: &Value, keys: &[&str]) -> worker::Result<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::to_string)
        .ok_or_else(|| worker::Error::RustError(format!("{} is required", keys.join(" or "))))
}

fn bind(
    statement: D1PreparedStatement,
    params: Vec<JsValue>,
) -> worker::Result<D1PreparedStatement> {
    if params.is_empty() {
        Ok(statement)
    } else {
        statement.bind(&params)
    }
}

fn json_ok(value: impl Serialize) -> worker::Result<Response> {
    Response::from_json(&json!({"ok": true, "data": value}))
}

fn json_error(status: StatusCode, code: &str, message: &str) -> worker::Result<Response> {
    let response = Response::from_json(&json!({
        "ok": false,
        "error": {"code": code, "message": message}
    }))?;
    Ok(response.with_status(status.as_u16()))
}

fn mcp_response(
    status: u16,
    headers: BTreeMap<String, String>,
    body: Option<Value>,
) -> worker::Result<Response> {
    let mut response = if let Some(body) = body {
        Response::from_json(&body)?
    } else {
        Response::empty()?
    }
    .with_status(status);
    for (name, value) in headers {
        response.headers_mut().set(&name, &value)?;
    }
    Ok(response)
}

fn harden(response: &mut HttpResponse) {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
}

fn worker_error(error: impl ToString) -> worker::Error {
    worker::Error::RustError(error.to_string())
}
