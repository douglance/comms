#![cfg(target_arch = "wasm32")]

use axum::{Json, response::IntoResponse};
use comms_interactions::{
    AgentIdentity, AnswerOutcome, QuestionAnswer, QuestionRecord, QuestionRequest, QuestionState,
    RejectReason, ResumeSignal, SlackMessageRef, SlackRequestHeaders, is_expirable,
    parse_slack_callback, slack_message_payload, state_name, validate_question,
    verify_slack_signature, wait_outcome,
};
use getrandom::getrandom;
use http_body_util::BodyExt;
use js_sys::{Function, Object, Promise, Reflect};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::Response as WebResponse;
use worker::{Env, HttpRequest};

use crate::auth::Agent;

const CONTROL_BINDING: &str = "CONTROL";

#[derive(Clone)]
pub struct SlackQuestionConfig {
    pub bot_token: String,
    pub signing_secret: String,
    pub owner_slack_id: String,
    pub default_channel: String,
}

impl SlackQuestionConfig {
    pub async fn from_env(env: &Env) -> worker::Result<Self> {
        let bot_token = match crate::slack_oauth::installation(env).await {
            Ok(value) => value
                .get("bot_token")
                .and_then(Value::as_str)
                .ok_or_else(|| worker::Error::RustError("SLACK_CREDENTIAL_INVALID".into()))?
                .to_owned(),
            Err(error) if error.to_string().contains("SLACK_NOT_INSTALLED") => env
                .secret("SLACK_BOT_TOKEN")
                .map(|v| v.to_string())
                .unwrap_or_default(),
            Err(error) => return Err(error),
        };
        Ok(Self {
            bot_token,
            signing_secret: env.secret("SLACK_SIGNING_SECRET")?.to_string(),
            owner_slack_id: env.var("OWNER_SLACK_ID")?.to_string(),
            default_channel: env
                .var("SLACK_DEFAULT_CHANNEL")
                .map(|v| v.to_string())
                .unwrap_or_default(),
        })
    }
}
#[derive(Deserialize)]
struct CreateQuestionBody {
    idempotency_key: Option<String>,
    text: Option<String>,
    channel: Option<String>,
    thread_ts: Option<String>,
    blocks: Option<Value>,
    #[serde(default)]
    choices: Vec<comms_interactions::QuestionChoice>,
    deadline_seconds: Option<i64>,
    timeout_seconds: Option<i64>,
    #[serde(default)]
    no_deadline: bool,
    request: Option<QuestionRequest>,
    session_id: Option<String>,
}
#[derive(Deserialize)]
struct IdBody {
    id: String,
}
#[derive(Deserialize)]
struct CancelBody {
    id: Option<String>,
    reason: Option<String>,
}
#[derive(Deserialize)]
struct QuestionRow {
    record_json: String,
    request_hash: Option<String>,
}
#[derive(Deserialize)]
struct CallbackRow {
    question_id: String,
    outcome: String,
}

pub async fn handle_agent_question(
    request: HttpRequest,
    env: Env,
    agent: Agent,
    config: SlackQuestionConfig,
) -> worker::Result<axum::response::Response> {
    crate::auth::ensure_agent_active(&env, &agent).await?;
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    match (method.as_str(), path.as_str()) {
        ("POST", "/questions") | ("POST", "/api/question/create") => {
            create_question(request, &env, agent, &config).await
        }
        _ if method == "GET" && path.starts_with("/questions/") && path.ends_with("/wait") => {
            status_or_wait(&env, &agent.id, question_id_from_path(&path, "/wait"), true).await
        }
        _ if method == "GET" && path.starts_with("/questions/") => {
            status_or_wait(&env, &agent.id, question_id_from_path(&path, ""), false).await
        }
        ("POST", "/api/question/status") => {
            let body: IdBody = json_body(request).await?;
            status_or_wait(&env, &agent.id, &body.id, false).await
        }
        ("POST", "/api/question/wait") => {
            let body: IdBody = json_body(request).await?;
            status_or_wait(&env, &agent.id, &body.id, true).await
        }
        _ if method == "POST" && path.starts_with("/questions/") && path.ends_with("/cancel") => {
            cancel_question_body(
                &env,
                &agent.id,
                question_id_from_path(&path, "/cancel"),
                json_body(request)
                    .await
                    .unwrap_or(CancelBody {
                        id: None,
                        reason: None,
                    })
                    .reason,
            )
            .await
        }
        ("POST", "/api/question/cancel") => {
            let body: CancelBody = json_body(request).await?;
            let id = body
                .id
                .ok_or_else(|| worker::Error::RustError("MISSING_ID".into()))?;
            cancel_question_body(&env, &agent.id, &id, body.reason).await
        }
        _ => Ok(error_response(404, "NOT_FOUND", "Question route not found")),
    }
}

pub async fn handle_slack_question_callback(
    request: HttpRequest,
    env: Env,
    config: SlackQuestionConfig,
) -> worker::Result<axum::response::Response> {
    let headers = SlackRequestHeaders {
        timestamp: header(&request, "x-slack-request-timestamp")?,
        signature: header(&request, "x-slack-signature")?,
        content_type: request
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
    };
    let raw = body_bytes(request).await?;
    verify_slack_signature(&config.signing_secret, &raw, &headers, now_seconds())
        .map_err(worker_error)?;
    let json_payload = serde_json::from_slice::<Value>(&raw).ok();
    if let Some(payload) = &json_payload {
        if payload.get("type").and_then(Value::as_str) == Some("url_verification") {
            return Ok(Json(json!({"challenge":payload["challenge"]})).into_response());
        }
        if let Some(team) = payload
            .get("team_id")
            .or_else(|| payload.pointer("/team/id"))
            .and_then(Value::as_str)
            && team != env.var("SLACK_TEAM_ID")?.to_string()
        {
            return Ok(error_response(
                403,
                "SLACK_WORKSPACE_MISMATCH",
                "Slack workspace does not match",
            ));
        }
    }
    let callback = if let Some(payload) = &json_payload {
        if payload.get("type").and_then(Value::as_str) == Some("event_callback") {
            let event = &payload["event"];
            if event.get("user").and_then(Value::as_str) != Some(config.owner_slack_id.as_str())
                || event.get("subtype").is_some()
                || event.get("bot_id").is_some()
            {
                return Ok(success(200, json!({"accepted":false})));
            }
            let channel = event.get("channel").and_then(Value::as_str).unwrap_or("");
            let thread = event.get("thread_ts").and_then(Value::as_str).unwrap_or("");
            if channel.is_empty() || thread.is_empty() {
                return Ok(success(200, json!({"accepted":false})));
            }
            let row: Option<QuestionRow> = control_db(&env)?.prepare("SELECT record_json FROM questions WHERE json_extract(record_json,'$.message.channel')=?1 AND (json_extract(record_json,'$.message.ts')=?2 OR json_extract(record_json,'$.request.destination.thread_ts')=?2) ORDER BY CASE WHEN status='waiting' THEN 0 ELSE 1 END, created_at DESC, id DESC LIMIT 1")
                .bind(&[JsValue::from_str(channel), JsValue::from_str(thread)])?.first(None).await?;
            let Some(row) = row else {
                return Ok(success(200, json!({"accepted":false})));
            };
            let record: QuestionRecord = serde_json::from_str(&row.record_json)
                .map_err(|e| worker::Error::RustError(e.to_string()))?;
            comms_interactions::SlackCallback {
                callback_id: format!(
                    "event:{}",
                    payload
                        .get("event_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| worker::Error::RustError(
                            "SLACK_EVENT_ID_REQUIRED".into()
                        ))?
                ),
                user_id: config.owner_slack_id.clone(),
                question_id: record.id,
                choice_id: None,
                value: event.get("text").cloned().unwrap_or(Value::Null),
                payload: payload.clone(),
            }
        } else {
            parse_slack_callback(&raw, headers.content_type.as_deref()).map_err(worker_error)?
        }
    } else {
        parse_slack_callback(&raw, headers.content_type.as_deref()).map_err(worker_error)?
    };

    let team = callback
        .payload
        .get("team_id")
        .or_else(|| callback.payload.pointer("/team/id"))
        .and_then(Value::as_str);
    if team != Some(env.var("SLACK_TEAM_ID")?.to_string().as_str()) {
        return Ok(error_response(
            403,
            "SLACK_WORKSPACE_MISMATCH",
            "Slack workspace does not match",
        ));
    }
    if callback.user_id != config.owner_slack_id {
        return Ok(success(
            200,
            json!({"accepted": false, "outcome": AnswerOutcome::Rejected { reason: RejectReason::OwnerMismatch, record: None }}),
        ));
    }
    if let Some(existing) = callback_row(&env, &callback.callback_id).await? {
        let record = load_record(&env, &existing.question_id)
            .await?
            .ok_or_else(|| worker::Error::RustError("QUESTION_NOT_FOUND".into()))?
            .0;
        if existing.outcome != "received" || !is_expirable(&record) {
            let resume = record.answer.clone().map(|answer| ResumeSignal {
                agent_id: record.agent.agent_id.clone(),
                question_id: record.id.clone(),
                answer,
            });
            return Ok(success(
                200,
                json!({"accepted": true, "outcome": duplicate_outcome(&existing.outcome, record), "resume": resume }),
            ));
        }
    }
    let now = now_seconds();
    insert_callback(
        &env,
        &callback.callback_id,
        &callback.question_id,
        &callback.user_id,
        now,
        "received",
    )
    .await?;
    let Some((mut candidate, _)) = load_record(&env, &callback.question_id).await? else {
        update_callback_outcome(&env, &callback.callback_id, "question_not_found").await?;
        return Ok(success(
            200,
            json!({"accepted": false, "outcome": AnswerOutcome::Rejected { reason: RejectReason::QuestionNotFound, record: None }}),
        ));
    };
    if callback.payload.get("actions").is_some() {
        let channel = callback
            .payload
            .pointer("/container/channel_id")
            .or_else(|| callback.payload.pointer("/channel/id"))
            .and_then(Value::as_str);
        let ts = callback
            .payload
            .pointer("/container/message_ts")
            .or_else(|| callback.payload.pointer("/message/ts"))
            .and_then(Value::as_str);
        if !candidate.message.as_ref().is_some_and(|message| {
            channel == Some(message.channel.as_str()) && ts == Some(message.ts.as_str())
        }) {
            return Ok(error_response(
                403,
                "QUESTION_MESSAGE_MISMATCH",
                "Slack control does not belong to this question message",
            ));
        }
    }
    if candidate
        .deadline_at
        .is_some_and(|deadline| deadline <= now)
        && is_expirable(&candidate)
    {
        candidate.state = QuestionState::Expired;
        candidate.updated_at = now;
        cas_transition(&env, &candidate, &["waiting", "pending_delivery"]).await?;
        update_callback_outcome(&env, &callback.callback_id, "expired").await?;
        return Ok(success(
            200,
            json!({"accepted": false, "outcome": AnswerOutcome::Rejected { reason: RejectReason::Expired, record: Some(candidate) }}),
        ));
    }
    if candidate.state != QuestionState::Waiting {
        let reason = reason_for_non_waiting(&candidate.state);
        update_callback_outcome(
            &env,
            &callback.callback_id,
            outcome_name_for_reason(&reason),
        )
        .await?;
        return Ok(success(
            200,
            json!({"accepted": false, "outcome": AnswerOutcome::Rejected { reason, record: Some(candidate) }}),
        ));
    }
    let answer = QuestionAnswer {
        question_id: candidate.id.clone(),
        owner_user_id: callback.user_id,
        callback_id: callback.callback_id.clone(),
        choice_id: callback.choice_id,
        value: callback.value,
        answered_at: now,
    };
    candidate.answer = Some(answer.clone());
    candidate.state = QuestionState::Answered;
    candidate.updated_at = now;
    cas_transition(&env, &candidate, &["waiting"]).await?;
    let record = load_record(&env, &candidate.id)
        .await?
        .ok_or_else(|| worker::Error::RustError("QUESTION_NOT_FOUND".into()))?
        .0;
    if record
        .answer
        .as_ref()
        .is_some_and(|stored| stored.callback_id == callback.callback_id)
    {
        update_callback_outcome(&env, &callback.callback_id, "answered").await?;
        let resume = ResumeSignal {
            agent_id: record.agent.agent_id.clone(),
            question_id: record.id.clone(),
            answer,
        };
        Ok(success(
            200,
            json!({"accepted": true, "outcome": AnswerOutcome::Answered { record: record.clone(), resume: Box::new(resume.clone()) }, "resume": resume}),
        ))
    } else {
        update_callback_outcome(&env, &callback.callback_id, "already_answered").await?;
        Ok(success(
            200,
            json!({"accepted": false, "outcome": AnswerOutcome::Rejected { reason: RejectReason::AlreadyAnswered, record: Some(record) }}),
        ))
    }
}

async fn create_question(
    request: HttpRequest,
    env: &Env,
    agent: Agent,
    config: &SlackQuestionConfig,
) -> worker::Result<axum::response::Response> {
    let body: CreateQuestionBody = json_body(request).await?;
    let mut question = body.request.unwrap_or_else(|| QuestionRequest {
        text: body.text.unwrap_or_default(),
        destination: comms_interactions::SlackDestination {
            channel: body.channel.unwrap_or_default(),
            thread_ts: body.thread_ts,
        },
        blocks: body.blocks,
        choices: body.choices,
        deadline_seconds: body.deadline_seconds.or(body.timeout_seconds),
        no_deadline: body.no_deadline,
    });
    let session = if body.session_id.is_some() || question.destination.channel.trim().is_empty() {
        let invoker =
            crate::slack::WorkerSlackBackend::from_env(env.clone(), agent.clone()).await?;
        let session = invoker
            .load_session(body.session_id.as_deref())
            .await
            .map_err(worker::Error::RustError)?;
        if body.session_id.is_some() && session.is_none() {
            return Err(worker::Error::RustError("SESSION_NOT_FOUND".into()));
        }
        session
    } else {
        None
    };
    let agent_identity = AgentIdentity {
        agent_id: agent.id,
        label: agent.label,
    };
    let request_hash = request_hash(&question)?;
    if let Some(key) = body
        .idempotency_key
        .as_deref()
        .filter(|key| !key.trim().is_empty())
        && let Some((record, stored_hash)) =
            load_by_idempotency(env, &agent_identity.agent_id, key).await?
    {
        if stored_hash.as_deref() == Some(request_hash.as_str()) {
            return Ok(success(
                200,
                json!({"question": record, "idempotent_replay": true}),
            ));
        }
        return Ok(error_response(
            409,
            "IDEMPOTENCY_CONFLICT",
            "idempotency_key already belongs to a different question request",
        ));
    }
    if let Some(session) = &session {
        question.destination.channel = session.channel_id.clone();
        question.destination.thread_ts = Some(session.thread_ts.clone());
    }
    if question.destination.channel.trim().is_empty() {
        question.destination.channel = if config.default_channel.trim().is_empty() {
            slack_owner_dm(env, &config.bot_token, &config.owner_slack_id)
                .await
                .map_err(worker_error)?
        } else {
            config.default_channel.clone()
        };
    }
    let id = random_id("q")?;
    validate_question(&id, &agent_identity, &question).map_err(worker_error)?;
    let now = now_seconds();
    let deadline_at = if question.no_deadline {
        None
    } else {
        Some(
            now + question
                .deadline_seconds
                .unwrap_or(comms_interactions::DEFAULT_DEADLINE_SECONDS),
        )
    };
    let mut record = QuestionRecord {
        id,
        agent: agent_identity,
        request: question,
        state: QuestionState::PendingDelivery,
        created_at: now,
        updated_at: now,
        deadline_at,
        message: None,
        answer: None,
        cancelled_at: None,
        cancel_reason: None,
    };
    insert_record(env, &record, body.idempotency_key.as_deref(), &request_hash).await?;
    let mut payload = slack_message_payload(&record);
    if let Some(session) = &session {
        payload["username"] = json!(session.name);
        if let Some(icon) = &session.icon_emoji {
            payload["icon_emoji"] = json!(icon);
        }
        if let Some(icon) = &session.icon_url {
            payload["icon_url"] = json!(icon);
        }
    }
    let message = slack_post_message(env, &config.bot_token, &payload)
        .await
        .map_err(worker_error)?;
    record.message = Some(message);
    record.state = QuestionState::Waiting;
    record.updated_at = now_seconds();
    cas_transition(env, &record, &["pending_delivery"]).await?;
    let record = load_record(env, &record.id)
        .await?
        .ok_or_else(|| worker::Error::RustError("QUESTION_NOT_FOUND".into()))?
        .0;
    Ok(success(200, json!({"question": record})))
}

async fn status_or_wait(
    env: &Env,
    agent_id: &str,
    id: &str,
    wait: bool,
) -> worker::Result<axum::response::Response> {
    let record = load_agent_record(env, id, agent_id).await?;
    let record = expire_if_due(env, record, now_seconds()).await?;
    if wait {
        Ok(success(200, json!({"wait": wait_outcome(record)})))
    } else {
        Ok(success(200, json!({"question": record})))
    }
}
async fn cancel_question_body(
    env: &Env,
    agent_id: &str,
    id: &str,
    reason: Option<String>,
) -> worker::Result<axum::response::Response> {
    let mut record = load_agent_record(env, id, agent_id).await?;
    if !is_expirable(&record) {
        return Ok(error_response(
            409,
            "QUESTION_NOT_CANCELLABLE",
            "Question is not waiting for an answer",
        ));
    }
    let now = now_seconds();
    record.state = QuestionState::Cancelled;
    record.cancelled_at = Some(now);
    record.cancel_reason = reason;
    record.updated_at = now;
    cas_transition(env, &record, &["pending_delivery", "waiting"]).await?;
    let record = load_record(env, id)
        .await?
        .ok_or_else(|| worker::Error::RustError("QUESTION_NOT_FOUND".into()))?
        .0;
    Ok(success(200, json!({"question": record})))
}
async fn load_agent_record(env: &Env, id: &str, agent_id: &str) -> worker::Result<QuestionRecord> {
    let record = load_record(env, id)
        .await?
        .ok_or_else(|| worker::Error::RustError("QUESTION_NOT_FOUND".into()))?
        .0;
    if record.agent.agent_id != agent_id {
        return Err(worker::Error::RustError("QUESTION_FORBIDDEN".into()));
    }
    Ok(record)
}
async fn expire_if_due(
    env: &Env,
    mut record: QuestionRecord,
    now: i64,
) -> worker::Result<QuestionRecord> {
    if is_expirable(&record) && record.deadline_at.is_some_and(|deadline| deadline <= now) {
        record.state = QuestionState::Expired;
        record.updated_at = now;
        cas_transition(env, &record, &["pending_delivery", "waiting"]).await?;
        record = load_record(env, &record.id)
            .await?
            .ok_or_else(|| worker::Error::RustError("QUESTION_NOT_FOUND".into()))?
            .0;
    }
    Ok(record)
}
async fn load_record(
    env: &Env,
    id: &str,
) -> worker::Result<Option<(QuestionRecord, Option<String>)>> {
    let row: Option<QuestionRow> = control_db(env)?
        .prepare("SELECT record_json, request_hash FROM questions WHERE id = ?1")
        .bind(&[JsValue::from_str(id)])?
        .first(None)
        .await?;
    row.map(|row| {
        serde_json::from_str(&row.record_json)
            .map(|record| (record, row.request_hash))
            .map_err(|error| worker::Error::RustError(error.to_string()))
    })
    .transpose()
}
async fn load_by_idempotency(
    env: &Env,
    agent_id: &str,
    key: &str,
) -> worker::Result<Option<(QuestionRecord, Option<String>)>> {
    let row: Option<QuestionRow> = control_db(env)?.prepare("SELECT record_json, request_hash FROM questions WHERE agent_id = ?1 AND idempotency_key = ?2").bind(&[JsValue::from_str(agent_id), JsValue::from_str(key)])?.first(None).await?;
    row.map(|row| {
        serde_json::from_str(&row.record_json)
            .map(|record| (record, row.request_hash))
            .map_err(|error| worker::Error::RustError(error.to_string()))
    })
    .transpose()
}
async fn insert_record(
    env: &Env,
    record: &QuestionRecord,
    idempotency_key: Option<&str>,
    request_hash: &str,
) -> worker::Result<()> {
    let json = record_json(record)?;
    control_db(env)?.prepare("INSERT INTO questions(id, agent_id, idempotency_key, request_hash, status, deadline_at, created_at, updated_at, record_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)").bind(&[JsValue::from_str(&record.id), JsValue::from_str(&record.agent.agent_id), opt_str(idempotency_key), JsValue::from_str(request_hash), JsValue::from_str(state_name(&record.state)), opt_i64(record.deadline_at), JsValue::from_f64(record.created_at as f64), JsValue::from_f64(record.updated_at as f64), JsValue::from_str(&json)])?.run().await?;
    Ok(())
}
async fn cas_transition(
    env: &Env,
    record: &QuestionRecord,
    allowed_statuses: &[&str],
) -> worker::Result<()> {
    let placeholders = allowed_statuses
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "UPDATE questions SET agent_id = ?1, status = ?2, deadline_at = ?3, updated_at = ?4, record_json = ?5 WHERE id = ?6 AND status IN ({})",
        placeholders
    );
    let json = record_json(record)?;
    let mut values = vec![
        JsValue::from_str(&record.agent.agent_id),
        JsValue::from_str(state_name(&record.state)),
        opt_i64(record.deadline_at),
        JsValue::from_f64(record.updated_at as f64),
        JsValue::from_str(&json),
        JsValue::from_str(&record.id),
    ];
    for status in allowed_statuses {
        values.push(JsValue::from_str(status));
    }
    control_db(env)?.prepare(&sql).bind(&values)?.run().await?;
    Ok(())
}
async fn callback_row(env: &Env, callback_id: &str) -> worker::Result<Option<CallbackRow>> {
    control_db(env)?
        .prepare("SELECT question_id, outcome FROM question_callbacks WHERE callback_id = ?1")
        .bind(&[JsValue::from_str(callback_id)])?
        .first(None)
        .await
}
async fn insert_callback(
    env: &Env,
    callback_id: &str,
    question_id: &str,
    owner: &str,
    received_at: i64,
    outcome: &str,
) -> worker::Result<()> {
    control_db(env)?.prepare("INSERT OR IGNORE INTO question_callbacks(callback_id, question_id, owner_user_id, received_at, outcome) VALUES (?1, ?2, ?3, ?4, ?5)").bind(&[JsValue::from_str(callback_id), JsValue::from_str(question_id), JsValue::from_str(owner), JsValue::from_f64(received_at as f64), JsValue::from_str(outcome)])?.run().await?;
    Ok(())
}
async fn update_callback_outcome(
    env: &Env,
    callback_id: &str,
    outcome: &str,
) -> worker::Result<()> {
    control_db(env)?
        .prepare("UPDATE question_callbacks SET outcome = ?1 WHERE callback_id = ?2")
        .bind(&[JsValue::from_str(outcome), JsValue::from_str(callback_id)])?
        .run()
        .await?;
    Ok(())
}
fn control_db(env: &Env) -> worker::Result<worker::d1::D1Database> {
    env.d1(CONTROL_BINDING)
}

async fn slack_owner_dm(
    env: &Env,
    token: &str,
    owner: &str,
) -> Result<String, comms_interactions::InteractionError> {
    let response = fetch_json(
        env,
        "https://slack.com/api/conversations.open",
        token,
        &json!({"users": owner}),
    )
    .await?;
    if !response.get("ok").and_then(Value::as_bool).unwrap_or(false) {
        return Err(comms_interactions::InteractionError::Delivery(format!(
            "slack conversations.open failed: {}",
            response
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        )));
    }
    response
        .pointer("/channel/id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            comms_interactions::InteractionError::Delivery(
                "slack conversations.open response missing channel id".into(),
            )
        })
}
async fn slack_post_message(
    env: &Env,
    token: &str,
    payload: &Value,
) -> Result<SlackMessageRef, comms_interactions::InteractionError> {
    let response = fetch_json(
        env,
        "https://slack.com/api/chat.postMessage",
        token,
        payload,
    )
    .await?;
    if !response.get("ok").and_then(Value::as_bool).unwrap_or(false) {
        return Err(comms_interactions::InteractionError::Delivery(format!(
            "slack chat.postMessage failed: {}",
            response
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        )));
    }
    let channel = response
        .get("channel")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            comms_interactions::InteractionError::Delivery("slack response missing channel".into())
        })?
        .to_owned();
    let ts = response
        .get("ts")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            comms_interactions::InteractionError::Delivery("slack response missing ts".into())
        })?
        .to_owned();
    Ok(SlackMessageRef {
        channel,
        ts: ts.clone(),
        thread_ts: Some(ts),
    })
}
async fn fetch_json(
    env: &Env,
    url: &str,
    token: &str,
    payload: &Value,
) -> Result<Value, comms_interactions::InteractionError> {
    let method = url.strip_prefix("https://slack.com/api/").ok_or_else(|| {
        comms_interactions::InteractionError::Delivery("Slack endpoint rejected".into())
    })?;
    let url = crate::slack_oauth::api_url(env, method)
        .map_err(|e| comms_interactions::InteractionError::Delivery(e.to_string()))?;
    let global = js_sys::global();
    let fetch = Reflect::get(&global, &JsValue::from_str("fetch"))
        .map_err(|_| comms_interactions::InteractionError::Delivery("fetch unavailable".into()))?
        .dyn_into::<Function>()
        .map_err(|_| comms_interactions::InteractionError::Delivery("fetch unavailable".into()))?;
    let headers = Object::new();
    Reflect::set(
        &headers,
        &JsValue::from_str("authorization"),
        &JsValue::from_str(&format!("Bearer {token}")),
    )
    .ok();
    Reflect::set(
        &headers,
        &JsValue::from_str("content-type"),
        &JsValue::from_str("application/json; charset=utf-8"),
    )
    .ok();
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
        &JsValue::from_str("POST"),
    )
    .ok();
    Reflect::set(&init, &JsValue::from_str("headers"), &headers).ok();
    Reflect::set(
        &init,
        &JsValue::from_str("body"),
        &JsValue::from_str(&payload.to_string()),
    )
    .ok();
    let promise = fetch
        .call2(&global, &JsValue::from_str(&url), &init)
        .map_err(|_| comms_interactions::InteractionError::Delivery("fetch failed".into()))?
        .dyn_into::<Promise>()
        .map_err(|_| comms_interactions::InteractionError::Delivery("fetch failed".into()))?;
    let response = JsFuture::from(promise)
        .await
        .map_err(|_| comms_interactions::InteractionError::Delivery("fetch failed".into()))?
        .dyn_into::<WebResponse>()
        .map_err(|_| {
            comms_interactions::InteractionError::Delivery("fetch response invalid".into())
        })?;
    if (300..400).contains(&response.status()) {
        return Err(comms_interactions::InteractionError::Delivery(
            "Slack redirect rejected".into(),
        ));
    }
    let text =
        JsFuture::from(response.text().map_err(|_| {
            comms_interactions::InteractionError::Delivery("fetch body failed".into())
        })?)
        .await
        .map_err(|_| comms_interactions::InteractionError::Delivery("fetch body failed".into()))?
        .as_string()
        .ok_or_else(|| {
            comms_interactions::InteractionError::Delivery("fetch body was not text".into())
        })?;
    serde_json::from_str(&text)
        .map_err(|error| comms_interactions::InteractionError::Delivery(error.to_string()))
}

fn duplicate_outcome(outcome: &str, record: QuestionRecord) -> AnswerOutcome {
    match outcome {
        "answered" => AnswerOutcome::Duplicate { record },
        "expired" => AnswerOutcome::Rejected {
            reason: RejectReason::Expired,
            record: Some(record),
        },
        "cancelled" => AnswerOutcome::Rejected {
            reason: RejectReason::Cancelled,
            record: Some(record),
        },
        "already_answered" => AnswerOutcome::Rejected {
            reason: RejectReason::AlreadyAnswered,
            record: Some(record),
        },
        "question_not_found" => AnswerOutcome::Rejected {
            reason: RejectReason::QuestionNotFound,
            record: None,
        },
        _ => AnswerOutcome::Rejected {
            reason: RejectReason::NotWaiting,
            record: Some(record),
        },
    }
}
fn reason_for_non_waiting(state: &QuestionState) -> RejectReason {
    match state {
        QuestionState::Answered => RejectReason::AlreadyAnswered,
        QuestionState::Expired => RejectReason::Expired,
        QuestionState::Cancelled => RejectReason::Cancelled,
        _ => RejectReason::NotWaiting,
    }
}
fn outcome_name_for_reason(reason: &RejectReason) -> &'static str {
    match reason {
        RejectReason::AlreadyAnswered => "already_answered",
        RejectReason::Expired => "expired",
        RejectReason::Cancelled => "cancelled",
        RejectReason::QuestionNotFound => "question_not_found",
        _ => "not_waiting",
    }
}
fn question_id_from_path<'a>(path: &'a str, suffix: &str) -> &'a str {
    path.trim_start_matches("/questions/")
        .trim_end_matches(suffix)
        .trim_end_matches('/')
}
fn record_json(record: &QuestionRecord) -> worker::Result<String> {
    serde_json::to_string(record).map_err(|error| worker::Error::RustError(error.to_string()))
}
fn request_hash(request: &QuestionRequest) -> worker::Result<String> {
    let bytes =
        serde_json::to_vec(request).map_err(|error| worker::Error::RustError(error.to_string()))?;
    Ok(hex_lower(&Sha256::digest(&bytes)))
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
fn opt_i64(value: Option<i64>) -> JsValue {
    value
        .map(|v| JsValue::from_f64(v as f64))
        .unwrap_or(JsValue::NULL)
}
fn opt_str(value: Option<&str>) -> JsValue {
    value.map(JsValue::from_str).unwrap_or(JsValue::NULL)
}
fn now_seconds() -> i64 {
    js_sys::Date::now().floor() as i64 / 1000
}
fn random_id(prefix: &str) -> worker::Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom(&mut bytes).map_err(|_| worker::Error::RustError("RANDOM_FAILED".into()))?;
    Ok(format!(
        "{prefix}_{}",
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}
fn header(request: &HttpRequest, name: &str) -> worker::Result<String> {
    request
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| worker::Error::RustError(format!("missing header {name}")))
}
async fn json_body<T: for<'de> Deserialize<'de>>(request: HttpRequest) -> worker::Result<T> {
    serde_json::from_slice(&body_bytes(request).await?)
        .map_err(|error| worker::Error::RustError(format!("INVALID_JSON: {error}")))
}
async fn body_bytes(request: HttpRequest) -> worker::Result<Vec<u8>> {
    let bytes = request
        .into_body()
        .collect()
        .await
        .map_err(|_| worker::Error::RustError("BODY_READ_FAILED".into()))?
        .to_bytes();
    if bytes.len() > 256 * 1024 {
        return Err(worker::Error::RustError("BODY_TOO_LARGE".into()));
    }
    Ok(bytes.to_vec())
}
fn success(status: u16, data: Value) -> axum::response::Response {
    let mut response = Json(json!({"ok": true, "data": data})).into_response();
    *response.status_mut() = axum::http::StatusCode::from_u16(status).unwrap();
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
}
fn error_response(status: u16, code: &str, message: &str) -> axum::response::Response {
    let mut response =
        Json(json!({"ok": false, "error": {"code": code, "message": message}})).into_response();
    *response.status_mut() = axum::http::StatusCode::from_u16(status).unwrap();
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
}
fn worker_error(error: comms_interactions::InteractionError) -> worker::Error {
    worker::Error::RustError(error.to_string())
}
