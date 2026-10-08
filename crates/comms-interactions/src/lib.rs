use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    sync::{Arc, Mutex},
};

pub const DEFAULT_DEADLINE_SECONDS: i64 = 86_400;
pub const SLACK_REPLAY_WINDOW_SECONDS: i64 = 300;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentIdentity {
    pub agent_id: String,
    pub label: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlackDestination {
    pub channel: String,
    pub thread_ts: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuestionChoice {
    pub id: String,
    pub text: String,
    pub value: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct QuestionRequest {
    pub text: String,
    pub destination: SlackDestination,
    #[serde(default)]
    pub blocks: Option<Value>,
    #[serde(default)]
    pub choices: Vec<QuestionChoice>,
    pub deadline_seconds: Option<i64>,
    #[serde(default)]
    pub no_deadline: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlackMessageRef {
    pub channel: String,
    pub ts: String,
    pub thread_ts: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QuestionState {
    PendingDelivery,
    Waiting,
    Answered,
    Expired,
    Cancelled,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct QuestionAnswer {
    pub question_id: String,
    pub owner_user_id: String,
    pub callback_id: String,
    pub choice_id: Option<String>,
    pub value: Value,
    pub answered_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ResumeSignal {
    pub agent_id: String,
    pub question_id: String,
    pub answer: QuestionAnswer,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct QuestionRecord {
    pub id: String,
    pub agent: AgentIdentity,
    pub request: QuestionRequest,
    pub state: QuestionState,
    pub created_at: i64,
    pub updated_at: i64,
    pub deadline_at: Option<i64>,
    pub message: Option<SlackMessageRef>,
    pub answer: Option<QuestionAnswer>,
    pub cancelled_at: Option<i64>,
    pub cancel_reason: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SlackRequestHeaders {
    pub timestamp: String,
    pub signature: String,
    pub content_type: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SlackCallback {
    pub callback_id: String,
    pub user_id: String,
    pub question_id: String,
    pub choice_id: Option<String>,
    pub value: Value,
    pub payload: Value,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AnswerAttempt {
    pub callback_id: String,
    pub question_id: String,
    pub owner_user_id: String,
    pub choice_id: Option<String>,
    pub value: Value,
    pub received_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum AnswerOutcome {
    Answered {
        record: QuestionRecord,
        resume: Box<ResumeSignal>,
    },
    Duplicate {
        record: QuestionRecord,
    },
    Rejected {
        reason: RejectReason,
        record: Option<QuestionRecord>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    OwnerMismatch,
    QuestionNotFound,
    NotWaiting,
    Expired,
    Cancelled,
    AlreadyAnswered,
    InvalidSignature,
    InvalidCallback,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum WaitOutcome {
    Waiting {
        record: QuestionRecord,
    },
    Answered {
        record: QuestionRecord,
        resume: Box<ResumeSignal>,
    },
    Expired {
        record: QuestionRecord,
    },
    Cancelled {
        record: QuestionRecord,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InteractionError {
    InvalidInput(String),
    Store(String),
    Delivery(String),
    Parse(String),
    Signature(String),
}
impl fmt::Display for InteractionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(s) => write!(f, "invalid input: {s}"),
            Self::Store(s) => write!(f, "store error: {s}"),
            Self::Delivery(s) => write!(f, "delivery error: {s}"),
            Self::Parse(s) => write!(f, "parse error: {s}"),
            Self::Signature(s) => write!(f, "signature error: {s}"),
        }
    }
}
impl std::error::Error for InteractionError {}

#[async_trait::async_trait(?Send)]
pub trait QuestionStore {
    async fn insert_pending(&self, record: QuestionRecord) -> Result<(), InteractionError>;
    async fn get(&self, id: &str) -> Result<Option<QuestionRecord>, InteractionError>;
    async fn mark_delivered(
        &self,
        id: &str,
        msg: SlackMessageRef,
        now: i64,
    ) -> Result<QuestionRecord, InteractionError>;
    async fn expire_question(
        &self,
        id: &str,
        now: i64,
    ) -> Result<Option<QuestionRecord>, InteractionError>;
    async fn cancel_question(
        &self,
        id: &str,
        agent_id: &str,
        reason: Option<String>,
        now: i64,
    ) -> Result<QuestionRecord, InteractionError>;
    async fn answer_first(&self, attempt: AnswerAttempt)
    -> Result<AnswerOutcome, InteractionError>;
}
#[async_trait::async_trait(?Send)]
pub trait QuestionDelivery {
    async fn deliver(&self, record: &QuestionRecord) -> Result<SlackMessageRef, InteractionError>;
}
pub trait Clock {
    fn now_seconds(&self) -> i64;
}

pub struct QuestionService<S, D, C> {
    pub store: S,
    delivery: D,
    clock: C,
    owner_slack_id: String,
}
impl<S, D, C> QuestionService<S, D, C> {
    pub fn new(store: S, delivery: D, clock: C, owner_slack_id: impl Into<String>) -> Self {
        Self {
            store,
            delivery,
            clock,
            owner_slack_id: owner_slack_id.into(),
        }
    }
}
impl<S: QuestionStore, D: QuestionDelivery, C: Clock> QuestionService<S, D, C> {
    pub async fn create(
        &self,
        id: impl Into<String>,
        agent: AgentIdentity,
        request: QuestionRequest,
    ) -> Result<QuestionRecord, InteractionError> {
        let id = id.into();
        validate_question(&id, &agent, &request)?;
        let now = self.clock.now_seconds();
        let deadline_at = if request.no_deadline {
            None
        } else {
            Some(now + request.deadline_seconds.unwrap_or(DEFAULT_DEADLINE_SECONDS))
        };
        let record = QuestionRecord {
            id,
            agent,
            request,
            state: QuestionState::PendingDelivery,
            created_at: now,
            updated_at: now,
            deadline_at,
            message: None,
            answer: None,
            cancelled_at: None,
            cancel_reason: None,
        };
        self.store.insert_pending(record.clone()).await?;
        let msg = self.delivery.deliver(&record).await?;
        self.store.mark_delivered(&record.id, msg, now).await
    }
    pub async fn status(&self, id: &str) -> Result<Option<QuestionRecord>, InteractionError> {
        let now = self.clock.now_seconds();
        match self.store.get(id).await? {
            Some(r) if is_expirable(&r) && r.deadline_at.is_some_and(|d| d <= now) => {
                self.store.expire_question(id, now).await
            }
            other => Ok(other),
        }
    }
    pub async fn wait(&self, id: &str) -> Result<WaitOutcome, InteractionError> {
        let r = self
            .status(id)
            .await?
            .ok_or_else(|| InteractionError::InvalidInput("question not found".into()))?;
        Ok(wait_outcome(r))
    }
    pub async fn cancel(
        &self,
        id: &str,
        agent_id: &str,
        reason: Option<String>,
    ) -> Result<QuestionRecord, InteractionError> {
        self.store
            .cancel_question(id, agent_id, reason, self.clock.now_seconds())
            .await
    }
    pub async fn handle_slack_callback(
        &self,
        secret: &str,
        headers: &SlackRequestHeaders,
        raw: &[u8],
    ) -> Result<AnswerOutcome, InteractionError> {
        verify_slack_signature(secret, raw, headers, self.clock.now_seconds())?;
        let cb = parse_slack_callback(raw, headers.content_type.as_deref())?;
        if cb.user_id != self.owner_slack_id {
            return Ok(AnswerOutcome::Rejected {
                reason: RejectReason::OwnerMismatch,
                record: None,
            });
        }
        self.store
            .answer_first(AnswerAttempt {
                callback_id: cb.callback_id,
                question_id: cb.question_id,
                owner_user_id: cb.user_id,
                choice_id: cb.choice_id,
                value: cb.value,
                received_at: self.clock.now_seconds(),
            })
            .await
    }
}

pub fn validate_question(
    id: &str,
    agent: &AgentIdentity,
    request: &QuestionRequest,
) -> Result<(), InteractionError> {
    if id.trim().is_empty() {
        return Err(InteractionError::InvalidInput(
            "question id is required".into(),
        ));
    }
    if agent.agent_id.trim().is_empty() {
        return Err(InteractionError::InvalidInput(
            "agent id is required".into(),
        ));
    }
    if request.text.trim().is_empty() {
        return Err(InteractionError::InvalidInput("text is required".into()));
    }
    if request.destination.channel.trim().is_empty() {
        return Err(InteractionError::InvalidInput(
            "destination channel is required".into(),
        ));
    }
    if request.deadline_seconds.is_some_and(|s| s <= 0) {
        return Err(InteractionError::InvalidInput(
            "deadline_seconds must be positive".into(),
        ));
    }
    Ok(())
}
pub fn state_name(state: &QuestionState) -> &'static str {
    match state {
        QuestionState::PendingDelivery => "pending_delivery",
        QuestionState::Waiting => "waiting",
        QuestionState::Answered => "answered",
        QuestionState::Expired => "expired",
        QuestionState::Cancelled => "cancelled",
    }
}
pub fn is_expirable(r: &QuestionRecord) -> bool {
    matches!(
        r.state,
        QuestionState::PendingDelivery | QuestionState::Waiting
    )
}
pub fn wait_outcome(r: QuestionRecord) -> WaitOutcome {
    match r.state {
        QuestionState::Answered => WaitOutcome::Answered {
            resume: Box::new(ResumeSignal {
                agent_id: r.agent.agent_id.clone(),
                question_id: r.id.clone(),
                answer: r.answer.clone().expect("answered question has answer"),
            }),
            record: r,
        },
        QuestionState::Expired => WaitOutcome::Expired { record: r },
        QuestionState::Cancelled => WaitOutcome::Cancelled { record: r },
        _ => WaitOutcome::Waiting { record: r },
    }
}

pub fn slack_message_payload(r: &QuestionRecord) -> Value {
    let mut blocks = r
        .request
        .blocks
        .as_ref()
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| {
            vec![json!({"type":"section","text":{"type":"mrkdwn","text":r.request.text}})]
        });
    if !r.request.choices.is_empty() {
        let elements = r.request.choices.iter().map(|c| json!({"type":"button","action_id":format!("comms_question_answer:{}",c.id),"text":{"type":"plain_text","text":c.text},"value":json!({"question_id":r.id,"choice_id":c.id,"answer":c.value.as_deref().unwrap_or(&c.id)}).to_string()})).collect::<Vec<_>>();
        blocks.push(json!({"type":"actions","block_id":format!("comms_question:{}",r.id),"elements":elements}));
    }
    let mut payload =
        json!({"channel":r.request.destination.channel,"text":r.request.text,"blocks":blocks});
    if let Some(thread_ts) = &r.request.destination.thread_ts {
        payload["thread_ts"] = Value::String(thread_ts.clone());
    }
    payload
}
pub fn verify_slack_signature(
    secret: &str,
    raw: &[u8],
    headers: &SlackRequestHeaders,
    now: i64,
) -> Result<(), InteractionError> {
    let ts = headers
        .timestamp
        .parse::<i64>()
        .map_err(|_| InteractionError::Signature("invalid x-slack-request-timestamp".into()))?;
    if (now - ts).abs() > SLACK_REPLAY_WINDOW_SECONDS {
        return Err(InteractionError::Signature(
            "slack timestamp outside replay window".into(),
        ));
    }
    let expected = slack_signature(secret, &headers.timestamp, raw);
    if constant_time_eq(expected.as_bytes(), headers.signature.as_bytes()) {
        Ok(())
    } else {
        Err(InteractionError::Signature(
            "slack signature mismatch".into(),
        ))
    }
}
pub fn slack_signature(secret: &str, timestamp: &str, raw: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key");
    mac.update(b"v0:");
    mac.update(timestamp.as_bytes());
    mac.update(b":");
    mac.update(raw);
    format!("v0={}", hex_lower(&mac.finalize().into_bytes()))
}
pub fn parse_slack_callback(
    raw: &[u8],
    content_type: Option<&str>,
) -> Result<SlackCallback, InteractionError> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| InteractionError::Parse("callback body must be utf8".into()))?;
    let payload_text = if content_type
        .unwrap_or("")
        .starts_with("application/x-www-form-urlencoded")
    {
        form_urlencoded::parse(raw)
            .find(|(k, _)| k == "payload")
            .map(|(_, v)| v.into_owned())
            .ok_or_else(|| InteractionError::Parse("form body missing payload".into()))?
    } else {
        text.to_owned()
    };
    let payload: Value = serde_json::from_str(&payload_text)
        .map_err(|e| InteractionError::Parse(format!("invalid slack payload json: {e}")))?;
    let user_id = payload
        .pointer("/user/id")
        .and_then(Value::as_str)
        .or_else(|| payload.pointer("/event/user").and_then(Value::as_str))
        .ok_or_else(|| InteractionError::Parse("slack payload missing user id".into()))?
        .to_owned();
    let (question_id, choice_id, value) = extract_answer(&payload)?;
    Ok(SlackCallback {
        callback_id: format!("sha256:{}", sha256_hex(raw)),
        user_id,
        question_id,
        choice_id,
        value,
        payload,
    })
}
fn extract_answer(payload: &Value) -> Result<(String, Option<String>, Value), InteractionError> {
    if let Some(action) = payload.pointer("/actions/0") {
        let mut question_id = action
            .get("block_id")
            .and_then(Value::as_str)
            .and_then(|s| s.strip_prefix("comms_question:"))
            .map(str::to_owned);
        let mut choice_id = None;
        let mut value = action.clone();
        if let Some(raw) = action.get("value").and_then(Value::as_str) {
            if let Ok(parsed) = serde_json::from_str::<Value>(raw) {
                question_id = question_id.or_else(|| {
                    parsed
                        .get("question_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                });
                choice_id = parsed
                    .get("choice_id")
                    .or_else(|| parsed.get("id"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                value = parsed
                    .get("answer")
                    .or_else(|| parsed.get("value"))
                    .cloned()
                    .unwrap_or(parsed);
            } else {
                value = Value::String(raw.to_owned());
            }
        }
        return question_id
            .map(|id| (id, choice_id, value))
            .ok_or_else(|| InteractionError::Parse("callback missing question id".into()));
    }
    if let Some(view) = payload.get("view") {
        let id = view
            .get("private_metadata")
            .and_then(Value::as_str)
            .and_then(|m| {
                serde_json::from_str::<Value>(m)
                    .ok()
                    .and_then(|v| {
                        v.get("question_id")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .or_else(|| Some(m.to_owned()).filter(|s| !s.is_empty()))
            })
            .ok_or_else(|| InteractionError::Parse("view callback missing question id".into()))?;
        return Ok((
            id,
            None,
            view.pointer("/state/values")
                .cloned()
                .unwrap_or_else(|| view.clone()),
        ));
    }
    Err(InteractionError::Parse(
        "unsupported slack callback payload".into(),
    ))
}
fn hex_lower(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(H[(byte >> 4) as usize] as char);
        out.push(H[(byte & 0x0f) as usize] as char);
    }
    out
}
fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    for i in 0..left.len().max(right.len()) {
        diff |= (left.get(i).copied().unwrap_or(0) ^ right.get(i).copied().unwrap_or(0)) as usize;
    }
    diff == 0
}

#[derive(Clone, Default)]
pub struct MemoryQuestionStore {
    inner: Arc<Mutex<MemoryState>>,
}
#[derive(Default)]
struct MemoryState {
    questions: BTreeMap<String, QuestionRecord>,
    callbacks: HashMap<String, String>,
}
impl MemoryQuestionStore {
    pub fn new() -> Self {
        Self::default()
    }
}
#[async_trait::async_trait(?Send)]
impl QuestionStore for MemoryQuestionStore {
    async fn insert_pending(&self, record: QuestionRecord) -> Result<(), InteractionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| InteractionError::Store("lock poisoned".into()))?;
        if inner.questions.contains_key(&record.id) {
            return Err(InteractionError::Store("question already exists".into()));
        }
        inner.questions.insert(record.id.clone(), record);
        Ok(())
    }
    async fn get(&self, id: &str) -> Result<Option<QuestionRecord>, InteractionError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| InteractionError::Store("lock poisoned".into()))?
            .questions
            .get(id)
            .cloned())
    }
    async fn mark_delivered(
        &self,
        id: &str,
        msg: SlackMessageRef,
        now: i64,
    ) -> Result<QuestionRecord, InteractionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| InteractionError::Store("lock poisoned".into()))?;
        let record = inner
            .questions
            .get_mut(id)
            .ok_or_else(|| InteractionError::Store("question not found".into()))?;
        record.message = Some(msg);
        record.state = QuestionState::Waiting;
        record.updated_at = now;
        Ok(record.clone())
    }
    async fn expire_question(
        &self,
        id: &str,
        now: i64,
    ) -> Result<Option<QuestionRecord>, InteractionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| InteractionError::Store("lock poisoned".into()))?;
        let Some(record) = inner.questions.get_mut(id) else {
            return Ok(None);
        };
        if is_expirable(record) {
            record.state = QuestionState::Expired;
            record.updated_at = now;
        }
        Ok(Some(record.clone()))
    }
    async fn cancel_question(
        &self,
        id: &str,
        agent_id: &str,
        reason: Option<String>,
        now: i64,
    ) -> Result<QuestionRecord, InteractionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| InteractionError::Store("lock poisoned".into()))?;
        let record = inner
            .questions
            .get_mut(id)
            .ok_or_else(|| InteractionError::Store("question not found".into()))?;
        if record.agent.agent_id != agent_id {
            return Err(InteractionError::Store(
                "agent does not own question".into(),
            ));
        }
        if !is_expirable(record) {
            return Err(InteractionError::Store(
                "question is not cancellable".into(),
            ));
        }
        record.state = QuestionState::Cancelled;
        record.cancelled_at = Some(now);
        record.cancel_reason = reason;
        record.updated_at = now;
        Ok(record.clone())
    }
    async fn answer_first(
        &self,
        attempt: AnswerAttempt,
    ) -> Result<AnswerOutcome, InteractionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| InteractionError::Store("lock poisoned".into()))?;
        if let Some(question_id) = inner.callbacks.get(&attempt.callback_id) {
            let record = inner
                .questions
                .get(question_id)
                .cloned()
                .ok_or_else(|| InteractionError::Store("question not found".into()))?;
            return Ok(AnswerOutcome::Duplicate { record });
        }
        inner
            .callbacks
            .insert(attempt.callback_id.clone(), attempt.question_id.clone());
        let Some(record) = inner.questions.get_mut(&attempt.question_id) else {
            return Ok(AnswerOutcome::Rejected {
                reason: RejectReason::QuestionNotFound,
                record: None,
            });
        };
        if record.deadline_at.is_some_and(|d| d <= attempt.received_at) {
            record.state = QuestionState::Expired;
            record.updated_at = attempt.received_at;
            return Ok(AnswerOutcome::Rejected {
                reason: RejectReason::Expired,
                record: Some(record.clone()),
            });
        }
        if record.state != QuestionState::Waiting {
            let reason = match record.state {
                QuestionState::Answered => RejectReason::AlreadyAnswered,
                QuestionState::Expired => RejectReason::Expired,
                QuestionState::Cancelled => RejectReason::Cancelled,
                _ => RejectReason::NotWaiting,
            };
            return Ok(AnswerOutcome::Rejected {
                reason,
                record: Some(record.clone()),
            });
        }
        let answer = QuestionAnswer {
            question_id: record.id.clone(),
            owner_user_id: attempt.owner_user_id,
            callback_id: attempt.callback_id,
            choice_id: attempt.choice_id,
            value: attempt.value,
            answered_at: attempt.received_at,
        };
        record.state = QuestionState::Answered;
        record.answer = Some(answer.clone());
        record.updated_at = attempt.received_at;
        let resume = ResumeSignal {
            agent_id: record.agent.agent_id.clone(),
            question_id: record.id.clone(),
            answer,
        };
        Ok(AnswerOutcome::Answered {
            record: record.clone(),
            resume: Box::new(resume),
        })
    }
}
#[derive(Clone, Debug)]
pub struct FixedClock(pub i64);
impl Clock for FixedClock {
    fn now_seconds(&self) -> i64 {
        self.0
    }
}
#[derive(Clone, Debug)]
pub struct StaticDelivery {
    pub message: SlackMessageRef,
}
#[async_trait::async_trait(?Send)]
impl QuestionDelivery for StaticDelivery {
    async fn deliver(&self, _: &QuestionRecord) -> Result<SlackMessageRef, InteractionError> {
        Ok(self.message.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> QuestionRequest {
        QuestionRequest {
            text: "Deploy?".into(),
            destination: SlackDestination {
                channel: "C1".into(),
                thread_ts: None,
            },
            blocks: None,
            choices: vec![QuestionChoice {
                id: "yes".into(),
                text: "Yes".into(),
                value: None,
            }],
            deadline_seconds: None,
            no_deadline: false,
        }
    }
    fn service(now: i64) -> QuestionService<MemoryQuestionStore, StaticDelivery, FixedClock> {
        QuestionService::new(
            MemoryQuestionStore::new(),
            StaticDelivery {
                message: SlackMessageRef {
                    channel: "C1".into(),
                    ts: "1.0".into(),
                    thread_ts: Some("1.0".into()),
                },
            },
            FixedClock(now),
            "UOWNER",
        )
    }
    fn body(user: &str) -> Vec<u8> {
        let payload = json!({"user":{"id":user},"actions":[{"block_id":"comms_question:q1","value":json!({"question_id":"q1","choice_id":"yes","answer":"yes"}).to_string()}]});
        format!(
            "payload={}",
            form_urlencoded::byte_serialize(payload.to_string().as_bytes()).collect::<String>()
        )
        .into_bytes()
    }
    #[tokio::test]
    async fn owner_first_answer_resumes_and_duplicate_dedups() {
        let s = service(100);
        s.create(
            "q1",
            AgentIdentity {
                agent_id: "agent-a".into(),
                label: None,
            },
            request(),
        )
        .await
        .unwrap();
        let wrong = body("UOTHER");
        let h = SlackRequestHeaders {
            timestamp: "100".into(),
            signature: slack_signature("secret", "100", &wrong),
            content_type: Some("application/x-www-form-urlencoded".into()),
        };
        assert!(matches!(
            s.handle_slack_callback("secret", &h, &wrong).await.unwrap(),
            AnswerOutcome::Rejected {
                reason: RejectReason::OwnerMismatch,
                ..
            }
        ));
        let raw = body("UOWNER");
        let h = SlackRequestHeaders {
            timestamp: "100".into(),
            signature: slack_signature("secret", "100", &raw),
            content_type: Some("application/x-www-form-urlencoded".into()),
        };
        assert!(matches!(
            s.handle_slack_callback("secret", &h, &raw).await.unwrap(),
            AnswerOutcome::Answered { .. }
        ));
        assert!(matches!(
            s.handle_slack_callback("secret", &h, &raw).await.unwrap(),
            AnswerOutcome::Duplicate { .. }
        ));
    }
    #[tokio::test]
    async fn stale_controls_do_not_replace_first_answer() {
        let s = service(200);
        s.create(
            "q1",
            AgentIdentity {
                agent_id: "agent-a".into(),
                label: None,
            },
            request(),
        )
        .await
        .unwrap();
        assert!(matches!(
            s.store
                .answer_first(AnswerAttempt {
                    callback_id: "first".into(),
                    question_id: "q1".into(),
                    owner_user_id: "UOWNER".into(),
                    choice_id: None,
                    value: json!("one"),
                    received_at: 200
                })
                .await
                .unwrap(),
            AnswerOutcome::Answered { .. }
        ));
        assert!(matches!(
            s.store
                .answer_first(AnswerAttempt {
                    callback_id: "second".into(),
                    question_id: "q1".into(),
                    owner_user_id: "UOWNER".into(),
                    choice_id: None,
                    value: json!("two"),
                    received_at: 201
                })
                .await
                .unwrap(),
            AnswerOutcome::Rejected {
                reason: RejectReason::AlreadyAnswered,
                ..
            }
        ));
    }
    #[test]
    fn verifies_official_slack_signature_fixture() {
        let body=b"token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
        assert_eq!(
            slack_signature("8f742231b10e8888abcd99yyyzzz85a5", "1531420618", body),
            "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503"
        );
    }
}
