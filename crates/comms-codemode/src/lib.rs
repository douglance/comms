//! Agent-scoped host adapters for Incurs Code Mode.
//!
//! This crate does not implement another JavaScript engine. It builds the comms
//! lifecycle from the shared Incurs `ToolCatalog`, host-provided durable storage,
//! the published local QuickJS executor when enabled, and the published five-tool
//! MCP facade when enabled.

use std::fmt;
use std::sync::Arc;

use incurs::cli::Cli;
use incurs_codemode::{
    ArtifactStore, Clock, CodeExecutor, CodeMode, CodeModeRunOptions, Connector,
    DefaultToolPolicyResolver, ExecutionState, ExecutionStatus, IncurConnector, MemoryStore,
    ReplayPolicy, RuntimeStore, SearchOutput, ToolAnnotations, ToolOrigin, ToolPolicy,
    ToolPolicyResolver,
};
use serde::{Deserialize, Serialize};

mod question;

#[cfg(feature = "remote")]
pub mod remote;

pub use question::{
    HumanQuestionConnector, MemoryQuestionAnswerStore, PendingHumanQuestion, QuestionAnswer,
    QuestionAnswerStore, pending_human_questions,
};

#[cfg(feature = "remote")]
pub use remote::RemoteCodeModeService;

pub const DEFAULT_NAMESPACE: &str = "comms";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slack_team_id: Option<String>,
}

impl AgentIdentity {
    pub fn new(id: impl Into<String>) -> Result<Self, BuildError> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(BuildError::InvalidAgentIdentity(
                "agent id must not be empty".to_string(),
            ));
        }
        Ok(Self {
            id,
            label: None,
            slack_team_id: None,
        })
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn with_slack_team_id(mut self, slack_team_id: impl Into<String>) -> Self {
        self.slack_team_id = Some(slack_team_id.into());
        self
    }

    pub fn storage_scope(&self) -> StoreScope {
        StoreScope(format!("agent:{}", self.id))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreScope(String);

impl StoreScope {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RetentionMode {
    #[default]
    Durable,
    ZeroRetentionEphemeral,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentCodeModeConfig {
    pub namespace: String,
    pub retention: RetentionMode,
    pub connector_instructions: Option<String>,
}

impl Default for AgentCodeModeConfig {
    fn default() -> Self {
        Self {
            namespace: DEFAULT_NAMESPACE.to_string(),
            retention: RetentionMode::Durable,
            connector_instructions: None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BuildError {
    InvalidAgentIdentity(String),
    InvalidNamespace(String),
    ToolCatalog(String),
    ZeroRetentionRequiresEphemeralHost,
    Runtime(String),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAgentIdentity(message) => write!(f, "invalid agent identity: {message}"),
            Self::InvalidNamespace(message) => write!(f, "invalid Code Mode namespace: {message}"),
            Self::ToolCatalog(message) => {
                write!(f, "failed to build Incurs tool catalog: {message}")
            }
            Self::ZeroRetentionRequiresEphemeralHost => write!(
                f,
                "zero-retention Slack search cannot use the durable Code Mode runtime"
            ),
            Self::Runtime(message) => write!(f, "failed to start Code Mode runtime: {message}"),
        }
    }
}

impl std::error::Error for BuildError {}

pub struct AgentCodeModeBuilder {
    identity: AgentIdentity,
    cli: Cli,
    config: AgentCodeModeConfig,
    extra_connectors: Vec<Arc<dyn Connector>>,
}

struct AgentCodeModeParts {
    store: Arc<dyn RuntimeStore>,
    connectors: Vec<Arc<dyn Connector>>,
}

impl AgentCodeModeBuilder {
    pub fn new(identity: AgentIdentity, cli: Cli) -> Self {
        Self {
            identity,
            cli,
            config: AgentCodeModeConfig::default(),
            extra_connectors: Vec::new(),
        }
    }

    pub fn with_config(mut self, config: AgentCodeModeConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.config.namespace = namespace.into();
        self
    }

    pub fn with_connector_instructions(mut self, instructions: impl Into<String>) -> Self {
        self.config.connector_instructions = Some(instructions.into());
        self
    }

    pub fn with_connector(mut self, connector: Arc<dyn Connector>) -> Self {
        self.extra_connectors.push(connector);
        self
    }

    pub fn identity(&self) -> &AgentIdentity {
        &self.identity
    }

    pub fn storage_scope(&self) -> StoreScope {
        self.identity.storage_scope()
    }

    pub fn build_with_executor<E>(
        self,
        store: Arc<dyn RuntimeStore>,
        executor: E,
    ) -> Result<CodeMode, BuildError>
    where
        E: CodeExecutor + 'static,
    {
        let parts = self.into_parts(store)?;
        Ok(CodeMode::new(parts.store, executor, parts.connectors))
    }

    pub fn build_with_clock_and_artifact_store<E, C>(
        self,
        store: Arc<dyn RuntimeStore>,
        artifacts: Arc<dyn ArtifactStore>,
        executor: E,
        clock: C,
    ) -> Result<CodeMode, BuildError>
    where
        E: CodeExecutor + 'static,
        C: Clock + 'static,
    {
        let parts = self.into_parts(store)?;
        Ok(CodeMode::with_clock_and_artifact_store(
            parts.store,
            artifacts,
            executor,
            parts.connectors,
            clock,
        ))
    }

    pub fn build_ephemeral_with_executor<E>(
        self,
        executor: E,
    ) -> Result<EphemeralCodeMode, BuildError>
    where
        E: CodeExecutor + 'static,
    {
        let store: Arc<dyn RuntimeStore> = Arc::new(MemoryStore::default());
        let connectors = self.into_connectors()?;
        Ok(EphemeralCodeMode::new(store, executor, connectors))
    }

    #[cfg(feature = "local")]
    pub fn build_local_service(
        self,
        store: Arc<dyn RuntimeStore>,
        options: incurs_codemode_local::LocalExecutorOptions,
    ) -> Result<incurs_codemode_local::LocalCodeModeService, BuildError> {
        let parts = self.into_parts(store)?;
        incurs_codemode_local::LocalCodeModeService::spawn(move || {
            CodeMode::new(
                parts.store,
                incurs_codemode_local::LocalExecutor::new(options),
                parts.connectors,
            )
        })
        .map_err(BuildError::Runtime)
    }

    fn into_parts(self, store: Arc<dyn RuntimeStore>) -> Result<AgentCodeModeParts, BuildError> {
        if self.config.retention == RetentionMode::ZeroRetentionEphemeral {
            return Err(BuildError::ZeroRetentionRequiresEphemeralHost);
        }
        let connectors = self.into_connectors()?;
        Ok(AgentCodeModeParts { store, connectors })
    }

    fn into_connectors(self) -> Result<Vec<Arc<dyn Connector>>, BuildError> {
        validate_namespace(&self.config.namespace)?;
        let catalog = self
            .cli
            .try_tool_catalog()
            .map_err(|error| BuildError::ToolCatalog(error.to_string()))?;
        let instructions = self
            .config
            .connector_instructions
            .unwrap_or_else(|| default_connector_instructions(&self.identity));
        let connector = IncurConnector::new(catalog)
            .with_name(self.config.namespace)
            .with_instructions(instructions)
            .with_policy_resolver(Arc::new(CommsToolPolicyResolver))
            .with_call_options(incurs::tool::ToolCallOptions::isolated());
        let mut connectors: Vec<Arc<dyn Connector>> = vec![Arc::new(connector)];
        connectors.extend(self.extra_connectors);
        Ok(connectors)
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct CommsToolPolicyResolver;

impl ToolPolicyResolver for CommsToolPolicyResolver {
    fn resolve(&self, origin: ToolOrigin, annotations: &ToolAnnotations) -> ToolPolicy {
        let mut policy = DefaultToolPolicyResolver.resolve(origin, annotations);
        if origin == ToolOrigin::Local {
            policy.requires_approval = false;
            if annotations.read_only == Some(true) && annotations.destructive != Some(true) {
                policy.replay = ReplayPolicy::Reexecute;
            }
        }
        policy
    }
}

pub struct EphemeralCodeMode {
    inner: CodeMode,
    store: Arc<dyn RuntimeStore>,
}

impl EphemeralCodeMode {
    fn new(
        store: Arc<dyn RuntimeStore>,
        executor: impl CodeExecutor + 'static,
        connectors: Vec<Arc<dyn Connector>>,
    ) -> Self {
        Self {
            inner: CodeMode::new(Arc::clone(&store), executor, connectors),
            store,
        }
    }

    pub async fn search(&self, query: &str) -> Result<SearchOutput, String> {
        self.inner.search(query).await
    }

    pub async fn execute(&self, code: &str) -> Result<ExecutionState, String> {
        self.execute_with(code, CodeModeRunOptions::default()).await
    }

    pub async fn execute_with(
        &self,
        code: &str,
        options: CodeModeRunOptions,
    ) -> Result<ExecutionState, String> {
        let state = self.inner.execute_with(code, options).await?;
        let execution_id = state.id.clone();
        let paused = state.status == ExecutionStatus::Paused;
        let snapshot = zero_retention_snapshot(state);
        self.store.delete_execution(&execution_id).await?;
        if paused {
            return Err(
                "zero-retention Code Mode cannot suspend; use durable Code Mode for blocking human questions"
                    .to_string(),
            );
        }
        Ok(snapshot)
    }
}

pub fn zero_retention_snapshot(mut state: ExecutionState) -> ExecutionState {
    state.code.clear();
    state.log.clear();
    state.logs.clear();
    state.capabilities = None;
    state.events.clear();
    state
}

#[cfg(feature = "mcp")]
pub fn mcp_server(
    service: Arc<dyn incurs_codemode::CodeModeService>,
) -> incurs_codemode_mcp::CodeModeMcpServer {
    incurs_codemode_mcp::CodeModeMcpServer::new(service)
        .with_projection(incurs_codemode_mcp::ExecutionProjection::Reduced)
        .with_identity("comms-codemode", env!("CARGO_PKG_VERSION"))
}

#[cfg(feature = "mcp")]
pub async fn serve_mcp_stdio(
    service: Arc<dyn incurs_codemode::CodeModeService>,
) -> Result<(), String> {
    incurs_codemode_mcp::serve_stdio(service).await
}

fn validate_namespace(namespace: &str) -> Result<(), BuildError> {
    if namespace.is_empty() {
        return Err(BuildError::InvalidNamespace(
            "namespace must not be empty".to_string(),
        ));
    }
    if !namespace
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(BuildError::InvalidNamespace(format!(
            "{namespace:?} must contain only ASCII letters, digits, or underscores"
        )));
    }
    Ok(())
}

fn default_connector_instructions(identity: &AgentIdentity) -> String {
    let mut text = format!(
        "Calls run as authenticated comms agent {}. The Code Mode sandbox has no ambient filesystem, process environment, network, or secret access; use this namespace for all Slack and comms actions.",
        identity.id
    );
    if let Some(team) = &identity.slack_team_id {
        text.push_str(&format!(" Slack team: {team}."));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use incurs::command::{
        CommandDef, McpAnnotations, McpCommandOptions, TypedContext, TypedResult,
    };
    use incurs_codemode::{
        CodeModeRunOptions, ConnectorDescription, ExecuteResult, ExecutionHost, ExecutionStatus,
        MemoryStore,
    };
    use serde_json::{Value, json};

    #[derive(Clone, Copy)]
    struct NoopExecutor;

    #[async_trait::async_trait(?Send)]
    impl CodeExecutor for NoopExecutor {
        async fn execute(
            &self,
            _code: &str,
            _connectors: &[ConnectorDescription],
            _execution_id: &str,
            _host: Arc<ExecutionHost>,
        ) -> Result<ExecuteResult, String> {
            Ok(ExecuteResult {
                result: Some(json!(null)),
                error: None,
                logs: Vec::new(),
            })
        }
    }

    #[derive(Clone, Copy)]
    struct LoggingExecutor;

    #[async_trait::async_trait(?Send)]
    impl CodeExecutor for LoggingExecutor {
        async fn execute(
            &self,
            _code: &str,
            _connectors: &[ConnectorDescription],
            _execution_id: &str,
            _host: Arc<ExecutionHost>,
        ) -> Result<ExecuteResult, String> {
            Ok(ExecuteResult {
                result: Some(json!({ "ok": true })),
                error: None,
                logs: vec!["private transcript".to_string()],
            })
        }
    }

    #[derive(Deserialize, Serialize, incurs::Options)]
    struct EchoOptions {
        value: String,
    }

    fn echo_cli() -> Cli {
        let command = CommandDef::typed::<(), EchoOptions, (), Value, _, _>(
            "echo",
            |ctx: TypedContext<(), EchoOptions, ()>| async move {
                TypedResult::ok(json!({ "value": ctx.options.value }))
            },
        )
        .description("Echo a value")
        .mcp(McpCommandOptions {
            annotations: Some(McpAnnotations {
                read_only_hint: Some(true),
                ..McpAnnotations::default()
            }),
            ..McpCommandOptions::default()
        })
        .done();
        Cli::create("slack").command("echo", command)
    }

    #[test]
    fn rejects_zero_retention_on_durable_runtime() {
        let identity = AgentIdentity::new("agent-1").unwrap();
        let config = AgentCodeModeConfig {
            retention: RetentionMode::ZeroRetentionEphemeral,
            ..AgentCodeModeConfig::default()
        };
        let error = match AgentCodeModeBuilder::new(identity, echo_cli())
            .with_config(config)
            .build_with_executor(Arc::new(MemoryStore::default()), NoopExecutor)
        {
            Ok(_) => panic!("zero-retention durable build unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(error, BuildError::ZeroRetentionRequiresEphemeralHost);
    }

    #[test]
    fn reports_agent_storage_scope() {
        let identity = AgentIdentity::new("agent-1").unwrap();
        let builder = AgentCodeModeBuilder::new(identity, echo_cli());
        assert_eq!(builder.storage_scope().as_str(), "agent:agent-1");
    }

    #[tokio::test]
    async fn zero_retention_ephemeral_strips_execution_transcript() {
        let identity = AgentIdentity::new("agent-1").unwrap();
        let config = AgentCodeModeConfig {
            retention: RetentionMode::ZeroRetentionEphemeral,
            ..AgentCodeModeConfig::default()
        };
        let codemode = AgentCodeModeBuilder::new(identity, echo_cli())
            .with_config(config)
            .build_ephemeral_with_executor(LoggingExecutor)
            .unwrap();

        let execution = codemode
            .execute("return 'private slack search';")
            .await
            .unwrap();

        assert_eq!(execution.status, ExecutionStatus::Completed);
        assert_eq!(execution.result, Some(json!({ "ok": true })));
        assert!(execution.code.is_empty());
        assert!(execution.log.is_empty());
        assert!(execution.logs.is_empty());
        assert!(execution.events.is_empty());
        assert!(execution.capabilities.is_none());
    }

    #[cfg(feature = "local")]
    #[tokio::test]
    async fn executes_catalog_tools_in_local_quickjs() {
        let identity = AgentIdentity::new("agent-1")
            .unwrap()
            .with_slack_team_id("T123");
        let codemode = AgentCodeModeBuilder::new(identity, echo_cli())
            .with_namespace("slack")
            .build_with_executor(
                Arc::new(MemoryStore::default()),
                incurs_codemode_local::LocalExecutor::default(),
            )
            .unwrap();

        let execution = codemode
            .execute_with(
                "return await slack.echo({ value: 'hello' });",
                CodeModeRunOptions::default(),
            )
            .await
            .unwrap();

        assert_eq!(execution.status, ExecutionStatus::Completed);
        assert_eq!(execution.result, Some(json!({ "value": "hello" })));
    }

    #[cfg(feature = "local")]
    #[tokio::test]
    async fn human_question_suspends_and_resumes_after_answer_is_stored() {
        let identity = AgentIdentity::new("agent-1").unwrap();
        let answers = Arc::new(MemoryQuestionAnswerStore::default());
        let human = Arc::new(HumanQuestionConnector::new(Arc::clone(&answers)));
        let codemode = AgentCodeModeBuilder::new(identity, echo_cli())
            .with_connector(human)
            .build_with_executor(
                Arc::new(MemoryStore::default()),
                incurs_codemode_local::LocalExecutor::default(),
            )
            .unwrap();

        let execution = codemode
            .execute("const reply = await human.ask({ key: 'deploy', prompt: 'Ship it?' }); return reply.answer;")
            .await
            .unwrap();

        assert_eq!(execution.status, ExecutionStatus::Paused);
        let pending = pending_human_questions(&execution, "human");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].key, "deploy");
        assert_eq!(pending[0].prompt.as_deref(), Some("Ship it?"));

        answers.put_answer(
            &execution.id,
            "deploy",
            QuestionAnswer::new(json!("approved"), Some("doug".to_string()), 123),
        );
        let resumed = codemode
            .approve(&execution.id, pending[0].seq)
            .await
            .unwrap();

        assert_eq!(resumed.status, ExecutionStatus::Completed);
        assert_eq!(resumed.result, Some(json!("approved")));
    }

    #[cfg(feature = "local")]
    #[tokio::test]
    async fn authorized_local_mutations_run_once_across_human_resume() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let command = CommandDef::typed::<(), EchoOptions, (), Value, _, _>(
            "write",
            move |ctx: TypedContext<(), EchoOptions, ()>| {
                let calls = Arc::clone(&observed);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    TypedResult::ok(json!({"value": ctx.options.value}))
                }
            },
        )
        .done();
        let answers = Arc::new(MemoryQuestionAnswerStore::default());
        let codemode = AgentCodeModeBuilder::new(
            AgentIdentity::new("agent").unwrap(),
            Cli::create("comms").command("write", command),
        )
        .with_connector(Arc::new(HumanQuestionConnector::new(Arc::clone(&answers))))
        .build_with_executor(
            Arc::new(MemoryStore::default()),
            incurs_codemode_local::LocalExecutor::default(),
        )
        .unwrap();
        let state = codemode.execute(
            "await comms.write({value:'delivered'}); return await human.ask({key:'continue',prompt:'Continue?'})"
        ).await.unwrap();
        assert_eq!(state.status, ExecutionStatus::Paused);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let pending = pending_human_questions(&state, "human");
        assert_eq!(pending.len(), 1);
        answers.put_answer(
            &state.id,
            "continue",
            QuestionAnswer::new(json!("yes"), Some("owner".into()), 1),
        );
        let resumed = codemode.approve(&state.id, pending[0].seq).await.unwrap();
        assert_eq!(resumed.status, ExecutionStatus::Completed);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "completed mutations must not replay"
        );
    }

    #[cfg(feature = "mcp")]
    #[test]
    fn mcp_server_exposes_five_lifecycle_tools() {
        use incurs_codemode::{ExecutionState, SearchOutput};

        struct EmptyService;

        #[async_trait::async_trait]
        impl incurs_codemode::CodeModeService for EmptyService {
            async fn search(&self, _query: String) -> Result<SearchOutput, String> {
                Err("unused".to_string())
            }

            async fn execute(
                &self,
                _code: String,
                _options: CodeModeRunOptions,
            ) -> Result<ExecutionState, String> {
                Err("unused".to_string())
            }

            async fn execution(&self, _execution_id: String) -> Result<ExecutionState, String> {
                Err("unused".to_string())
            }

            async fn artifact(
                &self,
                _execution_id: String,
                _artifact_id: String,
            ) -> Result<Value, String> {
                Err("unused".to_string())
            }

            async fn approve(
                &self,
                _execution_id: String,
                _seq: u64,
                _options: CodeModeRunOptions,
            ) -> Result<ExecutionState, String> {
                Err("unused".to_string())
            }

            async fn reject(
                &self,
                _execution_id: String,
                _seq: u64,
            ) -> Result<ExecutionState, String> {
                Err("unused".to_string())
            }

            async fn cancel(&self, _execution_id: String) -> Result<ExecutionState, String> {
                Err("unused".to_string())
            }
        }

        let server = mcp_server(Arc::new(EmptyService));
        let names = server
            .tools()
            .iter()
            .map(|tool| tool.name.to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "codemode_search",
                "codemode_execute",
                "codemode_execution",
                "codemode_decide",
                "codemode_cancel"
            ]
        );
    }
}
