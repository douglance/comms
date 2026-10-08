use comms_slack_api::validate_blocks_value;
use comms_slack_api::{Coverage, Invocation, Registry};
use serde_json::{Value, json};
use std::sync::Arc;
struct Echo;
#[async_trait::async_trait]
impl Invocation for Echo {
    async fn invoke(&self, method: &str, params: Value) -> Result<Value, String> {
        Ok(json!({"method": method, "params": params}))
    }
}
#[test]
fn embedded_registry_contains_schema_backed_slack_methods() {
    let registry = Registry::embedded().expect("embedded catalog loads");
    assert!(
        registry.methods().len() >= 170,
        "method count {}",
        registry.methods().len()
    );
    let post = registry
        .get("chat.postMessage")
        .expect("chat.postMessage exists");
    assert_eq!(post.coverage, Coverage::SdkSchema);
    assert!(post.docs_url.contains("chat.postMessage"));
    assert!(
        post.input_schema
            .get("properties")
            .and_then(|v| v.get("channel"))
            .is_some()
    );
}
#[test]
fn unresolved_methods_are_explicit_and_inspectable() {
    let registry = Registry::embedded().expect("embedded catalog loads");
    assert_eq!(
        registry.coverage().method_count,
        registry.coverage().schema_methods + registry.coverage().docs_only_methods
    );
    assert_eq!(
        registry.coverage().docs_only_methods,
        registry.coverage().unresolved.len()
    );
    for name in &registry.coverage().unresolved {
        assert_eq!(
            registry
                .get(name)
                .expect("unresolved method exists")
                .coverage,
            Coverage::DocsOnly
        );
    }
}
#[test]
fn search_is_bounded_and_source_linked() {
    let registry = Registry::embedded().expect("embedded catalog loads");
    let hits = registry.search("post message", 5, 64);
    assert!(!hits.is_empty());
    assert!(hits.iter().all(|h| h.summary.len() <= 64));
    assert!(hits.iter().any(|h| h.url.contains("slack.dev")));
}
#[tokio::test]
async fn cli_group_builds_with_invoker() {
    let _cli = comms_slack_api::cli(Arc::new(Echo));
}

#[test]
fn block_kit_validation_rejects_bad_shapes() {
    assert!(validate_blocks_value(&serde_json::json!([{ "type": "section" }])).is_ok());
    assert!(validate_blocks_value(&serde_json::json!("bad")).is_err());
    assert!(validate_blocks_value(&serde_json::json!([{}])).is_err());
}

#[test]
fn no_method_name_has_markdown_suffix() {
    let registry = Registry::embedded().expect("embedded catalog loads");
    let bad: Vec<_> = registry
        .methods()
        .iter()
        .filter(|method| method.name.ends_with(".md"))
        .map(|method| method.name.as_str())
        .collect();
    assert!(
        bad.is_empty(),
        "method names must not include markdown suffixes: {bad:?}"
    );
}

#[tokio::test]
async fn native_cli_decodes_json_params_before_invocation() {
    let cli = comms_slack_api::cli(Arc::new(Echo));
    let mut output = Vec::new();
    let status = cli
        .run_to(
            vec![
                "invoke".into(),
                "--method".into(),
                "chat.postMessage".into(),
                "--params".into(),
                r#"{"channel":"C123","text":"hello"}"#.into(),
                "--json".into(),
            ],
            &mut output,
            incurs::cli::Runtime::new("slack", std::collections::HashMap::new(), false),
        )
        .await
        .unwrap();
    assert_eq!(status, None, "{}", String::from_utf8_lossy(&output));
    let result: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["method"], "chat.postMessage");
    assert_eq!(result["params"], json!({"channel":"C123","text":"hello"}));
}

#[tokio::test]
async fn rest_methods_are_discoverable_and_invokable_through_native_cli() {
    let registry = Registry::embedded().unwrap();
    assert_eq!(
        registry
            .methods()
            .iter()
            .filter(|m| m.name.starts_with("scim."))
            .count(),
        32
    );
    assert_eq!(
        registry
            .methods()
            .iter()
            .filter(|m| m.name.starts_with("audit."))
            .count(),
        3
    );
    assert_eq!(registry.methods().len(), registry.coverage().method_count);
    let names: std::collections::HashSet<_> = registry.methods().iter().map(|m| &m.name).collect();
    assert_eq!(names.len(), registry.methods().len());
    let cli = comms_slack_api::cli(Arc::new(Echo));
    let mut output = Vec::new();
    let status = cli
        .run_to(
            vec![
                "invoke".into(),
                "--method".into(),
                "scim.v2.users.update".into(),
                "--params".into(),
                r#"{"id":"U_OTHER","body":{"active":true}}"#.into(),
                "--json".into(),
            ],
            &mut output,
            incurs::cli::Runtime::new("slack", std::collections::HashMap::new(), false),
        )
        .await
        .unwrap();
    assert_eq!(status, None, "{}", String::from_utf8_lossy(&output));
    let result: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["method"], "scim.v2.users.update");
    assert_eq!(
        result["params"],
        json!({"id":"U_OTHER","body":{"active":true}})
    );
}

#[test]
fn legacy_schema_records_are_attributed_to_openapi() {
    assert_eq!(
        serde_json::from_str::<Coverage>(r#""schema""#).unwrap(),
        Coverage::OpenapiSchema
    );
    let registry = Registry::embedded().unwrap();
    let sdk = registry
        .methods()
        .iter()
        .filter(|m| m.coverage == Coverage::SdkSchema)
        .count();
    let openapi = registry
        .methods()
        .iter()
        .filter(|m| m.coverage == Coverage::OpenapiSchema)
        .count();
    assert_eq!(sdk, registry.coverage().sdk_schema_methods);
    assert_eq!(openapi, registry.coverage().openapi_schema_methods);
}

#[tokio::test]
async fn legal_hold_and_status_methods_are_available_through_incurs() {
    let registry = Registry::embedded().unwrap();
    assert_eq!(
        registry
            .methods()
            .iter()
            .filter(|m| m.name.starts_with("admin.legalHold."))
            .count(),
        9
    );
    for (method, params) in [
        ("status.current", json!({})),
        ("status.history", json!({})),
        (
            "admin.legalHold.entities.add",
            json!({"policy_id":"H123","entities":[{"entity_type":"USER","entity_id":"U_OTHER"}]}),
        ),
    ] {
        let cli = comms_slack_api::cli(Arc::new(Echo));
        let mut output = Vec::new();
        let status = cli
            .run_to(
                vec![
                    "invoke".into(),
                    "--method".into(),
                    method.into(),
                    "--params".into(),
                    params.to_string(),
                    "--json".into(),
                ],
                &mut output,
                incurs::cli::Runtime::new("slack", std::collections::HashMap::new(), false),
            )
            .await
            .unwrap();
        assert_eq!(status, None, "{}", String::from_utf8_lossy(&output));
        let result: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(result["method"], method);
        assert_eq!(result["params"], params);
    }
}

#[tokio::test]
async fn upload_command_delegates_blob_references_and_decodes_completion_params() {
    let cli = comms_slack_api::cli(Arc::new(Echo));
    let mut output = Vec::new();
    let status = cli
        .run_to(
            vec![
                "upload".into(),
                "--blob-id".into(),
                "blb_test".into(),
                "--filename".into(),
                "report.bin".into(),
                "--idempotency-key".into(),
                "upload-test".into(),
                "--complete-params".into(),
                r#"{"channel_id":"C123","initial_comment":"Report"}"#.into(),
                "--json".into(),
            ],
            &mut output,
            incurs::cli::Runtime::new("slack", std::collections::HashMap::new(), false),
        )
        .await
        .unwrap();
    assert_eq!(status, None, "{}", String::from_utf8_lossy(&output));
    let result: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["method"], "files.uploadExternal");
    assert_eq!(result["params"]["blob_id"], "blb_test");
    assert_eq!(
        result["params"]["complete_params"],
        json!({"channel_id":"C123","initial_comment":"Report"})
    );
}

#[tokio::test]
async fn session_commands_preserve_custom_identity_and_rich_blocks() {
    let cli = comms_slack_api::cli(Arc::new(Echo));
    for (args, method) in [
        (
            vec![
                "session",
                "start",
                "--session-id",
                "research",
                "--name",
                "Ada",
                "--icon-emoji",
                ":microscope:",
            ],
            "comms.sessions.start",
        ),
        (
            vec![
                "session",
                "send",
                "--session-id",
                "research",
                "--blocks",
                r#"[{"type":"section","text":{"type":"mrkdwn","text":"*Report*"}}]"#,
                "--idempotency-key",
                "report",
            ],
            "comms.sessions.send",
        ),
        (
            vec![
                "session",
                "status",
                "--session-id",
                "research",
                "--status",
                "suspended",
                "--idempotency-key",
                "waiting",
            ],
            "comms.sessions.status",
        ),
    ] {
        let mut output = Vec::new();
        let mut args: Vec<String> = args.into_iter().map(str::to_owned).collect();
        args.push("--json".into());
        let status = cli
            .run_to(
                args,
                &mut output,
                incurs::cli::Runtime::new("slack", std::collections::HashMap::new(), false),
            )
            .await
            .unwrap();
        assert_eq!(status, None, "{}", String::from_utf8_lossy(&output));
        let result: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(result["method"], method);
        assert_eq!(result["params"]["session_id"], "research");
        if method.ends_with("start") {
            assert_eq!(result["params"]["name"], "Ada");
            assert_eq!(result["params"]["icon_emoji"], ":microscope:");
        }
        if method.ends_with("send") {
            assert!(result["params"]["blocks"].is_array());
        }
    }
}
