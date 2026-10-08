use comms_core::{Backend, cli};
use incurs::cli::Runtime;
use serde_json::{Value, json};
use std::sync::Arc;
struct Echo;
#[async_trait::async_trait]
impl Backend for Echo {
    async fn call(&self, operation: &str, input: Value) -> Result<Value, String> {
        Ok(json!({"operation":operation,"input":input}))
    }
}
#[tokio::test]
async fn sql_preserves_agent_chosen_statement_and_bound_values() {
    let app = cli(Arc::new(Echo));
    let mut output = Vec::new();
    let status = app
        .run_to(
            vec![
                "sql".into(),
                "--sql".into(),
                "CREATE TABLE arbitrary_name (body TEXT)".into(),
                "--params".into(),
                "[\"hello\",null,42]".into(),
                "--format".into(),
                "json".into(),
            ],
            &mut output,
            Runtime::new("comms", Default::default(), false),
        )
        .await
        .unwrap();
    assert_eq!(
        status.unwrap_or(0),
        0,
        "{}",
        String::from_utf8_lossy(&output)
    );
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        value["input"]["sql"],
        "CREATE TABLE arbitrary_name (body TEXT)"
    );
    assert_eq!(value["input"]["params"], json!(["hello", null, 42]));
}

#[tokio::test]
async fn rich_question_cli_preserves_json_blocks_and_choices() {
    let app = cli(Arc::new(Echo));
    let blocks = json!([{"type":"section","text":{"type":"mrkdwn","text":"Ship this?"}}]);
    let choices = json!([{"id":"yes","text":"Ship","value":"yes"}]);
    let mut output = Vec::new();
    let status = app
        .run_to(
            vec![
                "question".into(),
                "create".into(),
                "--text".into(),
                "Ship this?".into(),
                "--blocks".into(),
                blocks.to_string(),
                "--choices".into(),
                choices.to_string(),
                "--idempotency-key".into(),
                "one".into(),
                "--json".into(),
            ],
            &mut output,
            Runtime::new("comms", Default::default(), false),
        )
        .await
        .unwrap();
    assert_eq!(status, None, "{}", String::from_utf8_lossy(&output));
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["operation"], "question_create");
    assert_eq!(value["input"]["blocks"], blocks);
    assert_eq!(value["input"]["choices"], choices);
}

#[tokio::test]
async fn linear_query_preserves_variables_and_selected_fields() {
    let app = cli(Arc::new(Echo));
    let mut output = Vec::new();
    let query = "query($id:String!){ issue(id:$id){id title parent{id} children{nodes{id}}} }";
    let status = app
        .run_to(
            vec![
                "linear".into(),
                "query".into(),
                "--query".into(),
                query.into(),
                "--variables".into(),
                r#"{"id":"LAN-2"}"#.into(),
                "--json".into(),
            ],
            &mut output,
            Runtime::new("comms", Default::default(), false),
        )
        .await
        .unwrap();
    assert_eq!(status, None, "{}", String::from_utf8_lossy(&output));
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["operation"], "linear_query");
    assert_eq!(value["input"]["query"], query);
    assert_eq!(value["input"]["variables"], json!({"id":"LAN-2"}));
}
