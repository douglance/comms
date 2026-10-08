use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use comms_core::Backend;
use incurs::cli::Runtime;
use serde_json::{Value, json};

#[derive(Default)]
struct Capture(Mutex<Vec<Value>>);

#[async_trait::async_trait]
impl Backend for Capture {
    async fn call(&self, operation: &str, input: Value) -> Result<Value, String> {
        assert_eq!(operation, "question_create");
        self.0.lock().unwrap().push(input);
        Ok(json!({"question":{"id":"fixture"}}))
    }
}

#[tokio::test]
async fn no_deadline_disables_question_timeout() {
    for (flags, expected) in [
        (vec![], false),
        (vec!["--no-deadline"], true),
        (vec!["--deadline", "false"], true),
        (vec!["--deadline", "true"], false),
    ] {
        let backend = Arc::new(Capture::default());
        let cli = comms_core::cli(backend.clone());
        let mut argv = vec![
            "question",
            "create",
            "--text",
            "Continue?",
            "--idempotency-key",
            "fixture",
            "--format",
            "json",
        ];
        argv.extend(flags);
        let mut output = Vec::new();
        let status = cli
            .run_to(
                argv.into_iter().map(String::from).collect(),
                &mut output,
                Runtime::new("comms", HashMap::new(), false),
            )
            .await
            .unwrap();
        assert_eq!(status, None, "{}", String::from_utf8_lossy(&output));
        let calls = backend.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["no_deadline"].as_bool().unwrap_or(false), expected);
        assert!(calls[0].get("deadline").is_none());
    }
}
