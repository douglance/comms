use comms_linear::*;
use serde_json::json;

#[test]
fn hosted_endpoints_are_stable() {
    assert_eq!(
        endpoints("https://comms.example").unwrap(),
        (
            "https://comms.example/linear/oauth/callback".into(),
            "https://comms.example/linear/events".into()
        )
    );
    for origin in [
        "http://localhost:8769",
        "https://user@comms.example",
        "https://comms.example/path",
        "https://comms.example?next=evil",
    ] {
        assert!(endpoints(origin).is_err(), "{origin}");
    }
}
#[test]
fn credentials_are_bound_to_one_agent() {
    let key = [17; 32];
    let value = json!({"client_secret":"private", "client_id":"app"});
    let sealed = seal(&key, &[3; 12], "agent-ceo", &value).unwrap();
    assert!(!sealed.contains("private"));
    assert_eq!(unseal(&key, "agent-ceo", &sealed).unwrap(), value);
    assert!(unseal(&key, "agent-cto", &sealed).is_err());
    assert!(unseal(&[18; 32], "agent-ceo", &sealed).is_err());
    let mut tampered: serde_json::Value = serde_json::from_str(&sealed).unwrap();
    tampered["data"] = json!("corrupted");
    assert!(unseal(&key, "agent-ceo", &tampered.to_string()).is_err());
}
#[test]
fn app_identity_must_match_role_and_workspace() {
    let provider = json!({"data":{"viewer":{"id":"app-ceo","name":"CEO"},"organization":{"id":"org-example","urlKey":"example-workspace"}}});
    let identity = verify_identity(&provider, "CEO", "example-workspace").unwrap();
    assert_eq!(identity["app_user_id"], "app-ceo");
    assert!(verify_identity(&provider, "CTO", "example-workspace").is_err());
    assert!(verify_identity(&provider, "CEO", "other-workspace").is_err());
    assert!(
        verify_identity(
            &json!({"errors":[{"message":"denied"}]}),
            "CEO",
            "example-workspace"
        )
        .is_err()
    );
}
#[test]
fn webhook_rejects_missing_signature() {
    assert!(verify_webhook(b"secret", "", b"{}", 1, "org").is_err());
}
#[test]
fn webhook_accepts_independently_signed_payload() {
    // Expected digest is produced by Python hashlib, independently of this implementation.
    let body = br#"{"organizationId":"org-example","webhookTimestamp":1000000,"type":"AgentSessionEvent","action":"created"}"#;
    let signature = "b7614f669dd05a787f3c76b4a302494b0524d4970d103eb0d284071fa9b6b3ef";
    assert!(verify_webhook(b"fixture-secret", signature, body, 1000000, "org-example").is_ok());
    assert!(verify_webhook(b"wrong-secret", signature, body, 1000000, "org-example").is_err());
    assert!(verify_webhook(b"fixture-secret", signature, body, 1000000, "other-org").is_err());
    assert!(verify_webhook(b"fixture-secret", signature, body, 1060001, "org-example").is_err());
    assert!(verify_webhook(b"fixture-secret", signature, body, 994999, "org-example").is_err());
    let changed = br#"{"organizationId":"org-example","webhookTimestamp":1000000,"type":"AgentSessionEvent","action":"prompted"}"#;
    assert!(
        verify_webhook(
            b"fixture-secret",
            signature,
            changed,
            1000000,
            "org-example"
        )
        .is_err()
    );
}

#[test]
fn retried_events_share_a_key_when_delivery_timestamp_changes() {
    let original = json!({"organizationId":"org","webhookTimestamp":100,"createdAt":"first","data":{"id":"issue"}});
    let retry = json!({"organizationId":"org","webhookTimestamp":200,"createdAt":"first","data":{"id":"issue"}});
    let later = json!({"organizationId":"org","webhookTimestamp":200,"createdAt":"second","data":{"id":"issue"}});
    assert_eq!(event_key(&original).unwrap(), event_key(&retry).unwrap());
    assert_ne!(event_key(&original).unwrap(), event_key(&later).unwrap());
}

fn run_ready<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("fixture unexpectedly suspended"),
    }
}

#[test]
fn temporary_tokens_are_revoked_after_success_and_provider_failure() {
    use std::{cell::RefCell, rc::Rc};
    for result in [Ok("provider result"), Err("provider failed")] {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let operation_calls = calls.clone();
        let revoke_calls = calls.clone();
        let (actual, cleanup) = run_ready(use_and_revoke(
            "fixture token".into(),
            move |token| async move {
                operation_calls.borrow_mut().push(format!("query:{token}"));
                result
            },
            move |token| async move {
                revoke_calls.borrow_mut().push(format!("revoke:{token}"));
                Ok(())
            },
        ));
        assert_eq!(actual, result);
        assert_eq!(cleanup, Ok(()));
        assert_eq!(
            *calls.borrow(),
            ["query:fixture token", "revoke:fixture token"]
        );
    }
}

#[test]
fn token_cleanup_failure_does_not_hide_a_completed_operation() {
    let (result, cleanup) = run_ready(use_and_revoke(
        "fixture token".into(),
        |_| async { Ok::<_, &str>("committed mutation") },
        |_| async { Err("revoke failed") },
    ));
    assert_eq!(result, Ok("committed mutation"));
    assert_eq!(cleanup, Err("revoke failed"));
}
