use async_trait::async_trait;
use comms_slack_api::Registry;
use comms_slack_runtime::*;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct Creds;

#[async_trait(?Send)]
impl CredentialProvider for Creds {
    async fn credential(&self, token_class: TokenClass) -> Result<Credential, RuntimeError> {
        Ok(Credential {
            workspace_id: "T123".into(),
            token_class,
            token: SlackSecret::new(format!("xox-{token_class:?}")),
        })
    }
}

#[derive(Clone, Default)]
struct Transport {
    seen: Arc<Mutex<Vec<TransportRequest>>>,
    response: Option<TransportResponse>,
}

#[async_trait(?Send)]
impl SlackTransport for Transport {
    async fn send(&self, request: TransportRequest) -> Result<TransportResponse, TransportError> {
        self.seen.lock().unwrap().push(request);
        Ok(self.response.clone().unwrap_or(TransportResponse {
            status: 200,
            headers: BTreeMap::new(),
            body: json!({"ok": true, "ts": "1.2"}),
        }))
    }
}

fn runtime(transport: Transport) -> SlackRuntime<Creds, Transport> {
    SlackRuntime::new(
        Registry::embedded().expect("embedded Slack catalog loads"),
        Creds,
        transport,
        InvocationPolicy {
            workspace_id: "T123".into(),
            owner_user_id: "UOWNER".into(),
            allow_admin: true,
        },
    )
}

#[tokio::test]
async fn invokes_with_injected_auth_and_preserves_slack_ok_false() {
    let transport = Transport {
        seen: Arc::new(Mutex::new(Vec::new())),
        response: Some(TransportResponse {
            status: 200,
            headers: BTreeMap::new(),
            body: json!({"ok": false, "error": "missing_scope"}),
        }),
    };
    let result = runtime(transport.clone())
        .invoke(Invocation {
            agent_id: "agent".into(),
            method: "chat.postMessage".into(),
            arguments: json!({"channel":"C1","text":"hi"}),
            idempotency_key: Some("one".into()),
        })
        .await
        .unwrap();
    assert!(!result.ok);
    assert_eq!(result.body["error"], "missing_scope");
    let seen = transport.seen.lock().unwrap();
    assert_eq!(seen[0].url, "https://slack.com/api/chat.postMessage");
    assert!(seen[0].authorization.starts_with("Bearer xox-"));
    assert!(!String::from_utf8_lossy(&seen[0].body).contains("xox-"));
}

#[tokio::test]
async fn rejects_caller_supplied_authority_and_owner_removal() {
    let err = runtime(Transport::default())
        .invoke(Invocation {
            agent_id: "agent".into(),
            method: "chat.postMessage".into(),
            arguments: json!({"channel":"C1","text":"hi","token":"steal"}),
            idempotency_key: None,
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("caller-supplied authority"));

    let err = runtime(Transport::default())
        .invoke(Invocation {
            agent_id: "agent".into(),
            method: "admin.apps.mcp.servers.permissions.set".into(),
            arguments: json!({"users":["UOWNER"]}),
            idempotency_key: None,
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("owner access"));
}

#[tokio::test]
async fn validates_catalog_input_schema_before_transport() {
    let transport = Transport::default();
    let err = runtime(transport.clone())
        .invoke(Invocation {
            agent_id: "agent".into(),
            method: "conversations.create".into(),
            arguments: json!({"is_private": true}),
            idempotency_key: None,
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("missing required argument `name`"));
    assert!(transport.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn denies_unclassified_admin_methods() {
    let err = runtime(Transport::default())
        .invoke(Invocation {
            agent_id: "agent".into(),
            method: "admin.users.remove".into(),
            arguments: json!({"user_id":"U123"}),
            idempotency_key: None,
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, RuntimeError::UnknownMethod(_)) || err.to_string().contains("not classified")
    );
}

#[test]
fn delivery_idempotency_and_retry_after_are_durable() {
    let store = MemoryDeliveryStore::default();
    let first = enqueue_delivery(
        &store,
        "T123",
        "k1",
        "chat.postMessage",
        json!({"text":"a"}),
        10,
    )
    .unwrap();
    let replay = enqueue_delivery(
        &store,
        "T123",
        "k1",
        "chat.postMessage",
        json!({"text":"a"}),
        10,
    )
    .unwrap();
    assert_eq!(first, replay);
    assert_eq!(
        enqueue_delivery(
            &store,
            "T123",
            "k1",
            "chat.postMessage",
            json!({"text":"b"}),
            10
        )
        .unwrap_err(),
        DeliveryError::IdempotencyConflict
    );

    let mut record = store.next_ready("T123", 10).unwrap().unwrap();
    mark_delivery_result(
        &mut record,
        &InvocationResult {
            ok: false,
            method: "chat.postMessage".into(),
            token_class: TokenClass::Bot,
            status: 429,
            body: json!({"ok":false,"error":"rate_limited"}),
            retry_after_ms: Some(2000),
            ambiguous_write: false,
        },
        10,
    );
    assert_eq!(record.state, DeliveryState::Pending);
    assert_eq!(record.next_attempt_at_ms, 2010);
}

#[test]
fn private_channel_create_yields_owner_invite_followup() {
    let followup = private_channel_owner_invite(
        "conversations.create",
        &json!({"name":"agent-room","is_private":true}),
        "UOWNER",
    )
    .unwrap();
    assert_eq!(followup["method"], "conversations.invite");
    assert_eq!(followup["arguments"]["users"], "UOWNER");
}

#[test]
fn redaction_removes_tokens_from_error_metadata() {
    let redacted = redacted_error(
        &json!({"error":"bad_auth","token":"xox-secret","nested":{"authorization":"Bearer x"}}),
    );
    assert_eq!(redacted["token"], "REDACTED");
    assert_eq!(redacted["nested"]["authorization"], "REDACTED");
}

struct BotOnly;
#[async_trait(?Send)]
impl CredentialProvider for BotOnly {
    async fn credential(&self, class: TokenClass) -> Result<Credential, RuntimeError> {
        if class != TokenClass::Bot {
            return Err(RuntimeError::MissingCredential(class));
        }
        Creds.credential(class).await
    }
}
#[tokio::test]
async fn bot_grants_read_bot_channels_without_owner_credentials() {
    let transport = Transport::default();
    let runtime = SlackRuntime::new(
        Registry::embedded().unwrap(),
        BotOnly,
        transport.clone(),
        InvocationPolicy {
            workspace_id: "T123".into(),
            owner_user_id: "UOWNER".into(),
            allow_admin: true,
        },
    );
    let result = runtime
        .invoke(Invocation {
            agent_id: "agent".into(),
            method: "conversations.members".into(),
            arguments: json!({"channel":"C123"}),
            idempotency_key: None,
        })
        .await
        .unwrap();
    assert_eq!(result.token_class, TokenClass::Bot);
    assert_eq!(transport.seen.lock().unwrap().len(), 1);
    let error = runtime
        .invoke(Invocation {
            agent_id: "agent".into(),
            method: "assistant.search.context".into(),
            arguments: json!({"query":"private owner content"}),
            idempotency_key: None,
        })
        .await
        .unwrap_err();
    assert_eq!(error, RuntimeError::MissingCredential(TokenClass::User));
    assert_eq!(transport.seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn get_requests_encode_query_parameters_instead_of_json() {
    let transport = Transport::default();
    runtime(transport.clone())
        .invoke(Invocation {
            agent_id: "agent".into(),
            method: "conversations.members".into(),
            arguments: json!({"channel":"C+123","cursor":"a=b c","limit":20}),
            idempotency_key: None,
        })
        .await
        .unwrap();
    let seen = transport.seen.lock().unwrap();
    assert_eq!(seen[0].http_method, "GET");
    assert_eq!(seen[0].content_type, "application/x-www-form-urlencoded");
    assert_eq!(
        String::from_utf8(seen[0].body.clone()).unwrap(),
        "channel=C%2B123&cursor=a%3Db+c&limit=20"
    );
}

#[tokio::test]
async fn rejects_workspace_override_before_transport() {
    let transport = Transport::default();
    let error = runtime(transport.clone())
        .invoke(Invocation {
            agent_id: "agent".into(),
            method: "conversations.list".into(),
            arguments: json!({"team_id":"T_OTHER"}),
            idempotency_key: None,
        })
        .await
        .unwrap_err();
    assert_eq!(
        error,
        RuntimeError::WorkspaceMismatch {
            expected: "T123".into(),
            actual: "T_OTHER".into()
        }
    );
    assert!(transport.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn scim_and_audit_use_rest_routes_and_preserve_json_bodies() {
    let transport = Transport::default();
    let runtime = runtime(transport.clone());
    for version in ["v1", "v2"] {
        runtime.invoke(Invocation {
            agent_id: "agent".into(),
            method: format!("scim.{version}.users.update"),
            arguments: json!({"id":"UOTHER","body":{"active":true,"emails":[{"value":"other@example.com"}]}}),
            idempotency_key: None,
        }).await.unwrap();
    }
    runtime
        .invoke(Invocation {
            agent_id: "agent".into(),
            method: "audit.logs.list".into(),
            arguments: json!({"action":"user_login","limit":10,"cursor":"a=b c"}),
            idempotency_key: None,
        })
        .await
        .unwrap();
    let seen = transport.seen.lock().unwrap();
    assert_eq!(seen[0].url, "https://api.slack.com/scim/v1/Users/UOTHER");
    assert_eq!(seen[1].url, "https://api.slack.com/scim/v2/Users/UOTHER");
    assert_eq!(seen[0].http_method, "PATCH");
    assert_eq!(seen[0].token_class, TokenClass::Scim);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&seen[0].body).unwrap(),
        json!({"active":true,"emails":[{"value":"other@example.com"}]})
    );
    assert_eq!(seen[2].url, "https://api.slack.com/audit/v1/logs");
    assert_eq!(seen[2].http_method, "GET");
    assert_eq!(seen[2].token_class, TokenClass::Audit);
    let encoded = String::from_utf8(seen[2].body.clone()).unwrap();
    let mut pairs: Vec<_> = encoded.split('&').collect();
    pairs.sort_unstable();
    assert_eq!(pairs, ["action=user_login", "cursor=a%3Db+c", "limit=10"]);
}

#[tokio::test]
async fn scim_owner_mutations_and_path_injection_never_reach_transport() {
    let transport = Transport::default();
    let runtime = runtime(transport.clone());
    for (method, params) in [
        ("scim.v1.users.delete", json!({"id":"UOWNER"})),
        (
            "scim.v2.users.update",
            json!({"id":"UOWNER","body":{"active":false}}),
        ),
        (
            "scim.v2.users.replace",
            json!({"id":"UOWNER","body":{"userName":"changed"}}),
        ),
        (
            "scim.v2.users.get",
            json!({"id":"../Users/UOWNER?token=steal"}),
        ),
    ] {
        assert!(
            runtime
                .invoke(Invocation {
                    agent_id: "agent".into(),
                    method: method.into(),
                    arguments: params,
                    idempotency_key: None
                })
                .await
                .is_err(),
            "{method}"
        );
    }
    assert!(transport.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn public_audit_metadata_needs_no_slack_credential() {
    let transport = Transport::default();
    let runtime = SlackRuntime::new(
        Registry::embedded().unwrap(),
        BotOnly,
        transport.clone(),
        InvocationPolicy {
            workspace_id: "T123".into(),
            owner_user_id: "UOWNER".into(),
            allow_admin: false,
        },
    );
    for name in ["audit.actions.list", "audit.schemas.list"] {
        assert!(
            runtime
                .invoke(Invocation {
                    agent_id: "agent".into(),
                    method: name.into(),
                    arguments: json!({}),
                    idempotency_key: None
                })
                .await
                .unwrap()
                .ok
        );
    }
    assert!(
        transport
            .seen
            .lock()
            .unwrap()
            .iter()
            .all(|r| r.authorization.is_empty())
    );
    assert_eq!(
        runtime
            .invoke(Invocation {
                agent_id: "agent".into(),
                method: "audit.logs.list".into(),
                arguments: json!({}),
                idempotency_key: None
            })
            .await
            .unwrap_err(),
        RuntimeError::MissingCredential(TokenClass::Audit)
    );
}

#[tokio::test]
async fn app_level_methods_use_app_credentials_not_bot_credentials() {
    let transport = Transport::default();
    let runtime = runtime(transport.clone());
    for (method, arguments) in [
        ("apps.connections.open", json!({})),
        (
            "apps.event.authorizations.list",
            json!({"event_context":"EC123"}),
        ),
    ] {
        let result = runtime
            .invoke(Invocation {
                agent_id: "agent".into(),
                method: method.into(),
                arguments,
                idempotency_key: None,
            })
            .await
            .unwrap();
        assert_eq!(result.token_class.as_str(), "app");
    }
    let seen = transport.seen.lock().unwrap();
    assert!(seen.iter().all(|r| r.authorization == "Bearer xox-App"));
    assert!(
        seen.iter()
            .all(|r| !String::from_utf8_lossy(&r.body).contains("xox-App"))
    );
}

#[tokio::test]
async fn admin_read_methods_allow_owner_filters_without_enabling_owner_mutations() {
    let registry = Registry::embedded().unwrap();
    let policy = InvocationPolicy {
        workspace_id: "T123".into(),
        owner_user_id: "UOWNER".into(),
        allow_admin: true,
    };
    for method in [
        "admin.roles.listAssignments",
        "admin.auth.policy.getEntities",
        "admin.conversations.getTeams",
        "admin.users.list",
    ] {
        assert_eq!(
            policy
                .authorize(registry.get(method).unwrap(), &json!({"user_id":"UOWNER"}))
                .unwrap(),
            TokenClass::Admin
        );
    }
    assert!(
        policy
            .authorize(
                registry.get("admin.users.remove").unwrap(),
                &json!({"user_id":"UOWNER"})
            )
            .is_err()
    );
    let locked = InvocationPolicy {
        allow_admin: false,
        ..policy
    };
    assert!(
        locked
            .authorize(registry.get("admin.users.list").unwrap(), &json!({}))
            .is_err()
    );
}

#[tokio::test]
async fn api_test_is_public_and_missing_app_tokens_fail_explicitly() {
    let transport = Transport::default();
    let runtime = SlackRuntime::new(
        Registry::embedded().unwrap(),
        BotOnly,
        transport.clone(),
        InvocationPolicy {
            workspace_id: "T123".into(),
            owner_user_id: "UOWNER".into(),
            allow_admin: true,
        },
    );
    assert!(
        runtime
            .invoke(Invocation {
                agent_id: "agent".into(),
                method: "api.test".into(),
                arguments: json!({}),
                idempotency_key: None
            })
            .await
            .unwrap()
            .ok
    );
    assert!(transport.seen.lock().unwrap()[0].authorization.is_empty());
    let error = runtime
        .invoke(Invocation {
            agent_id: "agent".into(),
            method: "apps.connections.open".into(),
            arguments: json!({}),
            idempotency_key: None,
        })
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("missing app Slack credential"),
        "{error}"
    );
    assert_eq!(transport.seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn status_endpoints_are_public_and_use_the_status_origin() {
    let transport = Transport::default();
    let runtime = SlackRuntime::new(
        Registry::embedded().unwrap(),
        BotOnly,
        transport.clone(),
        InvocationPolicy {
            workspace_id: "T123".into(),
            owner_user_id: "UOWNER".into(),
            allow_admin: true,
        },
    );
    for (method, path) in [("status.current", "current"), ("status.history", "history")] {
        let result = runtime
            .invoke(Invocation {
                agent_id: "agent".into(),
                method: method.into(),
                arguments: json!({}),
                idempotency_key: None,
            })
            .await
            .unwrap();
        assert_eq!(result.token_class, TokenClass::Public);
        let seen = transport.seen.lock().unwrap();
        let request = seen.last().unwrap();
        assert_eq!(
            request.url,
            format!("https://slack-status.com/api/v2.0.0/{path}")
        );
        assert_eq!(request.http_method, "GET");
        assert!(request.authorization.is_empty());
        assert!(request.body.is_empty());
        assert_eq!(
            comms_slack_runtime::fixture_route_suffix(&request.url),
            Some(format!("status/v2.0.0/{path}"))
        );
    }
    assert_eq!(
        comms_slack_runtime::fixture_route_suffix(
            "https://slack-status.com.evil/api/v2.0.0/current"
        ),
        None
    );
}

#[tokio::test]
async fn legal_hold_methods_use_admin_credentials_and_form_encoding() {
    let transport = Transport::default();
    let runtime = SlackRuntime::new(
        Registry::embedded().unwrap(),
        Creds,
        transport.clone(),
        InvocationPolicy {
            workspace_id: "T123".into(),
            owner_user_id: "UOWNER".into(),
            allow_admin: true,
        },
    );
    let cases = [
        ("policies.activate", json!({"policy_id":"H123"})),
        (
            "policies.create",
            json!({"name":"Case A","restrictions":["ONLY_DMS"]}),
        ),
        ("policies.info", json!({"policy_id":"H123"})),
        ("policies.list", json!({"limit":10})),
        ("policies.release", json!({"policy_id":"H123"})),
        (
            "policies.set",
            json!({"policy_id":"H123","description":"Updated"}),
        ),
        (
            "entities.add",
            json!({"policy_id":"H123","entities":[{"entity_type":"USER","entity_id":"U_OTHER"}]}),
        ),
        (
            "entities.list",
            json!({"policy_id":"H123","include_deleted":true}),
        ),
        (
            "entities.remove",
            json!({"policy_id":"H123","ids":["He123"]}),
        ),
    ];
    for (suffix, arguments) in cases {
        let method = format!("admin.legalHold.{suffix}");
        let result = runtime
            .invoke(Invocation {
                agent_id: "agent".into(),
                method: method.clone(),
                arguments,
                idempotency_key: None,
            })
            .await
            .unwrap();
        assert_eq!(result.token_class, TokenClass::Admin);
        let seen = transport.seen.lock().unwrap();
        let request = seen.last().unwrap();
        assert_eq!(request.url, format!("https://slack.com/api/{method}"));
        assert_eq!(request.http_method, "POST");
        assert_eq!(request.authorization, "Bearer xox-Admin");
        assert_eq!(request.content_type, "application/x-www-form-urlencoded");
        let body = String::from_utf8(request.body.clone()).unwrap();
        assert!(!body.contains("xox-"));
        if suffix == "entities.add" {
            let fields: std::collections::HashMap<_, _> = body
                .split('&')
                .map(|pair| pair.split_once('=').unwrap())
                .collect();
            assert_eq!(fields["policy_id"], "H123");
            let encoded = fields["entities"].as_bytes();
            let mut decoded = Vec::new();
            let mut i = 0;
            while i < encoded.len() {
                if encoded[i] == b'%' {
                    decoded.push(
                        u8::from_str_radix(
                            std::str::from_utf8(&encoded[i + 1..i + 3]).unwrap(),
                            16,
                        )
                        .unwrap(),
                    );
                    i += 3;
                } else {
                    decoded.push(encoded[i]);
                    i += 1;
                }
            }
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&decoded).unwrap(),
                json!([{"entity_type":"USER","entity_id":"U_OTHER"}])
            );
        }
    }
}

#[tokio::test]
async fn complete_upload_accepts_nonempty_file_arrays_and_rejects_mistyped_items() {
    let transport = Transport::default();
    let runtime = runtime(transport.clone());
    for arguments in [
        json!({"files":[{"id":"F_ONE","title":"Report"}]}),
        json!({"files":[{"id":"F_ONE"},{"id":"F_TWO","title":"Second"}]}),
    ] {
        assert!(
            runtime
                .invoke(Invocation {
                    agent_id: "agent".into(),
                    method: "files.completeUploadExternal".into(),
                    arguments,
                    idempotency_key: None
                })
                .await
                .unwrap()
                .ok
        );
    }
    for arguments in [
        json!({"files":[]}),
        json!({"files":[{"id":7}]}),
        json!({"files":[{"id":"F_ONE"},{"title":"Missing id"}]}),
    ] {
        assert!(
            runtime
                .invoke(Invocation {
                    agent_id: "agent".into(),
                    method: "files.completeUploadExternal".into(),
                    arguments,
                    idempotency_key: None
                })
                .await
                .is_err()
        );
    }
    assert_eq!(transport.seen.lock().unwrap().len(), 2);
}
