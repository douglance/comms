use comms_cli::credentials::{
    CredentialKind, CredentialProfile, CredentialSecret, CredentialStore, ProcessCredentialStore,
};

#[test]
fn external_vault_receives_secret_only_on_stdin() {
    let script = r#"
import json,sys
request=json.load(sys.stdin)
assert request["op"] in ("save","delete")
if request["op"] == "save":
    secret=request["secret"]
    assert secret and all(secret not in value for value in sys.argv)
print("null")
"#;
    let store = ProcessCredentialStore::new("python3", ["-c", script]);
    let profile = CredentialProfile::new("https://fixture.test", Some("agent".into()));
    store
        .save(
            &profile,
            CredentialKind::AgentAccess,
            &CredentialSecret::new("inert-fixture-token-482").unwrap(),
        )
        .unwrap();
    store.delete(&profile, CredentialKind::AgentAccess).unwrap();
}

#[test]
fn external_vault_loads_structured_response() {
    let script = r#"
import json,sys
request=json.load(sys.stdin)
assert request["op"] == "load"
print(json.dumps({"secret":request["account"] + ":fixture-value"}))
"#;
    let store = ProcessCredentialStore::new("python3", ["-c", script]);
    let profile = CredentialProfile::new("https://fixture.test", Some("agent".into()));
    let secret = store
        .load(&profile, CredentialKind::AgentRenewal)
        .unwrap()
        .unwrap();
    assert!(secret.expose().ends_with(":renewal:fixture-value"));
    assert!(!format!("{secret:?}").contains("fixture-value"));
}

#[test]
fn external_vault_failures_hide_stdout_and_stderr_secrets() {
    let script = r#"
import json,sys
request=json.load(sys.stdin)
secret=request["secret"]
print(secret)
print(secret,file=sys.stderr)
sys.exit(17)
"#;
    let store = ProcessCredentialStore::new("python3", ["-c", script]);
    let profile = CredentialProfile::new("https://fixture.test", None);
    let error = store
        .save(
            &profile,
            CredentialKind::Owner,
            &CredentialSecret::new("inert-error-secret-921").unwrap(),
        )
        .unwrap_err();
    assert!(!error.to_string().contains("inert-error-secret-921"));
    assert!(error.to_string().contains("17"));
}
