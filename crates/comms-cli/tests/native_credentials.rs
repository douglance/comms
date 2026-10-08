#![cfg(target_os = "macos")]
use comms_cli::credentials::{
    CredentialKind, CredentialProfile, CredentialSecret, CredentialStore, MacOsKeychainStore,
};

#[test]
fn native_keychain_round_trip_updates_and_deletes() {
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let profile = CredentialProfile::new(
        format!("https://native-fixture-{suffix}.invalid"),
        Some("roundtrip".into()),
    );
    let store = MacOsKeychainStore;
    struct Cleanup<'a>(&'a MacOsKeychainStore, &'a CredentialProfile);
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            let _ = self.0.delete(self.1, CredentialKind::Owner);
        }
    }
    let _cleanup = Cleanup(&store, &profile);
    let first = CredentialSecret::new("inert-fixture-one").unwrap();
    let second = CredentialSecret::new("inert-fixture-two").unwrap();
    store.save(&profile, CredentialKind::Owner, &first).unwrap();
    assert_eq!(
        store.load(&profile, CredentialKind::Owner).unwrap(),
        Some(first)
    );
    store
        .save(&profile, CredentialKind::Owner, &second)
        .unwrap();
    assert_eq!(
        store.load(&profile, CredentialKind::Owner).unwrap(),
        Some(second)
    );
    store.delete(&profile, CredentialKind::Owner).unwrap();
    assert!(
        store
            .load(&profile, CredentialKind::Owner)
            .unwrap()
            .is_none()
    );
}
