use std::collections::BTreeMap;
use std::ffi::c_void;
use std::fmt;
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

const SERVICE: &str = "comms.slack.agent";

type SecretMap = BTreeMap<(String, CredentialKind), CredentialSecret>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CredentialKind {
    AgentAccess,
    AgentRenewal,
    AgentId,
    Enrollment,
    EnrollmentId,
    Owner,
}

impl CredentialKind {
    fn suffix(self) -> &'static str {
        match self {
            Self::AgentAccess => "agent",
            Self::AgentRenewal => "renewal",
            Self::AgentId => "agent-id",
            Self::Enrollment => "enrollment",
            Self::EnrollmentId => "enrollment-id",
            Self::Owner => "owner",
        }
    }

    fn default_env(self) -> &'static str {
        match self {
            Self::AgentAccess => "COMMS_TOKEN",
            Self::AgentRenewal => "COMMS_RENEWAL_TOKEN",
            Self::AgentId => "COMMS_AGENT_ID",
            Self::Enrollment => "COMMS_ENROLLMENT_SECRET",
            Self::EnrollmentId => "COMMS_ENROLLMENT_ID",
            Self::Owner => "COMMS_OWNER_TOKEN",
        }
    }

    fn named_env_prefix(self) -> &'static str {
        match self {
            Self::AgentAccess => "COMMS_AGENT_TOKEN",
            Self::AgentRenewal => "COMMS_RENEWAL_TOKEN",
            Self::AgentId => "COMMS_AGENT_ID",
            Self::Enrollment => "COMMS_ENROLLMENT_SECRET",
            Self::EnrollmentId => "COMMS_ENROLLMENT_ID",
            Self::Owner => "COMMS_OWNER_TOKEN",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CredentialSecret(String);

impl CredentialSecret {
    pub fn new(value: impl Into<String>) -> Result<Self, CredentialError> {
        let value = value.into();
        if value.is_empty() {
            return Err(CredentialError::EmptySecret);
        }
        Ok(Self(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Debug for CredentialSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CredentialSecret")
            .field(&format_args!("[redacted; len={}]", self.0.len()))
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialProfile {
    pub base_url: String,
    pub profile: Option<String>,
}

impl CredentialProfile {
    pub fn new(base_url: impl Into<String>, profile: Option<String>) -> Self {
        let profile = profile.and_then(|value| {
            let trimmed = value.trim().to_string();
            (!trimmed.is_empty()).then_some(trimmed)
        });
        Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            profile,
        }
    }

    pub fn account(&self, kind: CredentialKind) -> String {
        match self.profile.as_deref() {
            Some(profile) => format!("{}:{}:{}", self.base_url, profile, kind.suffix()),
            None => format!("{}:default:{}", self.base_url, kind.suffix()),
        }
    }
}

pub trait CredentialStore: Send + Sync {
    fn load(
        &self,
        profile: &CredentialProfile,
        kind: CredentialKind,
    ) -> Result<Option<CredentialSecret>, CredentialError>;

    fn save(
        &self,
        profile: &CredentialProfile,
        kind: CredentialKind,
        secret: &CredentialSecret,
    ) -> Result<(), CredentialError>;

    fn delete(
        &self,
        profile: &CredentialProfile,
        kind: CredentialKind,
    ) -> Result<(), CredentialError>;
}

pub type SharedCredentialStore = Arc<dyn CredentialStore>;

pub fn default_credential_store() -> SharedCredentialStore {
    if let Some(executable) = std::env::var_os("COMMS_VAULT_EXECUTABLE") {
        return process_credential_store(
            executable.to_string_lossy(),
            std::iter::empty::<String>(),
        );
    }
    #[cfg(target_os = "macos")]
    {
        Arc::new(MacOsKeychainStore)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Arc::new(EnvCredentialStore::from_process())
    }
}

#[derive(Clone, Debug, Default)]
pub struct EnvCredentialStore {
    values: BTreeMap<String, String>,
}

impl EnvCredentialStore {
    pub fn from_process() -> Self {
        Self {
            values: std::env::vars().collect(),
        }
    }

    pub fn from_values(values: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            values: values.into_iter().collect(),
        }
    }

    pub fn env_name(profile: &CredentialProfile, kind: CredentialKind) -> String {
        match profile.profile.as_deref() {
            Some(profile) => format!("{}_{}", kind.named_env_prefix(), sanitize_env(profile)),
            None => kind.default_env().to_string(),
        }
    }
}

impl CredentialStore for EnvCredentialStore {
    fn load(
        &self,
        profile: &CredentialProfile,
        kind: CredentialKind,
    ) -> Result<Option<CredentialSecret>, CredentialError> {
        self.values
            .get(&Self::env_name(profile, kind))
            .cloned()
            .map(CredentialSecret::new)
            .transpose()
    }

    fn save(
        &self,
        _profile: &CredentialProfile,
        _kind: CredentialKind,
        _secret: &CredentialSecret,
    ) -> Result<(), CredentialError> {
        Err(CredentialError::ReadOnlyStore)
    }

    fn delete(
        &self,
        _profile: &CredentialProfile,
        _kind: CredentialKind,
    ) -> Result<(), CredentialError> {
        Err(CredentialError::ReadOnlyStore)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessCredentialStore {
    executable: String,
    args: Vec<String>,
}

impl ProcessCredentialStore {
    pub fn new(
        executable: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            executable: executable.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    fn call(
        &self,
        operation: &'static str,
        profile: &CredentialProfile,
        kind: CredentialKind,
        secret: Option<&CredentialSecret>,
    ) -> Result<Vec<u8>, CredentialError> {
        let mut request = json!({
            "op": operation,
            "service": SERVICE,
            "account": profile.account(kind),
            "kind": kind.suffix(),
        });
        if let Some(secret) = secret {
            request["secret"] = Value::String(secret.expose().to_string());
        }
        let mut child = Command::new(&self.executable)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(CredentialError::Io)?;
        {
            let stdin = child
                .stdin
                .as_mut()
                .ok_or(CredentialError::ExternalVaultProtocol)?;
            serde_json::to_writer(&mut *stdin, &request)
                .map_err(|_| CredentialError::ExternalVaultProtocol)?;
            stdin.write_all(b"\n").map_err(CredentialError::Io)?;
        }
        let output = child.wait_with_output().map_err(CredentialError::Io)?;
        if !output.status.success() {
            return Err(CredentialError::ExternalVaultFailed {
                operation,
                status: output.status.code(),
            });
        }
        Ok(output.stdout)
    }
}

impl CredentialStore for ProcessCredentialStore {
    fn load(
        &self,
        profile: &CredentialProfile,
        kind: CredentialKind,
    ) -> Result<Option<CredentialSecret>, CredentialError> {
        let output = self.call("load", profile, kind, None)?;
        if output.iter().all(u8::is_ascii_whitespace) {
            return Ok(None);
        }
        let value: Value =
            serde_json::from_slice(&output).map_err(|_| CredentialError::ExternalVaultProtocol)?;
        if value.is_null() {
            return Ok(None);
        }
        value
            .get("secret")
            .and_then(Value::as_str)
            .map(|secret| CredentialSecret::new(secret.to_string()))
            .transpose()
            .map_err(|_| CredentialError::ExternalVaultProtocol)?
            .ok_or(CredentialError::ExternalVaultProtocol)
            .map(Some)
    }

    fn save(
        &self,
        profile: &CredentialProfile,
        kind: CredentialKind,
        secret: &CredentialSecret,
    ) -> Result<(), CredentialError> {
        self.call("save", profile, kind, Some(secret)).map(|_| ())
    }

    fn delete(
        &self,
        profile: &CredentialProfile,
        kind: CredentialKind,
    ) -> Result<(), CredentialError> {
        self.call("delete", profile, kind, None).map(|_| ())
    }
}

pub fn process_credential_store(
    executable: impl Into<String>,
    args: impl IntoIterator<Item = impl Into<String>>,
) -> SharedCredentialStore {
    Arc::new(ProcessCredentialStore::new(executable, args))
}

#[derive(Debug, Default)]
pub struct MemoryCredentialStore {
    values: Mutex<SecretMap>,
}

impl MemoryCredentialStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(profile: &CredentialProfile, kind: CredentialKind) -> (String, CredentialKind) {
        (profile.account(kind), kind)
    }
}

impl CredentialStore for MemoryCredentialStore {
    fn load(
        &self,
        profile: &CredentialProfile,
        kind: CredentialKind,
    ) -> Result<Option<CredentialSecret>, CredentialError> {
        let values = self
            .values
            .lock()
            .map_err(|_| CredentialError::PoisonedStore)?;
        Ok(values.get(&Self::key(profile, kind)).cloned())
    }

    fn save(
        &self,
        profile: &CredentialProfile,
        kind: CredentialKind,
        secret: &CredentialSecret,
    ) -> Result<(), CredentialError> {
        let mut values = self
            .values
            .lock()
            .map_err(|_| CredentialError::PoisonedStore)?;
        values.insert(Self::key(profile, kind), secret.clone());
        Ok(())
    }

    fn delete(
        &self,
        profile: &CredentialProfile,
        kind: CredentialKind,
    ) -> Result<(), CredentialError> {
        let mut values = self
            .values
            .lock()
            .map_err(|_| CredentialError::PoisonedStore)?;
        values.remove(&Self::key(profile, kind));
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct MacOsKeychainStore;

impl CredentialStore for MacOsKeychainStore {
    fn load(
        &self,
        profile: &CredentialProfile,
        kind: CredentialKind,
    ) -> Result<Option<CredentialSecret>, CredentialError> {
        macos_keychain_load(&profile.account(kind))
    }

    fn save(
        &self,
        profile: &CredentialProfile,
        kind: CredentialKind,
        secret: &CredentialSecret,
    ) -> Result<(), CredentialError> {
        macos_keychain_save(&profile.account(kind), secret)
    }

    fn delete(
        &self,
        profile: &CredentialProfile,
        kind: CredentialKind,
    ) -> Result<(), CredentialError> {
        macos_keychain_delete(&profile.account(kind))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollmentCredentials {
    pub enrollment_id: String,
    pub enrollment: CredentialSecret,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentCredentials {
    pub agent_id: String,
    pub access: CredentialSecret,
    pub renewal: CredentialSecret,
    pub enrollment_id: Option<String>,
    pub root_enrollment_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerCredentials {
    pub owner_token: CredentialSecret,
}

pub struct CredentialProfileManager<'a> {
    store: &'a dyn CredentialStore,
}

impl<'a> CredentialProfileManager<'a> {
    pub fn new(store: &'a dyn CredentialStore) -> Self {
        Self { store }
    }

    pub fn save_owner(
        &self,
        profile: &CredentialProfile,
        credentials: &OwnerCredentials,
    ) -> Result<(), CredentialError> {
        self.store
            .save(profile, CredentialKind::Owner, &credentials.owner_token)
    }

    pub fn load_owner(
        &self,
        profile: &CredentialProfile,
    ) -> Result<Option<OwnerCredentials>, CredentialError> {
        Ok(self
            .store
            .load(profile, CredentialKind::Owner)?
            .map(|owner_token| OwnerCredentials { owner_token }))
    }

    pub fn save_enrollment(
        &self,
        profile: &CredentialProfile,
        credentials: &EnrollmentCredentials,
    ) -> Result<(), CredentialError> {
        self.store.save(
            profile,
            CredentialKind::EnrollmentId,
            &CredentialSecret::new(credentials.enrollment_id.clone())?,
        )?;
        self.store
            .save(profile, CredentialKind::Enrollment, &credentials.enrollment)
    }

    pub fn load_enrollment(
        &self,
        profile: &CredentialProfile,
    ) -> Result<Option<EnrollmentCredentials>, CredentialError> {
        let Some(enrollment_id) = self.store.load(profile, CredentialKind::EnrollmentId)? else {
            return Ok(None);
        };
        let Some(enrollment) = self.store.load(profile, CredentialKind::Enrollment)? else {
            return Ok(None);
        };
        Ok(Some(EnrollmentCredentials {
            enrollment_id: enrollment_id.into_inner(),
            enrollment,
        }))
    }

    pub fn save_agent(
        &self,
        profile: &CredentialProfile,
        credentials: &AgentCredentials,
    ) -> Result<(), CredentialError> {
        self.store.save(
            profile,
            CredentialKind::AgentId,
            &CredentialSecret::new(credentials.agent_id.clone())?,
        )?;
        self.store
            .save(profile, CredentialKind::AgentAccess, &credentials.access)?;
        self.store
            .save(profile, CredentialKind::AgentRenewal, &credentials.renewal)
    }

    pub fn load_agent(
        &self,
        profile: &CredentialProfile,
    ) -> Result<Option<AgentCredentials>, CredentialError> {
        let Some(agent_id) = self.store.load(profile, CredentialKind::AgentId)? else {
            return Ok(None);
        };
        let Some(access) = self.store.load(profile, CredentialKind::AgentAccess)? else {
            return Ok(None);
        };
        let Some(renewal) = self.store.load(profile, CredentialKind::AgentRenewal)? else {
            return Ok(None);
        };
        Ok(Some(AgentCredentials {
            agent_id: agent_id.into_inner(),
            access,
            renewal,
            enrollment_id: None,
            root_enrollment_id: None,
        }))
    }

    pub fn delete_agent(&self, profile: &CredentialProfile) -> Result<(), CredentialError> {
        for kind in [
            CredentialKind::AgentAccess,
            CredentialKind::AgentRenewal,
            CredentialKind::AgentId,
        ] {
            self.store.delete(profile, kind)?;
        }
        Ok(())
    }

    pub fn delete_enrollment(&self, profile: &CredentialProfile) -> Result<(), CredentialError> {
        for kind in [CredentialKind::Enrollment, CredentialKind::EnrollmentId] {
            self.store.delete(profile, kind)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum CredentialError {
    EmptySecret,
    ExternalVaultFailed {
        operation: &'static str,
        status: Option<i32>,
    },
    ExternalVaultProtocol,
    Io(std::io::Error),
    NativeStatus {
        operation: &'static str,
        status: i32,
    },
    PoisonedStore,
    ReadOnlyStore,
    UnsupportedNativeStore,
    Utf8,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySecret => formatter.write_str("credential secret must not be empty"),
            Self::ExternalVaultFailed { operation, status } => {
                write!(formatter, "credential vault {operation} failed")?;
                if let Some(status) = status {
                    write!(formatter, " with status {status}")?;
                }
                Ok(())
            }
            Self::ExternalVaultProtocol => {
                formatter.write_str("credential vault response was invalid")
            }
            Self::Io(error) => write!(formatter, "credential store failed: {error}"),
            Self::NativeStatus { operation, status } => {
                write!(
                    formatter,
                    "credential keychain {operation} failed with status {status}"
                )
            }
            Self::PoisonedStore => formatter.write_str("credential store lock is poisoned"),
            Self::ReadOnlyStore => formatter.write_str("credential store is read-only"),
            Self::UnsupportedNativeStore => {
                formatter.write_str("native credential store is unsupported")
            }
            Self::Utf8 => formatter.write_str("credential store returned invalid UTF-8"),
        }
    }
}

impl std::error::Error for CredentialError {}

#[cfg(target_os = "macos")]
fn macos_keychain_load(account: &str) -> Result<Option<CredentialSecret>, CredentialError> {
    macos::load(account)
}

#[cfg(not(target_os = "macos"))]
fn macos_keychain_load(_account: &str) -> Result<Option<CredentialSecret>, CredentialError> {
    Err(CredentialError::UnsupportedNativeStore)
}

#[cfg(target_os = "macos")]
fn macos_keychain_save(account: &str, secret: &CredentialSecret) -> Result<(), CredentialError> {
    macos::save(account, secret)
}

#[cfg(not(target_os = "macos"))]
fn macos_keychain_save(_account: &str, _secret: &CredentialSecret) -> Result<(), CredentialError> {
    Err(CredentialError::UnsupportedNativeStore)
}

#[cfg(target_os = "macos")]
fn macos_keychain_delete(account: &str) -> Result<(), CredentialError> {
    macos::delete(account)
}

#[cfg(not(target_os = "macos"))]
fn macos_keychain_delete(_account: &str) -> Result<(), CredentialError> {
    Err(CredentialError::UnsupportedNativeStore)
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::ptr;

    type OSStatus = i32;
    type SecKeychainItemRef = *mut c_void;
    type SecKeychainRef = *mut c_void;

    const ERR_SEC_SUCCESS: OSStatus = 0;
    const ERR_SEC_DUPLICATE_ITEM: OSStatus = -25299;
    const ERR_SEC_ITEM_NOT_FOUND: OSStatus = -25300;

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecKeychainAddGenericPassword(
            keychain: SecKeychainRef,
            service_name_length: u32,
            service_name: *const c_void,
            account_name_length: u32,
            account_name: *const c_void,
            password_length: u32,
            password_data: *const c_void,
            item_ref: *mut SecKeychainItemRef,
        ) -> OSStatus;

        fn SecKeychainFindGenericPassword(
            keychain: SecKeychainRef,
            service_name_length: u32,
            service_name: *const c_void,
            account_name_length: u32,
            account_name: *const c_void,
            password_length: *mut u32,
            password_data: *mut *mut c_void,
            item_ref: *mut SecKeychainItemRef,
        ) -> OSStatus;

        fn SecKeychainItemModifyAttributesAndData(
            item_ref: SecKeychainItemRef,
            attr_list: *const c_void,
            length: u32,
            data: *const c_void,
        ) -> OSStatus;

        fn SecKeychainItemDelete(item_ref: SecKeychainItemRef) -> OSStatus;
        fn SecKeychainItemFreeContent(attr_list: *mut c_void, data: *mut c_void) -> OSStatus;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFRelease(cf: *const c_void);
    }

    pub fn load(account: &str) -> Result<Option<CredentialSecret>, CredentialError> {
        let mut password_len = 0_u32;
        let mut password_data: *mut c_void = ptr::null_mut();
        let status = unsafe {
            SecKeychainFindGenericPassword(
                ptr::null_mut(),
                u32_len(SERVICE, "find")?,
                SERVICE.as_ptr().cast(),
                u32_len(account, "find")?,
                account.as_ptr().cast(),
                &mut password_len,
                &mut password_data,
                ptr::null_mut(),
            )
        };
        if status == ERR_SEC_ITEM_NOT_FOUND {
            return Ok(None);
        }
        if status != ERR_SEC_SUCCESS {
            return Err(CredentialError::NativeStatus {
                operation: "find",
                status,
            });
        }
        let bytes = unsafe {
            std::slice::from_raw_parts(password_data.cast::<u8>(), password_len as usize).to_vec()
        };
        let free_status = unsafe { SecKeychainItemFreeContent(ptr::null_mut(), password_data) };
        if free_status != ERR_SEC_SUCCESS {
            return Err(CredentialError::NativeStatus {
                operation: "free",
                status: free_status,
            });
        }
        let value = String::from_utf8(bytes).map_err(|_| CredentialError::Utf8)?;
        CredentialSecret::new(value).map(Some)
    }

    pub fn save(account: &str, secret: &CredentialSecret) -> Result<(), CredentialError> {
        let add_status = unsafe {
            SecKeychainAddGenericPassword(
                ptr::null_mut(),
                u32_len(SERVICE, "add")?,
                SERVICE.as_ptr().cast(),
                u32_len(account, "add")?,
                account.as_ptr().cast(),
                u32_len(secret.expose(), "add")?,
                secret.expose().as_ptr().cast(),
                ptr::null_mut(),
            )
        };
        match add_status {
            ERR_SEC_SUCCESS => Ok(()),
            ERR_SEC_DUPLICATE_ITEM => modify(account, secret),
            status => Err(CredentialError::NativeStatus {
                operation: "add",
                status,
            }),
        }
    }

    pub fn delete(account: &str) -> Result<(), CredentialError> {
        let Some(item) = find_item(account, "delete")? else {
            return Ok(());
        };
        let status = unsafe { SecKeychainItemDelete(item) };
        unsafe { CFRelease(item.cast_const()) };
        if status == ERR_SEC_SUCCESS || status == ERR_SEC_ITEM_NOT_FOUND {
            Ok(())
        } else {
            Err(CredentialError::NativeStatus {
                operation: "delete",
                status,
            })
        }
    }

    fn modify(account: &str, secret: &CredentialSecret) -> Result<(), CredentialError> {
        let item = find_item(account, "modify")?.ok_or(CredentialError::NativeStatus {
            operation: "modify-find",
            status: ERR_SEC_ITEM_NOT_FOUND,
        })?;
        let status = unsafe {
            SecKeychainItemModifyAttributesAndData(
                item,
                ptr::null(),
                u32_len(secret.expose(), "modify")?,
                secret.expose().as_ptr().cast(),
            )
        };
        unsafe { CFRelease(item.cast_const()) };
        if status == ERR_SEC_SUCCESS {
            Ok(())
        } else {
            Err(CredentialError::NativeStatus {
                operation: "modify",
                status,
            })
        }
    }

    fn find_item(
        account: &str,
        operation: &'static str,
    ) -> Result<Option<SecKeychainItemRef>, CredentialError> {
        let mut item: SecKeychainItemRef = ptr::null_mut();
        let status = unsafe {
            SecKeychainFindGenericPassword(
                ptr::null_mut(),
                u32_len(SERVICE, operation)?,
                SERVICE.as_ptr().cast(),
                u32_len(account, operation)?,
                account.as_ptr().cast(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut item,
            )
        };
        if status == ERR_SEC_ITEM_NOT_FOUND {
            return Ok(None);
        }
        if status != ERR_SEC_SUCCESS {
            return Err(CredentialError::NativeStatus { operation, status });
        }
        Ok(Some(item))
    }

    fn u32_len(value: &str, operation: &'static str) -> Result<u32, CredentialError> {
        value
            .len()
            .try_into()
            .map_err(|_| CredentialError::NativeStatus {
                operation,
                status: -1,
            })
    }
}

fn sanitize_env(profile: &str) -> String {
    profile
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_secret() {
        let secret = CredentialSecret::new("top-secret-token").unwrap();
        let rendered = format!("{secret:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("top-secret-token"));
    }

    #[test]
    fn env_store_uses_default_and_named_profile_names() {
        let store = EnvCredentialStore::from_values([
            ("COMMS_TOKEN".to_string(), "default-token".to_string()),
            (
                "COMMS_AGENT_TOKEN_BUILD_BOT".to_string(),
                "profile-token".to_string(),
            ),
            (
                "COMMS_ENROLLMENT_SECRET_BUILD_BOT".to_string(),
                "enroll-secret".to_string(),
            ),
        ]);
        let default = CredentialProfile::new("https://example.test", None);
        let named = CredentialProfile::new("https://example.test", Some("build-bot".into()));
        assert_eq!(
            store
                .load(&default, CredentialKind::AgentAccess)
                .unwrap()
                .unwrap()
                .expose(),
            "default-token"
        );
        assert_eq!(
            store
                .load(&named, CredentialKind::AgentAccess)
                .unwrap()
                .unwrap()
                .expose(),
            "profile-token"
        );
        assert_eq!(
            store
                .load(&named, CredentialKind::Enrollment)
                .unwrap()
                .unwrap()
                .expose(),
            "enroll-secret"
        );
    }

    #[test]
    fn profile_manager_saves_and_loads_named_agent_and_enrollment() {
        let store = MemoryCredentialStore::new();
        let manager = CredentialProfileManager::new(&store);
        let profile = CredentialProfile::new("https://example.test", Some("build-bot".into()));
        manager
            .save_enrollment(
                &profile,
                &EnrollmentCredentials {
                    enrollment_id: "enr_1".into(),
                    enrollment: CredentialSecret::new("reusable-secret").unwrap(),
                },
            )
            .unwrap();
        manager
            .save_agent(
                &profile,
                &AgentCredentials {
                    agent_id: "agt_1".into(),
                    access: CredentialSecret::new("access-token").unwrap(),
                    renewal: CredentialSecret::new("renewal-token").unwrap(),
                    enrollment_id: Some("enr_1".into()),
                    root_enrollment_id: Some("enr_1".into()),
                },
            )
            .unwrap();

        let enrollment = manager.load_enrollment(&profile).unwrap().unwrap();
        assert_eq!(enrollment.enrollment_id, "enr_1");
        assert_eq!(enrollment.enrollment.expose(), "reusable-secret");

        let agent = manager.load_agent(&profile).unwrap().unwrap();
        assert_eq!(agent.agent_id, "agt_1");
        assert_eq!(agent.access.expose(), "access-token");
        assert_eq!(agent.renewal.expose(), "renewal-token");

        manager.delete_agent(&profile).unwrap();
        assert!(manager.load_agent(&profile).unwrap().is_none());
    }
    #[test]
    fn profile_urls_ignore_trailing_slash() {
        assert_eq!(
            CredentialProfile::new("https://example.test/", None),
            CredentialProfile::new("https://example.test", None)
        );
    }
}
