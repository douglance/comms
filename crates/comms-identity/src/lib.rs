//! Portable identity, enrollment, and credential policy for agent comms hosts.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

pub const ACCESS_TTL_SECONDS: i64 = 24 * 60 * 60;
pub const RENEWAL_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;
pub const ENROLLMENT_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        if value.is_empty() {
            return Err(IdentityError::EmptySecret);
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

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Secret")
            .field(&format_args!("[redacted; len={}]", self.0.len()))
            .finish()
    }
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct UnixTime(pub i64);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EnrollmentRecord {
    pub id: String,
    pub root_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_name: Option<String>,
    pub secret_hash: String,
    pub created_at: UnixTime,
    pub expires_at: UnixTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<UnixTime>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AgentRecord {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrollment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_enrollment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_name: Option<String>,
    pub token_hash: String,
    pub renewal_hash: String,
    pub expires_at: UnixTime,
    pub renewal_expires_at: UnixTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<UnixTime>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct IssuedEnrollment {
    pub record: EnrollmentRecord,
    pub secret: Secret,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentSecrets {
    pub token: Secret,
    pub renewal: Secret,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct IssuedAgent {
    pub record: AgentRecord,
    pub token: Secret,
    pub renewal: Secret,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RenewedAgent {
    pub id: String,
    pub token: Secret,
    pub renewal: Secret,
    pub token_hash: String,
    pub renewal_hash: String,
    pub expires_at: UnixTime,
    pub renewal_expires_at: UnixTime,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct IdentityPolicy {
    pub access_ttl_seconds: i64,
    pub renewal_ttl_seconds: i64,
    pub enrollment_ttl_seconds: i64,
}

impl Default for IdentityPolicy {
    fn default() -> Self {
        Self {
            access_ttl_seconds: ACCESS_TTL_SECONDS,
            renewal_ttl_seconds: RENEWAL_TTL_SECONDS,
            enrollment_ttl_seconds: ENROLLMENT_TTL_SECONDS,
        }
    }
}

impl IdentityPolicy {
    pub fn issue_root_enrollment(
        &self,
        id: impl Into<String>,
        now: UnixTime,
        secret: Secret,
        label: Option<String>,
        profile_name: Option<String>,
    ) -> Result<IssuedEnrollment, IdentityError> {
        let id = id.into();
        let expires_at = add_seconds(now, self.enrollment_ttl_seconds)?;
        Ok(IssuedEnrollment {
            record: EnrollmentRecord {
                id: id.clone(),
                root_id: id,
                parent_id: None,
                label,
                profile_name,
                secret_hash: hash_secret(secret.expose()),
                created_at: now,
                expires_at,
                revoked_at: None,
            },
            secret,
        })
    }

    pub fn issue_agent(
        &self,
        enrollment: &EnrollmentRecord,
        now: UnixTime,
        agent_id: impl Into<String>,
        secrets: AgentSecrets,
        label: Option<String>,
        profile_name: Option<String>,
    ) -> Result<IssuedAgent, IdentityError> {
        ensure_enrollment_active(enrollment, now)?;
        let AgentSecrets { token, renewal } = secrets;
        let expires_at = add_seconds(now, self.access_ttl_seconds)?;
        let renewal_expires_at = add_seconds(now, self.renewal_ttl_seconds)?;
        Ok(IssuedAgent {
            record: AgentRecord {
                id: agent_id.into(),
                enrollment_id: Some(enrollment.id.clone()),
                root_enrollment_id: Some(enrollment.root_id.clone()),
                label: label.or_else(|| enrollment.label.clone()),
                profile_name: profile_name.or_else(|| enrollment.profile_name.clone()),
                token_hash: hash_secret(token.expose()),
                renewal_hash: hash_secret(renewal.expose()),
                expires_at,
                renewal_expires_at,
                revoked_at: None,
            },
            token,
            renewal,
        })
    }

    pub fn renew_agent(
        &self,
        agent: &AgentRecord,
        now: UnixTime,
        presented_renewal: &Secret,
        next_token: Secret,
        next_renewal: Secret,
        root_revoked_at: Option<UnixTime>,
    ) -> Result<RenewedAgent, IdentityError> {
        ensure_agent_active(agent, now, root_revoked_at)?;
        if agent.renewal_hash != hash_secret(presented_renewal.expose()) {
            return Err(IdentityError::RenewalSecretMismatch);
        }
        if agent.renewal_expires_at <= now {
            return Err(IdentityError::ExpiredRenewal);
        }
        let expires_at = add_seconds(now, self.access_ttl_seconds)?;
        let renewal_expires_at = add_seconds(now, self.renewal_ttl_seconds)?;
        let token_hash = hash_secret(next_token.expose());
        let renewal_hash = hash_secret(next_renewal.expose());
        Ok(RenewedAgent {
            id: agent.id.clone(),
            token: next_token,
            renewal: next_renewal,
            token_hash,
            renewal_hash,
            expires_at,
            renewal_expires_at,
        })
    }
}

pub fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hex(&hasher.finalize())
}

pub fn ensure_enrollment_active(
    enrollment: &EnrollmentRecord,
    now: UnixTime,
) -> Result<(), IdentityError> {
    if enrollment.revoked_at.is_some() {
        return Err(IdentityError::RevokedEnrollment);
    }
    if enrollment.expires_at <= now {
        return Err(IdentityError::ExpiredEnrollment);
    }
    Ok(())
}

pub fn ensure_agent_active(
    agent: &AgentRecord,
    now: UnixTime,
    root_revoked_at: Option<UnixTime>,
) -> Result<(), IdentityError> {
    if agent.revoked_at.is_some() {
        return Err(IdentityError::RevokedAgent);
    }
    if root_revoked_at.is_some() {
        return Err(IdentityError::RootRevoked);
    }
    if agent.expires_at <= now {
        return Err(IdentityError::ExpiredAccess);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityError {
    EmptySecret,
    ExpiredAccess,
    ExpiredEnrollment,
    ExpiredRenewal,
    RevokedAgent,
    RevokedEnrollment,
    RenewalSecretMismatch,
    RootRevoked,
    TimeOverflow,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptySecret => "secret must not be empty",
            Self::ExpiredAccess => "agent access token has expired",
            Self::ExpiredEnrollment => "enrollment has expired",
            Self::ExpiredRenewal => "renewal secret has expired",
            Self::RevokedAgent => "agent has been revoked",
            Self::RevokedEnrollment => "enrollment has been revoked",
            Self::RenewalSecretMismatch => "renewal secret does not match the agent",
            Self::RootRevoked => "root enrollment has been revoked",
            Self::TimeOverflow => "identity timestamp overflowed",
        })
    }
}

impl std::error::Error for IdentityError {}

fn add_seconds(now: UnixTime, seconds: i64) -> Result<UnixTime, IdentityError> {
    Ok(UnixTime(
        now.0
            .checked_add(seconds)
            .ok_or(IdentityError::TimeOverflow)?,
    ))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(value: &str) -> Secret {
        Secret::new(value).unwrap()
    }

    fn enrollment(policy: &IdentityPolicy) -> EnrollmentRecord {
        policy
            .issue_root_enrollment(
                "enr_root",
                UnixTime(100),
                secret("enrollment-secret"),
                Some("agent family".into()),
                None,
            )
            .unwrap()
            .record
    }

    #[test]
    fn redacts_secret_debug() {
        let rendered = format!("{:?}", secret("super-secret-value"));
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("super-secret-value"));
    }

    #[test]
    fn root_enrollment_defaults_to_thirty_days() {
        let issued = IdentityPolicy::default()
            .issue_root_enrollment("enr_1", UnixTime(10), secret("join"), None, None)
            .unwrap();
        assert_eq!(issued.record.root_id, "enr_1");
        assert_eq!(
            issued.record.expires_at,
            UnixTime(10 + ENROLLMENT_TTL_SECONDS)
        );
        assert_eq!(issued.record.secret_hash, hash_secret("join"));
    }

    #[test]
    fn expired_or_revoked_enrollment_cannot_issue_agent() {
        let policy = IdentityPolicy::default();
        let mut expired = enrollment(&policy);
        expired.expires_at = UnixTime(100);
        let err = policy
            .issue_agent(
                &expired,
                UnixTime(100),
                "agent_a",
                AgentSecrets {
                    token: secret("access"),
                    renewal: secret("renew"),
                },
                None,
                None,
            )
            .unwrap_err();
        assert_eq!(err, IdentityError::ExpiredEnrollment);

        let mut revoked = enrollment(&policy);
        revoked.revoked_at = Some(UnixTime(101));
        let err = policy
            .issue_agent(
                &revoked,
                UnixTime(102),
                "agent_b",
                AgentSecrets {
                    token: secret("access"),
                    renewal: secret("renew"),
                },
                None,
                None,
            )
            .unwrap_err();
        assert_eq!(err, IdentityError::RevokedEnrollment);
    }

    #[test]
    fn renewal_requires_current_secret_and_rotates_hashes() {
        let policy = IdentityPolicy::default();
        let agent = policy
            .issue_agent(
                &enrollment(&policy),
                UnixTime(200),
                "agent_a",
                AgentSecrets {
                    token: secret("access-a"),
                    renewal: secret("renew-a"),
                },
                None,
                Some("named".into()),
            )
            .unwrap()
            .record;

        let mismatch = policy
            .renew_agent(
                &agent,
                UnixTime(300),
                &secret("wrong"),
                secret("access-b"),
                secret("renew-b"),
                None,
            )
            .unwrap_err();
        assert_eq!(mismatch, IdentityError::RenewalSecretMismatch);

        let renewed = policy
            .renew_agent(
                &agent,
                UnixTime(300),
                &secret("renew-a"),
                secret("access-b"),
                secret("renew-b"),
                None,
            )
            .unwrap();
        assert_eq!(renewed.token_hash, hash_secret("access-b"));
        assert_eq!(renewed.renewal_hash, hash_secret("renew-b"));
        assert_ne!(renewed.token_hash, agent.token_hash);
        assert_eq!(renewed.expires_at, UnixTime(300 + ACCESS_TTL_SECONDS));
    }

    #[test]
    fn root_revocation_disables_existing_children() {
        let policy = IdentityPolicy::default();
        let agent = policy
            .issue_agent(
                &enrollment(&policy),
                UnixTime(200),
                "agent_a",
                AgentSecrets {
                    token: secret("access-a"),
                    renewal: secret("renew-a"),
                },
                None,
                None,
            )
            .unwrap()
            .record;
        let err = ensure_agent_active(&agent, UnixTime(201), Some(UnixTime(201))).unwrap_err();
        assert_eq!(err, IdentityError::RootRevoked);
    }
}
