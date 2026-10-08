use incurs::cli::Cli;
use incurs::command::{CommandDef, TypedResult};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::credentials::{
    AgentCredentials, CredentialProfile, CredentialProfileManager, CredentialSecret,
    EnrollmentCredentials, OwnerCredentials, SharedCredentialStore,
};
use crate::{AuthClient, CommsEnv, decode, endpoint, send_json_envelope, with_bearer};

const DEFAULT_BASE_URL: &str = "https://comms.example.com";

pub(crate) fn credential_cli(store: SharedCredentialStore) -> Cli {
    Cli::create("profile")
        .description("Secure Slack-agent credential profiles")
        .command("status", status_command(store.clone()))
        .command("save-owner", save_owner_command(store.clone()))
        .command("enroll", enroll_command(store.clone()))
        .command("join", join_command(store.clone()))
        .command("renew", renew_command(store.clone()))
        .command("revoke", revoke_command(store))
}

fn status_command(store: SharedCredentialStore) -> CommandDef {
    CommandDef::typed::<(), ProfileOptions, CommsEnv, CredentialStatusOutput, _, _>(
        "status",
        move |ctx| {
            let store = store.clone();
            async move {
                let profile = profile_from(
                    ctx.env.url.as_deref(),
                    ctx.options.url.as_deref(),
                    ctx.env.profile.as_deref(),
                    ctx.options.profile,
                );
                match status_for(store.as_ref(), profile) {
                    Ok(output) => TypedResult::ok(output),
                    Err(error) => TypedResult::error("CREDENTIAL_STATUS_FAILED", error.to_string()),
                }
            }
        },
    )
    .description("Show which credentials exist for a profile without printing secrets")
    .done()
}

fn save_owner_command(store: SharedCredentialStore) -> CommandDef {
    CommandDef::typed::<(), SaveOwnerOptions, CommsEnv, SavedOutput, _, _>(
        "save-owner",
        move |ctx| {
            let store = store.clone();
            async move {
                let profile = profile_from(
                    ctx.env.url.as_deref(),
                    ctx.options.url.as_deref(),
                    ctx.env.profile.as_deref(),
                    ctx.options.profile,
                );
                let Some(owner_token) = ctx.env.owner_token.as_deref() else {
                    return TypedResult::error("CONFIG_ERROR", "COMMS_OWNER_TOKEN is required");
                };
                match store_owner_token(
                    store.as_ref(),
                    &profile.base_url,
                    profile.profile,
                    owner_token,
                ) {
                    Ok(output) => TypedResult::ok(output),
                    Err(error) => TypedResult::error("OWNER_SAVE_FAILED", error),
                }
            }
        },
    )
    .description("Save an owner token in the native credential store")
    .done()
}

fn enroll_command(store: SharedCredentialStore) -> CommandDef {
    CommandDef::typed::<(), EnrollOptions, CommsEnv, EnrollmentOutput, _, _>("enroll", move |ctx| {
        let store = store.clone();
        async move {
            let profile = profile_from(
                ctx.env.url.as_deref(),
                ctx.options.url.as_deref(),
                ctx.env.profile.as_deref(),
                ctx.options.profile.clone(),
            );
            let owner_token =
                match owner_token(store.as_ref(), &profile, ctx.env.owner_token.as_deref()) {
                    Ok(token) => token,
                    Err(error) => return TypedResult::error("CONFIG_ERROR", error),
                };
            let client = match AuthClient::new(&profile.base_url) {
                Ok(client) => client,
                Err(error) => return TypedResult::error("CONFIG_ERROR", error),
            };
            match create_enrollment(&client, owner_token.expose(), &ctx.options).await {
                Ok(response) => {
                    let manager = CredentialProfileManager::new(store.as_ref());
                    let save = CredentialSecret::new(response.enrollment).and_then(|enrollment| {
                        manager.save_enrollment(
                            &profile,
                            &EnrollmentCredentials {
                                enrollment_id: response.enrollment_id.clone(),
                                enrollment,
                            },
                        )
                    });
                    match save {
                        Ok(()) => TypedResult::ok(EnrollmentOutput {
                            profile: profile.profile,
                            enrollment_id: response.enrollment_id,
                            expires_at: response.expires_at,
                            saved: true,
                        }),
                        Err(error) => {
                            TypedResult::error("ENROLLMENT_SAVE_FAILED", error.to_string())
                        }
                    }
                }
                Err(error) => TypedResult::error("ENROLLMENT_CREATE_FAILED", error),
            }
        }
    })
    .description("Create and save a reusable enrollment secret")
    .done()
}

fn join_command(store: SharedCredentialStore) -> CommandDef {
    CommandDef::typed::<(), JoinOptions, CommsEnv, AgentProfileOutput, _, _>("join", move |ctx| {
        let store = store.clone();
        async move {
            let profile = profile_from(
                ctx.env.url.as_deref(),
                ctx.options.url.as_deref(),
                ctx.env.profile.as_deref(),
                ctx.options.profile.clone(),
            );
            let manager = CredentialProfileManager::new(store.as_ref());
            let client = match AuthClient::new(&profile.base_url) {
                Ok(client) => client,
                Err(error) => return TypedResult::error("CONFIG_ERROR", error),
            };
            if profile.profile.is_some() {
                match manager.load_agent(&profile) {
                    Ok(Some(agent)) => {
                        return match renew_agent(&client, &agent.agent_id, agent.renewal.expose())
                            .await
                        {
                            Ok(response) => save_renew_response(manager, profile, response),
                            Err(error) => TypedResult::error("RENEW_FAILED", error),
                        };
                    }
                    Ok(None) => {}
                    Err(error) => return TypedResult::error("CONFIG_ERROR", error.to_string()),
                }
            }
            let enrollment = match ctx
                .options
                .enrollment
                .clone()
                .or(ctx.env.enrollment.clone())
            {
                Some(enrollment) => match CredentialSecret::new(enrollment) {
                    Ok(secret) => secret,
                    Err(error) => return TypedResult::error("CONFIG_ERROR", error.to_string()),
                },
                None => match manager.load_enrollment(&profile).and_then(|saved| {
                    if saved.is_some() || profile.profile.is_none() {
                        Ok(saved)
                    } else {
                        manager.load_enrollment(&CredentialProfile::new(
                            profile.base_url.clone(),
                            None,
                        ))
                    }
                }) {
                    Ok(Some(credentials)) => credentials.enrollment,
                    Ok(None) => {
                        return TypedResult::error("CONFIG_ERROR", "saved enrollment is required");
                    }
                    Err(error) => return TypedResult::error("CONFIG_ERROR", error.to_string()),
                },
            };
            match join_enrollment(&client, enrollment.expose(), &ctx.options).await {
                Ok(response) => save_agent_response(manager, profile, response),
                Err(error) => TypedResult::error("JOIN_FAILED", error),
            }
        }
    })
    .description("Join with a reusable enrollment; named profiles persist renewal credentials")
    .done()
}

fn renew_command(store: SharedCredentialStore) -> CommandDef {
    CommandDef::typed::<(), RenewOptions, CommsEnv, AgentProfileOutput, _, _>("renew", move |ctx| {
        let store = store.clone();
        async move {
            let profile_name = if ctx.options.profile.trim().is_empty() {
                return TypedResult::error("CONFIG_ERROR", "--profile is required for renewal");
            } else {
                Some(ctx.options.profile)
            };
            let profile = profile_from(
                ctx.env.url.as_deref(),
                ctx.options.url.as_deref(),
                ctx.env.profile.as_deref(),
                profile_name,
            );
            let manager = CredentialProfileManager::new(store.as_ref());
            let agent = match manager.load_agent(&profile) {
                Ok(Some(agent)) => agent,
                Ok(None) => {
                    return TypedResult::error("CONFIG_ERROR", "saved agent profile is required");
                }
                Err(error) => return TypedResult::error("CONFIG_ERROR", error.to_string()),
            };
            let client = match AuthClient::new(&profile.base_url) {
                Ok(client) => client,
                Err(error) => return TypedResult::error("CONFIG_ERROR", error),
            };
            match renew_agent(&client, &agent.agent_id, agent.renewal.expose()).await {
                Ok(response) => save_renew_response(manager, profile, response),
                Err(error) => TypedResult::error("RENEW_FAILED", error),
            }
        }
    })
    .description("Rotate a named profile access token using its renewal secret")
    .done()
}

fn revoke_command(store: SharedCredentialStore) -> CommandDef {
    CommandDef::typed::<(), RevokeOptions, CommsEnv, RevokeProfileOutput, _, _>(
        "revoke",
        move |ctx| {
            let store = store.clone();
            async move {
                let profile = profile_from(
                    ctx.env.url.as_deref(),
                    ctx.options.url.as_deref(),
                    ctx.env.profile.as_deref(),
                    ctx.options.profile.clone(),
                );
                let owner_token =
                    match owner_token(store.as_ref(), &profile, ctx.env.owner_token.as_deref()) {
                        Ok(token) => token,
                        Err(error) => return TypedResult::error("CONFIG_ERROR", error),
                    };
                let manager = CredentialProfileManager::new(store.as_ref());
                let id = match ctx.options.id {
                    Some(id) => id,
                    None => match manager.load_agent(&profile) {
                        Ok(Some(agent)) => agent.agent_id,
                        Ok(None) => {
                            return TypedResult::error("CONFIG_ERROR", "agent id is required");
                        }
                        Err(error) => return TypedResult::error("CONFIG_ERROR", error.to_string()),
                    },
                };
                let client = match AuthClient::new(&profile.base_url) {
                    Ok(client) => client,
                    Err(error) => return TypedResult::error("CONFIG_ERROR", error),
                };
                match revoke_agent(&client, owner_token.expose(), &id).await {
                    Ok(response) => {
                        let _ = manager.delete_agent(&profile);
                        TypedResult::ok(RevokeProfileOutput {
                            id: response.id,
                            revoked: response.revoked,
                        })
                    }
                    Err(error) => TypedResult::error("REVOKE_FAILED", error),
                }
            }
        },
    )
    .description("Revoke an agent id and clear the matching local profile")
    .done()
}

#[derive(Debug, Deserialize, incurs::Options)]
struct ProfileOptions {
    /// Override COMMS_URL for this command.
    url: Option<String>,
    /// Optional named profile. Omit it for the fresh default profile.
    profile: Option<String>,
}

#[derive(Debug, Deserialize, incurs::Options)]
struct SaveOwnerOptions {
    /// Override COMMS_URL for this command.
    url: Option<String>,
    /// Optional named profile. Omit it for the fresh default profile.
    profile: Option<String>,
}

#[derive(Debug, Deserialize, incurs::Options)]
struct EnrollOptions {
    /// Override COMMS_URL for this command.
    url: Option<String>,
    /// Optional named profile. Omit it for the fresh default profile.
    profile: Option<String>,
    /// Label for agents created from this enrollment.
    label: Option<String>,
    /// Profile name shown to the server when joining.
    profile_name: Option<String>,
    /// Enrollment lifetime in seconds; server defaults to 30 days.
    ttl_seconds: Option<i64>,
}

#[derive(Debug, Deserialize, incurs::Options)]
struct JoinOptions {
    /// Override COMMS_URL for this command.
    url: Option<String>,
    /// Optional named profile. Omit it for a fresh ephemeral agent credential.
    profile: Option<String>,
    /// Label for the new agent.
    label: Option<String>,
    /// Enrollment secret override; otherwise the saved enrollment is used.
    enrollment: Option<String>,
}

#[derive(Debug, Deserialize, incurs::Options)]
struct RenewOptions {
    /// Override COMMS_URL for this command.
    url: Option<String>,
    /// Named profile to renew.
    profile: String,
}

#[derive(Debug, Deserialize, incurs::Options)]
struct RevokeOptions {
    /// Override COMMS_URL for this command.
    url: Option<String>,
    /// Optional named profile. Omit it for the default profile.
    profile: Option<String>,
    /// Agent id to revoke; defaults to the saved profile agent id.
    id: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CredentialStatusOutput {
    pub profile: Option<String>,
    pub has_owner: bool,
    pub has_enrollment: bool,
    pub has_agent: bool,
    pub agent_id: Option<String>,
    pub enrollment_id: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct SavedOutput {
    pub profile: Option<String>,
    pub saved: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct EnrollmentOutput {
    pub profile: Option<String>,
    pub enrollment_id: String,
    pub expires_at: i64,
    pub saved: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AgentProfileOutput {
    pub profile: Option<String>,
    pub local_profile: String,
    pub agent_id: String,
    pub enrollment_id: Option<String>,
    pub root_enrollment_id: Option<String>,
    pub expires_at: i64,
    pub renewal_expires_at: Option<i64>,
    pub saved: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct RevokeProfileOutput {
    pub id: String,
    pub revoked: bool,
}

#[derive(Debug, Deserialize)]
struct EnrollmentResponse {
    enrollment_id: String,
    enrollment: String,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
struct JoinResponse {
    agent_id: String,
    token: String,
    renewal: Option<String>,
    expires_at: i64,
    renewal_expires_at: Option<i64>,
    enrollment_id: Option<String>,
    root_enrollment_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RenewResponse {
    agent_id: String,
    token: String,
    renewal: String,
    expires_at: i64,
    renewal_expires_at: i64,
}

#[derive(Debug, Deserialize)]
struct RevokeResponse {
    id: String,
    revoked: bool,
}

fn profile_from(
    env_url: Option<&str>,
    option_url: Option<&str>,
    env_profile: Option<&str>,
    profile: Option<String>,
) -> CredentialProfile {
    profile_from_parts(env_url, option_url, env_profile, profile)
}

pub(crate) fn profile_from_parts(
    env_url: Option<&str>,
    option_url: Option<&str>,
    env_profile: Option<&str>,
    option_profile: Option<String>,
) -> CredentialProfile {
    CredentialProfile::new(
        option_url.or(env_url).unwrap_or(DEFAULT_BASE_URL),
        option_profile.or_else(|| env_profile.map(str::to_owned)),
    )
}

pub(crate) fn store_owner_token(
    store: &dyn crate::credentials::CredentialStore,
    base_url: &str,
    profile: Option<String>,
    owner_token: &str,
) -> Result<SavedOutput, String> {
    let profile = CredentialProfile::new(base_url, profile);
    let owner_token =
        CredentialSecret::new(owner_token.to_string()).map_err(|error| error.to_string())?;
    CredentialProfileManager::new(store)
        .save_owner(&profile, &OwnerCredentials { owner_token })
        .map_err(|error| error.to_string())?;
    Ok(SavedOutput {
        profile: profile.profile,
        saved: true,
    })
}

fn status_for(
    store: &dyn crate::credentials::CredentialStore,
    profile: CredentialProfile,
) -> Result<CredentialStatusOutput, crate::credentials::CredentialError> {
    let manager = CredentialProfileManager::new(store);
    let owner = manager.load_owner(&profile)?;
    let enrollment = manager.load_enrollment(&profile)?;
    let agent = manager.load_agent(&profile)?;
    Ok(CredentialStatusOutput {
        profile: profile.profile,
        has_owner: owner.is_some(),
        has_enrollment: enrollment.is_some(),
        has_agent: agent.is_some(),
        agent_id: agent.as_ref().map(|agent| agent.agent_id.clone()),
        enrollment_id: enrollment.map(|enrollment| enrollment.enrollment_id),
    })
}

fn owner_token(
    store: &dyn crate::credentials::CredentialStore,
    profile: &CredentialProfile,
    env_owner_token: Option<&str>,
) -> Result<CredentialSecret, String> {
    if let Some(token) = env_owner_token {
        return CredentialSecret::new(token.to_string()).map_err(|error| error.to_string());
    }
    let manager = CredentialProfileManager::new(store);
    manager
        .load_owner(profile)
        .and_then(|saved| {
            if saved.is_some() || profile.profile.is_none() {
                Ok(saved)
            } else {
                manager.load_owner(&CredentialProfile::new(profile.base_url.clone(), None))
            }
        })
        .map_err(|error| error.to_string())?
        .map(|credentials| credentials.owner_token)
        .ok_or_else(|| "saved owner token is required".to_string())
}

fn save_agent_response(
    manager: CredentialProfileManager<'_>,
    requested_profile: CredentialProfile,
    response: JoinResponse,
) -> TypedResult<AgentProfileOutput> {
    let local_profile = requested_profile
        .profile
        .clone()
        .unwrap_or_else(|| response.agent_id.clone());
    let storage_profile = CredentialProfile::new(
        requested_profile.base_url.clone(),
        Some(local_profile.clone()),
    );
    let save = match (&response.renewal, &response.renewal_expires_at) {
        (Some(renewal), Some(_)) => CredentialSecret::new(response.token.clone())
            .and_then(|access| {
                CredentialSecret::new(renewal.clone()).map(|renewal| (access, renewal))
            })
            .and_then(|(access, renewal)| {
                manager.save_agent(
                    &storage_profile,
                    &AgentCredentials {
                        agent_id: response.agent_id.clone(),
                        access,
                        renewal,
                        enrollment_id: response.enrollment_id.clone(),
                        root_enrollment_id: response.root_enrollment_id.clone(),
                    },
                )
            }),
        _ => Err(crate::credentials::CredentialError::EmptySecret),
    };

    match save {
        Ok(()) => TypedResult::ok(AgentProfileOutput {
            profile: Some(local_profile.clone()),
            local_profile,
            agent_id: response.agent_id,
            enrollment_id: response.enrollment_id,
            root_enrollment_id: response.root_enrollment_id,
            expires_at: response.expires_at,
            renewal_expires_at: response.renewal_expires_at,
            saved: true,
        }),
        Err(error) => TypedResult::error("AGENT_SAVE_FAILED", error.to_string()),
    }
}

fn save_renew_response(
    manager: CredentialProfileManager<'_>,
    profile: CredentialProfile,
    response: RenewResponse,
) -> TypedResult<AgentProfileOutput> {
    let save = CredentialSecret::new(response.token.clone())
        .and_then(|access| {
            CredentialSecret::new(response.renewal.clone()).map(|renewal| (access, renewal))
        })
        .and_then(|(access, renewal)| {
            manager.save_agent(
                &profile,
                &AgentCredentials {
                    agent_id: response.agent_id.clone(),
                    access,
                    renewal,
                    enrollment_id: None,
                    root_enrollment_id: None,
                },
            )
        });

    match save {
        Ok(()) => {
            let local_profile = profile
                .profile
                .clone()
                .unwrap_or_else(|| response.agent_id.clone());
            TypedResult::ok(AgentProfileOutput {
                profile: Some(local_profile.clone()),
                local_profile,
                agent_id: response.agent_id,
                enrollment_id: None,
                root_enrollment_id: None,
                expires_at: response.expires_at,
                renewal_expires_at: Some(response.renewal_expires_at),
                saved: true,
            })
        }
        Err(error) => TypedResult::error("AGENT_SAVE_FAILED", error.to_string()),
    }
}

async fn create_enrollment(
    client: &AuthClient,
    owner_token: &str,
    options: &EnrollOptions,
) -> Result<EnrollmentResponse, String> {
    let request = with_bearer(
        client
            .client
            .post(endpoint(&client.base_url, "/owner/enrollments")?)
            .json(&json!({
                "label": options.label.as_deref(),
                "profile_name": options.profile_name.as_deref(),
                "ttl_seconds": options.ttl_seconds,
            })),
        Some(owner_token),
    )?;
    decode(send_json_envelope(request).await?)
}

async fn join_enrollment(
    client: &AuthClient,
    enrollment: &str,
    options: &JoinOptions,
) -> Result<JoinResponse, String> {
    decode(
        send_json_envelope(
            client
                .client
                .post(endpoint(&client.base_url, "/agent/join")?)
                .json(&json!({
                    "enrollment": enrollment,
                    "label": options.label.as_deref(),
                    "profile_name": options.profile.as_deref(),
                })),
        )
        .await?,
    )
}

async fn renew_agent(
    client: &AuthClient,
    agent_id: &str,
    renewal: &str,
) -> Result<RenewResponse, String> {
    decode(
        send_json_envelope(
            client
                .client
                .post(endpoint(&client.base_url, "/agent/renew")?)
                .json(&json!({"agent_id": agent_id, "renewal": renewal})),
        )
        .await?,
    )
}

async fn revoke_agent(
    client: &AuthClient,
    owner_token: &str,
    id: &str,
) -> Result<RevokeResponse, String> {
    let request = with_bearer(
        client
            .client
            .post(endpoint(&client.base_url, "/owner/revoke")?)
            .json(&json!({"id": id})),
        Some(owner_token),
    )?;
    decode(send_json_envelope(request).await?)
}
