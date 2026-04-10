use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Config types shared across crates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSecConfig {
    pub version: u32,
    pub credentials: HashMap<String, CredentialConfig>,
    pub approval: ApprovalConfig,
    pub policies: HashMap<String, PolicyConfig>,
    pub agents: HashMap<String, AgentConfig>,
}

/// How the proxy routes requests for this credential.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorType {
    /// Substitute credential value into the Authorization header,
    /// forward directly to X-TAP-Target. Default for backward compat.
    #[default]
    Direct,
    /// Route through the sidecar at `api_base`. Proxy constructs
    /// X-OAuth-Credential and X-OAuth-Target headers for the sidecar.
    Sidecar,
}

/// A credential entry (value stored encrypted in DB).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfig {
    pub description: String,
    pub api_base: Option<String>,
    #[serde(default)]
    pub substitution: SubstitutionConfig,
    /// Routing strategy. Defaults to `direct` for backward compatibility.
    #[serde(default)]
    pub connector: ConnectorType,
    /// When true and connector=sidecar, X-TAP-Target is treated as a
    /// relative path and prepended with api_base. Used for protocol translators
    /// (e.g., Telegram) where the target is a sidecar-internal endpoint.
    #[serde(default)]
    pub relative_target: bool,
    /// Auth header format for direct connectors. Defaults to "Bearer {value}".
    /// Use "{value}" as placeholder for the credential value.
    /// Examples: "Bearer {value}", "Bot {value}", "token={value}"
    #[serde(default)]
    pub auth_header_format: Option<String>,
    /// Explicit auth bindings for credentials that authenticate via headers
    /// other than Authorization. If empty, direct credentials fall back to
    /// Authorization with auth_header_format / Bearer semantics.
    #[serde(default)]
    pub auth_bindings: Vec<AuthBinding>,
}

/// A configured auth location that may receive a credential value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthBinding {
    pub header: String,
    pub format: String,
}

/// Where credential placeholders can be substituted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubstitutionConfig {
    /// Always true — placeholders in headers are always allowed.
    #[serde(default = "default_true")]
    pub headers: bool,
    /// Opt-in: allow placeholders in the request body.
    #[serde(default)]
    pub body: bool,
    /// When body=true, restrict to these content types.
    #[serde(default = "default_body_content_types")]
    pub body_content_types: Vec<String>,
}

impl Default for SubstitutionConfig {
    fn default() -> Self {
        Self {
            headers: true,
            body: false,
            body_content_types: default_body_content_types(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_body_content_types() -> Vec<String> {
    vec![
        "application/x-www-form-urlencoded".to_string(),
        "application/json".to_string(),
    ]
}

/// Approval channel config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalConfig {
    pub channel: String, // "telegram" for v0.1
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_approvals")]
    pub default_approvals_required: u32,
}

fn default_timeout() -> u64 {
    300
}

fn default_approvals() -> u32 {
    1
}

/// Per-credential policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// HTTP methods to auto-approve (e.g., ["GET"]).
    #[serde(default)]
    pub auto_approve: Vec<String>,
    /// HTTP methods requiring approval (e.g., ["POST", "PUT", "DELETE"]).
    #[serde(default)]
    pub require_approval: Vec<String>,
    /// URL patterns that are always auto-approved regardless of method.
    /// Matched as substring against the target URL.
    /// Example: ["/v1/search", "/v2/tweets/search"] auto-approves POST to search endpoints.
    #[serde(default)]
    pub auto_approve_urls: Vec<String>,
    /// Per-credential approval routing overrides.
    #[serde(default)]
    pub approval: Option<ApprovalRouting>,
}

/// Per-credential approval routing. Overrides the global approval config.
/// Channel-agnostic fields (allowed_approvers) apply to any channel.
/// Channel-specific blocks (telegram, slack, etc.) override routing for that channel.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApprovalRouting {
    /// User/account IDs that can approve requests for this credential.
    /// Empty = anyone in the channel can approve (default behavior).
    #[serde(default)]
    pub allowed_approvers: Vec<String>,
    /// Require WebAuthn passkey (biometric/YubiKey) for approval.
    /// When true, the notification channel (Telegram, Slack, etc.) sends a
    /// passkey URL instead of an inline approve button. Denial still works
    /// via inline button or the passkey page.
    #[serde(default)]
    pub require_passkey: bool,
    /// Telegram-specific routing overrides.
    #[serde(default)]
    pub telegram: Option<TelegramRouting>,
    /// Slack-specific routing overrides (future).
    #[serde(default)]
    pub slack: Option<SlackRouting>,
    /// Mobile app routing overrides (future).
    #[serde(default)]
    pub mobile: Option<MobileRouting>,
}

/// Telegram-specific approval routing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramRouting {
    /// Override chat_id for this credential's approval messages.
    pub chat_id: Option<String>,
}

/// Slack-specific approval routing (future).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackRouting {
    /// Slack channel to send approval messages to.
    pub channel: Option<String>,
}

/// Mobile app approval routing (future).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileRouting {
    /// Device IDs or user IDs to send push notifications to.
    #[serde(default)]
    pub device_ids: Vec<String>,
}

/// Telegram notification channel config (stored as JSON in notification_channels table).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramChannelConfig {
    pub chat_id: String,
}

/// An agent that can connect to the proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub description: Option<String>,
    /// Credential names this agent is allowed to use.
    pub credentials: Vec<String>,
    /// Max requests per hour (None = unlimited).
    #[serde(default)]
    pub rate_limit_per_hour: Option<u64>,
}

/// Validate that all agent credential references exist in the credentials section,
/// and that connector config is consistent.
pub fn validate(config: &AgentSecConfig) -> Result<(), crate::error::AgentSecError> {
    for (agent_name, agent_config) in &config.agents {
        for cred_name in &agent_config.credentials {
            if !config.credentials.contains_key(cred_name) {
                return Err(crate::error::AgentSecError::Config(format!(
                    "agent '{}' references credential '{}' which does not exist",
                    agent_name, cred_name
                )));
            }
        }
    }
    // Validate connector config consistency
    for (cred_name, cred_config) in &config.credentials {
        if cred_config.connector == ConnectorType::Sidecar && cred_config.api_base.is_none() {
            return Err(crate::error::AgentSecError::Config(format!(
                "credential '{}' has connector=sidecar but no api_base",
                cred_name
            )));
        }
        if cred_config.relative_target && cred_config.connector != ConnectorType::Sidecar {
            return Err(crate::error::AgentSecError::Config(format!(
                "credential '{}' has relative_target=true but connector is not sidecar",
                cred_name
            )));
        }
    }
    Ok(())
}
