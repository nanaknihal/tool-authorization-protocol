use async_trait::async_trait;

use crate::config::ApprovalRouting;
use crate::error::AgentSecError;
use crate::types::{ApprovalStatus, ProxyRequest};

/// Per-request approval context. Carries routing overrides from
/// the credential's policy config to the approval channel.
#[derive(Debug, Clone, Default)]
pub struct ApprovalContext {
    /// The team that owns the credential (for notification channel lookups).
    pub team_id: Option<String>,
    /// The credential name triggering the approval.
    pub credential_name: String,
    /// Per-credential routing overrides (chat_id, allowed_approvers, etc.).
    /// None = use global defaults.
    pub routing: Option<ApprovalRouting>,
    /// Optional WebAuthn approval URL for secure hardware-backed approval.
    pub approval_url: Option<String>,
    /// When true, approval MUST go through passkey — notification channel
    /// suppresses inline approve buttons and shows only the passkey link.
    pub require_passkey: bool,
}

/// Approval channel trait. Telegram is the v0.1 implementation.
/// Slack, iOS app, ntfy can implement this for v0.2+.
#[async_trait]
pub trait ApprovalChannel: Send + Sync {
    /// Send an approval request to the human approver.
    /// Returns a channel-specific request ID for tracking.
    async fn send_approval_request(
        &self,
        request: &ProxyRequest,
        credential_description: &str,
        context: &ApprovalContext,
    ) -> Result<String, AgentSecError>;

    /// Wait for an approval decision. Blocks until approved, denied, or timeout.
    async fn wait_for_decision(
        &self,
        channel_request_id: &str,
        timeout_seconds: u64,
    ) -> Result<ApprovalStatus, AgentSecError>;

    /// Format a human-readable message for the approval request.
    fn format_message(&self, request: &ProxyRequest, credential_description: &str) -> String;
}
