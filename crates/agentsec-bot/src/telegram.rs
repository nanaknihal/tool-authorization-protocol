//! Telegram approval channel implementing the ApprovalChannel trait.

use std::collections::HashMap;
use std::sync::Arc;

use agentsec_core::approval::{ApprovalChannel, ApprovalContext};
use agentsec_core::error::AgentSecError;
use agentsec_core::types::{ApprovalStatus, ProxyRequest};
use tokio::sync::{oneshot, Mutex};
use tracing::{error, info, warn};

use crate::config::TelegramConfig;

/// Session trust key: (agent_id, credential_name)
type TrustKey = (String, String);

pub struct TelegramChannel {
    config: TelegramConfig,
    http: reqwest::Client,
    /// Pending approvals: channel_request_id -> oneshot sender
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<ApprovalStatus>>>>,
    /// Receivers held until wait_for_decision: channel_request_id -> oneshot receiver
    receivers: Arc<Mutex<HashMap<String, oneshot::Receiver<ApprovalStatus>>>>,
    /// Trusted sessions: (agent_id, credential_name) that have been trust-approved
    trusted_sessions: Arc<Mutex<HashMap<TrustKey, bool>>>,
    /// Per-request allowed approvers: channel_request_id -> list of allowed user IDs.
    /// Empty list = anyone can approve.
    allowed_approvers: Arc<Mutex<HashMap<String, Vec<String>>>>,
    /// Sent message references: request_id -> (chat_id, message_id) for editing after decision
    sent_messages: Arc<Mutex<HashMap<String, (String, i64)>>>,
}

impl TelegramChannel {
    pub fn new(config: TelegramConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
            pending: Arc::new(Mutex::new(HashMap::new())),
            receivers: Arc::new(Mutex::new(HashMap::new())),
            trusted_sessions: Arc::new(Mutex::new(HashMap::new())),
            allowed_approvers: Arc::new(Mutex::new(HashMap::new())),
            sent_messages: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a pending approval. Stores the receiver for wait_for_decision.
    async fn register_pending(&self, request_id: &str) {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(request_id.to_string(), tx);
        self.receivers
            .lock()
            .await
            .insert(request_id.to_string(), rx);
    }

    /// Handle a Telegram callback query (from webhook).
    /// `callback_data` is "approve:{request_id}" or "deny:{request_id}".
    /// `user_id` is the Telegram user ID of the person who clicked the button.
    pub async fn handle_callback(
        &self,
        callback_data: &str,
        callback_query_id: &str,
        user_id: Option<&str>,
    ) -> Result<(), AgentSecError> {
        let (action, request_id) = callback_data
            .split_once(':')
            .ok_or_else(|| AgentSecError::Internal("Invalid callback data format".to_string()))?;

        let status = match action {
            "approve" => ApprovalStatus::Approved,
            "deny" => ApprovalStatus::Denied,
            _ => {
                return Err(AgentSecError::Internal(format!(
                    "Unknown callback action: {action}"
                )));
            }
        };

        // Check if this user is allowed to approve this request
        if let Some(uid) = user_id {
            let approvers = self.allowed_approvers.lock().await;
            if let Some(allowed) = approvers.get(request_id) {
                if !allowed.is_empty() && !allowed.contains(&uid.to_string()) {
                    warn!(request_id, user_id = uid, "User not in allowed_approvers list");
                    // Answer the callback with a rejection message
                    let answer_url = format!(
                        "https://api.telegram.org/bot{}/answerCallbackQuery",
                        self.config.bot_token
                    );
                    let _ = self
                        .http
                        .post(&answer_url)
                        .json(&serde_json::json!({
                            "callback_query_id": callback_query_id,
                            "text": "You are not authorized to approve this request.",
                            "show_alert": true,
                        }))
                        .send()
                        .await;
                    return Ok(());
                }
            }
        }

        // Answer the callback query (removes loading state from button)
        let answer_url = format!(
            "https://api.telegram.org/bot{}/answerCallbackQuery",
            self.config.bot_token
        );
        let answer_text = match &status {
            ApprovalStatus::Approved => "Approved",
            ApprovalStatus::Denied => "Denied",
            _ => "Processed",
        };
        let _ = self
            .http
            .post(&answer_url)
            .json(&serde_json::json!({
                "callback_query_id": callback_query_id,
                "text": answer_text,
            }))
            .send()
            .await;

        // Edit the original message to show the decision and remove buttons
        if let Some((chat_id, message_id)) = self.sent_messages.lock().await.remove(request_id) {
            let status_text = match &status {
                ApprovalStatus::Approved => "\u{2705} APPROVED",
                ApprovalStatus::Denied => "\u{274c} DENIED",
                _ => "PROCESSED",
            };
            let approver_info = user_id.map(|uid| format!(" by user {uid}")).unwrap_or_default();
            let edit_url = format!(
                "https://api.telegram.org/bot{}/editMessageReplyMarkup",
                self.config.bot_token
            );
            // Remove inline keyboard
            let _ = self.http.post(&edit_url)
                .json(&serde_json::json!({
                    "chat_id": chat_id,
                    "message_id": message_id,
                    "reply_markup": { "inline_keyboard": [] },
                }))
                .send()
                .await;

            // Append status as a reply
            let reply_url = format!(
                "https://api.telegram.org/bot{}/sendMessage",
                self.config.bot_token
            );
            let _ = self.http.post(&reply_url)
                .json(&serde_json::json!({
                    "chat_id": chat_id,
                    "text": format!("{status_text}{approver_info}"),
                    "reply_to_message_id": message_id,
                }))
                .send()
                .await;
        }

        // Resolve the pending approval
        if let Some(tx) = self.pending.lock().await.remove(request_id) {
            // Clean up allowed_approvers for this request
            self.allowed_approvers.lock().await.remove(request_id);
            if tx.send(status.clone()).is_err() {
                warn!(request_id, "Approval receiver already dropped");
            }
        } else {
            warn!(request_id, "No pending approval found for callback");
        }

        info!(request_id, ?status, "Approval callback processed");
        Ok(())
    }

    /// Simulate receiving an approve callback (for testing / webhook handling).
    pub async fn resolve_approval(&self, request_id: &str, status: ApprovalStatus) -> bool {
        if let Some(tx) = self.pending.lock().await.remove(request_id) {
            tx.send(status).is_ok()
        } else {
            false
        }
    }

    /// Mark an agent+credential as trusted for this session.
    pub async fn trust_session(&self, agent_id: &str, credential_name: &str) {
        self.trusted_sessions
            .lock()
            .await
            .insert((agent_id.to_string(), credential_name.to_string()), true);
    }

    /// Check if an agent+credential is trusted for this session.
    pub async fn should_auto_trust(&self, agent_id: &str, credential_name: &str) -> bool {
        self.trusted_sessions
            .lock()
            .await
            .contains_key(&(agent_id.to_string(), credential_name.to_string()))
    }

    /// Check if a request ID is pending.
    pub async fn is_pending(&self, request_id: &str) -> bool {
        self.pending.lock().await.contains_key(request_id)
    }

    /// Start a long-polling loop that fetches Telegram updates via getUpdates.
    /// This is the alternative to webhooks — works when the proxy isn't publicly accessible.
    /// Spawns a background tokio task. Call once at startup.
    ///
    /// If `store` is provided, text commands (/whitelist, /unwhitelist) are handled.
    pub fn start_polling(self: &Arc<Self>, store: Option<Arc<agentsec_core::store::ConfigStore>>) {
        let channel = self.clone();
        tokio::spawn(async move {
            let mut offset: i64 = 0;
            // Clear any existing webhook so Telegram delivers updates via getUpdates
            let delete_url = format!(
                "https://api.telegram.org/bot{}/deleteWebhook",
                channel.config.bot_token
            );
            let _ = channel.http.post(&delete_url).send().await;
            info!("Telegram polling started");
            loop {
                let url = format!(
                    "https://api.telegram.org/bot{}/getUpdates?offset={}&timeout=30&allowed_updates=[\"callback_query\",\"message\"]",
                    channel.config.bot_token, offset
                );
                let resp = match channel.http.get(&url).timeout(std::time::Duration::from_secs(35)).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("Telegram getUpdates error: {e}");
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        continue;
                    }
                };
                let body: serde_json::Value = match resp.json().await {
                    Ok(b) => b,
                    Err(e) => {
                        warn!("Telegram getUpdates parse error: {e}");
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        continue;
                    }
                };
                if let Some(results) = body.get("result").and_then(|r| r.as_array()) {
                    for update in results {
                        // Advance offset past this update
                        if let Some(uid) = update.get("update_id").and_then(|u| u.as_i64()) {
                            offset = uid + 1;
                        }
                        // Process callback_query (inline keyboard button press)
                        if let Some(cq) = update.get("callback_query") {
                            let data = cq.get("data").and_then(|d| d.as_str()).unwrap_or("");
                            let cq_id = cq.get("id").and_then(|d| d.as_str()).unwrap_or("");
                            let user_id = cq.get("from")
                                .and_then(|f| f.get("id"))
                                .and_then(|id| id.as_i64())
                                .map(|id| id.to_string());
                            if let Err(e) = channel.handle_callback(data, cq_id, user_id.as_deref()).await {
                                warn!(error = %e, "Telegram callback handling failed");
                            }
                        }
                        // Process text messages (admin commands)
                        if let Some(message) = update.get("message") {
                            let text = message.get("text").and_then(|t| t.as_str()).unwrap_or("");
                            let chat_id = message.get("chat").and_then(|c| c.get("id")).and_then(|id| id.as_i64());
                            let user_id = message.get("from").and_then(|f| f.get("id")).and_then(|id| id.as_i64());
                            let admin_chat_id = channel.config.chat_id.parse::<i64>().unwrap_or(0);

                            // Allow commands from:
                            // 1. The configured admin group chat
                            // 2. DMs from the TELEGRAM_ALLOWED_USER_ID (platform operator)
                            let allowed_user_id = std::env::var("TELEGRAM_ALLOWED_USER_ID")
                                .ok()
                                .and_then(|s| s.parse::<i64>().ok());
                            let is_admin_chat = chat_id == Some(admin_chat_id);
                            let is_allowed_dm = allowed_user_id.is_some() && user_id == allowed_user_id;

                            if !is_admin_chat && !is_allowed_dm {
                                continue;
                            }

                            let reply_chat = chat_id.unwrap_or(admin_chat_id);
                            if let Some(ref store) = store {
                                channel.handle_text_command(text, reply_chat, store).await;
                            }
                        }
                    }
                }
            }
        });
    }

    /// Handle admin text commands from Telegram.
    async fn handle_text_command(&self, text: &str, chat_id: i64, store: &agentsec_core::store::ConfigStore) {
        if let Some(email) = text.strip_prefix("/whitelist ").map(|s| s.trim().to_lowercase()) {
            if email.contains('@') && email.contains('.') {
                match store.add_to_whitelist(&email, "pro").await {
                    Ok(()) => self.send_reply(chat_id, &format!("✓ {} whitelisted (Pro tier)", email)).await,
                    Err(e) => self.send_reply(chat_id, &format!("✗ Failed: {e}")).await,
                }
            } else {
                self.send_reply(chat_id, "✗ Invalid email format").await;
            }
        } else if let Some(email) = text.strip_prefix("/unwhitelist ").map(|s| s.trim().to_lowercase()) {
            match store.remove_from_whitelist(&email).await {
                Ok(()) => self.send_reply(chat_id, &format!("✓ {} removed from whitelist", email)).await,
                Err(e) => self.send_reply(chat_id, &format!("✗ Failed: {e}")).await,
            }
        } else if text.trim() == "/whitelist" {
            match store.list_whitelist().await {
                Ok(entries) if entries.is_empty() => self.send_reply(chat_id, "No whitelisted emails.").await,
                Ok(entries) => {
                    let list = entries.iter().map(|(e, t)| format!("• {} ({})", e, t)).collect::<Vec<_>>().join("\n");
                    self.send_reply(chat_id, &format!("Whitelisted emails:\n{list}")).await;
                }
                Err(e) => self.send_reply(chat_id, &format!("✗ Failed: {e}")).await,
            }
        }
    }

    /// Send a plain text reply to a Telegram chat.
    async fn send_reply(&self, chat_id: i64, text: &str) {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.config.bot_token);
        let _ = self.http.post(&url)
            .json(&serde_json::json!({
                "chat_id": chat_id,
                "text": text,
            }))
            .send()
            .await;
    }

    /// Send a message via Telegram Bot API with inline keyboard.
    /// `target_chat_id` overrides the default chat_id if provided.
    /// When `passkey_url` is Some, the Approve button becomes a URL button
    /// pointing to the passkey page instead of a callback.
    async fn send_telegram_message(
        &self,
        text: &str,
        request_id: &str,
        target_chat_id: Option<&str>,
        passkey_url: Option<&str>,
    ) -> Result<(), AgentSecError> {
        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            self.config.bot_token
        );

        let chat_id = target_chat_id.unwrap_or(&self.config.chat_id);

        let inline_keyboard = if let Some(passkey_url) = passkey_url {
            // Passkey required: URL button for approve, callback for deny
            serde_json::json!({
                "inline_keyboard": [[
                    {
                        "text": "\u{1f510} Approve (Passkey)",
                        "url": passkey_url
                    },
                    {
                        "text": "\u{274c} Deny",
                        "callback_data": format!("deny:{request_id}")
                    }
                ]]
            })
        } else {
            // Standard: callback buttons for both
            serde_json::json!({
                "inline_keyboard": [[
                    {
                        "text": "\u{2705} Approve",
                        "callback_data": format!("approve:{request_id}")
                    },
                    {
                        "text": "\u{274c} Deny",
                        "callback_data": format!("deny:{request_id}")
                    }
                ]]
            })
        };

        let payload = serde_json::json!({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "reply_markup": inline_keyboard,
        });

        let resp = self
            .http
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AgentSecError::Internal(format!("Telegram API error: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_else(|_| "unknown".to_string());
            error!(%status, %body, "Telegram sendMessage failed");
            return Err(AgentSecError::Internal(format!(
                "Telegram API returned {status}: {body}"
            )));
        }

        // Capture the message ID so we can edit it after approval/denial
        if let Ok(body) = resp.json::<serde_json::Value>().await {
            if let Some(message_id) = body["result"]["message_id"].as_i64() {
                self.sent_messages
                    .lock()
                    .await
                    .insert(request_id.to_string(), (chat_id.to_string(), message_id));
            }
        }

        Ok(())
    }
}

/// Format a human-readable approval message for Telegram.
pub fn format_message(request: &ProxyRequest, credential_description: &str) -> String {
    let mut msg = String::new();

    msg.push_str("<b>\u{1f511} Approval Request</b>\n\n");
    msg.push_str(&format!(
        "<b>Agent:</b> {}\n",
        escape_html(&request.agent_id)
    ));

    for placeholder in &request.placeholders {
        msg.push_str(&format!(
            "<b>Credential:</b> {}\n",
            escape_html(&placeholder.credential_name)
        ));
    }

    msg.push_str(&format!(
        "<b>Description:</b> {}\n",
        escape_html(credential_description)
    ));
    msg.push_str(&format!("<b>Method:</b> {:?}\n", request.method));
    msg.push_str(&format!(
        "<b>Target:</b> {}\n",
        escape_html(&request.target_url)
    ));

    if let Some(body) = &request.body {
        if let Ok(body_str) = std::str::from_utf8(body) {
            let display_body = decode_base64_fields(body_str);
            let truncated = if display_body.len() > 1500 {
                format!("{}...", &display_body[..1500])
            } else {
                display_body
            };
            msg.push_str(&format!(
                "\n<b>Body:</b>\n<pre>{}</pre>",
                escape_html(&truncated)
            ));
        }
    }

    msg
}

/// If a JSON body contains string values that look like base64, decode them inline
/// so approval messages are human-readable. Works for any API (Gmail raw, etc.).
fn decode_base64_fields(body: &str) -> String {
    // Try to parse as JSON
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(body) else {
        return body.to_string();
    };

    fn decode_value(v: &mut serde_json::Value) {
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD, URL_SAFE};
        use base64::Engine;

        match v {
            serde_json::Value::String(s) => {
                // Heuristic: if the string is >40 chars and looks like base64, try decoding
                if s.len() > 40 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_' || c == '\n' || c == '\r') {
                    // Try URL-safe base64 first (Gmail uses this), then standard
                    let decoded = URL_SAFE_NO_PAD.decode(s.as_bytes())
                        .or_else(|_| URL_SAFE.decode(s.as_bytes()))
                        .or_else(|_| STANDARD.decode(s.as_bytes()));
                    if let Ok(bytes) = decoded {
                        if let Ok(text) = String::from_utf8(bytes) {
                            // Only replace if the result is readable text
                            if text.chars().all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t') {
                                *s = text;
                            }
                        }
                    }
                }
            }
            serde_json::Value::Object(map) => {
                for (_, val) in map.iter_mut() {
                    decode_value(val);
                }
            }
            serde_json::Value::Array(arr) => {
                for val in arr.iter_mut() {
                    decode_value(val);
                }
            }
            _ => {}
        }
    }

    decode_value(&mut value);
    // Pretty-print the decoded JSON
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| body.to_string())
}

/// Escape HTML special characters for Telegram HTML parse mode.
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[async_trait::async_trait]
impl ApprovalChannel for TelegramChannel {
    async fn send_approval_request(
        &self,
        request: &ProxyRequest,
        credential_description: &str,
        context: &ApprovalContext,
    ) -> Result<String, AgentSecError> {
        let channel_request_id = request.id.to_string();

        // Register pending approval
        self.register_pending(&channel_request_id).await;

        // Store allowed_approvers for validation during callback
        if let Some(routing) = &context.routing {
            if !routing.allowed_approvers.is_empty() {
                self.allowed_approvers
                    .lock()
                    .await
                    .insert(channel_request_id.clone(), routing.allowed_approvers.clone());
            }
        }

        // Determine target chat_id: per-credential override or global default
        let target_chat_id = context
            .routing
            .as_ref()
            .and_then(|r| r.telegram.as_ref())
            .and_then(|t| t.chat_id.as_deref());

        let mut message = self.format_message(request, credential_description);

        // Determine passkey URL for the inline keyboard button
        let passkey_url = if context.require_passkey {
            // Passkey required: the URL goes into the keyboard button
            if context.approval_url.is_some() {
                message.push_str("\n\n\u{1f510} <b>Passkey required</b> — tap the button below to approve with biometric/YubiKey.");
            }
            context.approval_url.as_deref()
        } else if let Some(ref url) = context.approval_url {
            // Passkey optional: show link in message body, keep normal approve button
            message.push_str(&format!(
                "\n\n\u{1f512} <a href=\"{}\">Secure approval (biometric/YubiKey)</a>",
                escape_html(url)
            ));
            None
        } else {
            None
        };

        // Send to Telegram
        if let Err(e) = self
            .send_telegram_message(&message, &channel_request_id, target_chat_id, passkey_url)
            .await
        {
            // Clean up pending on failure
            self.pending.lock().await.remove(&channel_request_id);
            self.receivers.lock().await.remove(&channel_request_id);
            self.allowed_approvers.lock().await.remove(&channel_request_id);
            return Err(e);
        }

        info!(
            request_id = %channel_request_id,
            agent_id = %request.agent_id,
            credential = %context.credential_name,
            chat_id = target_chat_id.unwrap_or(&self.config.chat_id),
            "Approval request sent to Telegram"
        );

        Ok(channel_request_id)
    }

    async fn wait_for_decision(
        &self,
        channel_request_id: &str,
        timeout_seconds: u64,
    ) -> Result<ApprovalStatus, AgentSecError> {
        let rx = self
            .receivers
            .lock()
            .await
            .remove(channel_request_id)
            .ok_or_else(|| {
                AgentSecError::Internal(format!(
                    "No pending receiver for request {channel_request_id}"
                ))
            })?;

        match tokio::time::timeout(std::time::Duration::from_secs(timeout_seconds), rx).await {
            Ok(Ok(status)) => Ok(status),
            Ok(Err(_)) => {
                // Sender dropped without sending
                Err(AgentSecError::Internal(
                    "Approval sender dropped".to_string(),
                ))
            }
            Err(_) => {
                // Timeout — clean up pending
                self.pending.lock().await.remove(channel_request_id);
                Err(AgentSecError::ApprovalTimeout(timeout_seconds))
            }
        }
    }

    fn format_message(&self, request: &ProxyRequest, credential_description: &str) -> String {
        format_message(request, credential_description)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentsec_core::types::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn test_request() -> ProxyRequest {
        ProxyRequest {
            id: Uuid::new_v4(),
            agent_id: "openclaw".to_string(),
            target_url: "https://api.twitter.com/2/tweets".to_string(),
            method: HttpMethod::Post,
            headers: vec![
                (
                    "Authorization".to_string(),
                    "Bearer <CREDENTIAL:twitter-holonym>".to_string(),
                ),
                ("Content-Type".to_string(), "application/json".to_string()),
            ],
            body: Some(br#"{"text":"Hello world"}"#.to_vec()),
            content_type: Some("application/json".to_string()),
            placeholders: vec![Placeholder {
                credential_name: "twitter-holonym".to_string(),
                position: PlaceholderPosition::Header("Authorization".to_string()),
            }],
            received_at: Utc::now(),
        }
    }

    #[test]
    fn format_message_contains_all_fields() {
        let request = test_request();
        let msg = format_message(&request, "Twitter API for @HolonymHQ");
        assert!(msg.contains("openclaw"));
        assert!(msg.contains("twitter-holonym"));
        assert!(msg.contains("Twitter API for @HolonymHQ"));
        assert!(msg.contains("Post")); // HttpMethod debug format
        assert!(msg.contains("api.twitter.com"));
        assert!(msg.contains("Hello world"));
    }

    #[test]
    fn format_message_truncates_long_body() {
        let mut request = test_request();
        let long_body = "a".repeat(2000);
        request.body = Some(long_body.as_bytes().to_vec());
        let msg = format_message(&request, "Test");
        // Body preview should be truncated at 1500 chars
        let body_section = msg.split("<b>Body:</b>").nth(1).unwrap_or("");
        assert!(body_section.contains("..."));
    }

    #[test]
    fn format_message_handles_no_body() {
        let mut request = test_request();
        request.body = None;
        let msg = format_message(&request, "Test");
        // Should not contain Body section with content
        assert!(!msg.contains("<pre>"));
    }

    #[test]
    fn format_message_escapes_html() {
        let mut request = test_request();
        request.body = Some(b"<script>alert('xss')</script>".to_vec());
        let msg = format_message(&request, "Test");
        assert!(msg.contains("&lt;script&gt;"));
        assert!(!msg.contains("<script>"));
    }

    #[test]
    fn trait_implementation_compiles() {
        fn assert_impl<T: agentsec_core::approval::ApprovalChannel>() {}
        assert_impl::<TelegramChannel>();
    }

    #[tokio::test]
    async fn pending_approval_tracked() {
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::new(config);
        channel.register_pending("req-123").await;
        assert!(channel.is_pending("req-123").await);
    }

    #[tokio::test]
    async fn approval_resolved_removes_pending() {
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::new(config);
        channel.register_pending("req-456").await;

        assert!(channel.is_pending("req-456").await);
        channel
            .resolve_approval("req-456", ApprovalStatus::Approved)
            .await;
        assert!(!channel.is_pending("req-456").await);

        // The receiver should have the status
        let rx = channel.receivers.lock().await.remove("req-456").unwrap();
        let status = rx.await.unwrap();
        assert_eq!(status, ApprovalStatus::Approved);
    }

    #[tokio::test]
    async fn deny_callback_sends_denied() {
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::new(config);
        channel.register_pending("req-789").await;

        channel
            .resolve_approval("req-789", ApprovalStatus::Denied)
            .await;

        let rx = channel.receivers.lock().await.remove("req-789").unwrap();
        let status = rx.await.unwrap();
        assert_eq!(status, ApprovalStatus::Denied);
    }

    #[tokio::test]
    async fn trust_session_tracks_agent() {
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::new(config);

        assert!(
            !channel
                .should_auto_trust("openclaw", "twitter-holonym")
                .await
        );

        channel.trust_session("openclaw", "twitter-holonym").await;

        assert!(
            channel
                .should_auto_trust("openclaw", "twitter-holonym")
                .await
        );
        // Different credential should not be trusted
        assert!(!channel.should_auto_trust("openclaw", "gmail-holonym").await);
    }

    #[tokio::test]
    async fn handle_callback_parses_approve() {
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::new(config);
        channel.register_pending("req-abc").await;

        // handle_callback will try to call Telegram API (answerCallbackQuery) which will fail,
        // but the approval resolution should still work
        let _ = channel.handle_callback("approve:req-abc", "cq-123", None).await;

        assert!(!channel.is_pending("req-abc").await);
        let rx = channel.receivers.lock().await.remove("req-abc").unwrap();
        let status = rx.await.unwrap();
        assert_eq!(status, ApprovalStatus::Approved);
    }

    #[tokio::test]
    async fn handle_callback_parses_deny() {
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::new(config);
        channel.register_pending("req-def").await;

        let _ = channel.handle_callback("deny:req-def", "cq-456", None).await;

        let rx = channel.receivers.lock().await.remove("req-def").unwrap();
        let status = rx.await.unwrap();
        assert_eq!(status, ApprovalStatus::Denied);
    }

    #[tokio::test]
    async fn handle_callback_invalid_format() {
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::new(config);
        let result = channel.handle_callback("invalid", "cq-789", None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn wait_for_decision_times_out() {
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = TelegramChannel::new(config);
        channel.register_pending("req-timeout").await;

        // Wait with 1 second timeout — nobody resolves it
        let result = channel.wait_for_decision("req-timeout", 1).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            AgentSecError::ApprovalTimeout(secs) => assert_eq!(secs, 1),
            other => panic!("Expected ApprovalTimeout, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn wait_for_decision_receives_approval() {
        let config = TelegramConfig {
            bot_token: "test".to_string(),
            chat_id: "-100".to_string(),
        };
        let channel = Arc::new(TelegramChannel::new(config));

        channel.register_pending("req-fast").await;

        // Spawn a task that resolves the approval after a short delay
        let ch = channel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            ch.resolve_approval("req-fast", ApprovalStatus::Approved)
                .await;
        });

        let result = channel.wait_for_decision("req-fast", 5).await;
        assert_eq!(result.unwrap(), ApprovalStatus::Approved);
    }
}
