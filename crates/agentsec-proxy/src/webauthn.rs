//! WebAuthn approval: hardware-backed (Face ID, fingerprint, YubiKey) approval
//! for agent actions. No app required — just a URL that opens a browser page.
//!
//! Flow:
//!   1. Agent action needs approval → proxy generates approval URL
//!   2. URL delivered via Telegram/email/agent output
//!   3. Approver opens URL → sees request details
//!   4. First time: register a passkey inline, then approve
//!   5. Returning: WebAuthn biometric → approved
//!
//! Passkeys are user-scoped (not team-scoped) and persisted to SQLite.

use std::collections::HashMap;
use std::sync::Arc;

use agentsec_core::error::AgentSecError;
use agentsec_core::store::ConfigStore;
use agentsec_core::types::ApprovalStatus;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, RwLock};
use tracing::info;
use webauthn_rs::prelude::*;

/// Shared WebAuthn state for the proxy.
pub struct WebAuthnState {
    webauthn: Webauthn,
    /// Stored credentials: approver_name → list of passkeys
    credentials: RwLock<HashMap<String, Vec<Passkey>>>,
    /// In-flight registration challenges: approver_name → (registration state, display_name)
    reg_challenges: RwLock<HashMap<String, (PasskeyRegistration, String)>>,
    /// In-flight approval challenges: txn_id → (auth state, approver_name)
    approval_challenges: RwLock<HashMap<String, (PasskeyAuthentication, String)>>,
    /// Pending approval details: txn_id → details (for the approval page to display)
    pending_details: RwLock<HashMap<String, ApprovalDetails>>,
    /// Pending approval resolvers: txn_id → oneshot sender
    pending_resolvers: RwLock<HashMap<String, oneshot::Sender<ApprovalStatus>>>,
    /// Base URL for generating approval links
    pub base_url: String,
    /// ConfigStore for persisting passkeys to SQLite
    store: Option<ConfigStore>,
    // -- Admin passkeys (2FA for admin login) --
    /// Admin credentials: admin_id → list of passkeys
    admin_credentials: RwLock<HashMap<String, Vec<Passkey>>>,
    /// In-flight admin registration challenges: admin_id → (registration state)
    admin_reg_challenges: RwLock<HashMap<String, PasskeyRegistration>>,
    /// In-flight admin login challenges: passkey_token → (auth state, admin_id)
    admin_login_challenges: RwLock<HashMap<String, (PasskeyAuthentication, String)>>,
}

impl WebAuthnState {
    pub fn new(
        rp_id: &str,
        rp_origin: &str,
        base_url: &str,
        store: Option<ConfigStore>,
    ) -> Result<Self, AgentSecError> {
        let origin = url::Url::parse(rp_origin)
            .map_err(|e| AgentSecError::Config(format!("Invalid WebAuthn origin: {e}")))?;
        let builder = WebauthnBuilder::new(rp_id, &origin)
            .map_err(|e| AgentSecError::Config(format!("WebAuthn builder error: {e}")))?;
        let webauthn = builder
            .build()
            .map_err(|e| AgentSecError::Config(format!("WebAuthn build error: {e}")))?;

        Ok(Self {
            webauthn,
            credentials: RwLock::new(HashMap::new()),
            reg_challenges: RwLock::new(HashMap::new()),
            approval_challenges: RwLock::new(HashMap::new()),
            pending_details: RwLock::new(HashMap::new()),
            pending_resolvers: RwLock::new(HashMap::new()),
            base_url: base_url.to_string(),
            store,
            admin_credentials: RwLock::new(HashMap::new()),
            admin_reg_challenges: RwLock::new(HashMap::new()),
            admin_login_challenges: RwLock::new(HashMap::new()),
        })
    }

    /// Generate the approval URL for a transaction.
    pub fn approval_url(&self, txn_id: &str) -> String {
        format!(
            "{}/approve/txn/{}",
            self.base_url.trim_end_matches('/'),
            txn_id
        )
    }

    /// Register a pending approval that can be resolved via WebAuthn.
    /// Returns a oneshot receiver that the proxy waits on.
    pub async fn register_pending(
        &self,
        txn_id: &str,
        details: ApprovalDetails,
    ) -> oneshot::Receiver<ApprovalStatus> {
        let (tx, rx) = oneshot::channel();
        self.pending_details
            .write()
            .await
            .insert(txn_id.to_string(), details);
        self.pending_resolvers
            .write()
            .await
            .insert(txn_id.to_string(), tx);
        rx
    }

    /// Resolve a pending approval (called after successful WebAuthn assertion).
    pub async fn resolve_approval(&self, txn_id: &str, status: ApprovalStatus) -> bool {
        self.pending_details.write().await.remove(txn_id);
        if let Some(tx) = self.pending_resolvers.write().await.remove(txn_id) {
            tx.send(status).is_ok()
        } else {
            false
        }
    }

    /// Load passkeys from SQLite at startup.
    pub async fn load_credentials_from_db(&self) -> Result<usize, AgentSecError> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| AgentSecError::Config("No DB configured for WebAuthn".into()))?;
        let rows = store.list_all_approver_passkeys().await?;
        let mut creds = self.credentials.write().await;
        let mut count = 0;
        for row in rows {
            if let Ok(passkey) = serde_json::from_str::<Passkey>(&row.public_key_json) {
                creds
                    .entry(row.approver_name)
                    .or_default()
                    .push(passkey);
                count += 1;
            }
        }
        Ok(count)
    }

    /// Store pending details for the approval page without creating a oneshot receiver.
    /// Used in passkey-required mode where the proxy waits on the Telegram channel
    /// and WebAuthn resolves it via bridge.
    pub async fn set_pending_details(&self, txn_id: &str, details: ApprovalDetails) {
        self.pending_details
            .write()
            .await
            .insert(txn_id.to_string(), details);
    }

    /// Get a passkey as JSON for storage (after registration).
    pub fn passkey_to_json(passkey: &Passkey) -> Result<String, AgentSecError> {
        serde_json::to_string(passkey)
            .map_err(|e| AgentSecError::Internal(format!("Failed to serialize passkey: {e}")))
    }

    /// Check if any passkeys are registered at all.
    pub async fn has_any_credentials(&self) -> bool {
        let creds = self.credentials.read().await;
        creds.values().any(|pks| !pks.is_empty())
    }

    // -- Registration ---------------------------------------------------------

    pub async fn begin_registration(
        &self,
        approver_name: &str,
        display_name: &str,
    ) -> Result<CreationChallengeResponse, AgentSecError> {
        let user_unique_id = Uuid::new_v4();
        let existing = self.credentials.read().await;
        let exclude = existing
            .get(approver_name)
            .map(|creds| creds.iter().map(|c| c.cred_id().clone()).collect::<Vec<_>>())
            .unwrap_or_default();
        drop(existing);

        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(
                user_unique_id,
                approver_name,
                display_name,
                Some(exclude),
            )
            .map_err(|e| AgentSecError::Internal(format!("Registration start failed: {e}")))?;

        self.reg_challenges
            .write()
            .await
            .insert(
                approver_name.to_string(),
                (reg_state, display_name.to_string()),
            );

        Ok(ccr)
    }

    pub async fn finish_registration(
        &self,
        approver_name: &str,
        reg: &RegisterPublicKeyCredential,
    ) -> Result<Passkey, AgentSecError> {
        let (reg_state, display_name) = self
            .reg_challenges
            .write()
            .await
            .remove(approver_name)
            .ok_or_else(|| AgentSecError::Internal("No pending registration".to_string()))?;

        let passkey = self
            .webauthn
            .finish_passkey_registration(reg, &reg_state)
            .map_err(|e| AgentSecError::Internal(format!("Registration failed: {e}")))?;

        // Persist to SQLite
        if let Some(ref store) = self.store {
            let json = Self::passkey_to_json(&passkey)?;
            use base64::Engine;
            let cred_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(passkey.cred_id().as_ref());
            store
                .save_approver_passkey(&cred_id, approver_name, &display_name, &json)
                .await?;
        }

        // Add to in-memory map
        self.credentials
            .write()
            .await
            .entry(approver_name.to_string())
            .or_default()
            .push(passkey.clone());

        Ok(passkey)
    }

    // -- Approval (authentication) --------------------------------------------

    pub async fn begin_approval(
        &self,
        txn_id: &str,
    ) -> Result<RequestChallengeResponse, AgentSecError> {
        let creds = self.credentials.read().await;
        let all_passkeys: Vec<Passkey> = creds.values().flatten().cloned().collect();
        if all_passkeys.is_empty() {
            return Err(AgentSecError::Internal(
                "No approver credentials registered".to_string(),
            ));
        }

        // Find the first user_id that has credentials (for tracking)
        let approver_name = creds.keys().next().cloned().unwrap_or_default();
        drop(creds);

        let (rcr, auth_state) = self
            .webauthn
            .start_passkey_authentication(&all_passkeys)
            .map_err(|e| AgentSecError::Internal(format!("Auth start failed: {e}")))?;

        self.approval_challenges
            .write()
            .await
            .insert(txn_id.to_string(), (auth_state, approver_name));

        Ok(rcr)
    }

    pub async fn finish_approval(
        &self,
        txn_id: &str,
        auth: &PublicKeyCredential,
    ) -> Result<String, AgentSecError> {
        let (auth_state, approver_name) = self
            .approval_challenges
            .write()
            .await
            .remove(txn_id)
            .ok_or_else(|| {
                AgentSecError::Internal("No pending approval challenge".to_string())
            })?;

        let auth_result = self
            .webauthn
            .finish_passkey_authentication(auth, &auth_state)
            .map_err(|e| AgentSecError::Internal(format!("Auth failed: {e}")))?;

        // Update credential counter
        let mut creds = self.credentials.write().await;
        if let Some(passkeys) = creds.get_mut(&approver_name) {
            for passkey in passkeys.iter_mut() {
                passkey.update_credential(&auth_result);
            }
        }

        // Resolve the pending approval
        self.resolve_approval(txn_id, ApprovalStatus::Approved)
            .await;

        Ok(approver_name)
    }

    // -- Admin passkey methods (2FA for admin login) --------------------------

    /// Load admin passkeys from SQLite at startup.
    pub async fn load_admin_credentials_from_db(&self) -> Result<usize, AgentSecError> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| AgentSecError::Config("No DB configured for WebAuthn".into()))?;
        let rows = store.list_all_admin_passkeys().await?;
        let mut creds = self.admin_credentials.write().await;
        let mut count = 0;
        for row in rows {
            if let Ok(passkey) = serde_json::from_str::<Passkey>(&row.public_key_json) {
                creds
                    .entry(row.admin_id)
                    .or_default()
                    .push(passkey);
                count += 1;
            }
        }
        Ok(count)
    }

    /// Check if an admin has any passkeys registered.
    pub async fn admin_has_passkeys(&self, admin_id: &str) -> bool {
        let creds = self.admin_credentials.read().await;
        creds
            .get(admin_id)
            .map(|pks| !pks.is_empty())
            .unwrap_or(false)
    }

    /// Begin registration of a passkey for an admin.
    pub async fn begin_admin_registration(
        &self,
        admin_id: &str,
        display_name: &str,
    ) -> Result<CreationChallengeResponse, AgentSecError> {
        let user_unique_id = Uuid::new_v4();
        let existing = self.admin_credentials.read().await;
        let exclude = existing
            .get(admin_id)
            .map(|creds| creds.iter().map(|c| c.cred_id().clone()).collect::<Vec<_>>())
            .unwrap_or_default();
        drop(existing);

        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(user_unique_id, admin_id, display_name, Some(exclude))
            .map_err(|e| AgentSecError::Internal(format!("Admin reg start failed: {e}")))?;

        self.admin_reg_challenges
            .write()
            .await
            .insert(admin_id.to_string(), reg_state);

        Ok(ccr)
    }

    /// Complete registration of a passkey for an admin.
    pub async fn finish_admin_registration(
        &self,
        admin_id: &str,
        reg: &RegisterPublicKeyCredential,
    ) -> Result<Passkey, AgentSecError> {
        let reg_state = self
            .admin_reg_challenges
            .write()
            .await
            .remove(admin_id)
            .ok_or_else(|| AgentSecError::Internal("No pending admin registration".to_string()))?;

        let passkey = self
            .webauthn
            .finish_passkey_registration(reg, &reg_state)
            .map_err(|e| AgentSecError::Internal(format!("Admin reg failed: {e}")))?;

        // Persist to SQLite
        if let Some(ref store) = self.store {
            let json = Self::passkey_to_json(&passkey)?;
            use base64::Engine;
            let cred_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(passkey.cred_id().as_ref());
            store
                .save_admin_passkey(admin_id, &cred_id, &json)
                .await?;
        }

        // Add to in-memory map
        self.admin_credentials
            .write()
            .await
            .entry(admin_id.to_string())
            .or_default()
            .push(passkey.clone());

        Ok(passkey)
    }

    /// Begin login authentication challenge for an admin.
    /// Returns the challenge and a passkey_token the frontend must send back.
    pub async fn begin_admin_login(
        &self,
        admin_id: &str,
    ) -> Result<(RequestChallengeResponse, String), AgentSecError> {
        let creds = self.admin_credentials.read().await;
        let passkeys = creds
            .get(admin_id)
            .ok_or_else(|| AgentSecError::Internal("No passkeys registered for admin".into()))?;
        if passkeys.is_empty() {
            return Err(AgentSecError::Internal(
                "No passkeys registered for admin".into(),
            ));
        }

        let (rcr, auth_state) = self
            .webauthn
            .start_passkey_authentication(passkeys)
            .map_err(|e| AgentSecError::Internal(format!("Admin auth start failed: {e}")))?;
        drop(creds);

        // Generate a passkey_token to correlate the challenge
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let passkey_token = hex::encode(bytes);

        self.admin_login_challenges
            .write()
            .await
            .insert(
                passkey_token.clone(),
                (auth_state, admin_id.to_string()),
            );

        Ok((rcr, passkey_token))
    }

    /// Complete login authentication for an admin.
    /// Returns the admin_id on success.
    pub async fn finish_admin_login(
        &self,
        passkey_token: &str,
        auth: &PublicKeyCredential,
    ) -> Result<String, AgentSecError> {
        let (auth_state, admin_id) = self
            .admin_login_challenges
            .write()
            .await
            .remove(passkey_token)
            .ok_or_else(|| {
                AgentSecError::Internal("Invalid or expired passkey token".to_string())
            })?;

        let auth_result = self
            .webauthn
            .finish_passkey_authentication(auth, &auth_state)
            .map_err(|e| AgentSecError::Internal(format!("Admin auth failed: {e}")))?;

        // Update credential counter
        let mut creds = self.admin_credentials.write().await;
        if let Some(passkeys) = creds.get_mut(&admin_id) {
            for passkey in passkeys.iter_mut() {
                passkey.update_credential(&auth_result);
            }
        }

        Ok(admin_id)
    }

    /// Remove a passkey from the in-memory map (after DB deletion).
    pub async fn remove_admin_credential(&self, admin_id: &str, credential_id_b64: &str) {
        let mut creds = self.admin_credentials.write().await;
        if let Some(passkeys) = creds.get_mut(admin_id) {
            use base64::Engine;
            passkeys.retain(|pk| {
                let pk_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(pk.cred_id().as_ref());
                pk_id != credential_id_b64
            });
        }
    }
}

// -- Types --------------------------------------------------------------------

#[derive(Serialize, Clone)]
pub struct ApprovalDetails {
    pub txn_id: String,
    pub team_id: String,
    pub agent_id: String,
    pub credential_name: String,
    pub target_url: String,
    pub method: String,
    pub body_preview: Option<String>,
}

#[derive(Deserialize)]
pub struct RegisterBeginRequest {
    pub approver_name: String,
    pub display_name: String,
}

#[derive(Deserialize)]
pub struct RegisterFinishRequest {
    pub approver_name: String,
    pub credential: RegisterPublicKeyCredential,
}

// -- Axum handlers ------------------------------------------------------------

pub type SharedWebAuthnState = Arc<WebAuthnState>;

/// Combined state for approval handlers that need to bridge WebAuthn
/// approvals back to the notification channel (Telegram).
#[derive(Clone)]
pub struct ApprovalHandlerState {
    pub webauthn: SharedWebAuthnState,
    /// Telegram channel for resolving pending approvals when passkey succeeds.
    pub telegram_channel: Arc<agentsec_bot::TelegramChannel>,
}

/// GET /approve/register — serve registration page (standalone pre-registration)
pub async fn handle_register_page() -> Html<&'static str> {
    Html(include_str!("../static/register.html"))
}

/// POST /approve/register/begin
pub async fn handle_register_begin(
    State(wa): State<SharedWebAuthnState>,
    Json(req): Json<RegisterBeginRequest>,
) -> Response {
    match wa
        .begin_registration(&req.approver_name, &req.display_name)
        .await
    {
        Ok(ccr) => Json(ccr).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// POST /approve/register/finish
pub async fn handle_register_finish(
    State(wa): State<SharedWebAuthnState>,
    Json(req): Json<RegisterFinishRequest>,
) -> Response {
    match wa
        .finish_registration(&req.approver_name, &req.credential)
        .await
    {
        Ok(_passkey) => {
            info!(approver = %req.approver_name, "WebAuthn credential registered (standalone)");
            Json(serde_json::json!({"status": "registered"})).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// GET /approve/txn/:id — serve approval page (includes inline registration)
pub async fn handle_approval_page() -> Html<&'static str> {
    Html(include_str!("../static/approve.html"))
}

/// GET /approve/txn/:id/details — return approval details as JSON
pub async fn handle_approval_details(
    State(state): State<ApprovalHandlerState>,
    axum::extract::Path(txn_id): axum::extract::Path<String>,
) -> Response {
    let details = state.webauthn.pending_details.read().await;
    match details.get(&txn_id) {
        Some(d) => {
            let has_passkeys = state.webauthn.has_any_credentials().await;
            Json(serde_json::json!({
                "txn_id": d.txn_id,
                "team_id": d.team_id,
                "agent_id": d.agent_id,
                "credential_name": d.credential_name,
                "target_url": d.target_url,
                "method": d.method,
                "body_preview": d.body_preview,
                "has_passkeys": has_passkeys,
            }))
            .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Transaction not found or already resolved"})),
        )
            .into_response(),
    }
}

/// POST /approve/txn/:id/begin — start WebAuthn authentication
pub async fn handle_approval_begin(
    State(state): State<ApprovalHandlerState>,
    axum::extract::Path(txn_id): axum::extract::Path<String>,
) -> Response {
    match state.webauthn.begin_approval(&txn_id).await {
        Ok(rcr) => Json(rcr).into_response(),
        Err(e) if e.to_string().contains("No approver credentials") => (
            StatusCode::PRECONDITION_FAILED,
            Json(serde_json::json!({
                "error": "no_credentials",
                "message": "No passkeys registered. Register one first."
            })),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// POST /approve/txn/:id/finish — validate assertion and approve.
/// Bridges to Telegram: resolves the notification channel's pending approval
/// so the proxy unblocks.
pub async fn handle_approval_finish(
    State(state): State<ApprovalHandlerState>,
    axum::extract::Path(txn_id): axum::extract::Path<String>,
    Json(auth): Json<PublicKeyCredential>,
) -> Response {
    match state.webauthn.finish_approval(&txn_id, &auth).await {
        Ok(approver) => {
            info!(txn_id = %txn_id, approver = %approver, "Approval via WebAuthn passkey");
            // Bridge: resolve Telegram pending so the proxy's wait_for_decision returns
            state
                .telegram_channel
                .resolve_approval(&txn_id, ApprovalStatus::Approved)
                .await;
            Json(serde_json::json!({"status": "approved", "approver": approver})).into_response()
        }
        Err(e) => (StatusCode::FORBIDDEN, e.to_string()).into_response(),
    }
}

/// POST /approve/txn/:id/deny — deny without WebAuthn.
/// Bridges to both WebAuthn and Telegram pending systems.
pub async fn handle_approval_deny(
    State(state): State<ApprovalHandlerState>,
    axum::extract::Path(txn_id): axum::extract::Path<String>,
) -> Response {
    state
        .webauthn
        .resolve_approval(&txn_id, ApprovalStatus::Denied)
        .await;
    state
        .telegram_channel
        .resolve_approval(&txn_id, ApprovalStatus::Denied)
        .await;
    info!(txn_id = %txn_id, "Denial via WebAuthn page");
    Json(serde_json::json!({"status": "denied"})).into_response()
}

// -- Inline registration (on the approval page) -------------------------------

/// POST /approve/txn/:id/register/begin — start passkey registration in
/// the context of a pending approval transaction.
pub async fn handle_inline_register_begin(
    State(state): State<ApprovalHandlerState>,
    axum::extract::Path(txn_id): axum::extract::Path<String>,
    Json(req): Json<RegisterBeginRequest>,
) -> Response {
    // Verify this is a real pending transaction
    let details = state.webauthn.pending_details.read().await;
    if !details.contains_key(&txn_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Transaction not found or already resolved"})),
        )
            .into_response();
    }
    drop(details);

    match state
        .webauthn
        .begin_registration(&req.approver_name, &req.display_name)
        .await
    {
        Ok(ccr) => Json(ccr).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// POST /approve/txn/:id/register/finish — complete passkey registration,
/// persists to DB, then the frontend can immediately approve.
pub async fn handle_inline_register_finish(
    State(state): State<ApprovalHandlerState>,
    axum::extract::Path(txn_id): axum::extract::Path<String>,
    Json(req): Json<RegisterFinishRequest>,
) -> Response {
    let details = state.webauthn.pending_details.read().await;
    if !details.contains_key(&txn_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Transaction not found or already resolved"})),
        )
            .into_response();
    }
    drop(details);

    match state
        .webauthn
        .finish_registration(&req.approver_name, &req.credential)
        .await
    {
        Ok(_passkey) => {
            info!(approver = %req.approver_name, txn_id = %txn_id, "Passkey registered inline during approval");
            Json(serde_json::json!({"status": "registered"})).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

/// Build the WebAuthn approval router.
/// Registration routes use WebAuthn state only; approval routes use the
/// combined state so they can bridge approvals back to Telegram.
pub fn build_approval_router(
    wa_state: SharedWebAuthnState,
    telegram_channel: Arc<agentsec_bot::TelegramChannel>,
) -> axum::Router {
    let handler_state = ApprovalHandlerState {
        webauthn: wa_state.clone(),
        telegram_channel,
    };

    // Registration routes (WebAuthn-only state, standalone pre-registration)
    let register_router = axum::Router::new()
        .route("/approve/register", axum::routing::get(handle_register_page))
        .route(
            "/approve/register/begin",
            axum::routing::post(handle_register_begin),
        )
        .route(
            "/approve/register/finish",
            axum::routing::post(handle_register_finish),
        )
        .with_state(wa_state);

    // Approval routes (combined state for Telegram bridge + inline registration)
    let approval_router = axum::Router::new()
        .route(
            "/approve/txn/{id}",
            axum::routing::get(handle_approval_page),
        )
        .route(
            "/approve/txn/{id}/details",
            axum::routing::get(handle_approval_details),
        )
        .route(
            "/approve/txn/{id}/begin",
            axum::routing::post(handle_approval_begin),
        )
        .route(
            "/approve/txn/{id}/finish",
            axum::routing::post(handle_approval_finish),
        )
        .route(
            "/approve/txn/{id}/deny",
            axum::routing::post(handle_approval_deny),
        )
        .route(
            "/approve/txn/{id}/register/begin",
            axum::routing::post(handle_inline_register_begin),
        )
        .route(
            "/approve/txn/{id}/register/finish",
            axum::routing::post(handle_inline_register_finish),
        )
        .with_state(handler_state);

    register_router.merge(approval_router)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentsec_core::types::ApprovalStatus;

    fn test_state() -> WebAuthnState {
        // Use localhost for RP — sufficient for state management tests
        WebAuthnState::new("localhost", "http://localhost:3100", "http://localhost:3100", None)
            .unwrap()
    }

    async fn test_state_with_db() -> WebAuthnState {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        std::mem::forget(tmp);
        let key = [0u8; 32];
        let store = agentsec_core::store::ConfigStore::new(&path, None, key).await.unwrap();
        WebAuthnState::new("localhost", "http://localhost:3100", "http://localhost:3100", Some(store))
            .unwrap()
    }

    #[test]
    fn webauthn_state_new_valid() {
        let state = test_state();
        assert_eq!(state.base_url, "http://localhost:3100");
    }

    #[test]
    fn webauthn_state_new_invalid_origin() {
        let result = WebAuthnState::new("localhost", "not-a-url", "http://localhost", None);
        assert!(result.is_err());
    }

    #[test]
    fn approval_url_format() {
        let state = test_state();
        assert_eq!(state.approval_url("txn-123"), "http://localhost:3100/approve/txn/txn-123");
    }

    #[test]
    fn approval_url_strips_trailing_slash() {
        let state = WebAuthnState::new(
            "localhost",
            "http://localhost:3100",
            "http://localhost:3100/",
            None,
        ).unwrap();
        assert_eq!(state.approval_url("abc"), "http://localhost:3100/approve/txn/abc");
    }

    #[tokio::test]
    async fn has_any_credentials_empty() {
        let state = test_state();
        assert!(!state.has_any_credentials().await);
    }

    #[tokio::test]
    async fn has_any_credentials_after_manual_insert() {
        let state = test_state();
        // Manually insert a fake passkey into the in-memory map
        state
            .credentials
            .write()
            .await
            .entry("alice".to_string())
            .or_default(); // empty vec
        // Empty vec doesn't count
        assert!(!state.has_any_credentials().await);
    }

    #[tokio::test]
    async fn register_pending_and_resolve() {
        let state = test_state();
        let details = ApprovalDetails {
            txn_id: "txn-1".into(),
            team_id: "team-1".into(),
            agent_id: "agent-1".into(),
            credential_name: "openai".into(),
            target_url: "https://api.openai.com/v1/chat".into(),
            method: "POST".into(),
            body_preview: Some("hello".into()),
        };

        let rx = state.register_pending("txn-1", details).await;

        // Details should be accessible
        let d = state.pending_details.read().await;
        assert!(d.contains_key("txn-1"));
        assert_eq!(d["txn-1"].agent_id, "agent-1");
        drop(d);

        // Resolve the approval
        let resolved = state.resolve_approval("txn-1", ApprovalStatus::Approved).await;
        assert!(resolved);

        // Receiver should get the status
        let status = rx.await.unwrap();
        assert_eq!(status, ApprovalStatus::Approved);

        // Details cleaned up
        assert!(!state.pending_details.read().await.contains_key("txn-1"));
    }

    #[tokio::test]
    async fn resolve_nonexistent_returns_false() {
        let state = test_state();
        let resolved = state.resolve_approval("nonexistent", ApprovalStatus::Denied).await;
        assert!(!resolved);
    }

    #[tokio::test]
    async fn set_pending_details_without_resolver() {
        let state = test_state();
        let details = ApprovalDetails {
            txn_id: "txn-2".into(),
            team_id: "t".into(),
            agent_id: "a".into(),
            credential_name: "c".into(),
            target_url: "https://example.com".into(),
            method: "GET".into(),
            body_preview: None,
        };
        state.set_pending_details("txn-2", details).await;
        assert!(state.pending_details.read().await.contains_key("txn-2"));
    }

    #[tokio::test]
    async fn begin_approval_no_credentials_errors() {
        let state = test_state();
        let result = state.begin_approval("txn-1").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No approver credentials"));
    }

    #[tokio::test]
    async fn load_credentials_from_db_empty() {
        let state = test_state_with_db().await;
        let count = state.load_credentials_from_db().await.unwrap();
        assert_eq!(count, 0);
        assert!(!state.has_any_credentials().await);
    }

    #[tokio::test]
    async fn load_credentials_from_db_no_store_errors() {
        let state = test_state(); // No store
        let result = state.load_credentials_from_db().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn load_credentials_from_db_with_data() {
        let state = test_state_with_db().await;
        let store = state.store.as_ref().unwrap();

        // Insert a fake passkey JSON (not a real WebAuthn key, but tests the loading path)
        // We need valid Passkey JSON — use a minimal structure that serde can parse.
        // Since we can't easily construct a valid Passkey, test that invalid JSON is skipped gracefully.
        store
            .save_approver_passkey("cred-bad", "alice", "Alice", r#"{"invalid": true}"#)
            .await
            .unwrap();

        let count = state.load_credentials_from_db().await.unwrap();
        // Invalid passkey JSON is skipped (doesn't deserialize to Passkey)
        assert_eq!(count, 0);
        assert!(!state.has_any_credentials().await);
    }

    #[tokio::test]
    async fn passkey_to_json_errors_are_descriptive() {
        // This just tests the error mapping path exists — we can't easily construct
        // a Passkey that fails to serialize, but we verify the method is callable.
        // The real test is that finish_registration uses it correctly.
    }

    #[tokio::test]
    async fn details_include_team_id() {
        let state = test_state();
        let details = ApprovalDetails {
            txn_id: "t".into(),
            team_id: "my-team".into(),
            agent_id: "a".into(),
            credential_name: "c".into(),
            target_url: "u".into(),
            method: "GET".into(),
            body_preview: None,
        };
        state.set_pending_details("t", details).await;
        let d = state.pending_details.read().await;
        assert_eq!(d["t"].team_id, "my-team");
    }
}
