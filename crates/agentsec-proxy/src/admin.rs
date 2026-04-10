//! Admin authentication and management API.
//!
//! Admins are humans — separate from agents. They authenticate with
//! email + password + passkey (WebAuthn). Agents use API keys.

use agentsec_core::config::AuthBinding;
use agentsec_core::error::AgentSecError;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::db_state::DbState;

// ---------------------------------------------------------------------------
// Password hashing (argon2)
// ---------------------------------------------------------------------------

/// Hash a password with argon2id.
pub fn hash_password(password: &str) -> Result<String, AgentSecError> {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AgentSecError::Internal(format!("Password hash failed: {e}")))?;
    Ok(hash.to_string())
}

/// Verify a password against an argon2id hash.
pub fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::{
        password_hash::{PasswordHash, PasswordVerifier},
        Argon2,
    };
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

// ---------------------------------------------------------------------------
// Session tokens
// ---------------------------------------------------------------------------

/// Generate a random 32-byte hex session token.
pub fn generate_session_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// SHA-256 hash of a session token (stored in DB, never the raw token).
pub fn hash_session_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Email verification codes
// ---------------------------------------------------------------------------

/// Generate a 6-digit verification code.
pub fn generate_verification_code() -> String {
    use rand::Rng;
    let code: u32 = rand::thread_rng().gen_range(100_000..1_000_000);
    format!("{code}")
}

/// SHA-256 hash of a verification code.
pub fn hash_verification_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Admin session extractor
// ---------------------------------------------------------------------------

/// Authenticated admin from a valid session token.
#[derive(Debug, Clone)]
pub struct AuthenticatedAdmin {
    pub id: String,
    pub team_id: String,
    pub email: String,
}

/// Extract and validate admin session from Authorization header.
pub async fn authenticate_admin(
    headers: &HeaderMap,
    db_state: &DbState,
) -> Result<AuthenticatedAdmin, (StatusCode, Json<serde_json::Value>)> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing Authorization: Bearer <token> header"})),
            )
        })?;

    let token_hash = hash_session_token(token);
    let admin = db_state
        .store()
        .validate_session(&token_hash)
        .await
        .map_err(|e| {
            warn!("Session validation error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Session validation failed"})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid or expired session"})),
            )
        })?;

    if !admin.email_verified {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Email not verified"})),
        ));
    }

    Ok(AuthenticatedAdmin {
        id: admin.id,
        team_id: admin.team_id,
        email: admin.email,
    })
}

// ---------------------------------------------------------------------------
// Request/response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SignupRequest {
    pub team_name: String,
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct VerifyEmailRequest {
    pub email: String,
    pub code: String,
}

#[derive(Deserialize)]
pub struct ResendVerificationRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct CreateCheckoutRequest {
    pub tier: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

use crate::proxy::AppState;

/// POST /signup — create a team and admin account.
pub async fn handle_signup(
    State(state): State<AppState>,
    Json(req): Json<SignupRequest>,
) -> Response {
    // Validate project name
    let team_name = req.team_name.trim().to_lowercase();
    if team_name.len() < 3 || team_name.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Project name must be 3-64 characters"})),
        )
            .into_response();
    }
    if !team_name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Project name must be lowercase alphanumeric with hyphens"})),
        )
            .into_response();
    }

    // Validate email (basic check)
    let email = req.email.trim().to_lowercase();
    if !email.contains('@') || !email.contains('.') {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid email format"})),
        )
            .into_response();
    }

    // Validate password
    if req.password.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Password must be at least 8 characters"})),
        )
            .into_response();
    }

    let store = state.db_state.store();

    // Check whitelist (managed hosting MVP)
    let whitelist_entry = store.get_whitelist_entry(&email).await.unwrap_or(None);
    let signup_tier = if let Some((_, tier)) = &whitelist_entry {
        tier.clone()
    } else {
        // Check if whitelist enforcement is enabled
        if std::env::var("AGENTSEC_REQUIRE_WHITELIST").unwrap_or_default() == "true" {
            return (StatusCode::FORBIDDEN, Json(json!({"error": "Managed hosting is in early access. Request access at toolsec.dev"}))).into_response();
        }
        "free".to_string()
    };

    // Check if email already exists
    if let Ok(Some(existing)) = store.get_admin_by_email(&email).await {
        if !existing.email_verified {
            // Account exists but unverified — let the user resend verification
            return (StatusCode::CONFLICT, Json(json!({
                "error": "Account already exists but is unverified. Use 'Resend Code' to get a new verification code.",
                "email": email,
                "unverified": true,
            }))).into_response();
        }
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "Email already registered"})),
        )
            .into_response();
    }

    // Check project name uniqueness
    if let Ok(Some(_)) = store.get_team_by_name(&team_name).await {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "Project name already taken"})),
        )
            .into_response();
    }

    // Hash password
    let password_hash = match hash_password(&req.password) {
        Ok(h) => h,
        Err(e) => {
            warn!("Password hash error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Internal error"})),
            )
                .into_response();
        }
    };

    // Create team
    let team_id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = store.create_team(&team_id, &team_name).await {
        warn!("Team creation error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to create team"})),
        )
            .into_response();
    }

    // Set tier if whitelisted
    if signup_tier != "free" {
        let _ = store.update_team_tier(&team_id, &signup_tier).await;
    }

    // Create admin
    let admin_id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = store
        .create_admin(&admin_id, &team_id, &email, &password_hash)
        .await
    {
        warn!("Admin creation error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to create admin"})),
        )
            .into_response();
    }

    // Generate and send verification code (always — even whitelisted users must verify email ownership)
    let code = generate_verification_code();
    let code_hash = hash_verification_code(&code);
    let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(15)).to_rfc3339();

    if let Err(e) = store
        .create_email_verification(&code_hash, &admin_id, &expires_at)
        .await
    {
        warn!("Verification creation error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to create verification"})),
        )
            .into_response();
    }

    // Send verification email via Resend
    let email_error = match crate::email::send_verification_email(&email, &code, &team_name).await {
        Ok(()) => None,
        Err(e) => {
            warn!("Email send error: {e}");
            Some(format!("{e}"))
        }
    };

    let message = if email_error.is_some() {
        format!("Verification code could not be delivered to {email}. Please contact support.")
    } else {
        format!("Verification code sent to {email}. Check your inbox.")
    };

    let mut resp = json!({
        "team_id": team_id,
        "team_name": team_name,
        "admin_id": admin_id,
        "email": email,
        "tier": signup_tier,
        "email_verified": false,
        "message": message,
    });
    if let Some(err) = email_error {
        resp["email_error"] = serde_json::Value::String(err);
    }

    (StatusCode::CREATED, Json(resp)).into_response()
}

/// POST /verify-email — verify email with 6-digit code.
/// Returns a passkey_setup_token for mandatory passkey registration.
pub async fn handle_verify_email(
    State(state): State<AppState>,
    Json(req): Json<VerifyEmailRequest>,
) -> Response {
    let code_hash = hash_verification_code(&req.code);

    match state
        .db_state
        .store()
        .validate_email_verification(&code_hash)
        .await
    {
        Ok(Some(admin_id)) => {
            // Generate a passkey_setup_token (10 min TTL) for mandatory passkey registration
            let setup_token = generate_session_token();
            let setup_token_hash = hash_session_token(&setup_token);
            let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();

            // Store as a short-lived session (same table, short TTL)
            if let Err(e) = state
                .db_state
                .store()
                .create_session(&setup_token_hash, &admin_id, &expires_at)
                .await
            {
                warn!("Setup token creation error: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Failed to create setup token"})),
                )
                    .into_response();
            }

            Json(json!({
                "verified": true,
                "passkey_setup_token": setup_token,
                "admin_id": admin_id,
            }))
            .into_response()
        }
        Ok(None) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Invalid or expired code"})),
        )
            .into_response(),
        Err(e) => {
            warn!("Verification error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Verification failed"})),
            )
                .into_response()
        }
    }
}

/// POST /resend-verification — resend a verification code to an unverified email.
pub async fn handle_resend_verification(
    State(state): State<AppState>,
    Json(req): Json<ResendVerificationRequest>,
) -> Response {
    let email = req.email.trim().to_lowercase();
    let store = state.db_state.store();

    let admin = match store.get_admin_by_email(&email).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "No account found with that email"})),
            )
                .into_response();
        }
        Err(e) => {
            warn!("Resend lookup error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Lookup failed"})),
            )
                .into_response();
        }
    };

    if admin.email_verified {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Email already verified. You can log in."})),
        )
            .into_response();
    }

    let code = generate_verification_code();
    let code_hash = hash_verification_code(&code);
    let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(15)).to_rfc3339();

    if let Err(e) = store
        .create_email_verification(&code_hash, &admin.id, &expires_at)
        .await
    {
        warn!("Verification creation error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to create verification"})),
        )
            .into_response();
    }

    // Get team name for the email
    let team_name = match store.get_team(&admin.team_id).await {
        Ok(Some(t)) => t.name,
        _ => "your team".to_string(),
    };

    match crate::email::send_verification_email(&email, &code, &team_name).await {
        Ok(()) => Json(json!({
            "message": format!("Verification code sent to {email}."),
            "email": email,
        }))
        .into_response(),
        Err(e) => {
            warn!("Email resend error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": format!("Failed to send email: {e}"),
                })),
            )
                .into_response()
        }
    }
}

/// POST /login — authenticate with email + password.
/// Always returns a WebAuthn challenge (passkey is mandatory 2FA).
/// Frontend must complete the challenge via POST /login/passkey.
pub async fn handle_login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Response {
    let email = req.email.trim().to_lowercase();
    let store = state.db_state.store();

    // Find admin by email
    let admin = match store.get_admin_by_email(&email).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid credentials"})),
            )
                .into_response();
        }
        Err(e) => {
            warn!("Login lookup error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Login failed"})),
            )
                .into_response();
        }
    };

    // Verify password
    if !verify_password(&req.password, &admin.password_hash) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid credentials"})),
        )
            .into_response();
    }

    // Check email verified
    if !admin.email_verified {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Email not verified. Check your inbox."})),
        )
            .into_response();
    }

    // Check if admin has passkeys — if not, they need to set up first
    let wa = match state.webauthn_state.as_ref() {
        Some(wa) => wa,
        None => {
            // WebAuthn not configured — fall back to password-only (legacy/self-hosted)
            let token = generate_session_token();
            let token_hash = hash_session_token(&token);
            let expires_at = (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();
            if let Err(e) = store
                .create_session(&token_hash, &admin.id, &expires_at)
                .await
            {
                warn!("Session creation error: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Failed to create session"})),
                )
                    .into_response();
            }
            return Json(json!({
                "session_token": token,
                "admin_id": admin.id,
                "team_id": admin.team_id,
                "expires_at": expires_at,
            }))
            .into_response();
        }
    };

    if !wa.admin_has_passkeys(&admin.id).await {
        // Admin has no passkeys — they need to set up. Issue a setup token.
        let setup_token = generate_session_token();
        let setup_token_hash = hash_session_token(&setup_token);
        let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339();
        if let Err(e) = store
            .create_session(&setup_token_hash, &admin.id, &expires_at)
            .await
        {
            warn!("Setup token creation error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Internal error"})),
            )
                .into_response();
        }
        return Json(json!({
            "needs_passkey_setup": true,
            "passkey_setup_token": setup_token,
            "admin_id": admin.id,
        }))
        .into_response();
    }

    // Generate WebAuthn challenge
    match wa.begin_admin_login(&admin.id).await {
        Ok((challenge, passkey_token)) => Json(json!({
            "requires_passkey": true,
            "challenge": challenge,
            "passkey_token": passkey_token,
            "admin_id": admin.id,
        }))
        .into_response(),
        Err(e) => {
            warn!("WebAuthn challenge error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to generate security key challenge"})),
            )
                .into_response()
        }
    }
}

/// POST /logout — invalidate the current session.
pub async fn handle_logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let token = match headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        Some(t) => t.to_string(),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing token"})),
            )
                .into_response();
        }
    };

    let token_hash = hash_session_token(&token);
    let _ = state.db_state.store().delete_session(&token_hash).await;

    Json(json!({"logged_out": true})).into_response()
}

// ---------------------------------------------------------------------------
// Admin CRUD helpers
// ---------------------------------------------------------------------------

/// Macro-like helper to authenticate admin and extract team_id, or return error response.
macro_rules! require_admin {
    ($state:expr, $headers:expr) => {
        match authenticate_admin(&$headers, &$state.db_state).await {
            Ok(admin) => admin,
            Err(resp) => return resp.into_response(),
        }
    };
}

// ---------------------------------------------------------------------------
// Credential management
// ---------------------------------------------------------------------------

/// GET /admin/credentials — list team's credentials (never returns values).
pub async fn handle_list_credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let admin = require_admin!(state, headers);
    let store = state.db_state.store();

    match store.list_credentials(&admin.team_id).await {
        Ok(creds) => {
            let list: Vec<serde_json::Value> = creds
                .iter()
                .map(|c| {
                    json!({
                        "name": c.name,
                        "description": c.description,
                        "connector": c.connector,
                        "api_base": c.api_base,
                        "relative_target": c.relative_target,
                        "auth_header_format": c.auth_header_format,
                        "auth_bindings": c.auth_bindings_json.as_deref().and_then(|raw| serde_json::from_str::<Vec<AuthBinding>>(raw).ok()).unwrap_or_default(),
                        "has_value": true, // DB doesn't easily tell us if value is set without decrypting
                    })
                })
                .collect();
            Json(json!({"credentials": list})).into_response()
        }
        Err(e) => {
            warn!("List credentials error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to list credentials"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct CreateCredentialRequest {
    pub name: String,
    pub description: String,
    pub connector: Option<String>,
    pub api_base: Option<String>,
    pub relative_target: Option<bool>,
    pub auth_header_format: Option<String>,
    pub auth_bindings: Option<Vec<AuthBinding>>,
    pub value: Option<String>,
}

/// POST /admin/credentials — create a credential (optionally with value).
pub async fn handle_create_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateCredentialRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    let store = state.db_state.store();

    // Check tier limits
    if let Ok(Some(team)) = store.get_team(&admin.team_id).await {
        let limits = get_tier_limits(&team.tier);
        if let Some(max) = limits.max_credentials {
            if let Ok(creds) = store.list_credentials(&admin.team_id).await {
                if creds.len() >= max {
                    return (StatusCode::PAYMENT_REQUIRED, Json(json!({"error": format!("Credential limit reached ({}). Upgrade your plan.", max)}))).into_response();
                }
            }
        }
    }

    let connector = req.connector.as_deref().unwrap_or("direct");
    let auth_bindings_json = req
        .auth_bindings
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Invalid auth_bindings: {e}")})),
            )
                .into_response()
        });
    let auth_bindings_json = match auth_bindings_json {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    if let Err(e) = store
        .create_credential(
            &admin.team_id,
            &req.name,
            &req.description,
            connector,
            req.api_base.as_deref(),
            req.relative_target.unwrap_or(false),
            req.auth_header_format.as_deref(),
            auth_bindings_json.as_deref(),
        )
        .await
    {
        let msg = format!("Failed to create credential: {e}");
        return (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response();
    }

    // Set value if provided (write-only — will never be returned)
    if let Some(ref value) = req.value {
        // For Google OAuth credentials the client sends only the refresh token.
        // Bundle the platform's OAuth client_id/secret server-side so they
        // never appear in client code or transit.
        let final_value = if connector == "sidecar" {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(value) {
                if parsed.get("refresh_token").is_some() && parsed.get("client_id").is_none() {
                    let cid = std::env::var("GOOGLE_OAUTH_CLIENT_ID").unwrap_or_default();
                    let csec = std::env::var("GOOGLE_OAUTH_CLIENT_SECRET").unwrap_or_default();
                    if !cid.is_empty() && !csec.is_empty() {
                        serde_json::json!({
                            "client_id": cid,
                            "client_secret": csec,
                            "refresh_token": parsed["refresh_token"],
                        })
                        .to_string()
                    } else {
                        value.clone()
                    }
                } else {
                    value.clone()
                }
            } else {
                value.clone()
            }
        } else {
            value.clone()
        };
        if let Err(e) = store
            .set_credential_value(&admin.team_id, &req.name, final_value.as_bytes())
            .await
        {
            warn!("Set credential value error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to set credential value"})),
            )
                .into_response();
        }
    }

    (
        StatusCode::CREATED,
        Json(json!({"name": req.name, "created": true})),
    )
        .into_response()
}

/// DELETE /admin/credentials/:name
pub async fn handle_delete_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    match state
        .db_state
        .store()
        .delete_credential(&admin.team_id, &name)
        .await
    {
        Ok(()) => Json(json!({"deleted": true})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Agent management
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateAgentRequest {
    pub id: String,
    pub description: Option<String>,
    pub rate_limit_per_hour: Option<i64>,
    pub roles: Option<Vec<String>>,
    pub credentials: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct UpdateAgentRequest {
    pub roles: Option<Vec<String>>,
    pub credentials: Option<Vec<String>>,
}

/// GET /admin/agents — list agents.
pub async fn handle_list_agents(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = require_admin!(state, headers);
    match state.db_state.store().list_agents(&admin.team_id).await {
        Ok(agents) => {
            let list: Vec<serde_json::Value> = agents
                .iter()
                .map(|a| {
                    json!({
                        "id": a.id,
                        "description": a.description,
                        "enabled": a.enabled,
                        "rate_limit_per_hour": a.rate_limit_per_hour,
                        "created_at": a.created_at,
                    })
                })
                .collect();
            Json(json!({"agents": list})).into_response()
        }
        Err(e) => {
            warn!("List agents error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to list agents"})),
            )
                .into_response()
        }
    }
}

/// POST /admin/agents — create an agent. Returns the API key (shown once).
pub async fn handle_create_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateAgentRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    let store = state.db_state.store();

    // Check tier limits
    if let Ok(Some(team)) = store.get_team(&admin.team_id).await {
        let limits = get_tier_limits(&team.tier);
        if let Some(max) = limits.max_agents {
            if let Ok(agents) = store.list_agents(&admin.team_id).await {
                if agents.len() >= max {
                    return (StatusCode::PAYMENT_REQUIRED, Json(json!({"error": format!("Agent limit reached ({}). Upgrade your plan.", max)}))).into_response();
                }
            }
        }
    }

    // Generate API key and hash
    let api_key = generate_session_token(); // Same random generation
    let key_hash = crate::auth::hash_api_key(&api_key);

    if let Err(e) = store
        .create_agent(
            &admin.team_id,
            &req.id,
            req.description.as_deref(),
            &key_hash,
            req.rate_limit_per_hour,
        )
        .await
    {
        let msg = format!("Failed to create agent: {e}");
        return (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response();
    }

    // Assign roles
    if let Some(ref roles) = req.roles {
        for role in roles {
            if let Err(e) = store
                .assign_role_to_agent(&admin.team_id, &req.id, role)
                .await
            {
                warn!("Role assignment error: {e}");
            }
        }
    }

    // Assign direct credentials
    if let Some(ref creds) = req.credentials {
        for cred in creds {
            if let Err(e) = store
                .add_direct_credential(&admin.team_id, &req.id, cred)
                .await
            {
                warn!("Credential assignment error: {e}");
            }
        }
    }

    (
        StatusCode::CREATED,
        Json(json!({
            "id": req.id,
            "api_key": api_key,
            "message": "Save this API key — it will not be shown again."
        })),
    )
        .into_response()
}

/// GET /admin/agents/:id — get agent details + effective credentials.
pub async fn handle_get_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    let store = state.db_state.store();

    match store.get_agent(&admin.team_id, &id).await {
        Ok(Some(agent)) => {
            let effective = store
                .get_agent_effective_credentials(&admin.team_id, &id)
                .await
                .unwrap_or_default();
            let mut sorted: Vec<_> = effective.into_iter().collect();
            sorted.sort();
            let direct_creds = store
                .get_agent_direct_credentials(&admin.team_id, &id)
                .await
                .unwrap_or_default();
            let roles = store
                .get_agent_roles(&admin.team_id, &id)
                .await
                .unwrap_or_default();

            Json(json!({
                "id": agent.id,
                "description": agent.description,
                "enabled": agent.enabled,
                "rate_limit_per_hour": agent.rate_limit_per_hour,
                "created_at": agent.created_at,
                "effective_credentials": sorted,
                "credentials": direct_creds,
                "roles": roles,
            }))
            .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Agent not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// PUT /admin/agents/:id — update an agent's credentials and roles.
pub async fn handle_update_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(req): Json<UpdateAgentRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    let store = state.db_state.store();

    // Verify agent exists
    if let Ok(None) | Err(_) = store.get_agent(&admin.team_id, &id).await {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Agent not found"})),
        )
            .into_response();
    }

    // Sync credentials: diff current vs desired
    if let Some(ref desired_creds) = req.credentials {
        let current = store
            .get_agent_direct_credentials(&admin.team_id, &id)
            .await
            .unwrap_or_default();
        let desired: std::collections::HashSet<&str> =
            desired_creds.iter().map(|s| s.as_str()).collect();
        let current_set: std::collections::HashSet<&str> =
            current.iter().map(|s| s.as_str()).collect();
        for add in desired.difference(&current_set) {
            let _ = store.add_direct_credential(&admin.team_id, &id, add).await;
        }
        for remove in current_set.difference(&desired) {
            let _ = store
                .remove_direct_credential(&admin.team_id, &id, remove)
                .await;
        }
    }

    // Sync roles
    if let Some(ref desired_roles) = req.roles {
        let current = store
            .get_agent_roles(&admin.team_id, &id)
            .await
            .unwrap_or_default();
        let desired: std::collections::HashSet<&str> =
            desired_roles.iter().map(|s| s.as_str()).collect();
        let current_set: std::collections::HashSet<&str> =
            current.iter().map(|s| s.as_str()).collect();
        for add in desired.difference(&current_set) {
            let _ = store.assign_role_to_agent(&admin.team_id, &id, add).await;
        }
        for remove in current_set.difference(&desired) {
            let _ = store
                .remove_role_from_agent(&admin.team_id, &id, remove)
                .await;
        }
    }

    Json(json!({"updated": true})).into_response()
}

/// DELETE /admin/agents/:id
pub async fn handle_delete_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    match state
        .db_state
        .store()
        .delete_agent(&admin.team_id, &id)
        .await
    {
        Ok(()) => Json(json!({"deleted": true})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// POST /admin/agents/:id/enable
pub async fn handle_enable_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    match state
        .db_state
        .store()
        .enable_agent(&admin.team_id, &id)
        .await
    {
        Ok(()) => Json(json!({"enabled": true})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// POST /admin/agents/:id/disable
pub async fn handle_disable_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    match state
        .db_state
        .store()
        .disable_agent(&admin.team_id, &id)
        .await
    {
        Ok(()) => Json(json!({"disabled": true})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Role management
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
    pub credentials: Option<Vec<String>>,
    pub rate_limit_per_hour: Option<i64>,
}

/// GET /admin/roles
pub async fn handle_list_roles(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = require_admin!(state, headers);
    match state.db_state.store().list_roles(&admin.team_id).await {
        Ok(roles) => {
            let list: Vec<serde_json::Value> = roles
                .iter()
                .map(|r| {
                    json!({
                        "name": r.name,
                        "description": r.description,
                        "rate_limit_per_hour": r.rate_limit_per_hour,
                    })
                })
                .collect();
            Json(json!({"roles": list})).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// POST /admin/roles — create role with optional initial credentials.
pub async fn handle_create_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateRoleRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    let store = state.db_state.store();

    if let Err(e) = store
        .create_role(
            &admin.team_id,
            &req.name,
            req.description.as_deref(),
            req.rate_limit_per_hour,
        )
        .await
    {
        let msg = format!("Failed to create role: {e}");
        return (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response();
    }

    if let Some(ref creds) = req.credentials {
        for cred in creds {
            if let Err(e) = store
                .add_credential_to_role(&admin.team_id, &req.name, cred)
                .await
            {
                warn!("Add credential to role error: {e}");
            }
        }
    }

    (
        StatusCode::CREATED,
        Json(json!({"name": req.name, "created": true})),
    )
        .into_response()
}

/// DELETE /admin/roles/:name
pub async fn handle_delete_role(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    match state
        .db_state
        .store()
        .delete_role(&admin.team_id, &name)
        .await
    {
        Ok(()) => Json(json!({"deleted": true})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Policy management
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SetPolicyRequest {
    pub auto_approve_methods: Option<Vec<String>>,
    pub require_approval_methods: Option<Vec<String>>,
    pub auto_approve_urls: Option<Vec<String>>,
    pub allowed_approvers: Option<Vec<String>>,
    pub telegram_chat_id: Option<String>,
    pub require_passkey: Option<bool>,
}

/// PUT /admin/policies/:cred_name
pub async fn handle_set_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(cred_name): axum::extract::Path<String>,
    Json(req): Json<SetPolicyRequest>,
) -> Response {
    let admin = require_admin!(state, headers);

    use agentsec_core::store::PolicyRow;
    let row = PolicyRow {
        team_id: admin.team_id.clone(),
        credential_name: cred_name.clone(),
        auto_approve_methods: req.auto_approve_methods.unwrap_or_default(),
        require_approval_methods: req.require_approval_methods.unwrap_or_default(),
        auto_approve_urls: req.auto_approve_urls.unwrap_or_default(),
        allowed_approvers: req.allowed_approvers.unwrap_or_default(),
        telegram_chat_id: req.telegram_chat_id,
        require_passkey: req.require_passkey.unwrap_or(false),
    };

    match state.db_state.store().set_policy(&row).await {
        Ok(()) => {
            // Invalidate the cached policy so the proxy picks up the change on the
            // next request rather than waiting for the cache TTL to expire.
            state
                .db_state
                .invalidate_policy_cache(&admin.team_id, &cred_name)
                .await;
            Json(json!({"credential": cred_name, "policy_set": true})).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// GET /admin/policies/:cred_name
pub async fn handle_get_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(cred_name): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    match state
        .db_state
        .store()
        .get_policy(&admin.team_id, &cred_name)
        .await
    {
        Ok(Some(p)) => Json(json!({
            "credential": cred_name,
            "auto_approve_methods": p.auto_approve_methods,
            "require_approval_methods": p.require_approval_methods,
            "auto_approve_urls": p.auto_approve_urls,
            "allowed_approvers": p.allowed_approvers,
            "telegram_chat_id": p.telegram_chat_id,
            "require_passkey": p.require_passkey,
        }))
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "No policy set for this credential"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Team info
// ---------------------------------------------------------------------------

/// GET /admin/team — get team info.
pub async fn handle_get_team(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = require_admin!(state, headers);
    match state.db_state.store().get_team(&admin.team_id).await {
        Ok(Some(team)) => Json(json!({
            "id": team.id,
            "name": team.name,
            "tier": team.tier,
            "created_at": team.created_at,
        }))
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Team not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Agent team links (multi-account / cross-team access)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LinkAgentRequest {
    pub agent_home_team_id: String,
    pub agent_id: String,
    pub role: Option<String>,
}

/// POST /admin/agent-links — link an external agent to this team.
/// The admin's own team is the linked_team_id (they're inviting a foreign agent in).
pub async fn handle_link_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LinkAgentRequest>,
) -> Response {
    let admin = require_admin!(state, headers);
    let store = state.db_state.store();

    // Verify the foreign agent exists
    match store
        .get_agent(&req.agent_home_team_id, &req.agent_id)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({
                "error": format!("Agent '{}' not found in team '{}'", req.agent_id, req.agent_home_team_id)
            }))).into_response();
        }
        Err(e) => {
            warn!("Agent lookup error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to look up agent"})),
            )
                .into_response();
        }
    }

    // Verify role exists in this team if specified
    if let Some(ref role_name) = req.role {
        match store.list_roles(&admin.team_id).await {
            Ok(roles) => {
                if !roles.iter().any(|r| r.name == *role_name) {
                    return (StatusCode::BAD_REQUEST, Json(json!({
                        "error": format!("Role '{}' not found in team '{}'", role_name, admin.team_id)
                    }))).into_response();
                }
            }
            Err(e) => {
                warn!("Role lookup error: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Failed to look up roles"})),
                )
                    .into_response();
            }
        }
    }

    match store
        .link_agent_to_team(
            &req.agent_home_team_id,
            &req.agent_id,
            &admin.team_id,
            req.role.as_deref(),
        )
        .await
    {
        Ok(()) => (
            StatusCode::CREATED,
            Json(json!({
                "linked": true,
                "agent_home_team_id": req.agent_home_team_id,
                "agent_id": req.agent_id,
                "linked_team_id": admin.team_id,
                "role": req.role,
            })),
        )
            .into_response(),
        Err(e) => {
            let msg = format!("Failed to link agent: {e}");
            (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response()
        }
    }
}

/// DELETE /admin/agent-links/{home_team_id}/{agent_id} — unlink a foreign agent from this team.
pub async fn handle_unlink_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path((home_team_id, agent_id)): axum::extract::Path<(String, String)>,
) -> Response {
    let admin = require_admin!(state, headers);

    match state
        .db_state
        .store()
        .unlink_agent_from_team(&home_team_id, &agent_id, &admin.team_id)
        .await
    {
        Ok(()) => Json(json!({"unlinked": true})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Notification channel management
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateNotificationChannelRequest {
    pub channel_type: String,
    pub name: String,
    pub config: serde_json::Value,
}

/// POST /admin/notification-channels — create a notification channel.
pub async fn handle_create_notification_channel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateNotificationChannelRequest>,
) -> Response {
    let admin = require_admin!(state, headers);

    // Validate channel type
    let channel_type = req.channel_type.trim().to_lowercase();
    if channel_type != "telegram" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("Unsupported channel type '{}'. Supported: telegram", channel_type)})),
        )
            .into_response();
    }

    // Validate name
    let name = req.name.trim().to_string();
    if name.is_empty() || name.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Channel name must be 1-64 characters"})),
        )
            .into_response();
    }

    // Validate config shape for telegram
    if channel_type == "telegram" {
        let chat_id = req.config.get("chat_id").and_then(|v| v.as_str());
        if chat_id.is_none() || chat_id.unwrap().is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Telegram config requires a non-empty 'chat_id' field"})),
            )
                .into_response();
        }
    }

    let config_json = serde_json::to_string(&req.config).unwrap_or_default();

    match state
        .db_state
        .store()
        .create_notification_channel(&admin.team_id, &channel_type, &name, &config_json)
        .await
    {
        Ok(id) => (
            StatusCode::CREATED,
            Json(json!({"id": id, "name": name, "channel_type": channel_type, "created": true})),
        )
            .into_response(),
        Err(e) => {
            let msg = format!("Failed to create notification channel: {e}");
            (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response()
        }
    }
}

/// GET /admin/notification-channels — list team's notification channels.
pub async fn handle_list_notification_channels(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let admin = require_admin!(state, headers);

    match state
        .db_state
        .store()
        .list_notification_channels(&admin.team_id)
        .await
    {
        Ok(channels) => {
            let list: Vec<serde_json::Value> = channels
                .iter()
                .map(|c| {
                    json!({
                        "id": c.id,
                        "channel_type": c.channel_type,
                        "name": c.name,
                        "config": serde_json::from_str::<serde_json::Value>(&c.config_json).unwrap_or_default(),
                        "enabled": c.enabled,
                        "created_at": c.created_at,
                    })
                })
                .collect();
            Json(json!({"notification_channels": list})).into_response()
        }
        Err(e) => {
            warn!("List notification channels error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to list notification channels"})),
            )
                .into_response()
        }
    }
}

/// DELETE /admin/notification-channels/:name
pub async fn handle_delete_notification_channel(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    match state
        .db_state
        .store()
        .delete_notification_channel(&admin.team_id, &name)
        .await
    {
        Ok(()) => Json(json!({"deleted": true})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// Agent team links
// ---------------------------------------------------------------------------

/// GET /admin/agent-links — list all foreign agents linked to this team.
pub async fn handle_list_agent_links(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let admin = require_admin!(state, headers);

    match state
        .db_state
        .store()
        .list_agent_links_for_team(&admin.team_id)
        .await
    {
        Ok(links) => {
            let list: Vec<serde_json::Value> = links
                .iter()
                .map(|l| {
                    json!({
                        "agent_home_team_id": l.agent_home_team_id,
                        "agent_id": l.agent_id,
                        "linked_team_id": l.linked_team_id,
                        "role": l.role_name,
                        "created_at": l.created_at,
                    })
                })
                .collect();
            Json(json!({"agent_links": list})).into_response()
        }
        Err(e) => {
            warn!("List agent links error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to list agent links"})),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Tier limits
// ---------------------------------------------------------------------------

/// Tier limits for managed hosting.
pub struct TierLimits {
    pub max_agents: Option<usize>, // None = unlimited
    pub max_credentials: Option<usize>,
    pub max_requests_per_month: Option<u64>,
}

pub fn get_tier_limits(tier: &str) -> TierLimits {
    match tier {
        "starter" => TierLimits {
            max_agents: Some(2),
            max_credentials: Some(5),
            max_requests_per_month: Some(5_000),
        },
        "pro" => TierLimits {
            max_agents: None,
            max_credentials: None,
            max_requests_per_month: Some(50_000),
        },
        "enterprise" => TierLimits {
            max_agents: None,
            max_credentials: None,
            max_requests_per_month: None,
        },
        _ => TierLimits {
            // "free" and self-hosted — no limits enforced by proxy
            max_agents: None,
            max_credentials: None,
            max_requests_per_month: None,
        },
    }
}

// ---------------------------------------------------------------------------
// Stripe billing
// ---------------------------------------------------------------------------

/// POST /billing/create-checkout-session — create a Stripe Checkout session for the authenticated admin.
/// Body: { "tier": "starter" | "pro" }
/// Returns: { "checkout_url": "https://checkout.stripe.com/..." }
pub async fn handle_create_checkout_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateCheckoutRequest>,
) -> Response {
    let admin = match authenticate_admin(&headers, &state.db_state).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let stripe_key = match std::env::var("STRIPE_SECRET_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "Billing not configured"})),
            )
                .into_response()
        }
    };

    // Map tier to Stripe price ID
    let price_id = match req.tier.as_str() {
        "starter" => match std::env::var("STRIPE_PRICE_STARTER") {
            Ok(p) => p,
            _ => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error": "Starter price not configured"})),
                )
                    .into_response()
            }
        },
        "pro" => match std::env::var("STRIPE_PRICE_PRO") {
            Ok(p) => p,
            _ => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error": "Pro price not configured"})),
                )
                    .into_response()
            }
        },
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Invalid tier. Use 'starter' or 'pro'"})),
            )
                .into_response()
        }
    };

    // Check if team already has a Stripe customer
    let team = match state.db_state.store().get_team(&admin.team_id).await {
        Ok(Some(t)) => t,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Team not found"})),
            )
                .into_response()
        }
    };

    // Create or reuse Stripe customer
    let customer_id = if let Some(cid) = team.stripe_customer_id {
        cid
    } else {
        // Create Stripe customer via API
        let client = reqwest::Client::new();
        let resp = client
            .post("https://api.stripe.com/v1/customers")
            .header("Authorization", format!("Bearer {stripe_key}"))
            .form(&[
                ("email", admin.email.as_str()),
                ("metadata[team_id]", admin.team_id.as_str()),
                ("metadata[team_name]", team.name.as_str()),
            ])
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => {
                let body: serde_json::Value = r.json().await.unwrap_or_default();
                let cid = body["id"].as_str().unwrap_or("").to_string();
                if cid.is_empty() {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "Failed to create Stripe customer"})),
                    )
                        .into_response();
                }
                // Save customer ID
                let _ = state
                    .db_state
                    .store()
                    .set_stripe_customer_id(&admin.team_id, &cid)
                    .await;
                cid
            }
            _ => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Stripe API error"})),
                )
                    .into_response()
            }
        }
    };

    // Determine success/cancel URLs
    let base_url =
        std::env::var("AGENTSEC_BASE_URL").unwrap_or_else(|_| "https://agentsec.dev".to_string());
    let success_url = format!("{base_url}/billing/success?session_id={{CHECKOUT_SESSION_ID}}");
    let cancel_url = format!("{base_url}/billing/cancel");

    // Create Checkout Session via Stripe API
    let client = reqwest::Client::new();
    let resp = client
        .post("https://api.stripe.com/v1/checkout/sessions")
        .header("Authorization", format!("Bearer {stripe_key}"))
        .form(&[
            ("customer", customer_id.as_str()),
            ("mode", "subscription"),
            ("line_items[0][price]", price_id.as_str()),
            ("line_items[0][quantity]", "1"),
            ("success_url", success_url.as_str()),
            ("cancel_url", cancel_url.as_str()),
            ("metadata[team_id]", admin.team_id.as_str()),
            ("metadata[tier]", req.tier.as_str()),
        ])
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let body: serde_json::Value = r.json().await.unwrap_or_default();
            let checkout_url = body["url"].as_str().unwrap_or("").to_string();
            Json(json!({"checkout_url": checkout_url})).into_response()
        }
        Ok(r) => {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            warn!("Stripe checkout error: {status} {body}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to create checkout session"})),
            )
                .into_response()
        }
        Err(e) => {
            warn!("Stripe request error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Stripe API error"})),
            )
                .into_response()
        }
    }
}

/// POST /stripe/webhook — handle Stripe webhook events.
/// Verifies the webhook signature, then processes the event.
pub async fn handle_stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let webhook_secret = match std::env::var("STRIPE_WEBHOOK_SECRET") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            warn!("STRIPE_WEBHOOK_SECRET not set, rejecting webhook");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    // Verify Stripe signature
    let sig_header = match headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
    {
        Some(s) => s.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Missing Stripe-Signature"})),
            )
                .into_response();
        }
    };

    let payload = match std::str::from_utf8(&body) {
        Ok(p) => p,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    // Verify HMAC-SHA256 signature
    if !verify_stripe_signature(payload, &sig_header, &webhook_secret) {
        warn!("Stripe webhook signature verification failed");
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Parse event
    let event: serde_json::Value = match serde_json::from_str(payload) {
        Ok(e) => e,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let event_type = event["type"].as_str().unwrap_or("");
    tracing::info!(event_type = %event_type, "Stripe webhook received");

    match event_type {
        "checkout.session.completed" => {
            let session = &event["data"]["object"];
            let team_id = session["metadata"]["team_id"].as_str().unwrap_or("");
            let tier = session["metadata"]["tier"].as_str().unwrap_or("");

            if !team_id.is_empty() && !tier.is_empty() {
                match state.db_state.store().update_team_tier(team_id, tier).await {
                    Ok(()) => {
                        tracing::info!(team_id = %team_id, tier = %tier, "Team tier upgraded via Stripe")
                    }
                    Err(e) => warn!(team_id = %team_id, "Failed to upgrade tier: {e}"),
                }
            }
        }
        "customer.subscription.deleted" | "customer.subscription.paused" => {
            // Downgrade to free
            let customer_id = event["data"]["object"]["customer"].as_str().unwrap_or("");
            if !customer_id.is_empty() {
                match state
                    .db_state
                    .store()
                    .get_team_by_stripe_customer(customer_id)
                    .await
                {
                    Ok(Some(team)) => {
                        let _ = state
                            .db_state
                            .store()
                            .update_team_tier(&team.id, "free")
                            .await;
                        tracing::info!(team_id = %team.id, "Team downgraded to free (subscription ended)");
                    }
                    _ => warn!(customer_id = %customer_id, "No team found for Stripe customer"),
                }
            }
        }
        "customer.subscription.updated" => {
            // Handle plan changes (upgrade/downgrade between starter and pro)
            let subscription = &event["data"]["object"];
            let customer_id = subscription["customer"].as_str().unwrap_or("");
            let status = subscription["status"].as_str().unwrap_or("");

            if status == "active" && !customer_id.is_empty() {
                // Get the price ID to determine tier
                let price_id = subscription["items"]["data"][0]["price"]["id"]
                    .as_str()
                    .unwrap_or("");
                let starter_price = std::env::var("STRIPE_PRICE_STARTER").unwrap_or_default();
                let pro_price = std::env::var("STRIPE_PRICE_PRO").unwrap_or_default();

                let new_tier = if price_id == starter_price {
                    "starter"
                } else if price_id == pro_price {
                    "pro"
                } else {
                    "" // unknown price
                };

                if !new_tier.is_empty() {
                    if let Ok(Some(team)) = state
                        .db_state
                        .store()
                        .get_team_by_stripe_customer(customer_id)
                        .await
                    {
                        let _ = state
                            .db_state
                            .store()
                            .update_team_tier(&team.id, new_tier)
                            .await;
                        tracing::info!(team_id = %team.id, tier = %new_tier, "Team tier changed");
                    }
                }
            }
        }
        _ => {
            // Ignore other events
        }
    }

    StatusCode::OK.into_response()
}

/// Verify Stripe webhook signature (HMAC-SHA256).
/// Note: the comparison uses `==` on lowercase hex strings, which is acceptable
/// since both sides are produced by the same hex encoding and the values are
/// not secret (they are MACs, not passwords).
fn verify_stripe_signature(payload: &str, sig_header: &str, secret: &str) -> bool {
    use hmac::{Hmac, Mac};

    // Parse the signature header: t=timestamp,v1=signature
    let mut timestamp = "";
    let mut signature = "";
    for part in sig_header.split(',') {
        let part = part.trim();
        if let Some(t) = part.strip_prefix("t=") {
            timestamp = t;
        } else if let Some(s) = part.strip_prefix("v1=") {
            signature = s;
        }
    }

    if timestamp.is_empty() || signature.is_empty() {
        return false;
    }

    // Build signed payload: timestamp.payload
    let signed_payload = format!("{timestamp}.{payload}");

    // Compute HMAC-SHA256
    type HmacSha256 = Hmac<sha2::Sha256>;
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(signed_payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    // Comparison on hex strings — see note on function doc
    expected == signature
}

/// POST /billing/portal — create a Stripe Billing Portal session for managing subscription.
pub async fn handle_billing_portal(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = match authenticate_admin(&headers, &state.db_state).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let stripe_key = match std::env::var("STRIPE_SECRET_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "Billing not configured"})),
            )
                .into_response()
        }
    };

    let team = match state.db_state.store().get_team(&admin.team_id).await {
        Ok(Some(t)) => t,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Team not found"})),
            )
                .into_response()
        }
    };

    let customer_id = match team.stripe_customer_id {
        Some(cid) => cid,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "No subscription found. Choose a plan first."})),
            )
                .into_response()
        }
    };

    let base_url =
        std::env::var("AGENTSEC_BASE_URL").unwrap_or_else(|_| "https://agentsec.dev".to_string());
    let return_url = format!("{base_url}/dashboard");

    let client = reqwest::Client::new();
    let resp = client
        .post("https://api.stripe.com/v1/billing_portal/sessions")
        .header("Authorization", format!("Bearer {stripe_key}"))
        .form(&[
            ("customer", customer_id.as_str()),
            ("return_url", return_url.as_str()),
        ])
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let body: serde_json::Value = r.json().await.unwrap_or_default();
            let portal_url = body["url"].as_str().unwrap_or("").to_string();
            Json(json!({"portal_url": portal_url})).into_response()
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to create billing portal session"})),
        )
            .into_response(),
    }
}

/// GET /billing/status — show current billing status.
pub async fn handle_get_billing(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let admin = match authenticate_admin(&headers, &state.db_state).await {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    let team = match state.db_state.store().get_team(&admin.team_id).await {
        Ok(Some(t)) => t,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Team not found"})),
            )
                .into_response()
        }
    };

    Json(json!({
        "tier": team.tier,
        "has_stripe_customer": team.stripe_customer_id.is_some(),
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Admin Passkey (WebAuthn 2FA)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SetupPasskeyBeginRequest {
    pub passkey_setup_token: String,
}

#[derive(Deserialize)]
pub struct SetupPasskeyFinishRequest {
    pub passkey_setup_token: String,
    pub credential: webauthn_rs_proto::RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
pub struct LoginPasskeyRequest {
    pub passkey_token: String,
    pub credential: webauthn_rs_proto::PublicKeyCredential,
}

/// POST /setup-passkey/begin — start passkey registration during signup.
/// Requires a passkey_setup_token (issued after email verification).
pub async fn handle_setup_passkey_begin(
    State(state): State<AppState>,
    Json(req): Json<SetupPasskeyBeginRequest>,
) -> Response {
    let token_hash = hash_session_token(&req.passkey_setup_token);
    let store = state.db_state.store();

    // Validate setup token (stored as a short-lived session)
    let admin = match store.validate_session(&token_hash).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid or expired setup token"})),
            )
                .into_response();
        }
        Err(e) => {
            warn!("Setup token validation error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Validation failed"})),
            )
                .into_response();
        }
    };

    let wa = match state.webauthn_state.as_ref() {
        Some(wa) => wa,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "WebAuthn not configured"})),
            )
                .into_response();
        }
    };

    match wa.begin_admin_registration(&admin.id, &admin.email).await {
        Ok(ccr) => Json(json!({
            "challenge": ccr,
            "admin_id": admin.id,
        }))
        .into_response(),
        Err(e) => {
            warn!("Passkey setup begin error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to start passkey setup"})),
            )
                .into_response()
        }
    }
}

/// POST /setup-passkey/finish — complete passkey registration during signup.
pub async fn handle_setup_passkey_finish(
    State(state): State<AppState>,
    Json(req): Json<SetupPasskeyFinishRequest>,
) -> Response {
    let token_hash = hash_session_token(&req.passkey_setup_token);
    let store = state.db_state.store();

    let admin = match store.validate_session(&token_hash).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid or expired setup token"})),
            )
                .into_response();
        }
        Err(e) => {
            warn!("Setup token validation error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Validation failed"})),
            )
                .into_response();
        }
    };

    let wa = match state.webauthn_state.as_ref() {
        Some(wa) => wa,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "WebAuthn not configured"})),
            )
                .into_response();
        }
    };

    match wa
        .finish_admin_registration(&admin.id, &req.credential)
        .await
    {
        Ok(_passkey) => {
            info!(admin_id = %admin.id, "Admin passkey registered during setup");
            // Invalidate the setup token
            let _ = store.delete_session(&token_hash).await;
            Json(json!({"status": "registered"})).into_response()
        }
        Err(e) => {
            warn!("Passkey setup finish error: {e}");
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Passkey registration failed: {e}")})),
            )
                .into_response()
        }
    }
}

/// POST /login/passkey — complete login with WebAuthn assertion.
pub async fn handle_login_passkey(
    State(state): State<AppState>,
    Json(req): Json<LoginPasskeyRequest>,
) -> Response {
    let wa = match state.webauthn_state.as_ref() {
        Some(wa) => wa,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "WebAuthn not configured"})),
            )
                .into_response();
        }
    };

    let admin_id = match wa
        .finish_admin_login(&req.passkey_token, &req.credential)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            warn!("Passkey login error: {e}");
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "Security key verification failed"})),
            )
                .into_response();
        }
    };

    let store = state.db_state.store();

    // Verify admin still exists and is active
    let admin = match store.get_admin(&admin_id).await {
        Ok(Some(a)) if a.email_verified => a,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Account not found or inactive"})),
            )
                .into_response();
        }
    };

    // Create session token
    let token = generate_session_token();
    let token_hash = hash_session_token(&token);
    let expires_at = (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339();

    if let Err(e) = store
        .create_session(&token_hash, &admin.id, &expires_at)
        .await
    {
        warn!("Session creation error: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to create session"})),
        )
            .into_response();
    }

    info!(admin_id = %admin.id, "Admin login completed with passkey");

    Json(json!({
        "session_token": token,
        "admin_id": admin.id,
        "team_id": admin.team_id,
        "expires_at": expires_at,
    }))
    .into_response()
}

/// POST /admin/passkey/register/begin — add an additional passkey (authenticated).
pub async fn handle_admin_passkey_register_begin(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let admin = require_admin!(state, headers);

    let wa = match state.webauthn_state.as_ref() {
        Some(wa) => wa,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "WebAuthn not configured"})),
            )
                .into_response();
        }
    };

    match wa.begin_admin_registration(&admin.id, &admin.email).await {
        Ok(ccr) => Json(json!({"challenge": ccr})).into_response(),
        Err(e) => {
            warn!("Admin passkey reg begin error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to start registration"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct AdminPasskeyRegisterFinish {
    pub credential: webauthn_rs_proto::RegisterPublicKeyCredential,
}

/// POST /admin/passkey/register/finish — complete additional passkey registration.
pub async fn handle_admin_passkey_register_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AdminPasskeyRegisterFinish>,
) -> Response {
    let admin = require_admin!(state, headers);

    let wa = match state.webauthn_state.as_ref() {
        Some(wa) => wa,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "WebAuthn not configured"})),
            )
                .into_response();
        }
    };

    match wa
        .finish_admin_registration(&admin.id, &req.credential)
        .await
    {
        Ok(_passkey) => {
            info!(admin_id = %admin.id, "Additional admin passkey registered");
            Json(json!({"status": "registered"})).into_response()
        }
        Err(e) => {
            warn!("Admin passkey reg finish error: {e}");
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Registration failed: {e}")})),
            )
                .into_response()
        }
    }
}

/// GET /admin/passkeys — list admin's registered passkeys.
pub async fn handle_list_admin_passkeys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let admin = require_admin!(state, headers);

    match state.db_state.store().list_admin_passkeys(&admin.id).await {
        Ok(passkeys) => {
            let list: Vec<serde_json::Value> = passkeys
                .iter()
                .map(|p| {
                    json!({
                        "credential_id": p.credential_id,
                        "created_at": p.created_at,
                    })
                })
                .collect();
            Json(json!({"passkeys": list})).into_response()
        }
        Err(e) => {
            warn!("List admin passkeys error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to list passkeys"})),
            )
                .into_response()
        }
    }
}

/// DELETE /admin/passkeys/:credential_id — remove a passkey (must keep at least one).
pub async fn handle_delete_admin_passkey(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(credential_id): axum::extract::Path<String>,
) -> Response {
    let admin = require_admin!(state, headers);
    let store = state.db_state.store();

    // Check count — must keep at least one
    match store.count_admin_passkeys(&admin.id).await {
        Ok(count) if count <= 1 => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "Cannot delete your last security key. You must have at least one."}))).into_response();
        }
        Err(e) => {
            warn!("Count admin passkeys error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to check passkey count"})),
            )
                .into_response();
        }
        _ => {}
    }

    match store.delete_admin_passkey(&admin.id, &credential_id).await {
        Ok(true) => {
            // Also remove from in-memory WebAuthn state
            if let Some(ref wa) = state.webauthn_state {
                wa.remove_admin_credential(&admin.id, &credential_id).await;
            }
            Json(json!({"deleted": true})).into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Passkey not found"})),
        )
            .into_response(),
        Err(e) => {
            warn!("Delete admin passkey error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to delete passkey"})),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_password_produces_argon2_hash() {
        let hash = hash_password("test-password-123").unwrap();
        assert!(hash.starts_with("$argon2"));
        assert!(hash.len() > 50);
    }

    #[test]
    fn hash_password_different_inputs_differ() {
        let h1 = hash_password("password1").unwrap();
        let h2 = hash_password("password2").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_password_same_input_different_salts() {
        let h1 = hash_password("same-password").unwrap();
        let h2 = hash_password("same-password").unwrap();
        // Different salts → different hashes
        assert_ne!(h1, h2);
    }

    #[test]
    fn verify_password_correct() {
        let hash = hash_password("correct-horse").unwrap();
        assert!(verify_password("correct-horse", &hash));
    }

    #[test]
    fn verify_password_incorrect() {
        let hash = hash_password("correct-horse").unwrap();
        assert!(!verify_password("wrong-horse", &hash));
    }

    #[test]
    fn verify_password_invalid_hash_format() {
        assert!(!verify_password("anything", "not-a-valid-hash"));
    }

    #[test]
    fn verify_password_empty_string() {
        assert!(!verify_password("", "not-a-valid-hash"));
    }

    #[test]
    fn generate_session_token_length() {
        let token = generate_session_token();
        // 32 bytes → 64 hex chars
        assert_eq!(token.len(), 64);
    }

    #[test]
    fn generate_session_token_is_hex() {
        let token = generate_session_token();
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_session_token_unique() {
        let t1 = generate_session_token();
        let t2 = generate_session_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn hash_session_token_deterministic() {
        let h1 = hash_session_token("my-token");
        let h2 = hash_session_token("my-token");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_session_token_different_inputs_differ() {
        let h1 = hash_session_token("token-a");
        let h2 = hash_session_token("token-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_session_token_is_sha256_hex() {
        let hash = hash_session_token("test");
        // SHA-256 → 64 hex chars
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_verification_code_is_6_digits() {
        for _ in 0..100 {
            let code = generate_verification_code();
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
            let num: u32 = code.parse().unwrap();
            assert!(num >= 100_000 && num < 1_000_000);
        }
    }

    #[test]
    fn hash_verification_code_deterministic() {
        let h1 = hash_verification_code("123456");
        let h2 = hash_verification_code("123456");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_verification_code_different_codes_differ() {
        let h1 = hash_verification_code("123456");
        let h2 = hash_verification_code("654321");
        assert_ne!(h1, h2);
    }
}
