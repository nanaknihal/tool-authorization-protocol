//! Server-side Google OAuth 2.0 consent flow.
//!
//! Two endpoints:
//! - `POST /admin/oauth/google/start` (authenticated) — returns Google auth URL
//! - `GET /oauth/google/callback` (public) — receives redirect, exchanges code, stores credential

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use tracing::warn;

use crate::admin::{
    authenticate_admin, generate_session_token, get_tier_limits, hash_session_token,
};
use crate::proxy::AppState;

/// Pending OAuth flow stored in memory. Expires after 10 minutes.
#[derive(Clone)]
pub struct OAuthPending {
    pub admin_id: String,
    pub team_id: String,
    pub credential_name: String,
    pub credential_description: String,
    pub expires_at: chrono::DateTime<Utc>,
}

const STATE_TTL_SECS: i64 = 600; // 10 minutes

const GOOGLE_SCOPES: &str = "\
https://mail.google.com/ \
https://www.googleapis.com/auth/calendar \
https://www.googleapis.com/auth/drive \
https://www.googleapis.com/auth/spreadsheets";

// ---------------------------------------------------------------------------
// POST /admin/oauth/google/start
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct OAuthStartRequest {
    pub credential_name: String,
    pub credential_description: String,
}

pub async fn handle_google_oauth_start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<OAuthStartRequest>,
) -> Response {
    let admin = match authenticate_admin(&headers, &state.db_state).await {
        Ok(a) => a,
        Err(resp) => return resp.into_response(),
    };
    let store = state.db_state.store();

    // Validate name
    let name = req.credential_name.trim().to_lowercase();
    if name.is_empty() || name.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Credential name must be 1-64 characters"})),
        )
            .into_response();
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Credential name must be lowercase alphanumeric with hyphens"})),
        )
            .into_response();
    }

    // Check credential doesn't already exist
    if let Ok(Some(_)) = store.get_credential(&admin.team_id, &name).await {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "Credential name already exists"})),
        )
            .into_response();
    }

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

    // Read env
    let client_id = match std::env::var("GOOGLE_OAUTH_CLIENT_ID") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "Google OAuth not configured"})),
            )
                .into_response()
        }
    };
    let redirect_uri = match std::env::var("GOOGLE_OAUTH_REDIRECT_URI") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "GOOGLE_OAUTH_REDIRECT_URI not configured"})),
            )
                .into_response()
        }
    };

    // Generate state token
    let state_token = generate_session_token();
    let state_hash = hash_session_token(&state_token);

    let pending = OAuthPending {
        admin_id: admin.id.clone(),
        team_id: admin.team_id.clone(),
        credential_name: name,
        credential_description: req.credential_description,
        expires_at: Utc::now() + chrono::Duration::seconds(STATE_TTL_SECS),
    };

    // Store state and prune expired entries
    {
        let mut map = state.oauth_states.lock().unwrap();
        let now = Utc::now();
        map.retain(|_, v| v.expires_at > now);
        map.insert(state_hash, pending);
    }

    // Build Google auth URL
    let mut auth_url = url::Url::parse("https://accounts.google.com/o/oauth2/v2/auth").unwrap();
    auth_url
        .query_pairs_mut()
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", GOOGLE_SCOPES)
        .append_pair("access_type", "offline")
        .append_pair("prompt", "consent")
        .append_pair("state", &state_token);
    let auth_url = auth_url.to_string();

    Json(json!({ "auth_url": auth_url })).into_response()
}

// ---------------------------------------------------------------------------
// GET /oauth/google/callback
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

pub async fn handle_google_oauth_callback(
    State(state): State<AppState>,
    Query(q): Query<OAuthCallbackQuery>,
) -> Response {
    // Helper to redirect with error
    let err_redirect = |reason: &str| {
        Redirect::to(&format!("/dashboard?oauth=error&reason={reason}")).into_response()
    };

    // User denied
    if q.error.is_some() {
        return err_redirect("access_denied");
    }

    let state_token = match q.state {
        Some(ref s) if !s.is_empty() => s,
        _ => return err_redirect("missing_state"),
    };

    // Validate + consume state
    let pending = {
        let state_hash = hash_session_token(state_token);
        let mut map = state.oauth_states.lock().unwrap();
        match map.remove(&state_hash) {
            Some(p) if p.expires_at > Utc::now() => p,
            Some(_) => return err_redirect("expired_state"),
            None => return err_redirect("invalid_state"),
        }
    };

    let code = match q.code {
        Some(ref c) if !c.is_empty() => c,
        _ => return err_redirect("missing_code"),
    };

    // Read server-side secrets
    let client_id = std::env::var("GOOGLE_OAUTH_CLIENT_ID").unwrap_or_default();
    let client_secret = std::env::var("GOOGLE_OAUTH_CLIENT_SECRET").unwrap_or_default();
    let redirect_uri = std::env::var("GOOGLE_OAUTH_REDIRECT_URI").unwrap_or_default();
    if client_id.is_empty() || client_secret.is_empty() || redirect_uri.is_empty() {
        warn!("Google OAuth env vars missing during callback");
        return err_redirect("server_error");
    }

    // Exchange code for tokens
    let token_resp = reqwest::Client::new()
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("code", code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", redirect_uri.as_str()),
        ])
        .send()
        .await;

    let token_body: serde_json::Value = match token_resp {
        Ok(resp) if resp.status().is_success() => match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to parse Google token response: {e}");
                return err_redirect("token_exchange_failed");
            }
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!("Google token exchange failed ({status}): {body}");
            return err_redirect("token_exchange_failed");
        }
        Err(e) => {
            warn!("Google token exchange request failed: {e}");
            return err_redirect("token_exchange_failed");
        }
    };

    let refresh_token = match token_body.get("refresh_token").and_then(|v| v.as_str()) {
        Some(rt) => rt.to_string(),
        None => {
            warn!("No refresh_token in Google response");
            return err_redirect("no_refresh_token");
        }
    };

    // Create credential
    let store = state.db_state.store();

    if let Err(e) = store
        .create_credential(
            &pending.team_id,
            &pending.credential_name,
            &pending.credential_description,
            "sidecar",
            Some("http://127.0.0.1:8081"),
            false,
            None,
            None,
        )
        .await
    {
        warn!("Failed to create credential: {e}");
        return err_redirect("credential_exists");
    }

    // Store value with server-side secrets bundled
    let cred_value = json!({
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
    })
    .to_string();

    if let Err(e) = store
        .set_credential_value(
            &pending.team_id,
            &pending.credential_name,
            cred_value.as_bytes(),
        )
        .await
    {
        warn!("Failed to store credential value: {e}");
        // Clean up the half-created credential
        let _ = store
            .delete_credential(&pending.team_id, &pending.credential_name)
            .await;
        return err_redirect("server_error");
    }

    let mut success_url = url::Url::parse("http://localhost/dashboard").unwrap();
    success_url
        .query_pairs_mut()
        .append_pair("oauth", "success")
        .append_pair("cred", &pending.credential_name);
    // Use only the path+query (relative redirect)
    let redirect_path = format!(
        "{}?{}",
        success_url.path(),
        success_url.query().unwrap_or("")
    );
    Redirect::to(&redirect_path).into_response()
}
