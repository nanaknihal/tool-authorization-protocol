//! Inline Google OAuth2 token refresh for sidecar credentials.
//!
//! When a sidecar credential's value contains a Google OAuth refresh token
//! bundle (JSON with client_id, client_secret, refresh_token), the proxy
//! exchanges the refresh token for a fresh access token and injects it
//! directly — no external sidecar service needed.

use serde::Deserialize;

/// Parsed Google OAuth credential value.
#[derive(Debug, Deserialize)]
pub struct GoogleOAuthCredential {
    pub client_id: String,
    pub client_secret: String,
    pub refresh_token: String,
}

/// Try to parse a credential value as a Google OAuth bundle.
/// Returns None if it's not valid Google OAuth JSON.
pub fn parse_google_oauth(cred_value: &str) -> Option<GoogleOAuthCredential> {
    serde_json::from_str(cred_value).ok()
}

/// Exchange a refresh token for a fresh access token.
pub async fn refresh_access_token(cred: &GoogleOAuthCredential) -> Result<String, String> {
    let resp = reqwest::Client::new()
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", cred.client_id.as_str()),
            ("client_secret", cred.client_secret.as_str()),
            ("refresh_token", cred.refresh_token.as_str()),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .await
        .map_err(|e| format!("Token refresh request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Token refresh returned {status}: {body}"));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse token response: {e}"))?;

    body["access_token"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "Token response missing access_token".to_string())
}
