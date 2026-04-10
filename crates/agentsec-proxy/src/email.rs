//! Email sending via Resend API.

use agentsec_core::error::AgentSecError;
use serde_json::json;

/// Send an email verification code via Resend.
pub async fn send_verification_email(
    to: &str,
    code: &str,
    team_name: &str,
) -> Result<(), AgentSecError> {
    let api_key = std::env::var("RESEND_API_KEY").map_err(|_| {
        AgentSecError::Config("RESEND_API_KEY not set — cannot send verification emails".into())
    })?;
    // Use RESEND_FROM_EMAIL if set, otherwise Resend's shared test domain.
    // For production, set RESEND_FROM_EMAIL to a verified domain (e.g., noreply@toolsec.org).
    let from = std::env::var("RESEND_FROM_EMAIL")
        .unwrap_or_else(|_| "ToolSec <onboarding@resend.dev>".to_string());

    let body = json!({
        "from": from,
        "to": [to],
        "subject": format!("ToolSec — verify your email for team '{}'", team_name),
        "text": format!(
            "Your ToolSec verification code is:\n\n  {}\n\nThis code expires in 15 minutes.\n\nIf you didn't sign up for ToolSec, you can ignore this email.",
            code
        ),
    });

    let client = reqwest::Client::new();
    let resp = client
        .post("https://api.resend.com/emails")
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&body)
        .send()
        .await
        .map_err(|e| AgentSecError::Internal(format!("Failed to send email: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(AgentSecError::Internal(format!(
            "Resend API error ({status}): {body}"
        )));
    }

    Ok(())
}
