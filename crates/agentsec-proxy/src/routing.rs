//! Unified routing: resolves X-TAP-Credential to an effective target
//! and headers based on the credential's connector type in config.

use std::collections::HashMap;
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

use agentsec_core::config::{AgentSecConfig, ConnectorType, CredentialConfig};

/// Resolved routing information for a unified-interface request.
#[derive(Debug)]
pub struct UnifiedRoute {
    /// Where to actually send the HTTP request.
    pub effective_target: String,
    /// What to show in audit logs and approval messages (the "real" API URL).
    pub display_target: String,
    /// Headers to forward (with credential injected for direct, or X-OAuth-* for sidecar).
    pub headers: Vec<(String, String)>,
    /// If set, the proxy must do an inline Google OAuth token refresh before forwarding.
    /// Contains the parsed credential JSON (client_id, client_secret, refresh_token).
    pub google_oauth: Option<crate::google_oauth::GoogleOAuthCredential>,
}

/// Resolve routing for a unified-interface request based on credential config.
///
/// Returns the effective target URL, display target, and headers to forward.
/// The caller handles whitelist check, policy, approval, forwarding, and audit.
pub fn resolve_unified_route(
    cred_name: &str,
    target_url: &str,
    method_str: &str,
    forward_headers: &[(String, String)],
    config: &AgentSecConfig,
    credential_values: &HashMap<String, String>,
) -> Result<UnifiedRoute, RouteError> {
    let cred_config = config
        .credentials
        .get(cred_name)
        .ok_or_else(|| RouteError::CredentialNotFound(cred_name.to_string()))?;

    let cred_value = credential_values.get(cred_name).map(|s| s.as_str());
    resolve_unified_route_with_config(
        cred_name,
        target_url,
        method_str,
        forward_headers,
        cred_config,
        cred_value,
    )
}

/// Resolve routing from an individual credential config + optional value.
/// Used by both YAML and DB modes.
pub fn resolve_unified_route_with_config(
    cred_name: &str,
    target_url: &str,
    method_str: &str,
    forward_headers: &[(String, String)],
    cred_config: &CredentialConfig,
    cred_value: Option<&str>,
) -> Result<UnifiedRoute, RouteError> {
    match cred_config.connector {
        ConnectorType::Direct => {
            let cred_value = cred_value
                .ok_or_else(|| RouteError::CredentialValueMissing(cred_name.to_string()))?;

            let mut headers: Vec<(String, String)> = forward_headers.to_vec();
            if cred_config.auth_bindings.is_empty() {
                let auth_value = match &cred_config.auth_header_format {
                    Some(fmt) => fmt.replace("{value}", cred_value),
                    None => format!("Bearer {}", cred_value),
                };

                headers.retain(|(n, _)| n.to_lowercase() != "authorization");
                headers.push(("Authorization".to_string(), auth_value));
            } else {
                let bound_headers: std::collections::HashSet<String> = cred_config
                    .auth_bindings
                    .iter()
                    .map(|binding| binding.header.to_lowercase())
                    .collect();
                headers.retain(|(n, _)| !bound_headers.contains(&n.to_lowercase()));
                for binding in &cred_config.auth_bindings {
                    headers.push((
                        binding.header.clone(),
                        binding.format.replace("{value}", cred_value),
                    ));
                }
            }

            Ok(UnifiedRoute {
                effective_target: target_url.to_string(),
                display_target: target_url.to_string(),
                headers,
                google_oauth: None,
            })
        }
        ConnectorType::Sidecar => {
            // Check if the credential value is a Google OAuth JSON bundle.
            // If so, skip the sidecar and route directly to the real API —
            // the proxy will do the token refresh inline before forwarding.
            let google_oauth = cred_value.and_then(crate::google_oauth::parse_google_oauth);

            if google_oauth.is_some() {
                // Route directly to the real API URL
                let mut headers: Vec<(String, String)> = forward_headers.to_vec();
                headers.retain(|(n, _)| n.to_lowercase() != "authorization");
                // Authorization header will be injected by the proxy after token refresh

                return Ok(UnifiedRoute {
                    effective_target: target_url.to_string(),
                    display_target: target_url.to_string(),
                    headers,
                    google_oauth,
                });
            }

            // Standard sidecar routing (non-Google OAuth)
            let sidecar_base = cred_config.api_base.as_deref().ok_or_else(|| {
                RouteError::ConfigError(format!(
                    "credential '{}' has connector=sidecar but no api_base",
                    cred_name
                ))
            })?;
            let sidecar_base = rewrite_sidecar_base(sidecar_base);

            let (effective_target, display_target) = if cred_config.relative_target {
                // Validate: reject path traversal
                if target_url.contains("..") {
                    return Err(RouteError::PathTraversal);
                }
                // Prepend sidecar base to relative path
                let base = sidecar_base.trim_end_matches('/');
                let path = if target_url.starts_with('/') {
                    target_url.to_string()
                } else {
                    format!("/{}", target_url)
                };
                (format!("{}{}", base, path), target_url.to_string())
            } else {
                // Target is the real API URL, route through sidecar
                (sidecar_base.to_string(), target_url.to_string())
            };

            // Build headers for the sidecar
            let mut headers: Vec<(String, String)> = forward_headers.to_vec();
            headers.push(("X-OAuth-Credential".to_string(), cred_name.to_string()));
            if !cred_config.relative_target {
                headers.push(("X-OAuth-Target".to_string(), target_url.to_string()));
            }
            headers.push(("X-TAP-Method".to_string(), method_str.to_string()));
            // Pass credential value to sidecar (e.g. JSON with OAuth keys)
            if let Some(val) = cred_value {
                headers.push(("X-OAuth-Credential-Data".to_string(), val.to_string()));
            }

            Ok(UnifiedRoute {
                effective_target,
                display_target,
                headers,
                google_oauth: None,
            })
        }
    }
}

fn rewrite_sidecar_base(sidecar_base: &str) -> String {
    if sidecar_base.contains("telegram-client:8082") {
        if let Ok(base) = std::env::var("AGENTSEC_EMBEDDED_TELEGRAM_BASE") {
            if !base.trim().is_empty() {
                return base;
            }
        }
        #[cfg(feature = "enclave")]
        {
            return "http://127.0.0.1:8082".to_string();
        }
    }

    sidecar_base.to_string()
}

#[derive(Debug)]
pub enum RouteError {
    CredentialNotFound(String),
    CredentialValueMissing(String),
    ConfigError(String),
    PathTraversal,
}

impl std::fmt::Display for RouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteError::CredentialNotFound(name) => write!(f, "Credential '{}' not found", name),
            RouteError::CredentialValueMissing(name) => {
                write!(f, "Credential '{}' value not configured", name)
            }
            RouteError::ConfigError(msg) => write!(f, "Config error: {}", msg),
            RouteError::PathTraversal => write!(f, "Path traversal not allowed in relative target"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentsec_core::config::*;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn make_config(cred_name: &str, cred: CredentialConfig) -> AgentSecConfig {
        let mut credentials = HashMap::new();
        credentials.insert(cred_name.to_string(), cred);
        AgentSecConfig {
            version: 1,
            credentials,
            approval: ApprovalConfig {
                channel: "mock".to_string(),
                timeout_seconds: 300,
                default_approvals_required: 1,
            },
            policies: HashMap::new(),
            agents: HashMap::new(),
        }
    }

    fn make_cred_values(name: &str, value: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert(name.to_string(), value.to_string());
        m
    }

    #[test]
    fn route_direct_injects_bearer_header() {
        let config = make_config(
            "slack",
            CredentialConfig {
                description: "Slack".to_string(),
                api_base: Some("https://slack.com/api".to_string()),
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Direct,
                relative_target: false,
                auth_header_format: None,
                auth_bindings: Vec::new(),
            },
        );
        let cred_values = make_cred_values("slack", "xoxb-secret-token");

        let route = resolve_unified_route(
            "slack",
            "https://slack.com/api/conversations.list",
            "GET",
            &[],
            &config,
            &cred_values,
        )
        .unwrap();

        assert_eq!(
            route.effective_target,
            "https://slack.com/api/conversations.list"
        );
        assert_eq!(route.display_target, route.effective_target);
        let auth = route
            .headers
            .iter()
            .find(|(n, _)| n == "Authorization")
            .unwrap();
        assert_eq!(auth.1, "Bearer xoxb-secret-token");
    }

    #[test]
    fn route_direct_custom_auth_format() {
        let config = make_config(
            "notion",
            CredentialConfig {
                description: "Notion".to_string(),
                api_base: None,
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Direct,
                relative_target: false,
                auth_header_format: Some("Bot {value}".to_string()),
                auth_bindings: Vec::new(),
            },
        );
        let cred_values = make_cred_values("notion", "ntn_secret");

        let route = resolve_unified_route(
            "notion",
            "https://api.notion.com/v1/pages",
            "GET",
            &[],
            &config,
            &cred_values,
        )
        .unwrap();

        let auth = route
            .headers
            .iter()
            .find(|(n, _)| n == "Authorization")
            .unwrap();
        assert_eq!(auth.1, "Bot ntn_secret");
    }

    #[test]
    fn route_sidecar_forwards_to_api_base() {
        let config = make_config(
            "google",
            CredentialConfig {
                description: "Google".to_string(),
                api_base: Some("http://oauth2-refresher:8081".to_string()),
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Sidecar,
                relative_target: false,
                auth_header_format: None,
                auth_bindings: Vec::new(),
            },
        );
        let cred_values = HashMap::new();

        let route = resolve_unified_route(
            "google",
            "https://gmail.googleapis.com/gmail/v1/users/me/messages",
            "GET",
            &[],
            &config,
            &cred_values,
        )
        .unwrap();

        assert_eq!(route.effective_target, "http://oauth2-refresher:8081");
        assert_eq!(
            route.display_target,
            "https://gmail.googleapis.com/gmail/v1/users/me/messages"
        );
    }

    #[test]
    fn route_sidecar_injects_oauth_headers() {
        let config = make_config(
            "google",
            CredentialConfig {
                description: "Google".to_string(),
                api_base: Some("http://oauth2-refresher:8081".to_string()),
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Sidecar,
                relative_target: false,
                auth_header_format: None,
                auth_bindings: Vec::new(),
            },
        );

        let route = resolve_unified_route(
            "google",
            "https://gmail.googleapis.com/gmail/v1/users/me/messages",
            "GET",
            &[],
            &config,
            &HashMap::new(),
        )
        .unwrap();

        let oauth_cred = route
            .headers
            .iter()
            .find(|(n, _)| n == "X-OAuth-Credential")
            .unwrap();
        assert_eq!(oauth_cred.1, "google");

        let oauth_target = route
            .headers
            .iter()
            .find(|(n, _)| n == "X-OAuth-Target")
            .unwrap();
        assert_eq!(
            oauth_target.1,
            "https://gmail.googleapis.com/gmail/v1/users/me/messages"
        );
    }

    #[test]
    fn route_sidecar_relative_prepends_base() {
        let config = make_config(
            "telegram",
            CredentialConfig {
                description: "Telegram".to_string(),
                api_base: Some("http://telegram-client:8082".to_string()),
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Sidecar,
                relative_target: true,
                auth_header_format: None,
                auth_bindings: Vec::new(),
            },
        );

        let route = resolve_unified_route(
            "telegram",
            "/dialogs?limit=10",
            "GET",
            &[],
            &config,
            &HashMap::new(),
        )
        .unwrap();

        assert_eq!(
            route.effective_target,
            "http://telegram-client:8082/dialogs?limit=10"
        );
        assert_eq!(route.display_target, "/dialogs?limit=10");
        // Relative target should NOT inject X-OAuth-Target
        assert!(route
            .headers
            .iter()
            .find(|(n, _)| n == "X-OAuth-Target")
            .is_none());
    }

    #[test]
    fn route_sidecar_relative_rejects_path_traversal() {
        let config = make_config(
            "telegram",
            CredentialConfig {
                description: "Telegram".to_string(),
                api_base: Some("http://telegram-client:8082".to_string()),
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Sidecar,
                relative_target: true,
                auth_header_format: None,
                auth_bindings: Vec::new(),
            },
        );

        let result = resolve_unified_route(
            "telegram",
            "/../etc/passwd",
            "GET",
            &[],
            &config,
            &HashMap::new(),
        );

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RouteError::PathTraversal));
    }

    #[test]
    fn route_unknown_credential_404() {
        let config = make_config(
            "slack",
            CredentialConfig {
                description: "Slack".to_string(),
                api_base: None,
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Direct,
                relative_target: false,
                auth_header_format: None,
                auth_bindings: Vec::new(),
            },
        );

        let result = resolve_unified_route(
            "nonexistent",
            "https://example.com",
            "GET",
            &[],
            &config,
            &HashMap::new(),
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RouteError::CredentialNotFound(_)
        ));
    }

    #[test]
    fn route_direct_custom_header_bindings() {
        let config = make_config(
            "datadog-api",
            CredentialConfig {
                description: "Datadog API".to_string(),
                api_base: None,
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Direct,
                relative_target: false,
                auth_header_format: None,
                auth_bindings: vec![agentsec_core::config::AuthBinding {
                    header: "DD-API-KEY".to_string(),
                    format: "{value}".to_string(),
                }],
            },
        );
        let cred_values = make_cred_values("datadog-api", "dd-secret");

        let route = resolve_unified_route(
            "datadog-api",
            "https://api.datadoghq.com/api/v1/validate",
            "GET",
            &[],
            &config,
            &cred_values,
        )
        .unwrap();

        assert!(route
            .headers
            .iter()
            .any(|(n, v)| n == "DD-API-KEY" && v == "dd-secret"));
        assert!(route.headers.iter().all(|(n, _)| n != "Authorization"));
    }

    #[test]
    fn route_telegram_sidecar_can_rewrite_to_embedded_loopback() {
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("AGENTSEC_EMBEDDED_TELEGRAM_BASE", "http://127.0.0.1:8082");

        let route = resolve_unified_route_with_config(
            "telegram",
            "/dialogs?limit=10",
            "GET",
            &[],
            &CredentialConfig {
                description: "Telegram".to_string(),
                api_base: Some("http://telegram-client:8082".to_string()),
                substitution: SubstitutionConfig::default(),
                connector: ConnectorType::Sidecar,
                relative_target: true,
                auth_header_format: None,
                auth_bindings: Vec::new(),
            },
            Some(r#"{"api_id":"123","api_hash":"abc","session_string":"session"}"#),
        )
        .unwrap();

        assert_eq!(
            route.effective_target,
            "http://127.0.0.1:8082/dialogs?limit=10"
        );
        std::env::remove_var("AGENTSEC_EMBEDDED_TELEGRAM_BASE");
    }
}
