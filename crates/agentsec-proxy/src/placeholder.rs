//! Parse <CREDENTIAL:name> placeholders from headers and body.
//! CRITICAL: validate placeholder positions to prevent credential exfiltration.

use agentsec_core::config::CredentialConfig;
use agentsec_core::error::AgentSecError;
use agentsec_core::types::{Placeholder, PlaceholderPosition};
use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

static PLACEHOLDER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<CREDENTIAL:([a-zA-Z0-9_-]+)>").unwrap());

/// Headers where credential placeholders are allowed.
const ALLOWED_AUTH_HEADERS: &[&str] = &["authorization", "x-api-key", "x-auth-token"];

fn allowed_header_for_credential(
    credential_configs: &HashMap<String, CredentialConfig>,
    credential_name: &str,
    header_name: &str,
) -> bool {
    match credential_configs.get(credential_name) {
        Some(config) if !config.auth_bindings.is_empty() => config
            .auth_bindings
            .iter()
            .any(|binding| binding.header.eq_ignore_ascii_case(header_name)),
        _ => ALLOWED_AUTH_HEADERS.contains(&header_name.to_lowercase().as_str()),
    }
}

/// Body JSON keys recognized as auth fields (where credential placeholders are allowed).
const ALLOWED_AUTH_BODY_KEYS: &[&str] = &[
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "auth_token",
    "bearer_token",
    "client_secret",
    "password",
    "secret",
    "credentials",
    "oauth_token",
];

/// Parse placeholders from request headers and body.
/// Returns PlaceholderPositionViolation if a placeholder appears in a non-auth position.
pub fn parse_placeholders(
    headers: &[(String, String)],
    body: Option<&[u8]>,
    content_type: Option<&str>,
    credential_configs: &HashMap<String, CredentialConfig>,
) -> Result<Vec<Placeholder>, AgentSecError> {
    let mut placeholders = Vec::new();

    // Parse from headers
    for (name, value) in headers {
        let matches: Vec<_> = PLACEHOLDER_RE.captures_iter(value).collect();
        for cap in &matches {
            let cred_name = cap[1].to_string();
            if cred_name.is_empty() {
                continue;
            }

            if !allowed_header_for_credential(credential_configs, &cred_name, name) {
                return Err(AgentSecError::PlaceholderPositionViolation {
                    credential: cred_name,
                    location: format!(
                        "header '{name}' is not an allowed auth header for this credential"
                    ),
                });
            }

            placeholders.push(Placeholder {
                credential_name: cred_name,
                position: PlaceholderPosition::Header(name.clone()),
            });
        }
    }

    // Parse from body
    if let Some(body_bytes) = body {
        let body_str = match std::str::from_utf8(body_bytes) {
            Ok(s) => s,
            Err(_) => return Ok(placeholders),
        };

        // Check if any placeholders exist in body
        let body_matches: Vec<_> = PLACEHOLDER_RE.captures_iter(body_str).collect();
        if body_matches.is_empty() {
            return Ok(placeholders);
        }

        // For each placeholder in body, check if body substitution is enabled
        for cap in &body_matches {
            let cred_name = cap[1].to_string();
            if cred_name.is_empty() {
                continue;
            }

            let config = credential_configs.get(&cred_name);
            let body_enabled = config.is_some_and(|c| c.substitution.body);

            if !body_enabled {
                return Err(AgentSecError::PlaceholderPositionViolation {
                    credential: cred_name,
                    location: "body (body substitution not enabled for this credential)"
                        .to_string(),
                });
            }

            // Check content type is allowed
            let ct = content_type.unwrap_or("");
            let allowed_types = config
                .map(|c| &c.substitution.body_content_types)
                .cloned()
                .unwrap_or_default();
            if !allowed_types.iter().any(|t| ct.starts_with(t.as_str())) {
                return Err(AgentSecError::PlaceholderPositionViolation {
                    credential: cred_name,
                    location: format!(
                        "body with content-type '{ct}' (not in allowed types: {allowed_types:?})"
                    ),
                });
            }

            // Validate the placeholder is in an auth field position
            validate_body_placeholder_position(body_str, &cred_name, ct)?;

            placeholders.push(Placeholder {
                credential_name: cred_name,
                position: PlaceholderPosition::Body,
            });
        }
    }

    Ok(placeholders)
}

/// Validate that a placeholder in the body is in a recognized auth field.
fn validate_body_placeholder_position(
    body: &str,
    cred_name: &str,
    content_type: &str,
) -> Result<(), AgentSecError> {
    let placeholder = format!("<CREDENTIAL:{cred_name}>");

    if content_type.starts_with("application/json") {
        // Parse as JSON and find which key contains the placeholder
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
            if !json_placeholder_in_auth_field(&value, &placeholder) {
                return Err(AgentSecError::PlaceholderPositionViolation {
                    credential: cred_name.to_string(),
                    location: "body content field (not a recognized auth field)".to_string(),
                });
            }
        }
    } else if content_type.starts_with("application/x-www-form-urlencoded") {
        // Parse key=value pairs and check keys
        if !form_placeholder_in_auth_field(body, &placeholder) {
            return Err(AgentSecError::PlaceholderPositionViolation {
                credential: cred_name.to_string(),
                location: "body form field (not a recognized auth field)".to_string(),
            });
        }
    }

    Ok(())
}

/// Check if a placeholder appears only in recognized auth keys in a JSON value.
fn json_placeholder_in_auth_field(value: &serde_json::Value, placeholder: &str) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                if let serde_json::Value::String(s) = val {
                    if s.contains(placeholder) {
                        let lower_key = key.to_lowercase();
                        if !ALLOWED_AUTH_BODY_KEYS.contains(&lower_key.as_str()) {
                            return false;
                        }
                    }
                }
                // Recurse into nested objects
                if val.is_object() && !json_placeholder_in_auth_field(val, placeholder) {
                    return false;
                }
            }
            true
        }
        serde_json::Value::String(s) => !s.contains(placeholder),
        serde_json::Value::Array(arr) => arr
            .iter()
            .all(|v| json_placeholder_in_auth_field(v, placeholder)),
        _ => true,
    }
}

/// Check if a placeholder in URL-encoded form data is in a recognized auth field.
fn form_placeholder_in_auth_field(body: &str, placeholder: &str) -> bool {
    for pair in body.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            if value.contains(placeholder) {
                let lower_key = key.to_lowercase();
                if !ALLOWED_AUTH_BODY_KEYS.contains(&lower_key.as_str()) {
                    return false;
                }
            }
        }
    }
    true
}

/// Substitute placeholders in headers with real credential values.
pub fn substitute_headers(
    headers: &[(String, String)],
    credential_values: &HashMap<String, String>,
) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let mut new_value = value.clone();
            for (cred_name, cred_value) in credential_values {
                let placeholder = format!("<CREDENTIAL:{cred_name}>");
                new_value = new_value.replace(&placeholder, cred_value);
            }
            (name.clone(), new_value)
        })
        .collect()
}

/// Substitute placeholders in request body with real credential values.
pub fn substitute_body(body: &[u8], credential_values: &HashMap<String, String>) -> Vec<u8> {
    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return body.to_vec(),
    };

    let mut result = body_str.to_string();
    for (cred_name, cred_value) in credential_values {
        let placeholder = format!("<CREDENTIAL:{cred_name}>");
        result = result.replace(&placeholder, cred_value);
    }
    result.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentsec_core::config::{AuthBinding, SubstitutionConfig};

    fn make_cred_config(body: bool) -> CredentialConfig {
        CredentialConfig {
            description: "test".to_string(),
            api_base: None,
            substitution: SubstitutionConfig {
                headers: true,
                body,
                body_content_types: vec![
                    "application/x-www-form-urlencoded".to_string(),
                    "application/json".to_string(),
                ],
            },
            connector: Default::default(),
            relative_target: false,
            auth_header_format: None,
            auth_bindings: Vec::new(),
        }
    }

    fn configs_map(name: &str, body: bool) -> HashMap<String, CredentialConfig> {
        let mut m = HashMap::new();
        m.insert(name.to_string(), make_cred_config(body));
        m
    }

    fn config_with_binding(header: &str) -> CredentialConfig {
        let mut config = make_cred_config(false);
        config.auth_bindings = vec![AuthBinding {
            header: header.to_string(),
            format: "{value}".to_string(),
        }];
        config
    }

    #[test]
    fn parse_single_placeholder_from_header() {
        let headers = vec![(
            "Authorization".to_string(),
            "Bearer <CREDENTIAL:twitter-key>".to_string(),
        )];
        let configs = configs_map("twitter-key", false);
        let result = parse_placeholders(&headers, None, None, &configs).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].credential_name, "twitter-key");
        assert_eq!(
            result[0].position,
            PlaceholderPosition::Header("Authorization".to_string())
        );
    }

    #[test]
    fn parse_multiple_placeholders_from_headers() {
        let headers = vec![
            (
                "Authorization".to_string(),
                "Bearer <CREDENTIAL:twitter-key>".to_string(),
            ),
            (
                "X-Api-Key".to_string(),
                "<CREDENTIAL:backup-key>".to_string(),
            ),
        ];
        let mut configs = configs_map("twitter-key", false);
        configs.insert("backup-key".to_string(), make_cred_config(false));
        let result = parse_placeholders(&headers, None, None, &configs).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].credential_name, "twitter-key");
        assert_eq!(result[1].credential_name, "backup-key");
    }

    #[test]
    fn parse_placeholder_from_body_when_opted_in() {
        let headers = vec![];
        let body = br#"{"token": "<CREDENTIAL:oauth-refresh>"}"#;
        let configs = configs_map("oauth-refresh", true);
        let result =
            parse_placeholders(&headers, Some(body), Some("application/json"), &configs).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].position, PlaceholderPosition::Body);
    }

    #[test]
    fn reject_body_placeholder_when_not_opted_in() {
        let headers = vec![];
        let body = br#"{"token": "<CREDENTIAL:secret>"}"#;
        let configs = configs_map("secret", false);
        let result = parse_placeholders(&headers, Some(body), Some("application/json"), &configs);
        assert!(result.is_err());
    }

    #[test]
    fn reject_body_placeholder_wrong_content_type() {
        let headers = vec![];
        let body = br#"token=<CREDENTIAL:secret>"#;
        let configs = configs_map("secret", true);
        // text/plain is not in allowed content types
        let result = parse_placeholders(&headers, Some(body), Some("text/plain"), &configs);
        assert!(result.is_err());
    }

    #[test]
    fn no_placeholders_passthrough() {
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "text/html".to_string()),
        ];
        let configs = HashMap::new();
        let result = parse_placeholders(&headers, None, None, &configs).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn malformed_placeholder_ignored() {
        // Empty name
        let headers = vec![(
            "Authorization".to_string(),
            "Bearer <CREDENTIAL:>".to_string(),
        )];
        let configs = HashMap::new();
        let result = parse_placeholders(&headers, None, None, &configs).unwrap();
        assert!(result.is_empty());

        // Missing colon
        let headers = vec![("Authorization".to_string(), "<CREDENTIAL>".to_string())];
        let result = parse_placeholders(&headers, None, None, &configs).unwrap();
        assert!(result.is_empty());

        // Unclosed bracket
        let headers = vec![(
            "Authorization".to_string(),
            "<CREDENTIAL:unclosed".to_string(),
        )];
        let result = parse_placeholders(&headers, None, None, &configs).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn placeholder_in_non_auth_header_rejected() {
        let headers = vec![(
            "X-Custom-Data".to_string(),
            "value <CREDENTIAL:secret>".to_string(),
        )];
        let configs = configs_map("secret", false);
        let result = parse_placeholders(&headers, None, None, &configs);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            AgentSecError::PlaceholderPositionViolation { credential, .. } => {
                assert_eq!(credential, "secret");
            }
            _ => panic!("Expected PlaceholderPositionViolation"),
        }
    }

    #[test]
    fn placeholder_in_custom_bound_header_accepted() {
        let headers = vec![(
            "DD-API-KEY".to_string(),
            "<CREDENTIAL:datadog-api>".to_string(),
        )];
        let mut configs = HashMap::new();
        configs.insert("datadog-api".to_string(), config_with_binding("DD-API-KEY"));
        let result = parse_placeholders(&headers, None, None, &configs).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].credential_name, "datadog-api");
    }

    #[test]
    fn placeholder_in_wrong_custom_bound_header_rejected() {
        let headers = vec![(
            "X-API-KEY".to_string(),
            "<CREDENTIAL:datadog-api>".to_string(),
        )];
        let mut configs = HashMap::new();
        configs.insert("datadog-api".to_string(), config_with_binding("DD-API-KEY"));
        let result = parse_placeholders(&headers, None, None, &configs);
        assert!(result.is_err());
    }

    #[test]
    fn placeholder_in_tweet_body_rejected() {
        let headers = vec![];
        let body = br#"{"text": "Hello <CREDENTIAL:slack-token> world"}"#;
        let configs = configs_map("slack-token", true);
        let result = parse_placeholders(&headers, Some(body), Some("application/json"), &configs);
        assert!(result.is_err());
        match result.unwrap_err() {
            AgentSecError::PlaceholderPositionViolation { credential, .. } => {
                assert_eq!(credential, "slack-token");
            }
            _ => panic!("Expected PlaceholderPositionViolation"),
        }
    }

    #[test]
    fn placeholder_in_auth_body_field_accepted() {
        let headers = vec![];
        let body =
            br#"{"grant_type": "refresh_token", "refresh_token": "<CREDENTIAL:oauth-refresh>"}"#;
        let configs = configs_map("oauth-refresh", true);
        let result =
            parse_placeholders(&headers, Some(body), Some("application/json"), &configs).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].credential_name, "oauth-refresh");
    }

    #[test]
    fn placeholder_in_url_encoded_body() {
        let headers = vec![];
        let body = b"grant_type=refresh_token&refresh_token=<CREDENTIAL:oauth-refresh>";
        let configs = configs_map("oauth-refresh", true);
        let result = parse_placeholders(
            &headers,
            Some(body),
            Some("application/x-www-form-urlencoded"),
            &configs,
        )
        .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].credential_name, "oauth-refresh");
    }
}
