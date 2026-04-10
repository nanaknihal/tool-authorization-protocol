//! Response sanitization: scan for credential values and redact them.
//!
//! Two modes:
//! 1. Pattern-based scrubbing (from cherry-picked sanitize.rs) for approval messages
//! 2. Exact-match credential scanning for proxy responses (new for AgentSec)

use base64::Engine;
use regex::Regex;
use std::sync::LazyLock;

/// Header names that must never be forwarded to approvers or the AI safety check.
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    "x-auth-token",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "www-authenticate",
    "x-csrf-token",
    "x-xsrf-token",
];

const REDACTED: &str = "[REDACTED]";

static CREDENTIAL_PATTERNS: LazyLock<Vec<(&str, Regex)>> = LazyLock::new(|| {
    vec![
        (
            "bearer_token",
            Regex::new(r"(?i)(bearer|basic)\s+[A-Za-z0-9\-._~+/]+=*").unwrap(),
        ),
        ("aws_key", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
        (
            "hex_secret",
            Regex::new(r"\b[0-9a-fA-F]{32,}\b").unwrap(),
        ),
        (
            "oauth_kv",
            Regex::new(r#"(?i)(oauth_token|oauth_token_secret|consumer_secret|access_token_secret|api_key|api_secret|secret_key|private_key)\s*[=:]\s*"?[^\s",}]+"?"#).unwrap(),
        ),
        (
            "jwt",
            Regex::new(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b").unwrap(),
        ),
        (
            "sk_key",
            Regex::new(r"\b(sk|pk|rk)[-_](live|test|prod|proj)?[-_]?[A-Za-z0-9]{20,}\b").unwrap(),
        ),
    ]
});

/// Max response body size for sanitization (10MB).
const MAX_SANITIZE_SIZE: usize = 10 * 1024 * 1024;

/// Result of response sanitization.
pub struct SanitizeResult {
    pub body: Vec<u8>,
    pub sanitized: bool,
    pub skipped: bool,
}

/// Sanitize a response body by scanning for exact credential values.
/// Also checks base64 and URL-encoded variants.
pub fn sanitize_response(
    body: &[u8],
    credential_values: &[(&str, &str)], // (credential_name, credential_value)
) -> SanitizeResult {
    if body.len() > MAX_SANITIZE_SIZE {
        return SanitizeResult {
            body: body.to_vec(),
            sanitized: false,
            skipped: true,
        };
    }

    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => {
            return SanitizeResult {
                body: body.to_vec(),
                sanitized: false,
                skipped: false,
            };
        }
    };

    let mut result = body_str.to_string();
    let mut any_redacted = false;

    for (cred_name, cred_value) in credential_values {
        if cred_value.is_empty() {
            continue;
        }

        let redacted_marker = format!("[REDACTED:{cred_name}]");

        // Exact match
        if result.contains(*cred_value) {
            result = result.replace(*cred_value, &redacted_marker);
            any_redacted = true;
        }

        // Base64-encoded variant
        let b64_encoded = base64::engine::general_purpose::STANDARD.encode(cred_value.as_bytes());
        if result.contains(&b64_encoded) {
            result = result.replace(&b64_encoded, &redacted_marker);
            any_redacted = true;
        }

        // URL-encoded variant
        let url_encoded = urlencod(cred_value);
        if url_encoded != *cred_value && result.contains(&url_encoded) {
            result = result.replace(&url_encoded, &redacted_marker);
            any_redacted = true;
        }
    }

    SanitizeResult {
        body: result.into_bytes(),
        sanitized: any_redacted,
        skipped: false,
    }
}

/// Simple percent-encoding for credential values.
fn urlencod(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push('%');
                result.push_str(&format!("{:02X}", b));
            }
        }
    }
    result
}

/// Sanitize a list of HTTP headers: replace sensitive header values with [REDACTED].
pub fn sanitize_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let lower = name.to_lowercase();
            if SENSITIVE_HEADERS.contains(&lower.as_str()) {
                (name.clone(), REDACTED.to_string())
            } else {
                (name.clone(), value.clone())
            }
        })
        .collect()
}

/// Scrub credential-like patterns from a string.
pub fn scrub_credentials(text: &str) -> String {
    let mut result = text.to_string();
    for (_name, pattern) in CREDENTIAL_PATTERNS.iter() {
        result = pattern.replace_all(&result, REDACTED).to_string();
    }
    result
}

/// Recursively sanitize a JSON value.
pub fn sanitize_json_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => serde_json::Value::String(scrub_credentials(s)),
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sanitize_json_value).collect())
        }
        serde_json::Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (key, val) in map {
                let lower_key = key.to_lowercase();
                if is_sensitive_key(&lower_key) {
                    new_map.insert(key.clone(), serde_json::Value::String(REDACTED.to_string()));
                } else {
                    new_map.insert(key.clone(), sanitize_json_value(val));
                }
            }
            serde_json::Value::Object(new_map)
        }
        other => other.clone(),
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let sensitive_keys = [
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "consumer_secret",
        "access_token_secret",
        "private_key",
        "client_secret",
        "auth_token",
        "credentials",
    ];
    sensitive_keys.contains(&key)
}

/// Sanitize a raw payload (for approval display / safety check).
pub fn sanitize_raw_payload(payload: &serde_json::Value) -> serde_json::Value {
    let mut sanitized = payload.clone();

    if let Some(obj) = sanitized.as_object_mut() {
        if let Some(headers) = obj.get("headers").cloned() {
            if let Some(arr) = headers.as_array() {
                let clean_headers: Vec<serde_json::Value> = arr
                    .iter()
                    .map(|pair| {
                        if let Some(pair_arr) = pair.as_array() {
                            if pair_arr.len() == 2 {
                                let name = pair_arr[0].as_str().unwrap_or("");
                                let lower = name.to_lowercase();
                                if SENSITIVE_HEADERS.contains(&lower.as_str()) {
                                    return serde_json::json!([name, REDACTED]);
                                }
                            }
                        }
                        pair.clone()
                    })
                    .collect();
                obj.insert(
                    "headers".to_string(),
                    serde_json::Value::Array(clean_headers),
                );
            }
        }

        if let Some(body) = obj.get("body").cloned() {
            obj.insert("body".to_string(), sanitize_json_value(&body));
        }

        if let Some(url) = obj.get("url").and_then(|u| u.as_str()) {
            obj.insert(
                "url".to_string(),
                serde_json::Value::String(scrub_credentials(url)),
            );
        }
    }

    sanitized
}

pub fn sanitize_summary(summary: &str) -> String {
    scrub_credentials(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Header sanitization ────────────────────────────────────────────

    #[test]
    fn strips_authorization_header() {
        let headers = vec![
            (
                "Authorization".to_string(),
                "Bearer sk-abc123xyz".to_string(),
            ),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        let result = sanitize_headers(&headers);
        assert_eq!(result[0].1, REDACTED);
        assert_eq!(result[1].1, "application/json");
    }

    #[test]
    fn strips_x_api_key_header() {
        let headers = vec![("X-Api-Key".to_string(), "my-secret-key-12345".to_string())];
        let result = sanitize_headers(&headers);
        assert_eq!(result[0].1, REDACTED);
    }

    #[test]
    fn header_matching_is_case_insensitive() {
        let headers = vec![
            ("AUTHORIZATION".to_string(), "token".to_string()),
            ("x-API-KEY".to_string(), "token".to_string()),
            ("Cookie".to_string(), "session=abc".to_string()),
        ];
        let result = sanitize_headers(&headers);
        assert!(result.iter().all(|(_, v)| v == REDACTED));
    }

    #[test]
    fn non_sensitive_headers_pass_through() {
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "text/html".to_string()),
            ("X-Request-Id".to_string(), "abc-123".to_string()),
        ];
        let result = sanitize_headers(&headers);
        assert_eq!(result[0].1, "application/json");
        assert_eq!(result[1].1, "text/html");
        assert_eq!(result[2].1, "abc-123");
    }

    // ── Credential scrubbing ───────────────────────────────────────────

    #[test]
    fn scrubs_bearer_tokens() {
        let text = "Here is the token: Bearer eyJhbGciOiJIUzI1NiJ9.test.sig please use it";
        let result = scrub_credentials(text);
        assert!(!result.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(result.contains(REDACTED));
    }

    #[test]
    fn scrubs_aws_keys() {
        let text = "AWS key: AKIAIOSFODNN7EXAMPLE";
        let result = scrub_credentials(text);
        assert!(!result.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn scrubs_jwt_tokens() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let text = format!("Token: {jwt}");
        let result = scrub_credentials(&text);
        assert!(!result.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
    }

    #[test]
    fn scrubs_sk_api_keys() {
        let text = "API key: sk-proj-abc123def456ghi789jkl012mno345";
        let result = scrub_credentials(text);
        assert!(!result.contains("sk-proj-abc123def456ghi789jkl012mno345"));
    }

    #[test]
    fn preserves_normal_text() {
        let text = "Post tweet as @company: \"Hello world! Check out our new product launch.\"";
        let result = scrub_credentials(text);
        assert_eq!(result, text);
    }

    #[test]
    fn preserves_short_hex_strings() {
        let text = "Like tweet 1234567890abcdef";
        let result = scrub_credentials(text);
        assert_eq!(result, text);
    }

    // ── JSON sanitization ──────────────────────────────────────────────

    #[test]
    fn sanitizes_sensitive_json_keys() {
        let value = json!({
            "text": "Hello world",
            "password": "super_secret_123",
            "api_key": "sk-test-abc123",
            "token": "Bearer xyz",
        });
        let result = sanitize_json_value(&value);
        assert_eq!(result["text"], "Hello world");
        assert_eq!(result["password"], REDACTED);
        assert_eq!(result["api_key"], REDACTED);
        assert_eq!(result["token"], REDACTED);
    }

    #[test]
    fn sanitizes_nested_json() {
        let value = json!({
            "action": "post",
            "auth": {
                "access_token": "my-token",
                "consumer_secret": "my-secret"
            },
            "body": {
                "text": "Hello"
            }
        });
        let result = sanitize_json_value(&value);
        assert_eq!(result["auth"]["access_token"], REDACTED);
        assert_eq!(result["auth"]["consumer_secret"], REDACTED);
        assert_eq!(result["body"]["text"], "Hello");
    }

    #[test]
    fn handles_empty_headers() {
        let result = sanitize_headers(&[]);
        assert!(result.is_empty());
    }

    // ── Response sanitization (exact-match credential scanning) ────────

    #[test]
    fn exact_credential_value_match_in_response() {
        let body = b"Your token is sk-live-abc123def456";
        let creds = vec![("credential-name", "sk-live-abc123def456")];
        let result = sanitize_response(body, &creds);
        let body_str = String::from_utf8(result.body).unwrap();
        assert!(body_str.contains("[REDACTED:credential-name]"));
        assert!(!body_str.contains("sk-live-abc123def456"));
        assert!(result.sanitized);
    }

    #[test]
    fn base64_encoded_credential_in_response() {
        let cred_value = "my-secret-api-key-12345";
        let b64 = base64::engine::general_purpose::STANDARD.encode(cred_value.as_bytes());
        let body = format!("encoded: {b64}");
        let creds = vec![("test-cred", cred_value)];
        let result = sanitize_response(body.as_bytes(), &creds);
        let body_str = String::from_utf8(result.body).unwrap();
        assert!(!body_str.contains(&b64));
        assert!(body_str.contains("[REDACTED:test-cred]"));
        assert!(result.sanitized);
    }

    #[test]
    fn url_encoded_credential_in_response() {
        let cred_value = "secret key+value&special=chars";
        let url_enc = urlencod(cred_value);
        let body = format!("param={url_enc}");
        let creds = vec![("test-cred", cred_value)];
        let result = sanitize_response(body.as_bytes(), &creds);
        let body_str = String::from_utf8(result.body).unwrap();
        assert!(!body_str.contains(&url_enc));
        assert!(body_str.contains("[REDACTED:test-cred]"));
        assert!(result.sanitized);
    }

    #[test]
    fn response_exceeds_buffer_cap() {
        let body = vec![b'A'; 11 * 1024 * 1024]; // 11MB
        let creds = vec![("cred", "secret")];
        let result = sanitize_response(&body, &creds);
        assert!(result.skipped);
        assert!(!result.sanitized);
        assert_eq!(result.body.len(), body.len());
    }

    #[test]
    fn clean_response_passthrough() {
        let body = br#"{"status": "ok", "data": [1,2,3]}"#;
        let creds = vec![("cred", "totally-different-secret")];
        let result = sanitize_response(body, &creds);
        assert!(!result.sanitized);
        assert_eq!(result.body, body);
    }

    #[test]
    fn multiple_credential_values_in_one_response() {
        let body = b"first: secret-aaa and second: secret-bbb here";
        let creds = vec![("cred-a", "secret-aaa"), ("cred-b", "secret-bbb")];
        let result = sanitize_response(body, &creds);
        let body_str = String::from_utf8(result.body).unwrap();
        assert!(body_str.contains("[REDACTED:cred-a]"));
        assert!(body_str.contains("[REDACTED:cred-b]"));
        assert!(!body_str.contains("secret-aaa"));
        assert!(!body_str.contains("secret-bbb"));
        assert!(result.sanitized);
    }

    // ── Raw payload sanitization ───────────────────────────────────────

    #[test]
    fn sanitize_raw_payload_strips_auth_headers() {
        let payload = json!({
            "method": "POST",
            "url": "https://api.x.com/2/tweets",
            "headers": [
                ["Authorization", "OAuth oauth_consumer_key=\"abc\""],
                ["Content-Type", "application/json"]
            ],
            "body": {"text": "Hello world"}
        });
        let result = sanitize_raw_payload(&payload);
        let headers = result["headers"].as_array().unwrap();
        assert_eq!(headers[0][1], REDACTED);
        assert_eq!(headers[1][1], "application/json");
    }

    #[test]
    fn sanitize_raw_payload_preserves_clean_payload() {
        let payload = json!({
            "method": "POST",
            "url": "https://api.x.com/2/tweets",
            "headers": [["Content-Type", "application/json"]],
            "body": {"text": "Hello world, this is a tweet!"}
        });
        let result = sanitize_raw_payload(&payload);
        assert_eq!(result["body"]["text"], "Hello world, this is a tweet!");
    }
}
