//! General-purpose OAuth 1.0a signing proxy.
//!
//! Receives HTTP requests, signs them with OAuth 1.0a credentials,
//! and forwards to the target API. Designed to sit behind AgentSec.
//!
//! Configuration via env vars:
//!   OAUTH_CRED_{NAME}_CONSUMER_KEY, _CONSUMER_SECRET, _ACCESS_TOKEN, _ACCESS_TOKEN_SECRET
//!   (auto-discovered by scanning for *_CONSUMER_KEY)

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use hmac::{Hmac, Mac};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde_json::json;
use sha1::Sha1;
use tracing::{info, warn};

/// RFC 5849 percent-encoding set: encode everything except unreserved chars.
const ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn percent_encode(s: &str) -> String {
    utf8_percent_encode(s, ENCODE_SET).to_string()
}

fn generate_nonce() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("{:032x}", rng.gen::<u128>())
}

fn generate_timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string()
}

#[derive(Clone)]
struct OAuthCredential {
    consumer_key: String,
    consumer_secret: String,
    access_token: String,
    access_token_secret: String,
}

#[derive(Clone)]
struct AppState {
    credentials: Arc<HashMap<String, OAuthCredential>>,
}

/// Build the OAuth 1.0a Authorization header.
fn sign_request(
    method: &str,
    url: &str,
    cred: &OAuthCredential,
    body_params: Option<&[(String, String)]>,
) -> String {
    let timestamp = generate_timestamp();
    let nonce = generate_nonce();

    let mut oauth_params: Vec<(String, String)> = vec![
        ("oauth_consumer_key".into(), cred.consumer_key.clone()),
        ("oauth_token".into(), cred.access_token.clone()),
        ("oauth_signature_method".into(), "HMAC-SHA1".into()),
        ("oauth_timestamp".into(), timestamp),
        ("oauth_nonce".into(), nonce),
        ("oauth_version".into(), "1.0".into()),
    ];

    // Collect all params for signature: oauth + query string + body (form-encoded)
    let mut all_params = oauth_params.clone();

    // Parse query string params
    if let Some(query) = url.find('?').map(|i| &url[i + 1..]) {
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                all_params.push((k.to_string(), v.to_string()));
            }
        }
    }

    // Include body params (only for form-urlencoded)
    if let Some(params) = body_params {
        all_params.extend(params.iter().cloned());
    }

    // Sort params
    all_params.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    // Build base URL (without query string)
    let base_url = url.find('?').map_or(url, |i| &url[..i]);

    // Signature base string
    let params_str = all_params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let base_string = format!(
        "{}&{}&{}",
        method.to_uppercase(),
        percent_encode(base_url),
        percent_encode(&params_str)
    );

    // Signing key
    let signing_key = format!(
        "{}&{}",
        percent_encode(&cred.consumer_secret),
        percent_encode(&cred.access_token_secret)
    );

    // HMAC-SHA1
    let mut mac =
        Hmac::<Sha1>::new_from_slice(signing_key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(base_string.as_bytes());
    let signature = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

    oauth_params.push(("oauth_signature".into(), signature));

    // Build Authorization header
    let auth_parts = oauth_params
        .iter()
        .map(|(k, v)| format!("{}=\"{}\"", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join(", ");

    format!("OAuth {auth_parts}")
}

/// Load OAuth credentials from environment variables.
/// Scans for OAUTH_CRED_{NAME}_CONSUMER_KEY to discover credential sets.
fn load_credentials() -> HashMap<String, OAuthCredential> {
    let mut creds = HashMap::new();
    let prefix = "OAUTH_CRED_";
    let suffix = "_CONSUMER_KEY";

    for (key, _) in std::env::vars() {
        if key.starts_with(prefix) && key.ends_with(suffix) {
            let name_upper = &key[prefix.len()..key.len() - suffix.len()];
            let name = name_upper.to_lowercase().replace('_', "-");

            let consumer_key = std::env::var(format!("{prefix}{name_upper}_CONSUMER_KEY"))
                .unwrap_or_default();
            let consumer_secret = std::env::var(format!("{prefix}{name_upper}_CONSUMER_SECRET"))
                .unwrap_or_default();
            let access_token = std::env::var(format!("{prefix}{name_upper}_ACCESS_TOKEN"))
                .unwrap_or_default();
            let access_token_secret =
                std::env::var(format!("{prefix}{name_upper}_ACCESS_TOKEN_SECRET"))
                    .unwrap_or_default();

            if consumer_key.is_empty()
                || consumer_secret.is_empty()
                || access_token.is_empty()
                || access_token_secret.is_empty()
            {
                warn!(credential = %name, "Incomplete OAuth credential — skipping");
                continue;
            }

            creds.insert(
                name.clone(),
                OAuthCredential {
                    consumer_key,
                    consumer_secret,
                    access_token,
                    access_token_secret,
                },
            );
            info!(credential = %name, "Loaded OAuth credential");
        }
    }
    creds
}

/// Request handler — AgentSec forwards using the real HTTP method from X-TAP-Method,
/// so we read the method directly from the incoming request.
async fn handle_request(
    method: axum::http::Method,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Health check via header (no path routing needed — AgentSec forwards to /)
    let cred_name = match headers.get("x-oauth-credential").and_then(|v| v.to_str().ok()) {
        Some(name) => name.trim().to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Missing X-OAuth-Credential header"})),
            )
                .into_response();
        }
    };

    let target_url = match headers.get("x-oauth-target").and_then(|v| v.to_str().ok()) {
        Some(url) => url.trim().to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "Missing X-OAuth-Target header"})),
            )
                .into_response();
        }
    };

    let method = method.as_str().to_uppercase();

    // Prefer inline credential data from proxy (JSON with OAuth keys),
    // fall back to env-var-loaded credentials by name.
    let cred = if let Some(data) = headers.get("x-oauth-credential-data").and_then(|v| v.to_str().ok()) {
        match serde_json::from_str::<serde_json::Value>(data) {
            Ok(v) => {
                let ck = v.get("consumer_key").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let cs = v.get("consumer_secret").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let at = v.get("access_token").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let ats = v.get("access_token_secret").and_then(|x| x.as_str()).unwrap_or("").to_string();
                if ck.is_empty() || cs.is_empty() || at.is_empty() || ats.is_empty() {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": "X-OAuth-Credential-Data JSON missing required fields: consumer_key, consumer_secret, access_token, access_token_secret"})),
                    ).into_response();
                }
                OAuthCredential { consumer_key: ck, consumer_secret: cs, access_token: at, access_token_secret: ats }
            }
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("Invalid X-OAuth-Credential-Data JSON: {e}")})),
                ).into_response();
            }
        }
    } else {
        match state.credentials.get(&cred_name) {
            Some(c) => c.clone(),
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({
                        "error": format!("Unknown credential: {cred_name}"),
                        "available": state.credentials.keys().collect::<Vec<_>>(),
                    })),
                )
                    .into_response();
            }
        }
    };

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Parse body params for OAuth signature (only form-urlencoded per RFC 5849)
    let body_params: Option<Vec<(String, String)>> =
        if content_type.contains("application/x-www-form-urlencoded") && !body.is_empty() {
            Some(
                form_urlencoded::parse(&body)
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            )
        } else {
            None
        };

    // Sign the request
    let auth_header = sign_request(&method, &target_url, &cred, body_params.as_deref());

    // Forward the signed request
    let client = reqwest::Client::new();
    let reqwest_method = match reqwest::Method::from_bytes(method.as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Invalid method: {method}")})),
            )
                .into_response();
        }
    };

    let mut req = client
        .request(reqwest_method, &target_url)
        .header("Authorization", &auth_header)
        .timeout(std::time::Duration::from_secs(30));

    // Copy through relevant headers
    let skip_headers: &[&str] = &[
        "host",
        "x-oauth-credential",
        "x-oauth-target",
        "x-tap-key",
        "x-tap-target",
        "x-tap-method",
        "transfer-encoding",
        "connection",
        "content-length",
        "authorization",
    ];
    for (name, value) in headers.iter() {
        if !skip_headers.contains(&name.as_str()) {
            if let Ok(v) = value.to_str() {
                req = req.header(name.as_str(), v);
            }
        }
    }

    if !body.is_empty() {
        req = req.body(body.to_vec());
    }

    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            let resp_headers = resp.headers().clone();
            let resp_body = resp.bytes().await.unwrap_or_default();

            let mut response = axum::http::Response::builder().status(status);
            for (name, value) in resp_headers.iter() {
                let n = name.as_str();
                if n != "transfer-encoding" && n != "connection" {
                    response = response.header(n, value);
                }
            }
            response
                .body(axum::body::Body::from(resp_body))
                .unwrap_or_else(|_| {
                    (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
                })
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "error": "upstream_error",
                "message": format!("{e}"),
                "target": target_url,
            })),
        )
            .into_response(),
    }
}

async fn handle_health(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "credentials": state.credentials.keys().collect::<Vec<_>>(),
    }))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("agentsec_signer=info".parse().unwrap()),
        )
        .json()
        .init();

    let credentials = load_credentials();
    info!(count = credentials.len(), "OAuth signer starting");

    let state = AppState {
        credentials: Arc::new(credentials),
    };

    // Accept any method on / — AgentSec forwards with the real upstream method
    // (GET for reads, POST for writes). The signer reads X-TAP-Method to
    // know what to sign, regardless of what method it receives.
    let app = axum::Router::new()
        .route("/health", axum::routing::get(handle_health))
        .route(
            "/",
            axum::routing::any(handle_request),
        )
        .fallback(handle_request)
        .with_state(state);

    let port = std::env::var("OAUTH_SIGNER_PORT").unwrap_or_else(|_| "8080".into());
    let addr = format!("0.0.0.0:{port}");
    info!("Listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// Parse form-urlencoded body into key-value pairs.
mod form_urlencoded {
    pub fn parse(input: &[u8]) -> impl Iterator<Item = (String, String)> + '_ {
        let s = std::str::from_utf8(input).unwrap_or("");
        s.split('&').filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((
                urlenccode_decode(k),
                urlenccode_decode(v),
            ))
        })
    }

    fn urlenccode_decode(s: &str) -> String {
        let s = s.replace('+', " ");
        percent_encoding::percent_decode_str(&s)
            .decode_utf8_lossy()
            .to_string()
    }
}
