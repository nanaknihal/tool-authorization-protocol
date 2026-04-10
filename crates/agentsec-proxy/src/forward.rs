//! HTTP client that forwards requests to target URLs.

use agentsec_core::error::AgentSecError;
use std::time::Duration;

/// Result of forwarding a request to the target.
#[derive(Debug)]
pub struct ForwardResult {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Maximum response body size (10MB).
const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

/// Forward a request to the target URL.
pub async fn forward_request(
    target_url: &str,
    method: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<ForwardResult, AgentSecError> {
    // Disable automatic redirects — reqwest's default policy strips the
    // Authorization header on cross-origin redirects, which breaks Google APIs
    // that redirect between subdomains (e.g. www.googleapis.com → calendar.googleapis.com).
    // The proxy returns the redirect response as-is; the agent can retry if needed.
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| AgentSecError::Internal(format!("Failed to create HTTP client: {e}")))?;

    let reqwest_method = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|e| AgentSecError::Internal(format!("Invalid HTTP method: {e}")))?;

    let mut req = client.request(reqwest_method, target_url);

    // Add headers (skip host and content-length, let reqwest handle those)
    for (name, value) in headers {
        let lower = name.to_lowercase();
        if lower == "host" || lower == "content-length" || lower == "transfer-encoding" {
            continue;
        }
        req = req.header(name.as_str(), value.as_str());
    }

    if let Some(body_bytes) = body {
        req = req.body(body_bytes.to_vec());
    }

    let response = req.send().await.map_err(|e| {
        if e.is_timeout() {
            AgentSecError::Upstream(format!("Request timed out: {e}"))
        } else if e.is_connect() {
            AgentSecError::Upstream(format!("Connection failed: {e}"))
        } else {
            AgentSecError::Upstream(format!("Request failed: {e}"))
        }
    })?;

    let status = response.status().as_u16();

    let resp_headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string()))
        .collect();

    // Read body with size check
    let body = response
        .bytes()
        .await
        .map_err(|e| AgentSecError::Upstream(format!("Failed to read response body: {e}")))?;

    if body.len() > MAX_RESPONSE_SIZE {
        tracing::warn!(
            size = body.len(),
            "Response body exceeds {MAX_RESPONSE_SIZE} bytes, sanitization will be skipped"
        );
    }

    Ok(ForwardResult {
        status,
        headers: resp_headers,
        body: body.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use tokio::net::TcpListener;

    async fn start_mock_server(router: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");

        let handle = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        (url, handle)
    }

    #[tokio::test]
    async fn successful_forward() {
        let app = Router::new().route("/test", get(|| async { "hello" }));
        let (url, _handle) = start_mock_server(app).await;

        let result = forward_request(
            &format!("{url}/test"),
            "GET",
            &[],
            None,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        assert_eq!(result.status, 200);
        assert_eq!(result.body, b"hello");
    }

    #[tokio::test]
    async fn forward_timeout() {
        let app = Router::new().route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                "done"
            }),
        );
        let (url, _handle) = start_mock_server(app).await;

        let result = forward_request(
            &format!("{url}/slow"),
            "GET",
            &[],
            None,
            Duration::from_secs(1),
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("timed out") || err.contains("timeout"));
    }

    #[tokio::test]
    async fn forward_response_too_large() {
        let app = Router::new().route(
            "/large",
            get(|| async {
                // Return 11MB body
                vec![b'A'; 11 * 1024 * 1024]
            }),
        );
        let (url, _handle) = start_mock_server(app).await;

        let result = forward_request(
            &format!("{url}/large"),
            "GET",
            &[],
            None,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        // Response is returned (not rejected) but it's larger than the cap
        assert_eq!(result.status, 200);
        assert!(result.body.len() > MAX_RESPONSE_SIZE);
    }

    #[tokio::test]
    async fn forward_preserves_response_headers() {
        let app = Router::new().route(
            "/headers",
            get(|| async {
                (
                    [("Content-Type", "application/json"), ("X-Custom", "value")],
                    "{}",
                )
            }),
        );
        let (url, _handle) = start_mock_server(app).await;

        let result = forward_request(
            &format!("{url}/headers"),
            "GET",
            &[],
            None,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        assert!(result
            .headers
            .iter()
            .any(|(n, v)| n == "content-type" && v.contains("application/json")));
        assert!(result
            .headers
            .iter()
            .any(|(n, v)| n == "x-custom" && v == "value"));
    }
}
