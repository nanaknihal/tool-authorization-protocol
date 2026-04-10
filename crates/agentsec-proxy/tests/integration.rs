//! Integration tests for the proxy round-trip.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use agentsec_core::approval::{ApprovalChannel, ApprovalContext};
use agentsec_core::config::AuthBinding;
use agentsec_core::error::AgentSecError;
use agentsec_core::store::{ConfigStore, PolicyRow};
use agentsec_core::types::*;
use agentsec_proxy::audit::InMemoryAuditLogger;
use agentsec_proxy::auth::hash_api_key;
use agentsec_proxy::db_state::DbState;
use agentsec_proxy::proxy::{build_router, AppState};
use axum::body::Body;
use axum::http::Request;
use serde_json::json;
use tower::util::ServiceExt;

fn test_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = i as u8;
    }
    key
}

/// Create a temporary ConfigStore backed by a real SQLite file.
async fn temp_store() -> (ConfigStore, tempfile::NamedTempFile) {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    let store = ConfigStore::new(&path, None, test_key()).await.unwrap();
    store.create_team("t1", "test-team").await.unwrap();
    (store, tmp)
}

struct MockApproval {
    auto_approve: bool,
    calls: std::sync::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl ApprovalChannel for MockApproval {
    async fn send_approval_request(
        &self,
        request: &ProxyRequest,
        _desc: &str,
        _context: &ApprovalContext,
    ) -> Result<String, AgentSecError> {
        self.calls.lock().unwrap().push(request.agent_id.clone());
        Ok("mock-id".to_string())
    }

    async fn wait_for_decision(
        &self,
        _id: &str,
        _timeout: u64,
    ) -> Result<ApprovalStatus, AgentSecError> {
        if self.auto_approve {
            Ok(ApprovalStatus::Approved)
        } else {
            Ok(ApprovalStatus::Denied)
        }
    }

    fn format_message(&self, _request: &ProxyRequest, _desc: &str) -> String {
        "mock".to_string()
    }
}

async fn make_state(
    mock_approval: Arc<dyn ApprovalChannel>,
) -> (AppState, Arc<InMemoryAuditLogger>, tempfile::NamedTempFile) {
    let enc_key = test_key();
    let key_hash = hash_api_key("integration-test-key");

    let (store, tmp) = temp_store().await;
    store
        .create_credential(
            "t1",
            "cred-a",
            "Credential A",
            "direct",
            None,
            false,
            None,
            None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "cred-a", b"secret123")
        .await
        .unwrap();
    store
        .create_agent("t1", "test-agent", None, &key_hash, None)
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "test-agent", "cred-a")
        .await
        .unwrap();
    store
        .set_policy(&PolicyRow {
            team_id: "t1".to_string(),
            credential_name: "cred-a".to_string(),
            auto_approve_methods: vec!["GET".to_string()],
            require_approval_methods: vec![
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
            ],
            auto_approve_urls: vec![],
            allowed_approvers: vec![],
            telegram_chat_id: None,
            require_passkey: false,
        })
        .await
        .unwrap();

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let audit_logger = Arc::new(InMemoryAuditLogger::new());
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock_approval,
        audit_logger: audit_logger.clone(),
        forward_timeout: Duration::from_secs(30),
        rate_counts: Arc::new(std::sync::Mutex::new(HashMap::new())),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
        oauth_states: Arc::new(std::sync::Mutex::new(HashMap::new())),
    };
    (state, audit_logger, tmp)
}

async fn start_mock_upstream() -> (String, tokio::task::JoinHandle<()>) {
    use axum::routing::get;

    let app = axum::Router::new()
        .route(
            "/api/data",
            get(|| async { axum::Json(json!({"data": "hello"})) }),
        )
        .route(
            "/api/leak",
            get(|| async { "response contains secret123 value" }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, handle)
}

#[tokio::test]
async fn integration_proxy_auto_approves_get() {
    let (upstream_url, _h) = start_mock_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock.clone()).await;
    let app = build_router(state.clone());

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-target", format!("{upstream_url}/api/data"))
        .header("x-tap-method", "GET")
        .header("authorization", "Bearer <CREDENTIAL:cred-a>")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"], "hello");

    // GET should be auto-approved - no approval channel calls
    assert!(mock.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn integration_proxy_rejects_unauthorized_agent() {
    let (upstream_url, _h) = start_mock_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "wrong-key")
        .header("x-tap-target", format!("{upstream_url}/api/data"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn integration_proxy_rejects_non_whitelisted_credential() {
    let (upstream_url, _h) = start_mock_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-target", format!("{upstream_url}/api/data"))
        .header("x-tap-method", "GET")
        .header("authorization", "Bearer <CREDENTIAL:cred-b>")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn integration_proxy_sanitizes_leaked_credential() {
    let (upstream_url, _h) = start_mock_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-target", format!("{upstream_url}/api/leak"))
        .header("x-tap-method", "GET")
        .header("authorization", "Bearer <CREDENTIAL:cred-a>")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(!body_str.contains("secret123"));
    assert!(body_str.contains("[REDACTED:cred-a]"));
}

#[tokio::test]
async fn integration_proxy_rejects_placeholder_in_body_content() {
    // DB credentials use default substitution (headers only), so body placeholders
    // are not parsed. Test that credential in header works but body text is passed through.
    let (upstream_url, _h) = start_mock_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock).await;
    let app = build_router(state);

    // With default substitution, a placeholder in the body is ignored (not substituted,
    // not validated), and only headers get substituted. This request should succeed.
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-target", format!("{upstream_url}/api/data"))
        .header("x-tap-method", "GET")
        .header("authorization", "Bearer <CREDENTIAL:cred-a>")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"text": "hello"}"#))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn integration_audit_log_written() {
    let (upstream_url, _h) = start_mock_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, audit, _tmp) = make_state(mock).await;
    let app = build_router(state.clone());

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-target", format!("{upstream_url}/api/data"))
        .header("x-tap-method", "GET")
        .header("authorization", "Bearer <CREDENTIAL:cred-a>")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let entries = audit.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].agent_id, "test-agent");
    assert_eq!(entries[0].method, HttpMethod::Get);
}

#[tokio::test]
async fn integration_proxy_rejects_hallucinated_tap_headers() {
    // This catches the "X-TAP-Body" hallucination directly, instead of letting
    // it degrade into a confusing upstream validation error later.
    let (upstream_url, _h) = start_mock_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-target", format!("{upstream_url}/api/data"))
        .header("x-tap-method", "POST")
        .header("x-tap-body", "hallucinated content")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 400);

    let body_bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let err = value["error"].as_str().unwrap_or("");
    assert!(err.to_lowercase().contains("x-tap-body"));
    let detail = value["detail"].as_str().unwrap_or("");
    assert!(detail.contains("HTTP request body"));
    assert!(detail.to_lowercase().contains("plain http headers"));
}

#[tokio::test]
async fn integration_proxy_rejects_hallucinated_tap_header_prefix() {
    let (upstream_url, _h) = start_mock_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-target", format!("{upstream_url}/api/data"))
        .header("x-tap-method", "GET")
        .header("x-tap-header-notion-version", "2022-06-28")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 400);

    let body_bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let err = value["error"].as_str().unwrap_or("");
    assert!(err.to_lowercase().contains("x-tap-header"));
    let detail = value["detail"].as_str().unwrap_or("");
    assert!(
        detail.to_lowercase().contains("notion-version")
            || detail.to_lowercase().contains("plain http headers")
    );
}

#[tokio::test]
async fn integration_proxy_accepts_all_known_tap_headers() {
    let (upstream_url, _h) = start_mock_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-target", format!("{upstream_url}/api/data"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_ne!(resp.status(), 400);
}

// =========================================================================
// Unified interface tests (X-TAP-Credential)
// =========================================================================

/// Helper: build state with direct credentials for unified interface testing.
async fn make_unified_direct_state(
    mock_approval: Arc<dyn ApprovalChannel>,
) -> (AppState, Arc<InMemoryAuditLogger>, tempfile::NamedTempFile) {
    let enc_key = test_key();
    let key_hash = hash_api_key("integration-test-key");

    let (store, tmp) = temp_store().await;
    store
        .create_credential(
            "t1",
            "direct-cred",
            "Direct test credential",
            "direct",
            None,
            false,
            None,
            None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "direct-cred", b"direct-secret-val")
        .await
        .unwrap();
    store
        .create_credential(
            "t1",
            "legacy-cred",
            "Legacy placeholder credential",
            "direct",
            None,
            false,
            None,
            None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "legacy-cred", b"legacy-secret-val")
        .await
        .unwrap();
    let custom_auth_bindings = serde_json::to_string(&vec![AuthBinding {
        header: "DD-API-KEY".to_string(),
        format: "{value}".to_string(),
    }])
    .unwrap();
    store
        .create_credential(
            "t1",
            "custom-auth-cred",
            "Custom header auth credential",
            "direct",
            None,
            false,
            None,
            Some(&custom_auth_bindings),
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "custom-auth-cred", b"dd-secret-val")
        .await
        .unwrap();
    store
        .create_agent("t1", "test-agent", None, &key_hash, None)
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "test-agent", "direct-cred")
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "test-agent", "legacy-cred")
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "test-agent", "custom-auth-cred")
        .await
        .unwrap();
    for cred in &["direct-cred", "legacy-cred", "custom-auth-cred"] {
        store
            .set_policy(&PolicyRow {
                team_id: "t1".to_string(),
                credential_name: cred.to_string(),
                auto_approve_methods: vec!["GET".to_string()],
                require_approval_methods: vec!["POST".to_string()],
                auto_approve_urls: vec![],
                allowed_approvers: vec![],
                telegram_chat_id: None,
                require_passkey: false,
            })
            .await
            .unwrap();
    }

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let audit_logger = Arc::new(InMemoryAuditLogger::new());
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock_approval,
        audit_logger: audit_logger.clone(),
        forward_timeout: Duration::from_secs(30),
        rate_counts: Arc::new(std::sync::Mutex::new(HashMap::new())),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
        oauth_states: Arc::new(std::sync::Mutex::new(HashMap::new())),
    };
    (state, audit_logger, tmp)
}

/// Helper: start a mock upstream that records received headers.
async fn start_recording_upstream() -> (
    String,
    tokio::task::JoinHandle<()>,
    Arc<std::sync::Mutex<Vec<Vec<(String, String)>>>>,
) {
    use axum::body::Bytes;
    use axum::http::HeaderMap;
    use axum::routing::get;

    let recorded: Arc<std::sync::Mutex<Vec<Vec<(String, String)>>>> =
        Arc::new(std::sync::Mutex::new(vec![]));
    let rec = recorded.clone();

    let app = axum::Router::new().route(
        "/test",
        get({
            let rec = rec.clone();
            move |headers: HeaderMap| {
                let rec = rec.clone();
                async move {
                    let hdrs: Vec<(String, String)> = headers
                        .iter()
                        .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or("").to_string()))
                        .collect();
                    rec.lock().unwrap().push(hdrs);
                    axum::Json(json!({"ok": true}))
                }
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, handle, recorded)
}

#[tokio::test]
async fn unified_direct_auto_approves_get() {
    let (upstream_url, _h, recorded) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, audit, _tmp) = make_unified_direct_state(mock.clone()).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-credential", "direct-cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    // Should be auto-approved (GET), no approval calls
    assert!(mock.calls.lock().unwrap().is_empty());

    // Upstream should have received Authorization: Bearer direct-secret-val
    let recs = recorded.lock().unwrap();
    assert_eq!(recs.len(), 1);
    let auth = recs[0]
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.as_str());
    assert_eq!(auth, Some("Bearer direct-secret-val"));

    // Audit log should have entry
    let entries = audit.entries();
    assert_eq!(entries.len(), 1);
}

#[tokio::test]
async fn unified_credential_not_in_whitelist_returns_403() {
    let (upstream_url, _h, _) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _, _tmp) = make_unified_direct_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-credential", "nonexistent-cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 403); // credential not in agent's whitelist
}

#[tokio::test]
async fn unified_and_legacy_coexist() {
    // Test that unified and legacy paths both work in the same proxy instance
    let (upstream_url, _h, recorded) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, audit, _tmp) = make_unified_direct_state(mock).await;

    // First: unified path
    let app1 = build_router(state.clone());
    let req1 = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-credential", "direct-cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();
    let resp1 = app1.oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), 200);

    // Second: legacy placeholder path
    let app2 = build_router(state.clone());
    let req2 = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .header("authorization", "Bearer <CREDENTIAL:legacy-cred>")
        .body(Body::empty())
        .unwrap();
    let resp2 = app2.oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), 200);

    // Both should have hit upstream
    let recs = recorded.lock().unwrap();
    assert_eq!(recs.len(), 2);

    // First used unified (Bearer direct-secret-val)
    let auth1 = recs[0]
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.as_str());
    assert_eq!(auth1, Some("Bearer direct-secret-val"));

    // Second used legacy placeholder (Bearer legacy-secret-val)
    let auth2 = recs[1]
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.as_str());
    assert_eq!(auth2, Some("Bearer legacy-secret-val"));

    // Both should be in audit log
    assert_eq!(audit.entries().len(), 2);
}

#[tokio::test]
async fn unified_response_sanitization() {
    // Upstream leaks credential in response — proxy should redact it
    use axum::routing::get;

    let app_upstream = axum::Router::new().route(
        "/leak",
        get(|| async { "the token is direct-secret-val oops" }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream_url = format!("http://{addr}");
    let _h = tokio::spawn(async move {
        axum::serve(listener, app_upstream).await.unwrap();
    });

    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _, _tmp) = make_unified_direct_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "integration-test-key")
        .header("x-tap-credential", "direct-cred")
        .header("x-tap-target", format!("{upstream_url}/leak"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(!body_str.contains("direct-secret-val"));
    assert!(body_str.contains("[REDACTED:direct-cred]"));
}

#[tokio::test]
async fn unified_services_endpoint() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _, _tmp) = make_unified_direct_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/agent/services")
        .header("x-tap-key", "integration-test-key")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["agent_id"], "test-agent");
    assert!(value["services"]["direct-cred"].is_object());
    assert!(value["services"]["legacy-cred"].is_object());
    assert!(value["usage"]["headers"]["X-TAP-Credential"].is_string());
    assert_eq!(
        value["services"]["direct-cred"]["auth_mode"],
        "authorization_header"
    );
    assert_eq!(
        value["services"]["direct-cred"]["auth_header_names"][0],
        "Authorization"
    );
    assert_eq!(
        value["services"]["custom-auth-cred"]["auth_mode"],
        "custom_headers"
    );
    assert_eq!(
        value["services"]["custom-auth-cred"]["auth_header_names"][0],
        "DD-API-KEY"
    );
    assert_eq!(value["usage"]["custom_upstream_headers_forwarded"], true);
    assert_eq!(value["usage"]["unknown_tap_headers_rejected"], true);
    assert_eq!(value["usage"]["supported_tap_headers"][0], "x-tap-key");
}

#[tokio::test]
async fn unified_services_requires_auth() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _, _tmp) = make_unified_direct_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/agent/services")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);
}

// =========================================================================
// Database mode integration tests
// =========================================================================

/// Helper: start a mock upstream that records headers, accepting both GET and POST.
async fn start_recording_post_upstream() -> (
    String,
    tokio::task::JoinHandle<()>,
    Arc<std::sync::Mutex<Vec<Vec<(String, String)>>>>,
) {
    use axum::http::HeaderMap;
    use axum::routing::{get, post};

    let recorded: Arc<std::sync::Mutex<Vec<Vec<(String, String)>>>> =
        Arc::new(std::sync::Mutex::new(vec![]));
    let rec = recorded.clone();

    let handler = |rec: Arc<std::sync::Mutex<Vec<Vec<(String, String)>>>>| {
        move |headers: HeaderMap| {
            let rec = rec.clone();
            async move {
                let hdrs: Vec<(String, String)> = headers
                    .iter()
                    .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();
                rec.lock().unwrap().push(hdrs);
                axum::Json(json!({"ok": true}))
            }
        }
    };

    let app = axum::Router::new()
        .route("/test", get(handler(rec.clone())))
        .route("/test", post(handler(rec.clone())));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, handle, recorded)
}

/// Build an AppState wired to a real SQLite database.
/// Sets up: credential "api-cred" (direct), agent "db-agent" with key "db-test-key",
/// policy: GET auto-approve, POST require-approval.
async fn make_db_state(
    mock_approval: Arc<dyn ApprovalChannel>,
) -> (AppState, Arc<InMemoryAuditLogger>, tempfile::NamedTempFile) {
    let enc_key = test_key();
    let (store, tmp) = temp_store().await;

    // Create credential
    store
        .create_credential(
            "t1",
            "api-cred",
            "API Credential",
            "direct",
            None,
            false,
            None,
            None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "api-cred", b"db-secret-val")
        .await
        .unwrap();

    // Create agent with API key hash
    let api_key = "db-test-key";
    let key_hash = hash_api_key(api_key);
    store
        .create_agent("t1", "db-agent", Some("Test DB agent"), &key_hash, None)
        .await
        .unwrap();

    // Grant credential directly to agent
    store
        .add_direct_credential("t1", "db-agent", "api-cred")
        .await
        .unwrap();

    // Set policy
    store
        .set_policy(&PolicyRow {
            team_id: "t1".to_string(),
            credential_name: "api-cred".to_string(),
            auto_approve_methods: vec!["GET".to_string()],
            require_approval_methods: vec!["POST".to_string(), "PUT".to_string()],
            auto_approve_urls: vec![],
            allowed_approvers: vec![],
            telegram_chat_id: None,
            require_passkey: false,
        })
        .await
        .unwrap();

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let audit_logger = Arc::new(InMemoryAuditLogger::new());

    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock_approval,
        audit_logger: audit_logger.clone(),
        forward_timeout: Duration::from_secs(30),
        rate_counts: Arc::new(std::sync::Mutex::new(HashMap::new())),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
        oauth_states: Arc::new(std::sync::Mutex::new(HashMap::new())),
    };
    (state, audit_logger, tmp)
}

#[tokio::test]
async fn db_mode_unified_auto_approves_get() {
    let (upstream_url, _h, recorded) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, audit, _tmp) = make_db_state(mock.clone()).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "db-test-key")
        .header("x-tap-credential", "api-cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    // GET auto-approved — no approval calls
    assert!(mock.calls.lock().unwrap().is_empty());

    // Upstream received Bearer with decrypted credential value
    let recs = recorded.lock().unwrap();
    assert_eq!(recs.len(), 1);
    let auth = recs[0]
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.as_str());
    assert_eq!(auth, Some("Bearer db-secret-val"));

    // Audit log written
    let entries = audit.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].agent_id, "db-agent");
}

#[tokio::test]
async fn db_mode_post_requires_approval() {
    let (upstream_url, _h, _recorded) = start_recording_post_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_db_state(mock.clone()).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "db-test-key")
        .header("x-tap-credential", "api-cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "POST")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    // POST should have triggered approval
    assert_eq!(mock.calls.lock().unwrap().len(), 1);
    assert_eq!(mock.calls.lock().unwrap()[0], "db-agent");
}

#[tokio::test]
async fn db_mode_rejects_invalid_api_key() {
    let (upstream_url, _h, _) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_db_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "wrong-key")
        .header("x-tap-credential", "api-cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn db_mode_rejects_non_whitelisted_credential() {
    let (upstream_url, _h, _) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_db_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "db-test-key")
        .header("x-tap-credential", "other-cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn db_mode_disabled_agent_rejected() {
    let (upstream_url, _h, _) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_db_state(mock).await;

    // Disable the agent
    state
        .db_state
        .store()
        .disable_agent("t1", "db-agent")
        .await
        .unwrap();

    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "db-test-key")
        .header("x-tap-credential", "api-cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn db_mode_rbac_role_grants_credential_access() {
    let (upstream_url, _h, recorded) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });

    let enc_key = test_key();
    let (store, _tmp) = temp_store().await;

    // Create credential
    store
        .create_credential(
            "t1",
            "slack",
            "Slack API",
            "direct",
            None,
            false,
            None,
            None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "slack", b"xoxb-slack-token")
        .await
        .unwrap();

    // Create role "comms" that includes "slack"
    store.create_role("t1", "comms", None, None).await.unwrap();
    store
        .add_credential_to_role("t1", "comms", "slack")
        .await
        .unwrap();

    // Create agent and assign role (NOT direct credential)
    let key_hash = hash_api_key("rbac-key");
    store
        .create_agent("t1", "rbac-bot", None, &key_hash, None)
        .await
        .unwrap();
    store
        .assign_role_to_agent("t1", "rbac-bot", "comms")
        .await
        .unwrap();

    // Set policy: auto-approve GET
    store
        .set_policy(&PolicyRow {
            team_id: "t1".to_string(),
            credential_name: "slack".to_string(),
            auto_approve_methods: vec!["GET".to_string()],
            require_approval_methods: vec!["POST".to_string()],
            auto_approve_urls: vec![],
            allowed_approvers: vec![],
            telegram_chat_id: None,
            require_passkey: false,
        })
        .await
        .unwrap();

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let audit_logger = Arc::new(InMemoryAuditLogger::new());

    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock,
        audit_logger: audit_logger.clone(),
        forward_timeout: Duration::from_secs(30),
        rate_counts: Arc::new(std::sync::Mutex::new(HashMap::new())),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
        oauth_states: Arc::new(std::sync::Mutex::new(HashMap::new())),
    };

    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "rbac-key")
        .header("x-tap-credential", "slack")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    // Upstream got the credential via role-based access
    let recs = recorded.lock().unwrap();
    assert_eq!(recs.len(), 1);
    let auth = recs[0]
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.as_str());
    assert_eq!(auth, Some("Bearer xoxb-slack-token"));

    assert_eq!(audit_logger.entries().len(), 1);
    assert_eq!(audit_logger.entries()[0].agent_id, "rbac-bot");
}

#[tokio::test]
async fn db_mode_rbac_multiple_roles_union() {
    let (upstream_url, _h, _) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });

    let enc_key = test_key();
    let (store, _tmp) = temp_store().await;

    // Create three credentials
    store
        .create_credential("t1", "slack", "Slack", "direct", None, false, None, None)
        .await
        .unwrap();
    store
        .set_credential_value("t1", "slack", b"slack-token")
        .await
        .unwrap();
    store
        .create_credential("t1", "github", "GitHub", "direct", None, false, None, None)
        .await
        .unwrap();
    store
        .set_credential_value("t1", "github", b"gh-token")
        .await
        .unwrap();
    store
        .create_credential("t1", "openai", "OpenAI", "direct", None, false, None, None)
        .await
        .unwrap();
    store
        .set_credential_value("t1", "openai", b"sk-openai")
        .await
        .unwrap();

    // Create two roles with different credentials
    store.create_role("t1", "comms", None, None).await.unwrap();
    store
        .add_credential_to_role("t1", "comms", "slack")
        .await
        .unwrap();
    store.create_role("t1", "dev", None, None).await.unwrap();
    store
        .add_credential_to_role("t1", "dev", "github")
        .await
        .unwrap();

    // Create agent with both roles + one direct credential
    let key_hash = hash_api_key("multi-key");
    store
        .create_agent("t1", "multi-bot", None, &key_hash, None)
        .await
        .unwrap();
    store
        .assign_role_to_agent("t1", "multi-bot", "comms")
        .await
        .unwrap();
    store
        .assign_role_to_agent("t1", "multi-bot", "dev")
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "multi-bot", "openai")
        .await
        .unwrap();

    // Auto-approve everything for simplicity
    for cred in &["slack", "github", "openai"] {
        store
            .set_policy(&PolicyRow {
                team_id: "t1".to_string(),
                credential_name: cred.to_string(),
                auto_approve_methods: vec!["GET".to_string()],
                require_approval_methods: vec![],
                auto_approve_urls: vec![],
                allowed_approvers: vec![],
                telegram_chat_id: None,
                require_passkey: false,
            })
            .await
            .unwrap();
    }

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock,
        audit_logger: Arc::new(InMemoryAuditLogger::new()),
        forward_timeout: Duration::from_secs(30),
        rate_counts: Arc::new(std::sync::Mutex::new(HashMap::new())),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
        oauth_states: Arc::new(std::sync::Mutex::new(HashMap::new())),
    };

    // Agent can access all three credentials (slack via comms, github via dev, openai direct)
    for cred in &["slack", "github", "openai"] {
        let app = build_router(state.clone());
        let req = Request::builder()
            .method("POST")
            .uri("/forward")
            .header("x-tap-key", "multi-key")
            .header("x-tap-credential", *cred)
            .header("x-tap-target", format!("{upstream_url}/test"))
            .header("x-tap-method", "GET")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200, "Failed to access credential '{cred}'");
    }

    // Agent cannot access a credential not in any role or direct
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "multi-key")
        .header("x-tap-credential", "not-assigned")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn db_mode_response_sanitizes_leaked_credential() {
    use axum::routing::get;

    let app_upstream = axum::Router::new().route(
        "/leak",
        get(|| async { "oops the token is db-secret-val leaked" }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream_url = format!("http://{addr}");
    let _h = tokio::spawn(async move {
        axum::serve(listener, app_upstream).await.unwrap();
    });

    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_db_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "db-test-key")
        .header("x-tap-credential", "api-cred")
        .header("x-tap-target", format!("{upstream_url}/leak"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        !body_str.contains("db-secret-val"),
        "Credential value leaked in response"
    );
    assert!(body_str.contains("[REDACTED:api-cred]"));
}

#[tokio::test]
async fn db_mode_rate_limit_enforced() {
    let (upstream_url, _h, _) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });

    let enc_key = test_key();
    let (store, _tmp) = temp_store().await;

    store
        .create_credential("t1", "cred", "Cred", "direct", None, false, None, None)
        .await
        .unwrap();
    store
        .set_credential_value("t1", "cred", b"val")
        .await
        .unwrap();

    // Agent with rate limit of 3 per hour (check_rate_limit uses >=, so 3 allows 2 requests)
    let key_hash = hash_api_key("rate-key");
    store
        .create_agent("t1", "rate-bot", None, &key_hash, Some(3))
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "rate-bot", "cred")
        .await
        .unwrap();
    store
        .set_policy(&PolicyRow {
            team_id: "t1".to_string(),
            credential_name: "cred".to_string(),
            auto_approve_methods: vec!["GET".to_string()],
            require_approval_methods: vec![],
            auto_approve_urls: vec![],
            allowed_approvers: vec![],
            telegram_chat_id: None,
            require_passkey: false,
        })
        .await
        .unwrap();

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock,
        audit_logger: Arc::new(InMemoryAuditLogger::new()),
        forward_timeout: Duration::from_secs(30),
        rate_counts: Arc::new(std::sync::Mutex::new(HashMap::new())),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
        oauth_states: Arc::new(std::sync::Mutex::new(HashMap::new())),
    };

    // First two requests succeed
    for i in 0..2 {
        let app = build_router(state.clone());
        let req = Request::builder()
            .method("POST")
            .uri("/forward")
            .header("x-tap-key", "rate-key")
            .header("x-tap-credential", "cred")
            .header("x-tap-target", format!("{upstream_url}/test"))
            .header("x-tap-method", "GET")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200, "Request {i} should succeed");
    }

    // Third request rate-limited
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "rate-key")
        .header("x-tap-credential", "cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 429);
}

#[tokio::test]
async fn db_mode_agent_services_endpoint() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_db_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/agent/services")
        .header("x-tap-key", "db-test-key")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["agent_id"], "db-agent");
    assert!(value["services"]["api-cred"].is_object());
    assert_eq!(
        value["services"]["api-cred"]["reads_auto_approved"],
        json!(true)
    );
    assert_eq!(
        value["services"]["api-cred"]["writes_need_approval"],
        json!(true)
    );
}

#[tokio::test]
async fn db_mode_agent_config_endpoint() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_db_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/agent/config")
        .header("x-tap-key", "db-test-key")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["agent_id"], "db-agent");
    let creds = value["credentials"].as_array().unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0]["name"], "api-cred");
    assert_eq!(creds[0]["description"], "API Credential");
}

#[tokio::test]
async fn db_mode_approval_denied_returns_403() {
    let (upstream_url, _h, _) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: false, // deny
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _audit, _tmp) = make_db_state(mock).await;
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "db-test-key")
        .header("x-tap-credential", "api-cred")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "POST") // requires approval
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn db_mode_sidecar_credential_routing() {
    // Set up a mock sidecar that records what it receives (handles GET on /)
    use axum::http::HeaderMap;
    use axum::routing::get;

    let recorded: Arc<std::sync::Mutex<Vec<Vec<(String, String)>>>> =
        Arc::new(std::sync::Mutex::new(vec![]));
    let rec = recorded.clone();

    let sidecar_app = axum::Router::new().route(
        "/",
        get({
            let rec = rec.clone();
            move |headers: HeaderMap| {
                let rec = rec.clone();
                async move {
                    let hdrs: Vec<(String, String)> = headers
                        .iter()
                        .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or("").to_string()))
                        .collect();
                    rec.lock().unwrap().push(hdrs);
                    axum::Json(json!({"ok": true}))
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let sidecar_url = format!("http://{addr}");
    let _h = tokio::spawn(async move {
        axum::serve(listener, sidecar_app).await.unwrap();
    });
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });

    let enc_key = test_key();
    let (store, _tmp) = temp_store().await;

    // Create sidecar credential (e.g., OAuth signer)
    store
        .create_credential(
            "t1",
            "twitter",
            "Twitter via OAuth signer",
            "sidecar",
            Some(&sidecar_url),
            false,
            None,
            None,
        )
        .await
        .unwrap();

    let key_hash = hash_api_key("sidecar-key");
    store
        .create_agent("t1", "sidecar-bot", None, &key_hash, None)
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "sidecar-bot", "twitter")
        .await
        .unwrap();
    store
        .set_policy(&PolicyRow {
            team_id: "t1".to_string(),
            credential_name: "twitter".to_string(),
            auto_approve_methods: vec!["GET".to_string()],
            require_approval_methods: vec![],
            auto_approve_urls: vec![],
            allowed_approvers: vec![],
            telegram_chat_id: None,
            require_passkey: false,
        })
        .await
        .unwrap();

    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock,
        audit_logger: Arc::new(InMemoryAuditLogger::new()),
        forward_timeout: Duration::from_secs(30),
        rate_counts: Arc::new(std::sync::Mutex::new(HashMap::new())),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
        oauth_states: Arc::new(std::sync::Mutex::new(HashMap::new())),
    };

    let app = build_router(state);

    // Agent sends request — proxy routes to sidecar with X-OAuth-* headers
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", "sidecar-key")
        .header("x-tap-credential", "twitter")
        .header("x-tap-target", "https://api.twitter.com/2/tweets")
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    // Sidecar should have received X-OAuth-Credential and X-OAuth-Target
    let recs = recorded.lock().unwrap();
    assert_eq!(recs.len(), 1);
    let oauth_cred = recs[0]
        .iter()
        .find(|(n, _)| n == "x-oauth-credential")
        .map(|(_, v)| v.as_str());
    assert_eq!(oauth_cred, Some("twitter"));
    let oauth_target = recs[0]
        .iter()
        .find(|(n, _)| n == "x-oauth-target")
        .map(|(_, v)| v.as_str());
    assert_eq!(oauth_target, Some("https://api.twitter.com/2/tweets"));
}

// =========================================================================
// Multi-tenant isolation + admin API tests
// =========================================================================

/// Helper: sign up a team, verify email manually, login, return session token.
async fn signup_and_login(
    state: &AppState,
    team_name: &str,
    email: &str,
    password: &str,
) -> String {
    let store = state.db_state.store();

    // Create team + admin directly (bypassing email verification for tests)
    let team_id = uuid::Uuid::new_v4().to_string();
    store.create_team(&team_id, team_name).await.unwrap();

    let admin_id = uuid::Uuid::new_v4().to_string();
    let pw_hash = agentsec_proxy::admin::hash_password(password).unwrap();
    store
        .create_admin(&admin_id, &team_id, email, &pw_hash)
        .await
        .unwrap();
    store.set_admin_email_verified(&admin_id).await.unwrap();

    // Login
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/login")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "email": email,
                "password": password,
            }))
            .unwrap(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200, "Login should succeed");

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    value["session_token"].as_str().unwrap().to_string()
}

/// Build a minimal AppState for admin/multi-tenant tests (empty DB, no pre-populated data).
async fn make_empty_state(
    mock_approval: Arc<dyn ApprovalChannel>,
) -> (AppState, tempfile::NamedTempFile) {
    let enc_key = test_key();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let store = ConfigStore::new(tmp.path().to_str().unwrap(), None, enc_key)
        .await
        .unwrap();
    let db_state = Arc::new(DbState::new(store, Duration::from_secs(30)));
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel: mock_approval,
        audit_logger: Arc::new(InMemoryAuditLogger::new()),
        forward_timeout: Duration::from_secs(30),
        rate_counts: Arc::new(std::sync::Mutex::new(HashMap::new())),
        db_state,
        webauthn_state: None,
        approval_timeout_secs: 300,
        oauth_states: Arc::new(std::sync::Mutex::new(HashMap::new())),
    };
    (state, tmp)
}

#[tokio::test]
async fn admin_signup_login_create_agent_full_flow() {
    let (upstream_url, _h, recorded) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;

    let token = signup_and_login(&state, "acme", "alice@acme.com", "password123").await;

    // Create credential via admin API
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/admin/credentials")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"name": "slack", "description": "Slack API", "value": "xoxb-secret"}"#,
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 201);

    // Set policy
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("PUT")
        .uri("/admin/policies/slack")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"auto_approve_methods": ["GET"]}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    // Create agent via admin API
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/admin/agents")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"id": "bot-1", "credentials": ["slack"]}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 201);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let agent_api_key = value["api_key"].as_str().unwrap().to_string();

    // Agent uses credential via /forward
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", &agent_api_key)
        .header("x-tap-credential", "slack")
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    // Upstream received the credential
    let recs = recorded.lock().unwrap();
    assert_eq!(recs.len(), 1);
    let auth = recs[0]
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.as_str());
    assert_eq!(auth, Some("Bearer xoxb-secret"));
}

#[tokio::test]
async fn cross_team_agent_isolation() {
    let (upstream_url, _h, _) = start_recording_upstream().await;
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;

    // Set up team A with credential + agent
    let token_a = signup_and_login(&state, "team-a", "a@a.com", "password123").await;
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/admin/credentials")
        .header("authorization", format!("Bearer {token_a}"))
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"name": "secret-a", "description": "Team A secret", "value": "team-a-val"}"#,
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 201);

    // Set up team B with agent
    let token_b = signup_and_login(&state, "team-b", "b@b.com", "password456").await;
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/admin/credentials")
        .header("authorization", format!("Bearer {token_b}"))
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"name": "secret-b", "description": "Team B secret", "value": "team-b-val"}"#,
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 201);

    // Create agent on team B
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/admin/agents")
        .header("authorization", format!("Bearer {token_b}"))
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"id": "b-bot", "credentials": ["secret-b"]}"#,
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 201);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let b_key = value["api_key"].as_str().unwrap().to_string();

    // ATTACK: Team B's agent tries to access Team A's credential
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", &b_key)
        .header("x-tap-credential", "secret-a") // Team A's credential!
        .header("x-tap-target", format!("{upstream_url}/test"))
        .header("x-tap-method", "GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Must be 403 — credential not in team B's scope
    assert_eq!(
        resp.status(),
        403,
        "Agent from team B must not access team A's credential"
    );
}

#[tokio::test]
async fn cross_team_admin_isolation() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;

    // Team A creates a credential
    let token_a = signup_and_login(&state, "alpha", "admin@alpha.com", "alpha123").await;
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/admin/credentials")
        .header("authorization", format!("Bearer {token_a}"))
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"name": "alpha-cred", "description": "Alpha secret", "value": "alpha-val"}"#,
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 201);

    // Team B admin tries to list credentials — should see empty (not team A's)
    let token_b = signup_and_login(&state, "beta", "admin@beta.com", "beta456").await;
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/admin/credentials")
        .header("authorization", format!("Bearer {token_b}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let creds = value["credentials"].as_array().unwrap();
    assert!(
        creds.is_empty(),
        "Team B admin must not see team A's credentials"
    );
}

#[tokio::test]
async fn credential_value_never_in_api_response() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;

    let token = signup_and_login(&state, "vault", "admin@vault.com", "vault123").await;

    // Create credential with a secret value
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/admin/credentials")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"name": "api-key", "description": "API Key", "value": "sk-supersecret123"}"#,
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 201);

    // GET /admin/credentials — value must NOT be in response
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/admin/credentials")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        !body_str.contains("sk-supersecret123"),
        "Credential value must NEVER appear in admin API response"
    );
    assert!(
        !body_str.contains("supersecret"),
        "No part of credential value should leak"
    );

    // Create agent + use /agent/config — value must NOT be there either
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/admin/agents")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"id": "bot", "credentials": ["api-key"]}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 201);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let agent_key = value["api_key"].as_str().unwrap().to_string();

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/agent/config")
        .header("x-tap-key", &agent_key)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        !body_str.contains("sk-supersecret123"),
        "Credential value must not leak via agent config endpoint"
    );
}

#[tokio::test]
async fn duplicate_team_name_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;

    // Sign up team "dup-test"
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"team_name": "dup-test", "email": "first@dup.com", "password": "password123"}"#,
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 201);

    // Try to sign up again with same team name
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"team_name": "dup-test", "email": "second@dup.com", "password": "password456"}"#,
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 409);
}

#[tokio::test]
async fn duplicate_email_rejected() {
    let mock = Arc::new(MockApproval {
        auto_approve: true,
        calls: std::sync::Mutex::new(vec![]),
    });
    let (state, _tmp) = make_empty_state(mock).await;

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"team_name": "team-one", "email": "same@email.com", "password": "password123"}"#,
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 201);

    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/signup")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"team_name": "team-two", "email": "same@email.com", "password": "password456"}"#,
        ))
        .unwrap();
    assert_eq!(app.oneshot(req).await.unwrap().status(), 409);
}
