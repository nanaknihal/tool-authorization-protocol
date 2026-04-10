//! End-to-end approval flow test.
//! Boots the REAL proxy + a mock approval channel + mock upstream.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use agentsec_core::approval::{ApprovalChannel, ApprovalContext};
use agentsec_core::error::AgentSecError;
use agentsec_core::store::{ConfigStore, PolicyRow};
use agentsec_core::types::*;
use agentsec_proxy::audit::InMemoryAuditLogger;
use agentsec_proxy::auth::hash_api_key;
use agentsec_proxy::proxy::{build_router, AppState};
use axum::body::Body;
use axum::http::{HeaderMap, Request};
use serde_json::json;
use tower::util::ServiceExt;

fn test_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = i as u8;
    }
    key
}

/// Mock approval channel that records calls and returns configurable decisions.
struct MockApprovalChannel {
    decision: ApprovalStatus,
    requests: std::sync::Mutex<Vec<MockApprovalRequest>>,
}

#[derive(Debug, Clone)]
struct MockApprovalRequest {
    agent_id: String,
    method: HttpMethod,
    target_url: String,
}

#[async_trait::async_trait]
impl ApprovalChannel for MockApprovalChannel {
    async fn send_approval_request(
        &self,
        request: &ProxyRequest,
        _desc: &str,
        _context: &ApprovalContext,
    ) -> Result<String, AgentSecError> {
        self.requests.lock().unwrap().push(MockApprovalRequest {
            agent_id: request.agent_id.clone(),
            method: request.method.clone(),
            target_url: request.target_url.clone(),
        });
        Ok(request.id.to_string())
    }

    async fn wait_for_decision(
        &self,
        _id: &str,
        _timeout: u64,
    ) -> Result<ApprovalStatus, AgentSecError> {
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(self.decision.clone())
    }

    fn format_message(&self, _request: &ProxyRequest, _desc: &str) -> String {
        "e2e mock".to_string()
    }
}

/// Mock upstream that records received requests and returns configurable responses.
#[derive(Clone, Default)]
struct RecordedUpstream {
    requests: Arc<std::sync::Mutex<Vec<UpstreamRequest>>>,
}

#[derive(Debug, Clone)]
struct UpstreamRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn start_mock_upstream(recorded: RecordedUpstream) -> (String, tokio::task::JoinHandle<()>) {
    use axum::routing::{get, post};

    let rec = recorded.clone();
    let app = axum::Router::new()
        .route(
            "/api/tweet",
            post({
                let rec = rec.clone();
                move |headers: HeaderMap, body: axum::body::Bytes| {
                    let rec = rec.clone();
                    async move {
                        let hdrs: Vec<(String, String)> = headers
                            .iter()
                            .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or("").to_string()))
                            .collect();
                        rec.requests.lock().unwrap().push(UpstreamRequest {
                            method: "POST".to_string(),
                            path: "/api/tweet".to_string(),
                            headers: hdrs,
                            body: body.to_vec(),
                        });
                        axum::Json(json!({"posted": true}))
                    }
                }
            }),
        )
        .route(
            "/api/tweet",
            get({
                let rec = rec.clone();
                move |headers: HeaderMap| {
                    let rec = rec.clone();
                    async move {
                        let hdrs: Vec<(String, String)> = headers
                            .iter()
                            .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or("").to_string()))
                            .collect();
                        rec.requests.lock().unwrap().push(UpstreamRequest {
                            method: "GET".to_string(),
                            path: "/api/tweet".to_string(),
                            headers: hdrs,
                            body: vec![],
                        });
                        axum::Json(json!({"tweets": []}))
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
    (url, handle)
}

async fn make_e2e_state(
    approval_channel: Arc<dyn ApprovalChannel>,
    _upstream_url: &str,
) -> (AppState, Arc<InMemoryAuditLogger>, tempfile::NamedTempFile) {
    let enc_key = test_key();
    let api_key = "e2e-key-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567abc890";
    let key_hash = hash_api_key(api_key);

    let tmp = tempfile::NamedTempFile::new().unwrap();
    let store = ConfigStore::new(tmp.path().to_str().unwrap(), None, enc_key)
        .await
        .unwrap();
    store.create_team("t1", "test-team").await.unwrap();
    store
        .create_credential(
            "t1",
            "e2e-cred",
            "E2E test credential",
            "direct",
            None,
            false,
            None,
            None,
        )
        .await
        .unwrap();
    store
        .set_credential_value("t1", "e2e-cred", b"real-secret-xyz")
        .await
        .unwrap();
    store
        .create_agent("t1", "e2e-agent", None, &key_hash, None)
        .await
        .unwrap();
    store
        .add_direct_credential("t1", "e2e-agent", "e2e-cred")
        .await
        .unwrap();
    store
        .set_policy(&PolicyRow {
            team_id: "t1".to_string(),
            credential_name: "e2e-cred".to_string(),
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

    let db_state = Arc::new(agentsec_proxy::db_state::DbState::new(
        store,
        Duration::from_secs(30),
    ));
    let audit_logger = Arc::new(InMemoryAuditLogger::new());
    let state = AppState {
        encryption_key: Arc::new(enc_key),
        approval_channel,
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

const E2E_API_KEY: &str = "e2e-key-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567abc890";

#[tokio::test]
async fn e2e_write_request_approval_flow() {
    let recorded = RecordedUpstream::default();
    let (upstream_url, _h) = start_mock_upstream(recorded.clone()).await;

    let mock_approval = Arc::new(MockApprovalChannel {
        decision: ApprovalStatus::Approved,
        requests: std::sync::Mutex::new(vec![]),
    });

    let (state, audit, _tmp) = make_e2e_state(mock_approval.clone(), &upstream_url).await;
    let app = build_router(state.clone());

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", E2E_API_KEY)
        .header("x-tap-target", format!("{upstream_url}/api/tweet"))
        .header("x-tap-method", "POST")
        .header("authorization", "Bearer <CREDENTIAL:e2e-cred>")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"text": "Hello from E2E test"}"#))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();

    // 1. MockApprovalChannel.send_approval_request was called exactly once
    let approval_requests = mock_approval.requests.lock().unwrap();
    assert_eq!(approval_requests.len(), 1);

    // 2. Approval request contained correct info
    assert_eq!(approval_requests[0].agent_id, "e2e-agent");
    assert_eq!(approval_requests[0].method, HttpMethod::Post);
    assert!(approval_requests[0].target_url.contains("/api/tweet"));
    drop(approval_requests);

    // 3. Proxy returned 200
    assert_eq!(resp.status(), 200);

    // 4. Mock upstream received the request with substituted credential
    let upstream_reqs = recorded.requests.lock().unwrap();
    assert_eq!(upstream_reqs.len(), 1);
    let auth_header = upstream_reqs[0]
        .headers
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.as_str())
        .unwrap();
    assert_eq!(auth_header, "Bearer real-secret-xyz");

    // 5. Mock upstream received the body
    let body_str = String::from_utf8(upstream_reqs[0].body.clone()).unwrap();
    assert!(body_str.contains("Hello from E2E test"));
    drop(upstream_reqs);

    // 6. Response body matches mock upstream
    let resp_body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert_eq!(value["posted"], true);

    // 7. Audit log entry
    let entries = audit.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].agent_id, "e2e-agent");
    assert_eq!(entries[0].method, HttpMethod::Post);
    assert_eq!(entries[0].approval_status, Some(ApprovalStatus::Approved));
}

#[tokio::test]
async fn e2e_write_request_denied() {
    let recorded = RecordedUpstream::default();
    let (upstream_url, _h) = start_mock_upstream(recorded.clone()).await;

    let mock_approval = Arc::new(MockApprovalChannel {
        decision: ApprovalStatus::Denied,
        requests: std::sync::Mutex::new(vec![]),
    });

    let (state, audit, _tmp) = make_e2e_state(mock_approval.clone(), &upstream_url).await;
    let app = build_router(state.clone());

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", E2E_API_KEY)
        .header("x-tap-target", format!("{upstream_url}/api/tweet"))
        .header("x-tap-method", "POST")
        .header("authorization", "Bearer <CREDENTIAL:e2e-cred>")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"text": "Should be denied"}"#))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();

    // 1. Proxy returns 403
    assert_eq!(resp.status(), 403);

    // 2. Mock upstream received ZERO requests
    let upstream_reqs = recorded.requests.lock().unwrap();
    assert_eq!(upstream_reqs.len(), 0);
    drop(upstream_reqs);

    // 3. Response contains denial indication
    let resp_body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8(resp_body.to_vec()).unwrap();
    assert!(
        body_str.to_lowercase().contains("denied"),
        "Body: {body_str}"
    );

    // 4. Audit log entry has denial status
    let entries = audit.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].approval_status, Some(ApprovalStatus::Denied));
}

#[tokio::test]
async fn e2e_read_request_skips_approval() {
    let recorded = RecordedUpstream::default();
    let (upstream_url, _h) = start_mock_upstream(recorded.clone()).await;

    let mock_approval = Arc::new(MockApprovalChannel {
        decision: ApprovalStatus::Approved,
        requests: std::sync::Mutex::new(vec![]),
    });

    let (state, audit, _tmp) = make_e2e_state(mock_approval.clone(), &upstream_url).await;
    let app = build_router(state.clone());

    let req = Request::builder()
        .method("POST")
        .uri("/forward")
        .header("x-tap-key", E2E_API_KEY)
        .header("x-tap-target", format!("{upstream_url}/api/tweet"))
        .header("x-tap-method", "GET")
        .header("authorization", "Bearer <CREDENTIAL:e2e-cred>")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();

    // 1. MockApprovalChannel.send_approval_request was NOT called
    let approval_requests = mock_approval.requests.lock().unwrap();
    assert_eq!(
        approval_requests.len(),
        0,
        "GET should not trigger approval"
    );
    drop(approval_requests);

    // 2. Proxy returned 200
    assert_eq!(resp.status(), 200);

    // 3. Mock upstream received the GET with real credential
    let upstream_reqs = recorded.requests.lock().unwrap();
    assert_eq!(upstream_reqs.len(), 1);
    let auth_header = upstream_reqs[0]
        .headers
        .iter()
        .find(|(n, _)| n == "authorization")
        .map(|(_, v)| v.as_str())
        .unwrap();
    assert_eq!(auth_header, "Bearer real-secret-xyz");
    drop(upstream_reqs);

    // 4. Audit log entry
    let entries = audit.entries();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].approval_status.is_none());
}
