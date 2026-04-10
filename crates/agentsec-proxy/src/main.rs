use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use agentsec_bot::TelegramChannel;
use agentsec_proxy::audit::AuditLogger;
use agentsec_proxy::proxy::{build_router, AppState};
use tokio::process::Command;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("agentsec=info".parse().unwrap()),
        )
        .json()
        .init();

    tracing::info!("AgentSec proxy starting");

    // 1. Load encryption key (env var in standard mode, Evervault KMS in enclave mode)
    let encryption_key = agentsec_proxy::key_provider::load_encryption_key()
        .await
        .unwrap_or_else(|e| panic!("Failed to load encryption key: {e}"));

    #[cfg(feature = "enclave")]
    tracing::info!("Encryption key loaded from Evervault enclave");
    #[cfg(not(feature = "enclave"))]
    tracing::info!("Encryption key loaded from environment");

    maybe_start_embedded_telegram_sidecar()
        .await
        .unwrap_or_else(|e| panic!("Failed to start embedded Telegram sidecar: {e}"));

    // 2. Initialize ConfigStore (local SQLite or remote Turso)
    let db_path = std::env::var("AGENTSEC_DB_PATH").unwrap_or_else(|_| "./agentsec.db".to_string());
    let turso_url = std::env::var("TURSO_DATABASE_URL").ok();
    let turso_token = std::env::var("TURSO_AUTH_TOKEN").ok();
    let db_url = turso_url.as_deref().unwrap_or(&db_path);
    let auth_token = turso_token.as_deref();
    let cache_ttl = std::env::var("AGENTSEC_CACHE_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30u64);
    let store = agentsec_core::store::ConfigStore::new(db_url, auth_token, encryption_key)
        .await
        .unwrap_or_else(|e| panic!("Failed to open DB at {db_url}: {e}"));
    tracing::info!(db = %db_url, cache_ttl_secs = cache_ttl, "ConfigStore initialized");
    let webauthn_store = store.clone(); // Clone before DbState consumes it
    let polling_store = Arc::new(store.clone()); // For Telegram command handling
    let db_state = Arc::new(agentsec_proxy::db_state::DbState::new(
        store,
        Duration::from_secs(cache_ttl),
    ));

    // 3. Initialize Telegram approval channel
    //    TELEGRAM_BOT_TOKEN is required (deployment-wide bot).
    //    In enclave mode: encrypted in DB via Evervault KMS (bootstraps from env on first run).
    //    TELEGRAM_CHAT_ID is optional — teams configure their own via admin API.
    let bot_token = agentsec_proxy::key_provider::load_secret(
        "TELEGRAM_BOT_TOKEN",
        "telegram_bot_token_ciphertext",
    )
    .await
    .unwrap_or_else(|e| panic!("Failed to load Telegram bot token: {e}"));
    if bot_token.is_empty() {
        panic!("TELEGRAM_BOT_TOKEN must not be empty");
    }
    let default_chat_id = agentsec_proxy::key_provider::load_secret(
        "TELEGRAM_CHAT_ID",
        "telegram_chat_id_ciphertext",
    )
    .await
    .unwrap_or_default();
    if default_chat_id.is_empty() {
        tracing::warn!("TELEGRAM_CHAT_ID not set — teams must configure notification channels via the admin API");
    }
    let telegram_config = agentsec_bot::TelegramConfig {
        bot_token,
        chat_id: default_chat_id,
    };
    let telegram_config_for_webhook = telegram_config.clone();
    let approval_channel = Arc::new(TelegramChannel::new(telegram_config));

    // 4. Initialize audit logger
    //    When Turso is configured, use DB-backed audit (persists across enclave redeployments).
    //    Otherwise, fall back to file-based audit.
    let audit_logger: Arc<dyn agentsec_proxy::audit::AuditLog> = if turso_url.is_some() {
        let handle = tokio::runtime::Handle::current();
        tracing::info!("Audit log: database-backed (Turso)");
        Arc::new(agentsec_proxy::audit::DbAuditLogger::new(
            db_state.store().clone(),
            handle,
        ))
    } else {
        let audit_path =
            std::env::var("AGENTSEC_AUDIT_LOG").unwrap_or_else(|_| "./audit.jsonl".to_string());
        tracing::info!("Audit log: {audit_path}");
        Arc::new(AuditLogger::new(PathBuf::from(&audit_path)))
    };

    // 4b. Start Telegram long-polling for callback responses
    approval_channel.start_polling(Some(polling_store));

    // 5. Build proxy state
    let forward_timeout = std::env::var("AGENTSEC_FORWARD_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30u64);
    let approval_timeout_secs = std::env::var("AGENTSEC_APPROVAL_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300u64);

    // 5b. Initialize WebAuthn if configured
    let webauthn_state = match (
        std::env::var("WEBAUTHN_RP_ID").ok(),
        std::env::var("WEBAUTHN_RP_ORIGIN").ok(),
        std::env::var("WEBAUTHN_BASE_URL").ok(),
    ) {
        (Some(rp_id), Some(rp_origin), Some(base_url)) => {
            match agentsec_proxy::webauthn::WebAuthnState::new(
                &rp_id,
                &rp_origin,
                &base_url,
                Some(webauthn_store),
            ) {
                Ok(wa) => {
                    let wa = Arc::new(wa);
                    // Load persisted passkeys from DB
                    match wa.load_credentials_from_db().await {
                        Ok(count) => tracing::info!(count, "Loaded approver passkeys from DB"),
                        Err(e) => tracing::warn!("Failed to load passkeys from DB: {e}"),
                    }
                    // Load admin passkeys for 2FA
                    match wa.load_admin_credentials_from_db().await {
                        Ok(count) => tracing::info!(count, "Loaded admin passkeys from DB"),
                        Err(e) => tracing::warn!("Failed to load admin passkeys from DB: {e}"),
                    }
                    tracing::info!(rp_id = %rp_id, "WebAuthn approval enabled");
                    Some(wa)
                }
                Err(e) => {
                    tracing::warn!("WebAuthn initialization failed: {e}");
                    None
                }
            }
        }
        _ => {
            tracing::info!("WebAuthn not configured (set WEBAUTHN_RP_ID, WEBAUTHN_RP_ORIGIN, WEBAUTHN_BASE_URL)");
            None
        }
    };

    let state = AppState {
        encryption_key: Arc::new(encryption_key),
        approval_channel: approval_channel.clone(),
        audit_logger,
        forward_timeout: Duration::from_secs(forward_timeout),
        rate_counts: Arc::new(std::sync::Mutex::new(HashMap::new())),
        db_state,
        webauthn_state: webauthn_state.clone(),
        approval_timeout_secs,
        oauth_states: Arc::new(std::sync::Mutex::new(HashMap::new())),
    };

    // 6. Build router with telegram webhook + optional WebAuthn
    let webhook_secret = std::env::var("TELEGRAM_WEBHOOK_SECRET")
        .ok()
        .filter(|s| !s.is_empty());
    if webhook_secret.is_some() {
        tracing::info!("Telegram webhook secret verification enabled");
    }
    let app = build_router_with_webhook(
        state,
        approval_channel,
        webhook_secret,
        webauthn_state,
        telegram_config_for_webhook,
    );

    let addr = std::env::var("AGENTSEC_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:3100".to_string());
    tracing::info!("Listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn maybe_start_embedded_telegram_sidecar() -> Result<(), String> {
    let default_enabled = if cfg!(feature = "enclave") { "1" } else { "0" };
    let enabled = std::env::var("AGENTSEC_ENABLE_EMBEDDED_TELEGRAM")
        .unwrap_or_else(|_| default_enabled.to_string());
    if enabled != "1" {
        tracing::info!("Embedded Telegram sidecar disabled");
        return Ok(());
    }

    let python = std::env::var("AGENTSEC_EMBEDDED_TELEGRAM_PYTHON")
        .unwrap_or_else(|_| "python3".to_string());
    let script = std::env::var("AGENTSEC_EMBEDDED_TELEGRAM_SCRIPT")
        .unwrap_or_else(|_| "/opt/agentsec/telegram_sidecar.py".to_string());
    let port =
        std::env::var("AGENTSEC_EMBEDDED_TELEGRAM_PORT").unwrap_or_else(|_| "8082".to_string());
    let health_url = format!("http://127.0.0.1:{port}/health");

    let mut child = Command::new(&python)
        .arg(&script)
        .env("PYTHONUNBUFFERED", "1")
        .env("TELEGRAM_SIDECAR_HOST", "127.0.0.1")
        .env("TELEGRAM_SIDECAR_PORT", &port)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("spawn {python} {script}: {e}"))?;

    for _ in 0..40 {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("check embedded Telegram sidecar status: {e}"))?
        {
            return Err(format!(
                "embedded Telegram sidecar exited early with status {status}"
            ));
        }

        match reqwest::get(&health_url).await {
            Ok(resp) if resp.status().is_success() => {
                let pid = child.id().unwrap_or_default();
                tracing::info!(pid, health_url = %health_url, "Embedded Telegram sidecar ready");
                tokio::spawn(async move {
                    match child.wait().await {
                        Ok(status) => tracing::warn!(?status, "Embedded Telegram sidecar exited"),
                        Err(e) => {
                            tracing::warn!(error = %e, "Failed waiting on embedded Telegram sidecar")
                        }
                    }
                });
                return Ok(());
            }
            _ => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }

    let _ = child.kill().await;
    Err(format!(
        "embedded Telegram sidecar did not become healthy at {health_url}"
    ))
}

/// Build the main router plus the Telegram webhook + optional WebAuthn routes.
fn build_router_with_webhook(
    state: AppState,
    approval_channel: Arc<TelegramChannel>,
    webhook_secret: Option<String>,
    webauthn_state: Option<Arc<agentsec_proxy::webauthn::WebAuthnState>>,
    telegram_config: agentsec_bot::TelegramConfig,
) -> axum::Router {
    use axum::extract::State as AxumState;
    use axum::http::StatusCode;
    use axum::Json;

    #[derive(Clone)]
    struct WebhookState {
        channel: Arc<TelegramChannel>,
        /// If set, reject webhook requests that don't carry this secret
        /// in the X-Telegram-Bot-Api-Secret-Token header.
        webhook_secret: Option<String>,
        db_state: Arc<agentsec_proxy::db_state::DbState>,
        telegram_config: agentsec_bot::TelegramConfig,
    }

    async fn send_telegram_reply(config: &agentsec_bot::TelegramConfig, chat_id: i64, text: &str) {
        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            config.bot_token
        );
        let client = reqwest::Client::new();
        let _ = client
            .post(&url)
            .json(&serde_json::json!({
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
            }))
            .send()
            .await;
    }

    async fn handle_telegram_webhook(
        AxumState(wh): AxumState<WebhookState>,
        headers: axum::http::HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> StatusCode {
        // Verify webhook secret if configured
        if let Some(ref expected) = wh.webhook_secret {
            let provided = headers
                .get("x-telegram-bot-api-secret-token")
                .and_then(|v| v.to_str().ok());
            match provided {
                Some(token) if token == expected => {}
                _ => {
                    tracing::warn!("Telegram webhook rejected: invalid or missing secret token");
                    return StatusCode::UNAUTHORIZED;
                }
            }
        }

        if let Some(callback_query) = body.get("callback_query") {
            let data = callback_query
                .get("data")
                .and_then(|d| d.as_str())
                .unwrap_or("");
            let cq_id = callback_query
                .get("id")
                .and_then(|d| d.as_str())
                .unwrap_or("");
            let user_id = callback_query
                .get("from")
                .and_then(|f| f.get("id"))
                .and_then(|id| id.as_i64())
                .map(|id| id.to_string());

            if let Err(e) = wh
                .channel
                .handle_callback(data, cq_id, user_id.as_deref())
                .await
            {
                tracing::warn!(error = %e, "Telegram callback handling failed");
                return StatusCode::BAD_REQUEST;
            }
        }

        // Handle text commands (admin whitelist management)
        if let Some(message) = body.get("message") {
            let text = message.get("text").and_then(|t| t.as_str()).unwrap_or("");
            let chat_id = message
                .get("chat")
                .and_then(|c| c.get("id"))
                .and_then(|id| id.as_i64());

            // Only process commands from the configured approval chat
            let admin_chat_id = wh.telegram_config.chat_id.parse::<i64>().unwrap_or(0);
            if chat_id != Some(admin_chat_id) {
                return StatusCode::OK; // ignore messages from other chats
            }

            if let Some(email) = text
                .strip_prefix("/whitelist ")
                .map(|s| s.trim().to_lowercase())
            {
                if email.contains('@') && email.contains('.') {
                    match wh.db_state.store().add_to_whitelist(&email, "pro").await {
                        Ok(()) => {
                            send_telegram_reply(
                                &wh.telegram_config,
                                admin_chat_id,
                                &format!("\u{2713} {email} whitelisted (Pro tier)"),
                            )
                            .await;
                        }
                        Err(e) => {
                            send_telegram_reply(
                                &wh.telegram_config,
                                admin_chat_id,
                                &format!("\u{2717} Failed: {e}"),
                            )
                            .await;
                        }
                    }
                } else {
                    send_telegram_reply(
                        &wh.telegram_config,
                        admin_chat_id,
                        "\u{2717} Invalid email format",
                    )
                    .await;
                }
            } else if let Some(email) = text
                .strip_prefix("/unwhitelist ")
                .map(|s| s.trim().to_lowercase())
            {
                match wh.db_state.store().remove_from_whitelist(&email).await {
                    Ok(()) => {
                        send_telegram_reply(
                            &wh.telegram_config,
                            admin_chat_id,
                            &format!("\u{2713} {email} removed from whitelist"),
                        )
                        .await;
                    }
                    Err(e) => {
                        send_telegram_reply(
                            &wh.telegram_config,
                            admin_chat_id,
                            &format!("\u{2717} Failed: {e}"),
                        )
                        .await;
                    }
                }
            } else if text.trim() == "/whitelist" {
                // List all whitelisted emails
                match wh.db_state.store().list_whitelist().await {
                    Ok(entries) if entries.is_empty() => {
                        send_telegram_reply(
                            &wh.telegram_config,
                            admin_chat_id,
                            "No whitelisted emails.",
                        )
                        .await;
                    }
                    Ok(entries) => {
                        let list = entries
                            .iter()
                            .map(|(e, t)| format!("\u{2022} {e} ({t})"))
                            .collect::<Vec<_>>()
                            .join("\n");
                        send_telegram_reply(
                            &wh.telegram_config,
                            admin_chat_id,
                            &format!("Whitelisted emails:\n{list}"),
                        )
                        .await;
                    }
                    Err(e) => {
                        send_telegram_reply(
                            &wh.telegram_config,
                            admin_chat_id,
                            &format!("\u{2717} Failed: {e}"),
                        )
                        .await;
                    }
                }
            }
        }

        StatusCode::OK
    }

    let wh_state = WebhookState {
        channel: approval_channel.clone(),
        webhook_secret,
        db_state: state.db_state.clone(),
        telegram_config,
    };

    let mut router = build_router(state).merge(
        axum::Router::new()
            .route(
                "/telegram/webhook",
                axum::routing::post(handle_telegram_webhook),
            )
            .with_state(wh_state),
    );

    if let Some(wa_state) = webauthn_state {
        router = router.merge(agentsec_proxy::webauthn::build_approval_router(
            wa_state,
            approval_channel,
        ));
    }

    router
}
