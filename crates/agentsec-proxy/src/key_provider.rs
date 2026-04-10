//! Encryption key provider: abstracts key source between standard (env var)
//! and enclave (Evervault KMS) modes.
//!
//! Standard mode: reads AGENTSEC_ENCRYPTION_KEY from environment.
//! Enclave mode (--features enclave): fetches key from Evervault's
//! in-enclave KMS endpoint at startup.

use agentsec_core::error::AgentSecError;

/// Load the 32-byte encryption key from the appropriate source.
///
/// In standard mode: reads AGENTSEC_ENCRYPTION_KEY env var (64 hex chars).
/// In enclave mode: fetches from Evervault KMS via the in-enclave API.
pub async fn load_encryption_key() -> Result<[u8; 32], AgentSecError> {
    #[cfg(feature = "enclave")]
    {
        load_from_evervault().await
    }
    #[cfg(not(feature = "enclave"))]
    {
        load_from_env()
    }
}

/// Standard mode: read key from AGENTSEC_ENCRYPTION_KEY env var.
#[cfg(not(feature = "enclave"))]
fn load_from_env() -> Result<[u8; 32], AgentSecError> {
    let hex_str = std::env::var("AGENTSEC_ENCRYPTION_KEY").map_err(|_| {
        AgentSecError::Encryption("AGENTSEC_ENCRYPTION_KEY env var is required".to_string())
    })?;
    crate::crypto::parse_encryption_key(&hex_str)
}

/// Open a DB connection for enclave key/secret storage.
///
/// Uses Turso (persistent) when TURSO_DATABASE_URL is set, otherwise local SQLite.
/// This ensures encryption key ciphertext survives enclave redeployments when
/// credentials are stored in Turso.
#[cfg(feature = "enclave")]
async fn open_enclave_db_conn() -> Result<libsql::Connection, AgentSecError> {
    let turso_url = std::env::var("TURSO_DATABASE_URL").ok();
    let turso_token = std::env::var("TURSO_AUTH_TOKEN").ok();

    let db = if let (Some(ref url), Some(ref token)) = (&turso_url, &turso_token) {
        if !token.is_empty() {
            tracing::info!("Enclave key storage: using Turso ({url})");
            libsql::Builder::new_remote(url.clone(), token.clone())
                .build()
                .await
                .map_err(|e| AgentSecError::Encryption(format!("Failed to open Turso for key: {e}")))?
        } else {
            let db_path = std::env::var("AGENTSEC_DB_PATH")
                .unwrap_or_else(|_| "./agentsec.db".to_string());
            tracing::info!("Enclave key storage: using local SQLite ({db_path})");
            libsql::Builder::new_local(&db_path)
                .build()
                .await
                .map_err(|e| AgentSecError::Encryption(format!("Failed to open DB for key: {e}")))?
        }
    } else {
        let db_path = std::env::var("AGENTSEC_DB_PATH")
            .unwrap_or_else(|_| "./agentsec.db".to_string());
        tracing::info!("Enclave key storage: using local SQLite ({db_path})");
        libsql::Builder::new_local(&db_path)
            .build()
            .await
            .map_err(|e| AgentSecError::Encryption(format!("Failed to open DB for key: {e}")))?
    };

    let conn = db.connect()
        .map_err(|e| AgentSecError::Encryption(format!("Failed to connect to DB for key: {e}")))?;

    // Ensure config table exists
    conn.execute(
        "CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        (),
    )
    .await
    .map_err(|e| AgentSecError::Encryption(format!("Failed to create config table: {e}")))?;

    Ok(conn)
}

/// Enclave mode: load or generate encryption key via Evervault's in-enclave
/// encrypt/decrypt endpoints. The key is stored as ciphertext in the DB --
/// only the enclave can decrypt it.
///
/// First startup: generate random 32 bytes -> encrypt via Evervault -> store ciphertext in DB.
/// Subsequent startups: read ciphertext from DB -> decrypt via Evervault -> use plaintext.
///
/// The key never exists as an env var or on disk in plaintext.
/// The Evervault enclave runtime exposes local endpoints:
///   POST http://127.0.0.1:9999/encrypt -- encrypt data (only enclave can decrypt)
///   POST http://127.0.0.1:9999/decrypt -- decrypt data (requires attestation)
///
/// IMPORTANT: When TURSO_DATABASE_URL is set, the key ciphertext is stored in
/// Turso (persistent) rather than local SQLite (ephemeral in enclaves). This
/// ensures the encryption key survives enclave redeployments.
#[cfg(feature = "enclave")]
async fn load_from_evervault() -> Result<[u8; 32], AgentSecError> {
    use rand::RngCore;

    // Use Turso if available (persistent across enclave redeployments),
    // otherwise fall back to local SQLite.
    let conn = open_enclave_db_conn().await?;

    let evervault_url = std::env::var("EVERVAULT_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:9999".to_string());
    let client = reqwest::Client::new();

    // Try to load existing encrypted key from DB
    let existing: Option<String> = {
        let mut rows = conn
            .query(
                "SELECT value FROM config WHERE key = 'encryption_key_ciphertext'",
                (),
            )
            .await
            .map_err(|e| AgentSecError::Encryption(format!("Failed to query config: {e}")))?;
        match rows.next().await {
            Ok(Some(row)) => Some(row.get::<String>(0)
                .map_err(|e| AgentSecError::Encryption(format!("Failed to read config value: {e}")))?),
            Ok(None) => None,
            Err(e) => return Err(AgentSecError::Encryption(format!("Failed to query config: {e}"))),
        }
    };

    if let Some(ciphertext) = existing {
        // Decrypt via Evervault
        tracing::info!("Enclave: decrypting existing encryption key from DB");
        let resp = client
            .post(format!("{}/decrypt", evervault_url))
            .json(&serde_json::json!({ "data": ciphertext }))
            .send()
            .await
            .map_err(|e| AgentSecError::Encryption(format!("Evervault decrypt failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AgentSecError::Encryption(format!(
                "Evervault decrypt returned {status}: {body}"
            )));
        }

        let body: serde_json::Value = resp.json().await
            .map_err(|e| AgentSecError::Encryption(format!("Failed to parse decrypt response: {e}")))?;

        let key_hex = body["data"]
            .as_str()
            .ok_or_else(|| AgentSecError::Encryption("Decrypt response missing 'data'".to_string()))?;

        return crate::crypto::parse_encryption_key(key_hex);
    }

    // No key exists -- generate, encrypt, and store
    tracing::info!("Enclave: generating new encryption key");
    let mut key_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key_bytes);
    let key_hex = hex::encode(&key_bytes);

    // Encrypt via Evervault
    let resp = client
        .post(format!("{}/encrypt", evervault_url))
        .json(&serde_json::json!({ "data": key_hex }))
        .send()
        .await
        .map_err(|e| AgentSecError::Encryption(format!("Evervault encrypt failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(AgentSecError::Encryption(format!(
            "Evervault encrypt returned {status}: {body}"
        )));
    }

    let body: serde_json::Value = resp.json().await
        .map_err(|e| AgentSecError::Encryption(format!("Failed to parse encrypt response: {e}")))?;

    let ciphertext = body["data"]
        .as_str()
        .ok_or_else(|| AgentSecError::Encryption("Encrypt response missing 'data'".to_string()))?;

    // Store ciphertext in DB
    conn.execute(
        "INSERT INTO config (key, value) VALUES ('encryption_key_ciphertext', ?1)",
        libsql::params![ciphertext],
    )
    .await
    .map_err(|e| AgentSecError::Encryption(format!("Failed to store encrypted key: {e}")))?;

    tracing::info!("Enclave: encryption key generated and stored (encrypted)");
    Ok(key_bytes)
}

/// Load a string secret from the appropriate source.
///
/// In standard mode: reads from the given env var.
/// In enclave mode: reads ciphertext from SQLite `config` table (key = `db_key`),
/// decrypts via Evervault KMS. If no ciphertext exists, reads from the env var,
/// encrypts via KMS, stores ciphertext, and returns the plaintext.
///
/// This allows secrets to be bootstrapped from env vars on first deploy, then
/// the env var can be deleted -- subsequent startups decrypt from DB.
pub async fn load_secret(env_var: &str, db_key: &str) -> Result<String, AgentSecError> {
    #[cfg(feature = "enclave")]
    {
        load_secret_enclave(env_var, db_key).await
    }
    #[cfg(not(feature = "enclave"))]
    {
        let _ = db_key; // unused in non-enclave mode
        std::env::var(env_var).map_err(|_| {
            AgentSecError::Encryption(format!("{env_var} env var is required"))
        })
    }
}

/// Enclave mode: load a secret from DB (decrypt) or bootstrap from env var (encrypt + store).
#[cfg(feature = "enclave")]
async fn load_secret_enclave(env_var: &str, db_key: &str) -> Result<String, AgentSecError> {
    let conn = open_enclave_db_conn().await?;

    let evervault_url = std::env::var("EVERVAULT_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:9999".to_string());
    let client = reqwest::Client::new();

    // Try to load existing encrypted secret from DB
    let existing: Option<String> = {
        let mut rows = conn
            .query(
                "SELECT value FROM config WHERE key = ?1",
                libsql::params![db_key],
            )
            .await
            .map_err(|e| AgentSecError::Encryption(format!("Failed to query config: {e}")))?;
        match rows.next().await {
            Ok(Some(row)) => Some(row.get::<String>(0)
                .map_err(|e| AgentSecError::Encryption(format!("Failed to read config value: {e}")))?),
            Ok(None) => None,
            Err(e) => return Err(AgentSecError::Encryption(format!("Failed to query config: {e}"))),
        }
    };

    if let Some(ciphertext) = existing {
        tracing::info!(key = %db_key, "Enclave: decrypting secret from DB");
        let resp = client
            .post(format!("{}/decrypt", evervault_url))
            .json(&serde_json::json!({ "data": ciphertext }))
            .send()
            .await
            .map_err(|e| AgentSecError::Encryption(format!("Evervault decrypt failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AgentSecError::Encryption(format!(
                "Evervault decrypt returned {status}: {body}"
            )));
        }

        let body: serde_json::Value = resp.json().await
            .map_err(|e| AgentSecError::Encryption(format!("Failed to parse decrypt response: {e}")))?;

        return body["data"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| AgentSecError::Encryption("Decrypt response missing 'data'".to_string()));
    }

    // No ciphertext in DB -- bootstrap from env var
    let plaintext = std::env::var(env_var).map_err(|_| {
        AgentSecError::Encryption(format!(
            "{env_var} not set and no encrypted value in DB for '{db_key}'"
        ))
    })?;

    tracing::info!(key = %db_key, "Enclave: encrypting secret from env var for storage");
    let resp = client
        .post(format!("{}/encrypt", evervault_url))
        .json(&serde_json::json!({ "data": plaintext }))
        .send()
        .await
        .map_err(|e| AgentSecError::Encryption(format!("Evervault encrypt failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(AgentSecError::Encryption(format!(
            "Evervault encrypt returned {status}: {body}"
        )));
    }

    let body: serde_json::Value = resp.json().await
        .map_err(|e| AgentSecError::Encryption(format!("Failed to parse encrypt response: {e}")))?;

    let ciphertext = body["data"]
        .as_str()
        .ok_or_else(|| AgentSecError::Encryption("Encrypt response missing 'data'".to_string()))?;

    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
        libsql::params![db_key, ciphertext],
    )
    .await
    .map_err(|e| AgentSecError::Encryption(format!("Failed to store encrypted secret: {e}")))?;

    tracing::info!(key = %db_key, "Enclave: secret encrypted and stored");
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "enclave"))]
    #[tokio::test]
    async fn test_load_from_env() {
        std::env::set_var(
            "AGENTSEC_ENCRYPTION_KEY",
            "0001020304050607080910111213141516171819202122232425262728293031",
        );
        let key = load_encryption_key().await.unwrap();
        assert_eq!(key[0], 0x00);
        assert_eq!(key[1], 0x01);
        std::env::remove_var("AGENTSEC_ENCRYPTION_KEY");
    }

    #[cfg(not(feature = "enclave"))]
    #[tokio::test]
    async fn test_load_from_env_missing() {
        std::env::remove_var("AGENTSEC_ENCRYPTION_KEY");
        let result = load_encryption_key().await;
        assert!(result.is_err());
    }
}
