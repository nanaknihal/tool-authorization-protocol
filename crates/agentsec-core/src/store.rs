//! SQLite-backed configuration store for AgentSec v0.2.
//!
//! Replaces static YAML config with a database that supports hot-reload,
//! RBAC roles, direct per-agent permissions, and encrypted credential storage.
//! Uses libsql for Turso (remote SQLite) support.

use crate::error::AgentSecError;
use std::collections::HashSet;

// Re-implement encrypt/decrypt here to avoid cross-crate dependency on agentsec-proxy.
// Same AES-256-GCM algorithm as crypto.rs.
mod crypto {
    use aes_gcm::aead::{Aead, KeyInit, OsRng};
    use aes_gcm::{Aes256Gcm, Nonce};
    use rand::RngCore;

    pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("Invalid key: {e}"))?;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {e}"))?;
        // Store as: nonce (12 bytes) || ciphertext
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 12 {
            return Err("Data too short for nonce".to_string());
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("Invalid key: {e}"))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TeamRow {
    pub id: String,
    pub name: String,
    pub tier: String,
    pub stripe_customer_id: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct AdminRow {
    pub id: String,
    pub team_id: String,
    pub email: String,
    pub password_hash: String,
    pub email_verified: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct CredentialRow {
    pub name: String,
    pub team_id: String,
    pub description: String,
    pub connector: String,
    pub api_base: Option<String>,
    pub relative_target: bool,
    pub auth_header_format: Option<String>,
    pub auth_bindings_json: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct AgentRow {
    pub id: String,
    pub team_id: String,
    pub description: Option<String>,
    pub api_key_hash: String,
    pub rate_limit_per_hour: Option<i64>,
    pub enabled: bool,
    pub is_admin: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct RoleRow {
    pub name: String,
    pub team_id: String,
    pub description: Option<String>,
    pub rate_limit_per_hour: Option<i64>,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct PolicyRow {
    pub credential_name: String,
    pub team_id: String,
    pub auto_approve_methods: Vec<String>,
    pub require_approval_methods: Vec<String>,
    pub auto_approve_urls: Vec<String>,
    pub allowed_approvers: Vec<String>,
    pub telegram_chat_id: Option<String>,
    pub require_passkey: bool,
}

#[derive(Debug, Clone)]
pub struct NotificationChannelRow {
    pub id: String,
    pub team_id: String,
    pub channel_type: String,
    pub name: String,
    pub config_json: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct ApproverPasskeyRow {
    pub credential_id: String,
    pub approver_name: String,
    pub display_name: String,
    pub public_key_json: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct AdminPasskeyRow {
    pub credential_id: String,
    pub admin_id: String,
    pub public_key_json: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct AgentTeamLink {
    pub agent_home_team_id: String,
    pub agent_id: String,
    pub linked_team_id: String,
    pub role_name: Option<String>,
    pub created_at: String,
}

// ---------------------------------------------------------------------------
// ConfigStore
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ConfigStore {
    conn: libsql::Connection,
    encryption_key: [u8; 32],
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS teams (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    tier TEXT NOT NULL DEFAULT 'free',
    stripe_customer_id TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admins (
    id TEXT PRIMARY KEY,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    token_hash TEXT PRIMARY KEY,
    admin_id TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS email_verifications (
    code_hash TEXT PRIMARY KEY,
    admin_id TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    name TEXT NOT NULL,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    connector TEXT NOT NULL DEFAULT 'direct',
    api_base TEXT,
    relative_target BOOLEAN NOT NULL DEFAULT FALSE,
    auth_header_format TEXT,
    auth_bindings_json TEXT,
    encrypted_value BLOB,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (team_id, name)
);

CREATE TABLE IF NOT EXISTS roles (
    name TEXT NOT NULL,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    description TEXT,
    rate_limit_per_hour INTEGER,
    created_at TEXT NOT NULL,
    PRIMARY KEY (team_id, name)
);

CREATE TABLE IF NOT EXISTS role_credentials (
    team_id TEXT NOT NULL,
    role_name TEXT NOT NULL,
    credential_name TEXT NOT NULL,
    PRIMARY KEY (team_id, role_name, credential_name),
    FOREIGN KEY (team_id, role_name) REFERENCES roles(team_id, name) ON DELETE CASCADE,
    FOREIGN KEY (team_id, credential_name) REFERENCES credentials(team_id, name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS agents (
    id TEXT NOT NULL,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    description TEXT,
    api_key_hash TEXT NOT NULL UNIQUE,
    rate_limit_per_hour INTEGER,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (team_id, id)
);

CREATE TABLE IF NOT EXISTS agent_roles (
    team_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    role_name TEXT NOT NULL,
    PRIMARY KEY (team_id, agent_id, role_name),
    FOREIGN KEY (team_id, agent_id) REFERENCES agents(team_id, id) ON DELETE CASCADE,
    FOREIGN KEY (team_id, role_name) REFERENCES roles(team_id, name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS agent_credentials (
    team_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    credential_name TEXT NOT NULL,
    PRIMARY KEY (team_id, agent_id, credential_name),
    FOREIGN KEY (team_id, agent_id) REFERENCES agents(team_id, id) ON DELETE CASCADE,
    FOREIGN KEY (team_id, credential_name) REFERENCES credentials(team_id, name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS policies (
    team_id TEXT NOT NULL,
    credential_name TEXT NOT NULL,
    auto_approve_methods TEXT NOT NULL DEFAULT '[]',
    require_approval_methods TEXT NOT NULL DEFAULT '[]',
    auto_approve_urls TEXT NOT NULL DEFAULT '[]',
    allowed_approvers TEXT NOT NULL DEFAULT '[]',
    telegram_chat_id TEXT,
    require_passkey INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (team_id, credential_name),
    FOREIGN KEY (team_id, credential_name) REFERENCES credentials(team_id, name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_team_links (
    agent_home_team_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    linked_team_id TEXT NOT NULL,
    role_name TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (agent_home_team_id, agent_id, linked_team_id),
    FOREIGN KEY (agent_home_team_id, agent_id) REFERENCES agents(team_id, id) ON DELETE CASCADE,
    FOREIGN KEY (linked_team_id) REFERENCES teams(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    credential_id TEXT PRIMARY KEY,
    admin_id TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    public_key_json TEXT NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approver_passkeys (
    credential_id TEXT PRIMARY KEY,
    approver_name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    public_key_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notification_channels (
    id TEXT PRIMARY KEY,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    channel_type TEXT NOT NULL DEFAULT 'telegram',
    name TEXT NOT NULL,
    config_json TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(team_id, name)
);

CREATE TABLE IF NOT EXISTS whitelist (
    email TEXT PRIMARY KEY,
    tier TEXT NOT NULL DEFAULT 'pro',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    request_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    credential_names TEXT NOT NULL,
    target_url TEXT NOT NULL,
    method TEXT NOT NULL,
    approval_status TEXT,
    upstream_status INTEGER,
    total_latency_ms INTEGER NOT NULL,
    approval_latency_ms INTEGER,
    upstream_latency_ms INTEGER,
    response_sanitized BOOLEAN NOT NULL DEFAULT FALSE,
    timestamp TEXT NOT NULL
)
"#;

impl ConfigStore {
    /// Open (or create) a database and initialize the schema.
    /// For local SQLite, pass a file path as `db_url` and `None` for `auth_token`.
    /// For remote Turso, pass the libsql:// URL and Some(auth_token).
    pub async fn new(
        db_url: &str,
        auth_token: Option<&str>,
        encryption_key: [u8; 32],
    ) -> Result<Self, AgentSecError> {
        let db = match auth_token {
            Some(token) if !token.is_empty() => {
                libsql::Builder::new_remote(db_url.to_string(), token.to_string())
                    .build()
                    .await
                    .map_err(|e| {
                        AgentSecError::Config(format!("Failed to connect to remote DB: {e}"))
                    })?
            }
            _ => libsql::Builder::new_local(db_url)
                .build()
                .await
                .map_err(|e| AgentSecError::Config(format!("Failed to open local DB: {e}")))?,
        };

        let conn = db
            .connect()
            .map_err(|e| AgentSecError::Config(format!("Failed to create connection: {e}")))?;

        // PRAGMA foreign_keys is a no-op on remote Turso but needed for local SQLite
        let _ = conn.execute("PRAGMA foreign_keys = ON", ()).await;

        // Run schema - split into individual statements since execute_batch
        // may not support multiple statements in all modes
        for statement in SCHEMA.split(';') {
            let stmt = statement.trim();
            if !stmt.is_empty() {
                conn.execute(stmt, ()).await.map_err(|e| {
                    AgentSecError::Config(format!("Schema init failed on '{stmt}': {e}"))
                })?;
            }
        }

        // Migrations for existing databases (ALTER TABLE is idempotent via error-ignore)
        let _ = conn
            .execute(
                "ALTER TABLE policies ADD COLUMN require_passkey INTEGER NOT NULL DEFAULT 0",
                (),
            )
            .await;
        let _ = conn
            .execute(
                "ALTER TABLE credentials ADD COLUMN auth_bindings_json TEXT",
                (),
            )
            .await;

        Ok(Self {
            conn,
            encryption_key,
        })
    }

    // -- Teams ----------------------------------------------------------------

    pub async fn create_team(&self, id: &str, name: &str) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();

        self.conn
            .execute(
                "INSERT INTO teams (id, name, created_at) VALUES (?1, ?2, ?3)",
                libsql::params![id, name, now],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to create team: {e}")))?;
        Ok(())
    }

    pub async fn get_team(&self, id: &str) -> Result<Option<TeamRow>, AgentSecError> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, name, tier, stripe_customer_id, created_at FROM teams WHERE id = ?1",
                libsql::params![id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get team: {e}")))?;
        match rows.next().await {
            Ok(Some(row)) => Ok(Some(TeamRow {
                id: row
                    .get::<String>(0)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get team: {e}")))?,
                name: row
                    .get::<String>(1)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get team: {e}")))?,
                tier: row
                    .get::<String>(2)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get team: {e}")))?,
                stripe_customer_id: row
                    .get::<Option<String>>(3)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get team: {e}")))?,
                created_at: row
                    .get::<String>(4)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get team: {e}")))?,
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(AgentSecError::Config(format!("Failed to get team: {e}"))),
        }
    }

    pub async fn get_team_by_name(&self, name: &str) -> Result<Option<TeamRow>, AgentSecError> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, name, tier, stripe_customer_id, created_at FROM teams WHERE name = ?1",
                libsql::params![name],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get team by name: {e}")))?;
        match rows.next().await {
            Ok(Some(row)) => Ok(Some(TeamRow {
                id: row.get::<String>(0).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get team by name: {e}"))
                })?,
                name: row.get::<String>(1).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get team by name: {e}"))
                })?,
                tier: row.get::<String>(2).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get team by name: {e}"))
                })?,
                stripe_customer_id: row.get::<Option<String>>(3).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get team by name: {e}"))
                })?,
                created_at: row.get::<String>(4).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get team by name: {e}"))
                })?,
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(AgentSecError::Config(format!(
                "Failed to get team by name: {e}"
            ))),
        }
    }

    pub async fn update_team_tier(&self, team_id: &str, tier: &str) -> Result<(), AgentSecError> {
        self.conn
            .execute(
                "UPDATE teams SET tier = ?1 WHERE id = ?2",
                libsql::params![tier, team_id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to update team tier: {e}")))?;
        Ok(())
    }

    pub async fn set_stripe_customer_id(
        &self,
        team_id: &str,
        customer_id: &str,
    ) -> Result<(), AgentSecError> {
        self.conn
            .execute(
                "UPDATE teams SET stripe_customer_id = ?1 WHERE id = ?2",
                libsql::params![customer_id, team_id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to set Stripe customer ID: {e}")))?;
        Ok(())
    }

    pub async fn get_team_by_stripe_customer(
        &self,
        customer_id: &str,
    ) -> Result<Option<TeamRow>, AgentSecError> {
        let mut rows = self.conn
            .query(
                "SELECT id, name, tier, stripe_customer_id, created_at FROM teams WHERE stripe_customer_id = ?1",
                libsql::params![customer_id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get team by Stripe customer: {e}")))?;
        match rows.next().await {
            Ok(Some(row)) => Ok(Some(TeamRow {
                id: row.get::<String>(0).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get team by Stripe customer: {e}"))
                })?,
                name: row.get::<String>(1).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get team by Stripe customer: {e}"))
                })?,
                tier: row.get::<String>(2).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get team by Stripe customer: {e}"))
                })?,
                stripe_customer_id: row.get::<Option<String>>(3).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get team by Stripe customer: {e}"))
                })?,
                created_at: row.get::<String>(4).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get team by Stripe customer: {e}"))
                })?,
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(AgentSecError::Config(format!(
                "Failed to get team by Stripe customer: {e}"
            ))),
        }
    }

    // -- Admins ---------------------------------------------------------------

    pub async fn create_admin(
        &self,
        id: &str,
        team_id: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();

        self.conn
            .execute(
                "INSERT INTO admins (id, team_id, email, password_hash, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                libsql::params![id, team_id, email, password_hash, now],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to create admin: {e}")))?;
        Ok(())
    }

    pub async fn get_admin_by_email(&self, email: &str) -> Result<Option<AdminRow>, AgentSecError> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, team_id, email, password_hash, email_verified, created_at, updated_at
                 FROM admins WHERE email = ?1",
                libsql::params![email],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get admin by email: {e}")))?;
        match rows.next().await {
            Ok(Some(row)) => Ok(Some(AdminRow {
                id: row.get::<String>(0).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get admin by email: {e}"))
                })?,
                team_id: row.get::<String>(1).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get admin by email: {e}"))
                })?,
                email: row.get::<String>(2).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get admin by email: {e}"))
                })?,
                password_hash: row.get::<String>(3).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get admin by email: {e}"))
                })?,
                email_verified: row.get::<bool>(4).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get admin by email: {e}"))
                })?,
                created_at: row.get::<String>(5).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get admin by email: {e}"))
                })?,
                updated_at: row.get::<String>(6).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get admin by email: {e}"))
                })?,
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(AgentSecError::Config(format!(
                "Failed to get admin by email: {e}"
            ))),
        }
    }

    pub async fn get_admin(&self, id: &str) -> Result<Option<AdminRow>, AgentSecError> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, team_id, email, password_hash, email_verified, created_at, updated_at
                 FROM admins WHERE id = ?1",
                libsql::params![id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get admin: {e}")))?;
        match rows.next().await {
            Ok(Some(row)) => Ok(Some(AdminRow {
                id: row
                    .get::<String>(0)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get admin: {e}")))?,
                team_id: row
                    .get::<String>(1)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get admin: {e}")))?,
                email: row
                    .get::<String>(2)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get admin: {e}")))?,
                password_hash: row
                    .get::<String>(3)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get admin: {e}")))?,
                email_verified: row
                    .get::<bool>(4)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get admin: {e}")))?,
                created_at: row
                    .get::<String>(5)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get admin: {e}")))?,
                updated_at: row
                    .get::<String>(6)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get admin: {e}")))?,
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(AgentSecError::Config(format!("Failed to get admin: {e}"))),
        }
    }

    pub async fn set_admin_email_verified(&self, admin_id: &str) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE admins SET email_verified = TRUE, updated_at = ?1 WHERE id = ?2",
                libsql::params![now, admin_id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to verify admin email: {e}")))?;
        Ok(())
    }

    // -- Credentials ----------------------------------------------------------

    pub async fn create_credential(
        &self,
        team_id: &str,
        name: &str,
        description: &str,
        connector: &str,
        api_base: Option<&str>,
        relative_target: bool,
        auth_header_format: Option<&str>,
        auth_bindings_json: Option<&str>,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        let api_base_owned = api_base.map(|s| s.to_string());
        let auth_header_format_owned = auth_header_format.map(|s| s.to_string());
        let auth_bindings_owned = auth_bindings_json.map(|s| s.to_string());

        self.conn
            .execute(
                "INSERT INTO credentials (team_id, name, description, connector, api_base, relative_target, auth_header_format, auth_bindings_json, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
                libsql::params![team_id, name, description, connector, api_base_owned, relative_target, auth_header_format_owned, auth_bindings_owned, now],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to create credential: {e}")))?;
        Ok(())
    }

    pub async fn get_credential(
        &self,
        team_id: &str,
        name: &str,
    ) -> Result<Option<CredentialRow>, AgentSecError> {
        let mut rows = self.conn
            .query(
                "SELECT name, team_id, description, connector, api_base, relative_target, auth_header_format, auth_bindings_json, created_at, updated_at
                 FROM credentials WHERE team_id = ?1 AND name = ?2",
                libsql::params![team_id, name],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?;
        match rows.next().await {
            Ok(Some(row)) => Ok(Some(CredentialRow {
                name: row
                    .get::<String>(0)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
                team_id: row
                    .get::<String>(1)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
                description: row
                    .get::<String>(2)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
                connector: row
                    .get::<String>(3)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
                api_base: row
                    .get::<Option<String>>(4)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
                relative_target: row
                    .get::<bool>(5)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
                auth_header_format: row
                    .get::<Option<String>>(6)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
                auth_bindings_json: row
                    .get::<Option<String>>(7)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
                created_at: row
                    .get::<String>(8)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
                updated_at: row
                    .get::<String>(9)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get credential: {e}")))?,
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(AgentSecError::Config(format!(
                "Failed to get credential: {e}"
            ))),
        }
    }

    pub async fn list_credentials(
        &self,
        team_id: &str,
    ) -> Result<Vec<CredentialRow>, AgentSecError> {
        let mut rows = self.conn
            .query(
                "SELECT name, team_id, description, connector, api_base, relative_target, auth_header_format, auth_bindings_json, created_at, updated_at
                 FROM credentials WHERE team_id = ?1 ORDER BY name",
                libsql::params![team_id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to list credentials: {e}")))?;
        let mut results = Vec::new();
        while let Some(row) = rows
            .next()
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to list credentials: {e}")))?
        {
            results.push(CredentialRow {
                name: row.get::<String>(0).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
                team_id: row.get::<String>(1).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
                description: row.get::<String>(2).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
                connector: row.get::<String>(3).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
                api_base: row.get::<Option<String>>(4).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
                relative_target: row.get::<bool>(5).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
                auth_header_format: row.get::<Option<String>>(6).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
                auth_bindings_json: row.get::<Option<String>>(7).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
                created_at: row.get::<String>(8).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
                updated_at: row.get::<String>(9).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list credentials: {e}"))
                })?,
            });
        }
        Ok(results)
    }

    pub async fn delete_credential(&self, team_id: &str, name: &str) -> Result<(), AgentSecError> {
        self.conn
            .execute(
                "DELETE FROM credentials WHERE team_id = ?1 AND name = ?2",
                libsql::params![team_id, name],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to delete credential: {e}")))?;
        Ok(())
    }

    pub async fn set_credential_value(
        &self,
        team_id: &str,
        name: &str,
        plaintext: &[u8],
    ) -> Result<(), AgentSecError> {
        let encrypted = crypto::encrypt(&self.encryption_key, plaintext)
            .map_err(|e| AgentSecError::Encryption(e))?;
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE credentials SET encrypted_value = ?1, updated_at = ?2 WHERE team_id = ?3 AND name = ?4",
                libsql::params![encrypted, now, team_id, name],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to set credential value: {e}")))?;
        Ok(())
    }

    pub async fn get_credential_value(
        &self,
        team_id: &str,
        name: &str,
    ) -> Result<Option<Vec<u8>>, AgentSecError> {
        let mut rows = self
            .conn
            .query(
                "SELECT encrypted_value FROM credentials WHERE team_id = ?1 AND name = ?2",
                libsql::params![team_id, name],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get credential value: {e}")))?;
        match rows.next().await {
            Ok(Some(row)) => {
                let blob: Option<Vec<u8>> = row.get::<Option<Vec<u8>>>(0).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get credential value: {e}"))
                })?;
                match blob {
                    Some(data) => {
                        let plaintext = crypto::decrypt(&self.encryption_key, &data)
                            .map_err(|e| AgentSecError::Encryption(e))?;
                        Ok(Some(plaintext))
                    }
                    None => Ok(None),
                }
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AgentSecError::Config(format!(
                "Failed to get credential value: {e}"
            ))),
        }
    }

    // -- Agents ---------------------------------------------------------------

    pub async fn create_agent(
        &self,
        team_id: &str,
        id: &str,
        description: Option<&str>,
        api_key_hash: &str,
        rate_limit_per_hour: Option<i64>,
    ) -> Result<(), AgentSecError> {
        self.create_agent_with_admin(
            team_id,
            id,
            description,
            api_key_hash,
            rate_limit_per_hour,
            false,
        )
        .await
    }

    pub async fn create_admin_agent(
        &self,
        team_id: &str,
        id: &str,
        description: Option<&str>,
        api_key_hash: &str,
    ) -> Result<(), AgentSecError> {
        self.create_agent_with_admin(team_id, id, description, api_key_hash, None, true)
            .await
    }

    async fn create_agent_with_admin(
        &self,
        team_id: &str,
        id: &str,
        description: Option<&str>,
        api_key_hash: &str,
        rate_limit_per_hour: Option<i64>,
        is_admin: bool,
    ) -> Result<(), AgentSecError> {
        let description_owned = description.map(|s| s.to_string());
        let now = chrono::Utc::now().to_rfc3339();

        self.conn
            .execute(
                "INSERT INTO agents (team_id, id, description, api_key_hash, rate_limit_per_hour, is_admin, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
                libsql::params![team_id, id, description_owned, api_key_hash, rate_limit_per_hour, is_admin, now],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to create agent: {e}")))?;
        Ok(())
    }

    pub async fn get_agent(
        &self,
        team_id: &str,
        id: &str,
    ) -> Result<Option<AgentRow>, AgentSecError> {
        let mut rows = self.conn
            .query(
                "SELECT id, team_id, description, api_key_hash, rate_limit_per_hour, enabled, is_admin, created_at, updated_at
                 FROM agents WHERE team_id = ?1 AND id = ?2",
                libsql::params![team_id, id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?;
        match rows.next().await {
            Ok(Some(row)) => Ok(Some(AgentRow {
                id: row
                    .get::<String>(0)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?,
                team_id: row
                    .get::<String>(1)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?,
                description: row
                    .get::<Option<String>>(2)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?,
                api_key_hash: row
                    .get::<String>(3)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?,
                rate_limit_per_hour: row
                    .get::<Option<i64>>(4)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?,
                enabled: row
                    .get::<bool>(5)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?,
                is_admin: row
                    .get::<bool>(6)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?,
                created_at: row
                    .get::<String>(7)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?,
                updated_at: row
                    .get::<String>(8)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get agent: {e}")))?,
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(AgentSecError::Config(format!("Failed to get agent: {e}"))),
        }
    }

    pub async fn list_agents(&self, team_id: &str) -> Result<Vec<AgentRow>, AgentSecError> {
        let mut rows = self.conn
            .query(
                "SELECT id, team_id, description, api_key_hash, rate_limit_per_hour, enabled, is_admin, created_at, updated_at
                 FROM agents WHERE team_id = ?1 ORDER BY id",
                libsql::params![team_id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?;
        let mut results = Vec::new();
        while let Some(row) = rows
            .next()
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?
        {
            results.push(AgentRow {
                id: row
                    .get::<String>(0)
                    .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?,
                team_id: row
                    .get::<String>(1)
                    .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?,
                description: row
                    .get::<Option<String>>(2)
                    .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?,
                api_key_hash: row
                    .get::<String>(3)
                    .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?,
                rate_limit_per_hour: row
                    .get::<Option<i64>>(4)
                    .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?,
                enabled: row
                    .get::<bool>(5)
                    .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?,
                is_admin: row
                    .get::<bool>(6)
                    .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?,
                created_at: row
                    .get::<String>(7)
                    .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?,
                updated_at: row
                    .get::<String>(8)
                    .map_err(|e| AgentSecError::Config(format!("Failed to list agents: {e}")))?,
            });
        }
        Ok(results)
    }

    pub async fn delete_agent(&self, team_id: &str, id: &str) -> Result<(), AgentSecError> {
        self.conn
            .execute(
                "DELETE FROM agents WHERE team_id = ?1 AND id = ?2",
                libsql::params![team_id, id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to delete agent: {e}")))?;
        Ok(())
    }

    pub async fn enable_agent(&self, team_id: &str, id: &str) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE agents SET enabled = TRUE, updated_at = ?1 WHERE team_id = ?2 AND id = ?3",
                libsql::params![now, team_id, id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to enable agent: {e}")))?;
        Ok(())
    }

    pub async fn disable_agent(&self, team_id: &str, id: &str) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE agents SET enabled = FALSE, updated_at = ?1 WHERE team_id = ?2 AND id = ?3",
                libsql::params![now, team_id, id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to disable agent: {e}")))?;
        Ok(())
    }

    /// Get the effective credential set for an agent: union of role credentials + direct credentials.
    pub async fn get_agent_effective_credentials(
        &self,
        team_id: &str,
        agent_id: &str,
    ) -> Result<HashSet<String>, AgentSecError> {
        let mut creds = HashSet::new();

        // Direct credentials
        let mut rows = self.conn
            .query(
                "SELECT credential_name FROM agent_credentials WHERE team_id = ?1 AND agent_id = ?2",
                libsql::params![team_id, agent_id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get effective credentials: {e}")))?;
        while let Some(row) = rows.next().await.map_err(|e| {
            AgentSecError::Config(format!("Failed to get effective credentials: {e}"))
        })? {
            let name: String = row.get::<String>(0).map_err(|e| {
                AgentSecError::Config(format!("Failed to get effective credentials: {e}"))
            })?;
            creds.insert(name);
        }

        // Role credentials (via agent_roles -> role_credentials)
        let mut rows = self
            .conn
            .query(
                "SELECT DISTINCT rc.credential_name
                 FROM agent_roles ar
                 JOIN role_credentials rc ON ar.team_id = rc.team_id AND ar.role_name = rc.role_name
                 WHERE ar.team_id = ?1 AND ar.agent_id = ?2",
                libsql::params![team_id, agent_id],
            )
            .await
            .map_err(|e| {
                AgentSecError::Config(format!("Failed to get effective credentials: {e}"))
            })?;
        while let Some(row) = rows.next().await.map_err(|e| {
            AgentSecError::Config(format!("Failed to get effective credentials: {e}"))
        })? {
            let name: String = row.get::<String>(0).map_err(|e| {
                AgentSecError::Config(format!("Failed to get effective credentials: {e}"))
            })?;
            creds.insert(name);
        }

        Ok(creds)
    }

    /// Authenticate an agent by API key hash. Returns the agent if found (caller checks enabled).
    pub async fn authenticate_agent(
        &self,
        api_key_hash: &str,
    ) -> Result<Option<AgentRow>, AgentSecError> {
        let mut rows = self.conn
            .query(
                "SELECT id, team_id, description, api_key_hash, rate_limit_per_hour, enabled, is_admin, created_at, updated_at
                 FROM agents WHERE api_key_hash = ?1",
                libsql::params![api_key_hash],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?;
        match rows.next().await {
            Ok(Some(row)) => Ok(Some(AgentRow {
                id: row
                    .get::<String>(0)
                    .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?,
                team_id: row
                    .get::<String>(1)
                    .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?,
                description: row
                    .get::<Option<String>>(2)
                    .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?,
                api_key_hash: row
                    .get::<String>(3)
                    .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?,
                rate_limit_per_hour: row
                    .get::<Option<i64>>(4)
                    .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?,
                enabled: row
                    .get::<bool>(5)
                    .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?,
                is_admin: row
                    .get::<bool>(6)
                    .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?,
                created_at: row
                    .get::<String>(7)
                    .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?,
                updated_at: row
                    .get::<String>(8)
                    .map_err(|e| AgentSecError::Config(format!("Failed to authenticate: {e}")))?,
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(AgentSecError::Config(format!(
                "Failed to authenticate: {e}"
            ))),
        }
    }

    // -- Roles ----------------------------------------------------------------

    pub async fn create_role(
        &self,
        team_id: &str,
        name: &str,
        description: Option<&str>,
        rate_limit_per_hour: Option<i64>,
    ) -> Result<(), AgentSecError> {
        let description_owned = description.map(|s| s.to_string());
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO roles (team_id, name, description, rate_limit_per_hour, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                libsql::params![team_id, name, description_owned, rate_limit_per_hour, now],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to create role: {e}")))?;
        Ok(())
    }

    pub async fn list_roles(&self, team_id: &str) -> Result<Vec<RoleRow>, AgentSecError> {
        let mut rows = self
            .conn
            .query(
                "SELECT name, team_id, description, rate_limit_per_hour, created_at
                 FROM roles WHERE team_id = ?1 ORDER BY name",
                libsql::params![team_id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to list roles: {e}")))?;
        let mut results = Vec::new();
        while let Some(row) = rows
            .next()
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to list roles: {e}")))?
        {
            results.push(RoleRow {
                name: row
                    .get::<String>(0)
                    .map_err(|e| AgentSecError::Config(format!("Failed to list roles: {e}")))?,
                team_id: row
                    .get::<String>(1)
                    .map_err(|e| AgentSecError::Config(format!("Failed to list roles: {e}")))?,
                description: row
                    .get::<Option<String>>(2)
                    .map_err(|e| AgentSecError::Config(format!("Failed to list roles: {e}")))?,
                rate_limit_per_hour: row
                    .get::<Option<i64>>(3)
                    .map_err(|e| AgentSecError::Config(format!("Failed to list roles: {e}")))?,
                created_at: row
                    .get::<String>(4)
                    .map_err(|e| AgentSecError::Config(format!("Failed to list roles: {e}")))?,
            });
        }
        Ok(results)
    }

    pub async fn delete_role(&self, team_id: &str, name: &str) -> Result<(), AgentSecError> {
        self.conn
            .execute(
                "DELETE FROM roles WHERE team_id = ?1 AND name = ?2",
                libsql::params![team_id, name],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to delete role: {e}")))?;
        Ok(())
    }

    pub async fn add_credential_to_role(
        &self,
        team_id: &str,
        role_name: &str,
        credential_name: &str,
    ) -> Result<(), AgentSecError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO role_credentials (team_id, role_name, credential_name) VALUES (?1, ?2, ?3)",
                libsql::params![team_id, role_name, credential_name],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to add credential to role: {e}")))?;
        Ok(())
    }

    pub async fn remove_credential_from_role(
        &self,
        team_id: &str,
        role_name: &str,
        credential_name: &str,
    ) -> Result<(), AgentSecError> {
        self.conn
            .execute(
                "DELETE FROM role_credentials WHERE team_id = ?1 AND role_name = ?2 AND credential_name = ?3",
                libsql::params![team_id, role_name, credential_name],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to remove credential from role: {e}")))?;
        Ok(())
    }

    // -- Agent assignments ----------------------------------------------------

    pub async fn assign_role_to_agent(
        &self,
        team_id: &str,
        agent_id: &str,
        role_name: &str,
    ) -> Result<(), AgentSecError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO agent_roles (team_id, agent_id, role_name) VALUES (?1, ?2, ?3)",
                libsql::params![team_id, agent_id, role_name],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to assign role: {e}")))?;
        Ok(())
    }

    pub async fn remove_role_from_agent(
        &self,
        team_id: &str,
        agent_id: &str,
        role_name: &str,
    ) -> Result<(), AgentSecError> {
        self.conn
            .execute(
                "DELETE FROM agent_roles WHERE team_id = ?1 AND agent_id = ?2 AND role_name = ?3",
                libsql::params![team_id, agent_id, role_name],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to remove role: {e}")))?;
        Ok(())
    }

    pub async fn get_agent_direct_credentials(
        &self,
        team_id: &str,
        agent_id: &str,
    ) -> Result<Vec<String>, AgentSecError> {
        let mut names = Vec::new();
        let mut rows = self.conn
            .query(
                "SELECT credential_name FROM agent_credentials WHERE team_id = ?1 AND agent_id = ?2",
                libsql::params![team_id, agent_id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get agent credentials: {e}")))?;
        while let Some(row) = rows
            .next()
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get agent credentials: {e}")))?
        {
            names.push(row.get::<String>(0).map_err(|e| {
                AgentSecError::Config(format!("Failed to get agent credentials: {e}"))
            })?);
        }
        Ok(names)
    }

    pub async fn get_agent_roles(
        &self,
        team_id: &str,
        agent_id: &str,
    ) -> Result<Vec<String>, AgentSecError> {
        let mut names = Vec::new();
        let mut rows = self
            .conn
            .query(
                "SELECT role_name FROM agent_roles WHERE team_id = ?1 AND agent_id = ?2",
                libsql::params![team_id, agent_id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get agent roles: {e}")))?;
        while let Some(row) = rows
            .next()
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get agent roles: {e}")))?
        {
            names.push(
                row.get::<String>(0).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get agent roles: {e}"))
                })?,
            );
        }
        Ok(names)
    }

    pub async fn add_direct_credential(
        &self,
        team_id: &str,
        agent_id: &str,
        credential_name: &str,
    ) -> Result<(), AgentSecError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO agent_credentials (team_id, agent_id, credential_name) VALUES (?1, ?2, ?3)",
                libsql::params![team_id, agent_id, credential_name],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to add direct credential: {e}")))?;
        Ok(())
    }

    pub async fn remove_direct_credential(
        &self,
        team_id: &str,
        agent_id: &str,
        credential_name: &str,
    ) -> Result<(), AgentSecError> {
        self.conn
            .execute(
                "DELETE FROM agent_credentials WHERE team_id = ?1 AND agent_id = ?2 AND credential_name = ?3",
                libsql::params![team_id, agent_id, credential_name],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to remove direct credential: {e}")))?;
        Ok(())
    }

    // -- Policies -------------------------------------------------------------

    pub async fn set_policy(&self, policy: &PolicyRow) -> Result<(), AgentSecError> {
        let auto = serde_json::to_string(&policy.auto_approve_methods).unwrap();
        let require = serde_json::to_string(&policy.require_approval_methods).unwrap();
        let urls = serde_json::to_string(&policy.auto_approve_urls).unwrap();
        let approvers = serde_json::to_string(&policy.allowed_approvers).unwrap();
        let passkey_val: i64 = if policy.require_passkey { 1 } else { 0 };

        self.conn
            .execute(
                "INSERT OR REPLACE INTO policies
                 (team_id, credential_name, auto_approve_methods, require_approval_methods, auto_approve_urls, allowed_approvers, telegram_chat_id, require_passkey)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                libsql::params![policy.team_id.clone(), policy.credential_name.clone(), auto, require, urls, approvers, policy.telegram_chat_id.clone(), passkey_val],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to set policy: {e}")))?;
        Ok(())
    }

    pub async fn get_policy(
        &self,
        team_id: &str,
        credential_name: &str,
    ) -> Result<Option<PolicyRow>, AgentSecError> {
        let mut rows = self.conn
            .query(
                "SELECT credential_name, team_id, auto_approve_methods, require_approval_methods, auto_approve_urls, allowed_approvers, telegram_chat_id, require_passkey
                 FROM policies WHERE team_id = ?1 AND credential_name = ?2",
                libsql::params![team_id, credential_name],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get policy: {e}")))?;
        match rows.next().await {
            Ok(Some(row)) => {
                let auto: String = row
                    .get::<String>(2)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get policy: {e}")))?;
                let require: String = row
                    .get::<String>(3)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get policy: {e}")))?;
                let urls: String = row
                    .get::<String>(4)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get policy: {e}")))?;
                let approvers: String = row
                    .get::<String>(5)
                    .map_err(|e| AgentSecError::Config(format!("Failed to get policy: {e}")))?;
                let passkey_int: i64 = row.get::<i64>(7).unwrap_or(0);
                Ok(Some(PolicyRow {
                    credential_name: row
                        .get::<String>(0)
                        .map_err(|e| AgentSecError::Config(format!("Failed to get policy: {e}")))?,
                    team_id: row
                        .get::<String>(1)
                        .map_err(|e| AgentSecError::Config(format!("Failed to get policy: {e}")))?,
                    auto_approve_methods: serde_json::from_str(&auto).unwrap_or_default(),
                    require_approval_methods: serde_json::from_str(&require).unwrap_or_default(),
                    auto_approve_urls: serde_json::from_str(&urls).unwrap_or_default(),
                    allowed_approvers: serde_json::from_str(&approvers).unwrap_or_default(),
                    telegram_chat_id: row
                        .get::<Option<String>>(6)
                        .map_err(|e| AgentSecError::Config(format!("Failed to get policy: {e}")))?,
                    require_passkey: passkey_int != 0,
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AgentSecError::Config(format!("Failed to get policy: {e}"))),
        }
    }

    // -- Notification Channels -------------------------------------------------

    pub async fn create_notification_channel(
        &self,
        team_id: &str,
        channel_type: &str,
        name: &str,
        config_json: &str,
    ) -> Result<String, AgentSecError> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO notification_channels (id, team_id, channel_type, name, config_json, enabled, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?6)",
                libsql::params![id.clone(), team_id, channel_type, name, config_json, now],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to create notification channel: {e}")))?;
        Ok(id)
    }

    pub async fn get_notification_channel(
        &self,
        team_id: &str,
        name: &str,
    ) -> Result<Option<NotificationChannelRow>, AgentSecError> {
        let mut rows = self.conn
            .query(
                "SELECT id, team_id, channel_type, name, config_json, enabled, created_at, updated_at
                 FROM notification_channels WHERE team_id = ?1 AND name = ?2",
                libsql::params![team_id, name],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get notification channel: {e}")))?;
        match rows.next().await {
            Ok(Some(row)) => Ok(Some(NotificationChannelRow {
                id: row.get::<String>(0).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get notification channel: {e}"))
                })?,
                team_id: row.get::<String>(1).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get notification channel: {e}"))
                })?,
                channel_type: row.get::<String>(2).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get notification channel: {e}"))
                })?,
                name: row.get::<String>(3).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get notification channel: {e}"))
                })?,
                config_json: row.get::<String>(4).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get notification channel: {e}"))
                })?,
                enabled: row.get::<bool>(5).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get notification channel: {e}"))
                })?,
                created_at: row.get::<String>(6).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get notification channel: {e}"))
                })?,
                updated_at: row.get::<String>(7).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get notification channel: {e}"))
                })?,
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(AgentSecError::Config(format!(
                "Failed to get notification channel: {e}"
            ))),
        }
    }

    pub async fn list_notification_channels(
        &self,
        team_id: &str,
    ) -> Result<Vec<NotificationChannelRow>, AgentSecError> {
        let mut rows = self.conn
            .query(
                "SELECT id, team_id, channel_type, name, config_json, enabled, created_at, updated_at
                 FROM notification_channels WHERE team_id = ?1 ORDER BY created_at",
                libsql::params![team_id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to list notification channels: {e}")))?;
        let mut results = Vec::new();
        while let Some(row) = rows.next().await.map_err(|e| {
            AgentSecError::Config(format!("Failed to list notification channels: {e}"))
        })? {
            results.push(NotificationChannelRow {
                id: row.get::<String>(0).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list notification channels: {e}"))
                })?,
                team_id: row.get::<String>(1).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list notification channels: {e}"))
                })?,
                channel_type: row.get::<String>(2).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list notification channels: {e}"))
                })?,
                name: row.get::<String>(3).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list notification channels: {e}"))
                })?,
                config_json: row.get::<String>(4).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list notification channels: {e}"))
                })?,
                enabled: row.get::<bool>(5).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list notification channels: {e}"))
                })?,
                created_at: row.get::<String>(6).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list notification channels: {e}"))
                })?,
                updated_at: row.get::<String>(7).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list notification channels: {e}"))
                })?,
            });
        }
        Ok(results)
    }

    pub async fn delete_notification_channel(
        &self,
        team_id: &str,
        name: &str,
    ) -> Result<(), AgentSecError> {
        let affected = self
            .conn
            .execute(
                "DELETE FROM notification_channels WHERE team_id = ?1 AND name = ?2",
                libsql::params![team_id, name],
            )
            .await
            .map_err(|e| {
                AgentSecError::Config(format!("Failed to delete notification channel: {e}"))
            })?;
        if affected == 0 {
            return Err(AgentSecError::Config(
                "Failed to delete notification channel: no matching channel found".to_string(),
            ));
        }
        Ok(())
    }

    /// Get the default Telegram chat_id for a team.
    /// Finds the first enabled telegram channel and parses chat_id from config_json.
    pub async fn get_default_telegram_chat_id(
        &self,
        team_id: &str,
    ) -> Result<Option<String>, AgentSecError> {
        let mut rows = self
            .conn
            .query(
                "SELECT config_json FROM notification_channels
                 WHERE team_id = ?1 AND channel_type = 'telegram' AND enabled = 1
                 ORDER BY created_at LIMIT 1",
                libsql::params![team_id],
            )
            .await
            .map_err(|e| {
                AgentSecError::Config(format!("Failed to get default telegram chat_id: {e}"))
            })?;
        match rows.next().await {
            Ok(Some(row)) => {
                let json_str: String = row.get::<String>(0).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get default telegram chat_id: {e}"))
                })?;
                let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap_or_default();
                Ok(parsed
                    .get("chat_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AgentSecError::Config(format!(
                "Failed to get default telegram chat_id: {e}"
            ))),
        }
    }

    // -- Sessions -------------------------------------------------------------

    pub async fn create_session(
        &self,
        token_hash: &str,
        admin_id: &str,
        expires_at: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();

        self.conn
            .execute(
                "INSERT INTO admin_sessions (token_hash, admin_id, expires_at, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                libsql::params![token_hash, admin_id, expires_at, now],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to create session: {e}")))?;
        Ok(())
    }

    /// Validate a session token hash. Returns the admin if valid and not expired.
    pub async fn validate_session(
        &self,
        token_hash: &str,
    ) -> Result<Option<AdminRow>, AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();

        let mut rows = self.conn
            .query(
                "SELECT a.id, a.team_id, a.email, a.password_hash, a.email_verified, a.created_at, a.updated_at
                 FROM admin_sessions s
                 JOIN admins a ON s.admin_id = a.id
                 WHERE s.token_hash = ?1 AND s.expires_at > ?2",
                libsql::params![token_hash, now],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to validate session: {e}")))?;
        match rows.next().await {
            Ok(Some(row)) => Ok(Some(AdminRow {
                id: row.get::<String>(0).map_err(|e| {
                    AgentSecError::Config(format!("Failed to validate session: {e}"))
                })?,
                team_id: row.get::<String>(1).map_err(|e| {
                    AgentSecError::Config(format!("Failed to validate session: {e}"))
                })?,
                email: row.get::<String>(2).map_err(|e| {
                    AgentSecError::Config(format!("Failed to validate session: {e}"))
                })?,
                password_hash: row.get::<String>(3).map_err(|e| {
                    AgentSecError::Config(format!("Failed to validate session: {e}"))
                })?,
                email_verified: row.get::<bool>(4).map_err(|e| {
                    AgentSecError::Config(format!("Failed to validate session: {e}"))
                })?,
                created_at: row.get::<String>(5).map_err(|e| {
                    AgentSecError::Config(format!("Failed to validate session: {e}"))
                })?,
                updated_at: row.get::<String>(6).map_err(|e| {
                    AgentSecError::Config(format!("Failed to validate session: {e}"))
                })?,
            })),
            Ok(None) => Ok(None),
            Err(e) => Err(AgentSecError::Config(format!(
                "Failed to validate session: {e}"
            ))),
        }
    }

    pub async fn delete_session(&self, token_hash: &str) -> Result<(), AgentSecError> {
        self.conn
            .execute(
                "DELETE FROM admin_sessions WHERE token_hash = ?1",
                libsql::params![token_hash],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to delete session: {e}")))?;
        Ok(())
    }

    // -- Email verification ---------------------------------------------------

    pub async fn create_email_verification(
        &self,
        code_hash: &str,
        admin_id: &str,
        expires_at: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();

        self.conn
            .execute(
                "INSERT INTO email_verifications (code_hash, admin_id, expires_at, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                libsql::params![code_hash, admin_id, expires_at, now],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to create verification: {e}")))?;
        Ok(())
    }

    /// Validate an email verification code. Returns admin_id if valid and not expired.
    /// Deletes the code on success (one-time use).
    pub async fn validate_email_verification(
        &self,
        code_hash: &str,
    ) -> Result<Option<String>, AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();

        // Try to find the verification code
        let mut rows = self
            .conn
            .query(
                "SELECT admin_id FROM email_verifications
                 WHERE code_hash = ?1 AND expires_at > ?2",
                libsql::params![code_hash, now.clone()],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to validate verification: {e}")))?;

        let admin_id: Option<String> = match rows.next().await {
            Ok(Some(row)) => Some(row.get::<String>(0).map_err(|e| {
                AgentSecError::Config(format!("Failed to validate verification: {e}"))
            })?),
            Ok(None) => None,
            Err(e) => {
                return Err(AgentSecError::Config(format!(
                    "Failed to validate verification: {e}"
                )))
            }
        };

        if let Some(ref id) = admin_id {
            // Delete used code
            self.conn
                .execute(
                    "DELETE FROM email_verifications WHERE code_hash = ?1",
                    libsql::params![code_hash],
                )
                .await
                .map_err(|e| {
                    AgentSecError::Config(format!("Failed to validate verification: {e}"))
                })?;
            // Mark admin as verified
            self.conn
                .execute(
                    "UPDATE admins SET email_verified = TRUE, updated_at = ?1 WHERE id = ?2",
                    libsql::params![now, id.clone()],
                )
                .await
                .map_err(|e| {
                    AgentSecError::Config(format!("Failed to validate verification: {e}"))
                })?;
        }

        Ok(admin_id)
    }

    // -- Agent Team Links -------------------------------------------------------

    /// Link an external agent to a team. Called by the linked team's admin.
    pub async fn link_agent_to_team(
        &self,
        agent_home_team_id: &str,
        agent_id: &str,
        linked_team_id: &str,
        role_name: Option<&str>,
    ) -> Result<(), AgentSecError> {
        let role = role_name.map(|s| s.to_string());
        let now = chrono::Utc::now().to_rfc3339();

        self.conn
            .execute(
                "INSERT INTO agent_team_links (agent_home_team_id, agent_id, linked_team_id, role_name, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                libsql::params![agent_home_team_id, agent_id, linked_team_id, role, now],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to link agent to team: {e}")))?;
        Ok(())
    }

    /// Unlink an external agent from a team.
    pub async fn unlink_agent_from_team(
        &self,
        agent_home_team_id: &str,
        agent_id: &str,
        linked_team_id: &str,
    ) -> Result<(), AgentSecError> {
        self.conn
            .execute(
                "DELETE FROM agent_team_links WHERE agent_home_team_id = ?1 AND agent_id = ?2 AND linked_team_id = ?3",
                libsql::params![agent_home_team_id, agent_id, linked_team_id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to unlink agent from team: {e}")))?;
        Ok(())
    }

    /// Get all teams an agent is linked to (from the agent's perspective).
    pub async fn get_agent_linked_teams(
        &self,
        agent_home_team_id: &str,
        agent_id: &str,
    ) -> Result<Vec<AgentTeamLink>, AgentSecError> {
        let mut rows = self
            .conn
            .query(
                "SELECT agent_home_team_id, agent_id, linked_team_id, role_name, created_at
                 FROM agent_team_links WHERE agent_home_team_id = ?1 AND agent_id = ?2",
                libsql::params![agent_home_team_id, agent_id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get agent linked teams: {e}")))?;
        let mut results = Vec::new();
        while let Some(row) = rows
            .next()
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get agent linked teams: {e}")))?
        {
            results.push(AgentTeamLink {
                agent_home_team_id: row.get::<String>(0).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get agent linked teams: {e}"))
                })?,
                agent_id: row.get::<String>(1).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get agent linked teams: {e}"))
                })?,
                linked_team_id: row.get::<String>(2).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get agent linked teams: {e}"))
                })?,
                role_name: row.get::<Option<String>>(3).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get agent linked teams: {e}"))
                })?,
                created_at: row.get::<String>(4).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get agent linked teams: {e}"))
                })?,
            });
        }
        Ok(results)
    }

    /// Check if an agent is linked to a specific team.
    pub async fn is_agent_linked_to_team(
        &self,
        agent_home_team_id: &str,
        agent_id: &str,
        linked_team_id: &str,
    ) -> Result<bool, AgentSecError> {
        let mut rows = self
            .conn
            .query(
                "SELECT COUNT(*) FROM agent_team_links
                 WHERE agent_home_team_id = ?1 AND agent_id = ?2 AND linked_team_id = ?3",
                libsql::params![agent_home_team_id, agent_id, linked_team_id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to check agent team link: {e}")))?;
        match rows.next().await {
            Ok(Some(row)) => {
                let count: i64 = row.get::<i64>(0).map_err(|e| {
                    AgentSecError::Config(format!("Failed to check agent team link: {e}"))
                })?;
                Ok(count > 0)
            }
            Ok(None) => Ok(false),
            Err(e) => Err(AgentSecError::Config(format!(
                "Failed to check agent team link: {e}"
            ))),
        }
    }

    /// Get effective credentials for an agent in a linked team.
    /// If the link has a role_name, return that role's credentials in the linked team.
    /// If no role_name, return ALL credentials in the linked team.
    pub async fn get_agent_linked_credentials(
        &self,
        agent_home_team_id: &str,
        agent_id: &str,
        linked_team_id: &str,
    ) -> Result<HashSet<String>, AgentSecError> {
        // First, find the link and its optional role_name
        let mut rows = self
            .conn
            .query(
                "SELECT role_name FROM agent_team_links
                 WHERE agent_home_team_id = ?1 AND agent_id = ?2 AND linked_team_id = ?3",
                libsql::params![agent_home_team_id, agent_id, linked_team_id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to get linked credentials: {e}")))?;

        let role_name_opt: Option<Option<String>> = match rows.next().await {
            Ok(Some(row)) => Some(row.get::<Option<String>>(0).map_err(|e| {
                AgentSecError::Config(format!("Failed to get linked credentials: {e}"))
            })?),
            Ok(None) => None,
            Err(e) => {
                return Err(AgentSecError::Config(format!(
                    "Failed to get linked credentials: {e}"
                )))
            }
        };

        let Some(role_name_opt) = role_name_opt else {
            // No link found
            return Ok(HashSet::new());
        };

        let mut creds = HashSet::new();

        if let Some(role_name) = role_name_opt {
            // Link specifies a role -- get that role's credentials in the linked team
            let mut rows = self
                .conn
                .query(
                    "SELECT credential_name FROM role_credentials
                     WHERE team_id = ?1 AND role_name = ?2",
                    libsql::params![linked_team_id, role_name],
                )
                .await
                .map_err(|e| {
                    AgentSecError::Config(format!("Failed to get linked credentials: {e}"))
                })?;
            while let Some(row) = rows.next().await.map_err(|e| {
                AgentSecError::Config(format!("Failed to get linked credentials: {e}"))
            })? {
                let name: String = row.get::<String>(0).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get linked credentials: {e}"))
                })?;
                creds.insert(name);
            }
        } else {
            // No role restriction -- get ALL credentials in the linked team
            let mut rows = self
                .conn
                .query(
                    "SELECT name FROM credentials WHERE team_id = ?1",
                    libsql::params![linked_team_id],
                )
                .await
                .map_err(|e| {
                    AgentSecError::Config(format!("Failed to get linked credentials: {e}"))
                })?;
            while let Some(row) = rows.next().await.map_err(|e| {
                AgentSecError::Config(format!("Failed to get linked credentials: {e}"))
            })? {
                let name: String = row.get::<String>(0).map_err(|e| {
                    AgentSecError::Config(format!("Failed to get linked credentials: {e}"))
                })?;
                creds.insert(name);
            }
        }

        Ok(creds)
    }

    /// List all agent links for a specific linked team (admin perspective -- "which foreign agents have access to my team?").
    pub async fn list_agent_links_for_team(
        &self,
        linked_team_id: &str,
    ) -> Result<Vec<AgentTeamLink>, AgentSecError> {
        let mut rows = self
            .conn
            .query(
                "SELECT agent_home_team_id, agent_id, linked_team_id, role_name, created_at
                 FROM agent_team_links WHERE linked_team_id = ?1
                 ORDER BY created_at",
                libsql::params![linked_team_id],
            )
            .await
            .map_err(|e| {
                AgentSecError::Config(format!("Failed to list agent links for team: {e}"))
            })?;
        let mut results = Vec::new();
        while let Some(row) = rows.next().await.map_err(|e| {
            AgentSecError::Config(format!("Failed to list agent links for team: {e}"))
        })? {
            results.push(AgentTeamLink {
                agent_home_team_id: row.get::<String>(0).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list agent links for team: {e}"))
                })?,
                agent_id: row.get::<String>(1).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list agent links for team: {e}"))
                })?,
                linked_team_id: row.get::<String>(2).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list agent links for team: {e}"))
                })?,
                role_name: row.get::<Option<String>>(3).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list agent links for team: {e}"))
                })?,
                created_at: row.get::<String>(4).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list agent links for team: {e}"))
                })?,
            });
        }
        Ok(results)
    }

    // -- Approver Passkeys ------------------------------------------------

    /// Save a WebAuthn passkey for an approver.
    pub async fn save_approver_passkey(
        &self,
        credential_id: &str,
        approver_name: &str,
        display_name: &str,
        public_key_json: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO approver_passkeys (credential_id, approver_name, display_name, public_key_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                libsql::params![credential_id, approver_name, display_name, public_key_json, now],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to save approver passkey: {e}")))?;
        Ok(())
    }

    /// List all approver passkeys (for loading into WebAuthnState at startup).
    pub async fn list_all_approver_passkeys(
        &self,
    ) -> Result<Vec<ApproverPasskeyRow>, AgentSecError> {
        let mut rows = self.conn
            .query(
                "SELECT credential_id, approver_name, display_name, public_key_json, created_at FROM approver_passkeys ORDER BY created_at",
                (),
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to list approver passkeys: {e}")))?;
        let mut results = Vec::new();
        while let Some(row) = rows
            .next()
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to list approver passkeys: {e}")))?
        {
            results.push(ApproverPasskeyRow {
                credential_id: row.get::<String>(0).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list approver passkeys: {e}"))
                })?,
                approver_name: row.get::<String>(1).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list approver passkeys: {e}"))
                })?,
                display_name: row.get::<String>(2).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list approver passkeys: {e}"))
                })?,
                public_key_json: row.get::<String>(3).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list approver passkeys: {e}"))
                })?,
                created_at: row.get::<String>(4).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list approver passkeys: {e}"))
                })?,
            });
        }
        Ok(results)
    }

    // -- Admin Passkeys (WebAuthn 2FA for admin login) ----------------------

    /// Save a WebAuthn passkey for an admin (2FA login).
    pub async fn save_admin_passkey(
        &self,
        admin_id: &str,
        credential_id: &str,
        public_key_json: &str,
    ) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO webauthn_credentials (credential_id, admin_id, public_key_json, counter, created_at) VALUES (?1, ?2, ?3, 0, ?4)",
                libsql::params![credential_id, admin_id, public_key_json, now],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to save admin passkey: {e}")))?;
        Ok(())
    }

    /// List all passkeys for an admin.
    pub async fn list_admin_passkeys(
        &self,
        admin_id: &str,
    ) -> Result<Vec<AdminPasskeyRow>, AgentSecError> {
        let mut rows = self.conn
            .query(
                "SELECT credential_id, admin_id, public_key_json, created_at FROM webauthn_credentials WHERE admin_id = ?1 ORDER BY created_at",
                libsql::params![admin_id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to list admin passkeys: {e}")))?;
        let mut results = Vec::new();
        while let Some(row) = rows
            .next()
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to list admin passkeys: {e}")))?
        {
            results.push(AdminPasskeyRow {
                credential_id: row.get::<String>(0).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list admin passkeys: {e}"))
                })?,
                admin_id: row.get::<String>(1).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list admin passkeys: {e}"))
                })?,
                public_key_json: row.get::<String>(2).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list admin passkeys: {e}"))
                })?,
                created_at: row.get::<String>(3).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list admin passkeys: {e}"))
                })?,
            });
        }
        Ok(results)
    }

    /// Delete an admin passkey by credential_id (only if admin owns it).
    pub async fn delete_admin_passkey(
        &self,
        admin_id: &str,
        credential_id: &str,
    ) -> Result<bool, AgentSecError> {
        let changed = self
            .conn
            .execute(
                "DELETE FROM webauthn_credentials WHERE credential_id = ?1 AND admin_id = ?2",
                libsql::params![credential_id, admin_id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to delete admin passkey: {e}")))?;
        Ok(changed > 0)
    }

    /// Count passkeys for an admin (used to prevent deleting last one).
    pub async fn count_admin_passkeys(&self, admin_id: &str) -> Result<i64, AgentSecError> {
        let mut rows = self
            .conn
            .query(
                "SELECT COUNT(*) FROM webauthn_credentials WHERE admin_id = ?1",
                libsql::params![admin_id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to count admin passkeys: {e}")))?;
        match rows.next().await {
            Ok(Some(row)) => row
                .get::<i64>(0)
                .map_err(|e| AgentSecError::Config(format!("Failed to count admin passkeys: {e}"))),
            _ => Ok(0),
        }
    }

    /// List all admin passkeys across all admins (for loading at startup).
    pub async fn list_all_admin_passkeys(&self) -> Result<Vec<AdminPasskeyRow>, AgentSecError> {
        let mut rows = self.conn
            .query(
                "SELECT credential_id, admin_id, public_key_json, created_at FROM webauthn_credentials ORDER BY created_at",
                (),
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to list all admin passkeys: {e}")))?;
        let mut results = Vec::new();
        while let Some(row) = rows
            .next()
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to list all admin passkeys: {e}")))?
        {
            results.push(AdminPasskeyRow {
                credential_id: row.get::<String>(0).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list all admin passkeys: {e}"))
                })?,
                admin_id: row.get::<String>(1).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list all admin passkeys: {e}"))
                })?,
                public_key_json: row.get::<String>(2).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list all admin passkeys: {e}"))
                })?,
                created_at: row.get::<String>(3).map_err(|e| {
                    AgentSecError::Config(format!("Failed to list all admin passkeys: {e}"))
                })?,
            });
        }
        Ok(results)
    }

    // -----------------------------------------------------------------------
    // Whitelist (managed hosting MVP)
    // -----------------------------------------------------------------------

    /// Add an email to the whitelist (or update its tier if already present).
    pub async fn add_to_whitelist(&self, email: &str, tier: &str) -> Result<(), AgentSecError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT OR REPLACE INTO whitelist (email, tier, created_at) VALUES (?1, ?2, ?3)",
                libsql::params![email, tier, now],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to add to whitelist: {e}")))?;
        Ok(())
    }

    /// Remove an email from the whitelist.
    pub async fn remove_from_whitelist(&self, email: &str) -> Result<(), AgentSecError> {
        self.conn
            .execute(
                "DELETE FROM whitelist WHERE email = ?1",
                libsql::params![email],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to remove from whitelist: {e}")))?;
        Ok(())
    }

    /// Look up a whitelisted email. Returns `Some((email, tier))` if found.
    pub async fn get_whitelist_entry(
        &self,
        email: &str,
    ) -> Result<Option<(String, String)>, AgentSecError> {
        let mut rows = self
            .conn
            .query(
                "SELECT email, tier FROM whitelist WHERE email = ?1",
                libsql::params![email],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to query whitelist: {e}")))?;
        match rows.next().await {
            Ok(Some(row)) => Ok(Some((
                row.get::<String>(0).map_err(|e| {
                    AgentSecError::Config(format!("Failed to query whitelist: {e}"))
                })?,
                row.get::<String>(1).map_err(|e| {
                    AgentSecError::Config(format!("Failed to query whitelist: {e}"))
                })?,
            ))),
            Ok(None) => Ok(None),
            Err(e) => Err(AgentSecError::Config(format!(
                "Failed to query whitelist: {e}"
            ))),
        }
    }

    /// List all whitelisted emails (newest first).
    pub async fn list_whitelist(&self) -> Result<Vec<(String, String)>, AgentSecError> {
        let mut rows = self
            .conn
            .query(
                "SELECT email, tier FROM whitelist ORDER BY created_at DESC",
                (),
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to list whitelist: {e}")))?;
        let mut results = Vec::new();
        while let Some(row) = rows
            .next()
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to list whitelist: {e}")))?
        {
            results.push((
                row.get::<String>(0)
                    .map_err(|e| AgentSecError::Config(format!("Failed to list whitelist: {e}")))?,
                row.get::<String>(1)
                    .map_err(|e| AgentSecError::Config(format!("Failed to list whitelist: {e}")))?,
            ));
        }
        Ok(results)
    }

    // -- Audit log ------------------------------------------------------------

    pub async fn write_audit_entry(
        &self,
        entry: &crate::types::AuditEntry,
    ) -> Result<(), AgentSecError> {
        let cred_names_json = serde_json::to_string(&entry.credential_names).map_err(|e| {
            AgentSecError::Config(format!("Failed to serialize credential_names: {e}"))
        })?;
        let method_str = serde_json::to_string(&entry.method)
            .map_err(|e| AgentSecError::Config(format!("Failed to serialize method: {e}")))?;
        // Strip quotes from serde serialized string (e.g. "\"GET\"" -> "GET")
        let method_str = method_str.trim_matches('"');
        let approval_str = entry.approval_status.as_ref().map(|s| {
            let j = serde_json::to_string(s).unwrap_or_default();
            j.trim_matches('"').to_string()
        });
        let timestamp = entry.timestamp.to_rfc3339();

        self.conn
            .execute(
                "INSERT OR REPLACE INTO audit_log (request_id, agent_id, credential_names, target_url, method, approval_status, upstream_status, total_latency_ms, approval_latency_ms, upstream_latency_ms, response_sanitized, timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                libsql::params![
                    entry.request_id.to_string(),
                    entry.agent_id.clone(),
                    cred_names_json,
                    entry.target_url.clone(),
                    method_str,
                    approval_str,
                    entry.upstream_status.map(|s| s as i64),
                    entry.total_latency_ms as i64,
                    entry.approval_latency_ms.map(|v| v as i64),
                    entry.upstream_latency_ms.map(|v| v as i64),
                    entry.response_sanitized,
                    timestamp,
                ],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to write audit entry: {e}")))?;
        Ok(())
    }

    pub async fn read_audit_entries(
        &self,
        agent_id: &str,
        limit: usize,
    ) -> Result<Vec<crate::types::AuditEntry>, AgentSecError> {
        use crate::types::{ApprovalStatus, HttpMethod};
        use chrono::DateTime;
        use uuid::Uuid;

        let mut rows = self.conn
            .query(
                "SELECT request_id, agent_id, credential_names, target_url, method, approval_status, upstream_status, total_latency_ms, approval_latency_ms, upstream_latency_ms, response_sanitized, timestamp FROM audit_log WHERE agent_id = ?1 ORDER BY timestamp DESC LIMIT ?2",
                libsql::params![agent_id, limit as i64],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to read audit entries: {e}")))?;

        let mut entries = Vec::new();
        while let Some(row) = rows
            .next()
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to read audit row: {e}")))?
        {
            let request_id_str: String = row
                .get(0)
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let agent_id: String = row
                .get(1)
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let cred_names_json: String = row
                .get(2)
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let target_url: String = row
                .get(3)
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let method_str: String = row
                .get(4)
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let approval_str: Option<String> = row
                .get(5)
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let upstream_status: Option<i64> = row
                .get(6)
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let total_latency_ms: i64 = row
                .get(7)
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let approval_latency_ms: Option<i64> = row
                .get(8)
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let upstream_latency_ms: Option<i64> = row
                .get(9)
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let response_sanitized: bool = row
                .get(10)
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;
            let timestamp_str: String = row
                .get(11)
                .map_err(|e| AgentSecError::Config(format!("audit row: {e}")))?;

            let request_id = Uuid::parse_str(&request_id_str).unwrap_or_default();
            let credential_names: Vec<String> =
                serde_json::from_str(&cred_names_json).unwrap_or_default();
            let method = HttpMethod::parse(&method_str);
            let approval_status: Option<ApprovalStatus> =
                approval_str.and_then(|s| serde_json::from_str(&format!("\"{s}\"")).ok());
            let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now());

            entries.push(crate::types::AuditEntry {
                request_id,
                agent_id,
                credential_names,
                target_url,
                method,
                approval_status,
                upstream_status: upstream_status.map(|s| s as u16),
                total_latency_ms: total_latency_ms as u64,
                approval_latency_ms: approval_latency_ms.map(|v| v as u64),
                upstream_latency_ms: upstream_latency_ms.map(|v| v as u64),
                response_sanitized,
                timestamp,
            });
        }
        // Reverse to chronological order (query was DESC)
        entries.reverse();
        Ok(entries)
    }

    pub async fn record_pending_approval(
        &self,
        request: &crate::types::ProxyRequest,
    ) -> Result<(), AgentSecError> {
        let credential_names = request
            .placeholders
            .iter()
            .map(|p| p.credential_name.clone())
            .collect();
        let entry = crate::types::AuditEntry {
            request_id: request.id,
            agent_id: request.agent_id.clone(),
            credential_names,
            target_url: request.target_url.clone(),
            method: request.method.clone(),
            approval_status: Some(crate::types::ApprovalStatus::Pending),
            upstream_status: None,
            total_latency_ms: 0,
            approval_latency_ms: None,
            upstream_latency_ms: None,
            response_sanitized: false,
            timestamp: request.received_at,
        };
        self.write_audit_entry(&entry).await
    }

    pub async fn set_approval_status(
        &self,
        request_id: &str,
        status: crate::types::ApprovalStatus,
    ) -> Result<(), AgentSecError> {
        let status_str = serde_json::to_string(&status)
            .map_err(|e| AgentSecError::Config(format!("Failed to serialize approval status: {e}")))?
            .trim_matches('"')
            .to_string();

        self.conn
            .execute(
                "UPDATE audit_log SET approval_status = ?1 WHERE request_id = ?2",
                libsql::params![status_str, request_id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to update approval status: {e}")))?;
        Ok(())
    }

    pub async fn get_approval_status(
        &self,
        request_id: &str,
    ) -> Result<Option<crate::types::ApprovalStatus>, AgentSecError> {
        let mut rows = self
            .conn
            .query(
                "SELECT approval_status FROM audit_log WHERE request_id = ?1 LIMIT 1",
                libsql::params![request_id],
            )
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to read approval status: {e}")))?;

        let Some(row) = rows
            .next()
            .await
            .map_err(|e| AgentSecError::Config(format!("Failed to read approval status: {e}")))? else {
            return Ok(None);
        };

        let approval_str: Option<String> = row
            .get(0)
            .map_err(|e| AgentSecError::Config(format!("Failed to read approval status: {e}")))?;

        Ok(approval_str.and_then(|s| serde_json::from_str(&format!("\"{s}\"")).ok()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        key
    }

    async fn test_store() -> ConfigStore {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        // Keep the file alive by leaking it (test only)
        std::mem::forget(tmp);
        ConfigStore::new(&path, None, test_key()).await.unwrap()
    }

    #[tokio::test]
    async fn test_create_and_get_credential() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();
        store
            .create_credential(
                "team-1",
                "slack",
                "Slack bot",
                "direct",
                Some("https://slack.com"),
                false,
                None,
                None,
            )
            .await
            .unwrap();

        let cred = store
            .get_credential("team-1", "slack")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cred.name, "slack");
        assert_eq!(cred.team_id, "team-1");
        assert_eq!(cred.description, "Slack bot");
        assert_eq!(cred.connector, "direct");
        assert_eq!(cred.api_base.as_deref(), Some("https://slack.com"));
    }

    #[tokio::test]
    async fn test_record_pending_and_update_approval_status() {
        let store = test_store().await;
        let request = crate::types::ProxyRequest {
            id: uuid::Uuid::new_v4(),
            agent_id: "agent-1".to_string(),
            target_url: "https://example.com/send".to_string(),
            method: crate::types::HttpMethod::Post,
            headers: vec![],
            body: None,
            content_type: None,
            placeholders: vec![],
            received_at: chrono::Utc::now(),
        };

        store.record_pending_approval(&request).await.unwrap();
        assert_eq!(
            store.get_approval_status(&request.id.to_string()).await.unwrap(),
            Some(crate::types::ApprovalStatus::Pending)
        );

        store
            .set_approval_status(&request.id.to_string(), crate::types::ApprovalStatus::Approved)
            .await
            .unwrap();
        assert_eq!(
            store.get_approval_status(&request.id.to_string()).await.unwrap(),
            Some(crate::types::ApprovalStatus::Approved)
        );
    }

    #[tokio::test]
    async fn test_create_and_get_agent() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();
        store
            .create_agent("team-1", "bot-1", Some("Test bot"), "hash123", Some(100))
            .await
            .unwrap();

        let agent = store.get_agent("team-1", "bot-1").await.unwrap().unwrap();
        assert_eq!(agent.id, "bot-1");
        assert_eq!(agent.team_id, "team-1");
        assert_eq!(agent.description.as_deref(), Some("Test bot"));
        assert!(agent.enabled);
        assert_eq!(agent.rate_limit_per_hour, Some(100));
    }

    #[tokio::test]
    async fn test_create_role_and_assign_to_agent() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();

        // Create credentials
        store
            .create_credential(
                "team-1", "slack", "Slack", "direct", None, false, None, None,
            )
            .await
            .unwrap();
        store
            .create_credential(
                "team-1", "notion", "Notion", "direct", None, false, None, None,
            )
            .await
            .unwrap();

        // Create role with credentials
        store
            .create_role("team-1", "marketing", Some("Marketing team"), Some(200))
            .await
            .unwrap();
        store
            .add_credential_to_role("team-1", "marketing", "slack")
            .await
            .unwrap();
        store
            .add_credential_to_role("team-1", "marketing", "notion")
            .await
            .unwrap();

        // Create agent and assign role
        store
            .create_agent("team-1", "mkt-bot", None, "hash456", None)
            .await
            .unwrap();
        store
            .assign_role_to_agent("team-1", "mkt-bot", "marketing")
            .await
            .unwrap();

        // Verify effective credentials
        let creds = store
            .get_agent_effective_credentials("team-1", "mkt-bot")
            .await
            .unwrap();
        assert!(creds.contains("slack"));
        assert!(creds.contains("notion"));
        assert_eq!(creds.len(), 2);
    }

    #[tokio::test]
    async fn test_effective_credentials_union() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();

        // Create credentials
        store
            .create_credential(
                "team-1", "slack", "Slack", "direct", None, false, None, None,
            )
            .await
            .unwrap();
        store
            .create_credential("team-1", "exa", "Exa", "direct", None, false, None, None)
            .await
            .unwrap();
        store
            .create_credential(
                "team-1", "mercury", "Mercury", "direct", None, false, None, None,
            )
            .await
            .unwrap();

        // Role gives slack + exa
        store
            .create_role("team-1", "team", None, None)
            .await
            .unwrap();
        store
            .add_credential_to_role("team-1", "team", "slack")
            .await
            .unwrap();
        store
            .add_credential_to_role("team-1", "team", "exa")
            .await
            .unwrap();

        // Agent gets role + direct mercury
        store
            .create_agent("team-1", "bot", None, "hash", None)
            .await
            .unwrap();
        store
            .assign_role_to_agent("team-1", "bot", "team")
            .await
            .unwrap();
        store
            .add_direct_credential("team-1", "bot", "mercury")
            .await
            .unwrap();

        // Union should be all three
        let creds = store
            .get_agent_effective_credentials("team-1", "bot")
            .await
            .unwrap();
        assert_eq!(creds.len(), 3);
        assert!(creds.contains("slack"));
        assert!(creds.contains("exa"));
        assert!(creds.contains("mercury"));
    }

    #[tokio::test]
    async fn test_credential_encryption_roundtrip() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();
        store
            .create_credential(
                "team-1",
                "secret",
                "Secret API",
                "direct",
                None,
                false,
                None,
                None,
            )
            .await
            .unwrap();

        let plaintext = b"super-secret-api-key-12345";
        store
            .set_credential_value("team-1", "secret", plaintext)
            .await
            .unwrap();

        let decrypted = store
            .get_credential_value("team-1", "secret")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_agent_enable_disable() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();
        store
            .create_agent("team-1", "bot", None, "hash", None)
            .await
            .unwrap();

        // Starts enabled
        let agent = store.get_agent("team-1", "bot").await.unwrap().unwrap();
        assert!(agent.enabled);

        // Disable
        store.disable_agent("team-1", "bot").await.unwrap();
        let agent = store.get_agent("team-1", "bot").await.unwrap().unwrap();
        assert!(!agent.enabled);

        // Authenticate returns the agent even when disabled (caller checks enabled)
        let auth = store.authenticate_agent("hash").await.unwrap();
        assert!(auth.is_some());
        assert!(!auth.unwrap().enabled);

        // Re-enable
        store.enable_agent("team-1", "bot").await.unwrap();
        let auth = store.authenticate_agent("hash").await.unwrap();
        assert!(auth.is_some());
        assert!(auth.unwrap().enabled);
    }

    #[tokio::test]
    async fn test_delete_role_cascades() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();

        store
            .create_credential(
                "team-1", "slack", "Slack", "direct", None, false, None, None,
            )
            .await
            .unwrap();
        store
            .create_role("team-1", "team", None, None)
            .await
            .unwrap();
        store
            .add_credential_to_role("team-1", "team", "slack")
            .await
            .unwrap();

        store
            .create_agent("team-1", "bot", None, "hash", None)
            .await
            .unwrap();
        store
            .assign_role_to_agent("team-1", "bot", "team")
            .await
            .unwrap();

        // Before delete: bot has slack via role
        let creds = store
            .get_agent_effective_credentials("team-1", "bot")
            .await
            .unwrap();
        assert!(creds.contains("slack"));

        // Delete role -- cascades to agent_roles and role_credentials
        store.delete_role("team-1", "team").await.unwrap();

        // After delete: bot has nothing
        let creds = store
            .get_agent_effective_credentials("team-1", "bot")
            .await
            .unwrap();
        assert!(creds.is_empty());
    }

    #[tokio::test]
    async fn test_policy_crud() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();
        store
            .create_credential(
                "team-1", "slack", "Slack", "direct", None, false, None, None,
            )
            .await
            .unwrap();

        let policy = PolicyRow {
            credential_name: "slack".to_string(),
            team_id: "team-1".to_string(),
            auto_approve_methods: vec!["GET".to_string()],
            require_approval_methods: vec!["POST".to_string(), "DELETE".to_string()],
            auto_approve_urls: vec!["/v1/search".to_string()],
            allowed_approvers: vec!["user123".to_string()],
            telegram_chat_id: Some("-12345".to_string()),
            require_passkey: true,
        };

        store.set_policy(&policy).await.unwrap();

        let fetched = store.get_policy("team-1", "slack").await.unwrap().unwrap();
        assert_eq!(fetched.team_id, "team-1");
        assert_eq!(fetched.auto_approve_methods, vec!["GET"]);
        assert_eq!(fetched.require_approval_methods, vec!["POST", "DELETE"]);
        assert_eq!(fetched.auto_approve_urls, vec!["/v1/search"]);
        assert_eq!(fetched.allowed_approvers, vec!["user123"]);
        assert_eq!(fetched.telegram_chat_id.as_deref(), Some("-12345"));
        assert!(fetched.require_passkey);
    }

    #[tokio::test]
    async fn test_admin_flag() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();

        // Regular agent
        store
            .create_agent("team-1", "bot", None, "hash1", None)
            .await
            .unwrap();
        let agent = store.get_agent("team-1", "bot").await.unwrap().unwrap();
        assert!(!agent.is_admin);

        // Admin agent
        store
            .create_admin_agent("team-1", "admin", Some("Admin user"), "hash2")
            .await
            .unwrap();
        let admin = store.get_agent("team-1", "admin").await.unwrap().unwrap();
        assert!(admin.is_admin);
        assert_eq!(admin.team_id, "team-1");

        // Auth returns is_admin flag and team_id
        let authed = store.authenticate_agent("hash2").await.unwrap().unwrap();
        assert!(authed.is_admin);
        assert_eq!(authed.id, "admin");
        assert_eq!(authed.team_id, "team-1");
    }

    #[tokio::test]
    async fn test_authenticate_agent() {
        let store = test_store().await;
        store.create_team("team-1", "test-team").await.unwrap();
        store
            .create_agent("team-1", "bot", None, "correct-hash", None)
            .await
            .unwrap();

        // Correct hash
        let agent = store.authenticate_agent("correct-hash").await.unwrap();
        assert!(agent.is_some());
        let agent = agent.unwrap();
        assert_eq!(agent.id, "bot");
        assert_eq!(agent.team_id, "team-1");

        // Wrong hash
        let agent = store.authenticate_agent("wrong-hash").await.unwrap();
        assert!(agent.is_none());
    }

    #[tokio::test]
    async fn test_notification_channel_crud() {
        let store = test_store().await;
        store.create_team("t1", "test-team").await.unwrap();

        // Create a telegram channel
        let config = r#"{"chat_id": "-100123"}"#;
        let id = store
            .create_notification_channel("t1", "telegram", "approvals", config)
            .await
            .unwrap();
        assert!(!id.is_empty());

        // Get by name
        let channel = store
            .get_notification_channel("t1", "approvals")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(channel.channel_type, "telegram");
        assert_eq!(channel.name, "approvals");
        assert_eq!(channel.config_json, config);
        assert!(channel.enabled);

        // List
        let channels = store.list_notification_channels("t1").await.unwrap();
        assert_eq!(channels.len(), 1);

        // Delete
        store
            .delete_notification_channel("t1", "approvals")
            .await
            .unwrap();
        let channels = store.list_notification_channels("t1").await.unwrap();
        assert_eq!(channels.len(), 0);

        // Delete nonexistent fails
        let result = store.delete_notification_channel("t1", "nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_notification_channel_unique_name() {
        let store = test_store().await;
        store.create_team("t1", "test-team").await.unwrap();

        let config = r#"{"chat_id": "-100123"}"#;
        store
            .create_notification_channel("t1", "telegram", "main", config)
            .await
            .unwrap();

        // Same name should fail
        let result = store
            .create_notification_channel("t1", "telegram", "main", config)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_default_telegram_chat_id() {
        let store = test_store().await;
        store.create_team("t1", "test-team").await.unwrap();

        // No channels -> None
        let chat_id = store.get_default_telegram_chat_id("t1").await.unwrap();
        assert!(chat_id.is_none());

        // Create telegram channel
        store
            .create_notification_channel("t1", "telegram", "main", r#"{"chat_id": "-999"}"#)
            .await
            .unwrap();

        let chat_id = store.get_default_telegram_chat_id("t1").await.unwrap();
        assert_eq!(chat_id.as_deref(), Some("-999"));

        // Different team has no channels
        store.create_team("t2", "other-team").await.unwrap();
        let chat_id = store.get_default_telegram_chat_id("t2").await.unwrap();
        assert!(chat_id.is_none());
    }

    #[tokio::test]
    async fn test_approver_passkey_save_and_list() {
        let store = test_store().await;

        // Empty initially
        let rows = store.list_all_approver_passkeys().await.unwrap();
        assert!(rows.is_empty());

        // Save two passkeys for different approvers
        store
            .save_approver_passkey("cred-1", "alice", "Alice Smith", r#"{"key":"pk1"}"#)
            .await
            .unwrap();
        store
            .save_approver_passkey("cred-2", "bob", "Bob Jones", r#"{"key":"pk2"}"#)
            .await
            .unwrap();

        let rows = store.list_all_approver_passkeys().await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].credential_id, "cred-1");
        assert_eq!(rows[0].approver_name, "alice");
        assert_eq!(rows[0].display_name, "Alice Smith");
        assert_eq!(rows[0].public_key_json, r#"{"key":"pk1"}"#);
        assert!(!rows[0].created_at.is_empty());
        assert_eq!(rows[1].credential_id, "cred-2");
        assert_eq!(rows[1].approver_name, "bob");
    }

    #[tokio::test]
    async fn test_approver_passkey_duplicate_credential_id_rejected() {
        let store = test_store().await;
        store
            .save_approver_passkey("cred-1", "alice", "Alice", r#"{"k":"v"}"#)
            .await
            .unwrap();
        // Same credential_id should fail (PK constraint)
        let result = store
            .save_approver_passkey("cred-1", "bob", "Bob", r#"{"k":"v2"}"#)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_approver_passkey_multiple_per_user() {
        let store = test_store().await;
        // One approver can have multiple passkeys (e.g., phone + YubiKey)
        store
            .save_approver_passkey("cred-a", "alice", "Alice", r#"{"device":"phone"}"#)
            .await
            .unwrap();
        store
            .save_approver_passkey("cred-b", "alice", "Alice", r#"{"device":"yubikey"}"#)
            .await
            .unwrap();

        let rows = store.list_all_approver_passkeys().await.unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.approver_name == "alice"));
    }
}
