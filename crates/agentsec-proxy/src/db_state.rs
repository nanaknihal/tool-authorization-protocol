//! Database-backed state for AgentSec proxy (v0.2).
//!
//! Wraps ConfigStore with an in-memory cache for hot-reload. The proxy checks
//! the cache first; on miss or TTL expiry, queries SQLite. Admin writes go
//! directly to the DB — the proxy picks up changes within the cache TTL.
//!
//! All caches are team-scoped: keys are (team_id, entity_name) tuples.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use agentsec_core::config::{ApprovalRouting, ConnectorType, CredentialConfig, PolicyConfig};
use agentsec_core::error::AgentSecError;
use agentsec_core::store::{AgentRow, ConfigStore, CredentialRow, PolicyRow};
use tokio::sync::RwLock;

/// Cached agent data.
struct CachedAgent {
    row: AgentRow,
    effective_credentials: HashSet<String>,
    fetched_at: Instant,
}

/// Cached credential data.
struct CachedCredential {
    row: CredentialRow,
    fetched_at: Instant,
}

/// Cached telegram chat_id lookup.
struct CachedTelegramChatId {
    chat_id: Option<String>,
    fetched_at: Instant,
}

/// Cached policy lookup. Stores Option so "no policy" is also cached.
struct CachedPolicy {
    row: Option<PolicyRow>,
    fetched_at: Instant,
}

/// Database-backed config with per-entity caching.
pub struct DbState {
    store: ConfigStore,
    /// Cache: (team_id, agent_id) → CachedAgent
    agent_cache: RwLock<HashMap<(String, String), CachedAgent>>,
    /// Cache: api_key_hash → Option<(team_id, agent_id)>
    auth_cache: RwLock<HashMap<String, Option<(String, String)>>>,
    /// Cache: (team_id, cred_name) → CachedCredential
    credential_cache: RwLock<HashMap<(String, String), CachedCredential>>,
    /// Cache: (team_id, cred_name) → CachedPolicy (with TTL)
    policy_cache: RwLock<HashMap<(String, String), CachedPolicy>>,
    /// Cache: team_id → default telegram chat_id
    telegram_chat_id_cache: RwLock<HashMap<String, CachedTelegramChatId>>,
    cache_ttl: Duration,
}

impl DbState {
    pub fn new(store: ConfigStore, cache_ttl: Duration) -> Self {
        Self {
            store,
            agent_cache: RwLock::new(HashMap::new()),
            auth_cache: RwLock::new(HashMap::new()),
            credential_cache: RwLock::new(HashMap::new()),
            policy_cache: RwLock::new(HashMap::new()),
            telegram_chat_id_cache: RwLock::new(HashMap::new()),
            cache_ttl,
        }
    }

    /// Authenticate an agent by API key hash. Global lookup (no team_id needed).
    /// Returns the full AgentRow including team_id if found.
    pub async fn authenticate(
        &self,
        api_key_hash: &str,
    ) -> Result<Option<AgentRow>, AgentSecError> {
        // Check auth cache
        {
            let cache = self.auth_cache.read().await;
            if let Some(cached) = cache.get(api_key_hash) {
                if let Some((team_id, agent_id)) = cached {
                    let agent_cache = self.agent_cache.read().await;
                    let key = (team_id.clone(), agent_id.clone());
                    if let Some(cached_agent) = agent_cache.get(&key) {
                        if cached_agent.fetched_at.elapsed() < self.cache_ttl {
                            return Ok(Some(cached_agent.row.clone()));
                        }
                    }
                } else {
                    return Ok(None); // Cached as "not found"
                }
            }
        }

        // Cache miss — query DB
        let result = self.store.authenticate_agent(api_key_hash).await?;

        // Update caches
        let mut auth_cache = self.auth_cache.write().await;
        match &result {
            Some(agent) => {
                auth_cache.insert(
                    api_key_hash.to_string(),
                    Some((agent.team_id.clone(), agent.id.clone())),
                );
                let effective = self
                    .store
                    .get_agent_effective_credentials(&agent.team_id, &agent.id)
                    .await?;
                let mut agent_cache = self.agent_cache.write().await;
                agent_cache.insert(
                    (agent.team_id.clone(), agent.id.clone()),
                    CachedAgent {
                        row: agent.clone(),
                        effective_credentials: effective,
                        fetched_at: Instant::now(),
                    },
                );
            }
            None => {
                auth_cache.insert(api_key_hash.to_string(), None);
            }
        }

        Ok(result)
    }

    /// Get the effective credential set for an agent.
    pub async fn get_effective_credentials(
        &self,
        team_id: &str,
        agent_id: &str,
    ) -> Result<HashSet<String>, AgentSecError> {
        let key = (team_id.to_string(), agent_id.to_string());
        // Check cache
        {
            let cache = self.agent_cache.read().await;
            if let Some(cached) = cache.get(&key) {
                if cached.fetched_at.elapsed() < self.cache_ttl {
                    return Ok(cached.effective_credentials.clone());
                }
            }
        }

        // Cache miss
        let creds = self
            .store
            .get_agent_effective_credentials(team_id, agent_id)
            .await?;

        // Update cache
        if let Ok(Some(row)) = self.store.get_agent(team_id, agent_id).await {
            let mut cache = self.agent_cache.write().await;
            cache.insert(
                key,
                CachedAgent {
                    row,
                    effective_credentials: creds.clone(),
                    fetched_at: Instant::now(),
                },
            );
        }

        Ok(creds)
    }

    /// Get a credential config (converted from DB row to the config type the proxy expects).
    pub async fn get_credential(
        &self,
        team_id: &str,
        name: &str,
    ) -> Result<Option<CredentialConfig>, AgentSecError> {
        let key = (team_id.to_string(), name.to_string());
        // Check cache
        {
            let cache = self.credential_cache.read().await;
            if let Some(cached) = cache.get(&key) {
                if cached.fetched_at.elapsed() < self.cache_ttl {
                    return Ok(Some(row_to_credential_config(&cached.row)));
                }
            }
        }

        // Cache miss
        let row = self.store.get_credential(team_id, name).await?;
        if let Some(ref row) = row {
            let mut cache = self.credential_cache.write().await;
            cache.insert(
                key,
                CachedCredential {
                    row: row.clone(),
                    fetched_at: Instant::now(),
                },
            );
        }

        Ok(row.map(|r| row_to_credential_config(&r)))
    }

    /// Get decrypted credential value (internal only — never expose via any API).
    pub async fn get_credential_value(
        &self,
        team_id: &str,
        name: &str,
    ) -> Result<Option<String>, AgentSecError> {
        match self.store.get_credential_value(team_id, name).await? {
            Some(bytes) => Ok(Some(String::from_utf8(bytes).map_err(|e| {
                AgentSecError::Config(format!("Credential value not UTF-8: {e}"))
            })?)),
            None => Ok(None),
        }
    }

    /// Get policy for a credential.
    pub async fn get_policy(
        &self,
        team_id: &str,
        credential_name: &str,
    ) -> Result<Option<PolicyConfig>, AgentSecError> {
        let key = (team_id.to_string(), credential_name.to_string());
        // Check cache (with TTL — policies can change via the admin API)
        {
            let cache = self.policy_cache.read().await;
            if let Some(cached) = cache.get(&key) {
                if cached.fetched_at.elapsed() < self.cache_ttl {
                    return Ok(cached.row.as_ref().map(row_to_policy_config));
                }
            }
        }

        // Cache miss or expired
        let row = self.store.get_policy(team_id, credential_name).await?;
        {
            let mut cache = self.policy_cache.write().await;
            cache.insert(
                key,
                CachedPolicy {
                    row: row.clone(),
                    fetched_at: Instant::now(),
                },
            );
        }

        Ok(row.map(|r| row_to_policy_config(&r)))
    }

    /// Invalidate the cached policy for a credential. Called by admin endpoints
    /// after writing a policy so the proxy picks up the change immediately.
    pub async fn invalidate_policy_cache(&self, team_id: &str, credential_name: &str) {
        let key = (team_id.to_string(), credential_name.to_string());
        let mut cache = self.policy_cache.write().await;
        cache.remove(&key);
    }

    /// Get agent rate limit.
    pub async fn get_agent_rate_limit(
        &self,
        team_id: &str,
        agent_id: &str,
    ) -> Result<Option<u64>, AgentSecError> {
        let key = (team_id.to_string(), agent_id.to_string());
        let cache = self.agent_cache.read().await;
        if let Some(cached) = cache.get(&key) {
            if cached.fetched_at.elapsed() < self.cache_ttl {
                return Ok(cached.row.rate_limit_per_hour.map(|r| r as u64));
            }
        }
        drop(cache);

        match self.store.get_agent(team_id, agent_id).await? {
            Some(row) => Ok(row.rate_limit_per_hour.map(|r| r as u64)),
            None => Ok(None),
        }
    }

    /// List all credentials for a team.
    pub async fn list_credentials(
        &self,
        team_id: &str,
    ) -> Result<Vec<(String, CredentialConfig)>, AgentSecError> {
        let rows = self.store.list_credentials(team_id).await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let name = r.name.clone();
                (name, row_to_credential_config(&r))
            })
            .collect())
    }

    /// Check if an agent can access a specific team (either home team or linked).
    /// Returns the effective credential set for the agent in that team.
    /// Returns None if the agent is not linked to the target team.
    pub async fn get_agent_credentials_in_team(
        &self,
        agent_home_team_id: &str,
        agent_id: &str,
        target_team_id: &str,
    ) -> Result<Option<HashSet<String>>, AgentSecError> {
        if agent_home_team_id == target_team_id {
            // Home team — use normal credential resolution
            Ok(Some(
                self.get_effective_credentials(agent_home_team_id, agent_id)
                    .await?,
            ))
        } else {
            // Cross-team — check link exists and get linked credentials
            let linked_creds = self
                .store
                .get_agent_linked_credentials(agent_home_team_id, agent_id, target_team_id)
                .await?;
            if linked_creds.is_empty() {
                // Check if link exists at all (link may exist but grant zero credentials)
                if self
                    .store
                    .is_agent_linked_to_team(agent_home_team_id, agent_id, target_team_id)
                    .await?
                {
                    Ok(Some(linked_creds)) // linked but no credentials assigned
                } else {
                    Ok(None) // not linked
                }
            } else {
                Ok(Some(linked_creds))
            }
        }
    }

    /// Get the default Telegram chat_id for a team from notification_channels.
    pub async fn get_default_telegram_chat_id(
        &self,
        team_id: &str,
    ) -> Result<Option<String>, AgentSecError> {
        // Check cache
        {
            let cache = self.telegram_chat_id_cache.read().await;
            if let Some(cached) = cache.get(team_id) {
                if cached.fetched_at.elapsed() < self.cache_ttl {
                    return Ok(cached.chat_id.clone());
                }
            }
        }

        // Cache miss
        let chat_id = self.store.get_default_telegram_chat_id(team_id).await?;
        {
            let mut cache = self.telegram_chat_id_cache.write().await;
            cache.insert(
                team_id.to_string(),
                CachedTelegramChatId {
                    chat_id: chat_id.clone(),
                    fetched_at: Instant::now(),
                },
            );
        }
        Ok(chat_id)
    }

    /// Get the underlying store (for admin operations that bypass cache).
    pub fn store(&self) -> &ConfigStore {
        &self.store
    }
}

/// Convert a DB credential row to the config type the proxy uses.
fn row_to_credential_config(row: &CredentialRow) -> CredentialConfig {
    let auth_bindings = row
        .auth_bindings_json
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default();

    CredentialConfig {
        description: row.description.clone(),
        api_base: row.api_base.clone(),
        substitution: Default::default(),
        connector: match row.connector.as_str() {
            "sidecar" => ConnectorType::Sidecar,
            _ => ConnectorType::Direct,
        },
        relative_target: row.relative_target,
        auth_header_format: row.auth_header_format.clone(),
        auth_bindings,
    }
}

/// Convert a DB policy row to the config type the proxy uses.
fn row_to_policy_config(row: &PolicyRow) -> PolicyConfig {
    PolicyConfig {
        auto_approve: row.auto_approve_methods.clone(),
        require_approval: row.require_approval_methods.clone(),
        auto_approve_urls: row.auto_approve_urls.clone(),
        approval: if row.allowed_approvers.is_empty()
            && row.telegram_chat_id.is_none()
            && !row.require_passkey
        {
            None
        } else {
            Some(ApprovalRouting {
                allowed_approvers: row.allowed_approvers.clone(),
                require_passkey: row.require_passkey,
                telegram: row.telegram_chat_id.as_ref().map(|id| {
                    agentsec_core::config::TelegramRouting {
                        chat_id: Some(id.clone()),
                    }
                }),
                slack: None,
                mobile: None,
            })
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentsec_core::store::PolicyRow;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        key
    }

    async fn test_db_state() -> DbState {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        std::mem::forget(tmp);
        let store = ConfigStore::new(&path, None, test_key()).await.unwrap();
        // Create a default team for tests
        store.create_team("t1", "test-team").await.unwrap();
        DbState::new(store, Duration::from_secs(30))
    }

    #[tokio::test]
    async fn test_authenticate_caches() {
        let db = test_db_state().await;
        db.store()
            .create_agent("t1", "bot", None, "hash123", Some(100))
            .await
            .unwrap();

        let agent = db.authenticate("hash123").await.unwrap().unwrap();
        assert_eq!(agent.id, "bot");
        assert_eq!(agent.team_id, "t1");

        let agent2 = db.authenticate("hash123").await.unwrap().unwrap();
        assert_eq!(agent2.id, "bot");

        let none = db.authenticate("wrong").await.unwrap();
        assert!(none.is_none());
    }

    #[tokio::test]
    async fn test_effective_credentials_via_db_state() {
        let db = test_db_state().await;

        db.store()
            .create_credential("t1", "slack", "Slack", "direct", None, false, None, None)
            .await
            .unwrap();
        db.store()
            .create_credential("t1", "exa", "Exa", "direct", None, false, None, None)
            .await
            .unwrap();
        db.store()
            .create_role("t1", "team", None, None)
            .await
            .unwrap();
        db.store()
            .add_credential_to_role("t1", "team", "slack")
            .await
            .unwrap();
        db.store()
            .create_agent("t1", "bot", None, "hash", None)
            .await
            .unwrap();
        db.store()
            .assign_role_to_agent("t1", "bot", "team")
            .await
            .unwrap();
        db.store()
            .add_direct_credential("t1", "bot", "exa")
            .await
            .unwrap();

        let creds = db.get_effective_credentials("t1", "bot").await.unwrap();
        assert_eq!(creds.len(), 2);
        assert!(creds.contains("slack"));
        assert!(creds.contains("exa"));
    }

    #[tokio::test]
    async fn test_credential_and_policy_lookup() {
        let db = test_db_state().await;

        db.store()
            .create_credential(
                "t1",
                "google",
                "Google",
                "sidecar",
                Some("http://refresher:8081"),
                false,
                None,
                None,
            )
            .await
            .unwrap();

        db.store()
            .set_policy(&PolicyRow {
                credential_name: "google".to_string(),
                team_id: "t1".to_string(),
                auto_approve_methods: vec!["GET".to_string()],
                require_approval_methods: vec!["POST".to_string()],
                auto_approve_urls: vec![],
                allowed_approvers: vec!["user1".to_string()],
                telegram_chat_id: None,
                require_passkey: false,
            })
            .await
            .unwrap();

        let cred = db.get_credential("t1", "google").await.unwrap().unwrap();
        assert_eq!(cred.connector, ConnectorType::Sidecar);
        assert_eq!(cred.api_base.as_deref(), Some("http://refresher:8081"));

        let policy = db.get_policy("t1", "google").await.unwrap().unwrap();
        assert_eq!(policy.auto_approve, vec!["GET"]);
        assert_eq!(policy.require_approval, vec!["POST"]);
    }

    #[tokio::test]
    async fn test_cache_ttl_expiry() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        std::mem::forget(tmp);
        let store = ConfigStore::new(&path, None, test_key()).await.unwrap();
        store.create_team("t1", "test-team").await.unwrap();
        let db = DbState::new(store, Duration::from_secs(0));

        db.store()
            .create_credential("t1", "test", "Test", "direct", None, false, None, None)
            .await
            .unwrap();
        db.store()
            .create_agent("t1", "bot", None, "hash", None)
            .await
            .unwrap();
        db.store()
            .add_direct_credential("t1", "bot", "test")
            .await
            .unwrap();

        let creds1 = db.get_effective_credentials("t1", "bot").await.unwrap();
        assert_eq!(creds1.len(), 1);

        db.store()
            .create_credential("t1", "new", "New", "direct", None, false, None, None)
            .await
            .unwrap();
        db.store()
            .add_direct_credential("t1", "bot", "new")
            .await
            .unwrap();

        let creds2 = db.get_effective_credentials("t1", "bot").await.unwrap();
        assert_eq!(creds2.len(), 2);
        assert!(creds2.contains("new"));
    }

    #[tokio::test]
    async fn test_default_telegram_chat_id_cached() {
        let db = test_db_state().await;

        // No channels → None
        let chat_id = db.get_default_telegram_chat_id("t1").await.unwrap();
        assert!(chat_id.is_none());

        // Create channel
        db.store()
            .create_notification_channel("t1", "telegram", "main", r#"{"chat_id": "-555"}"#)
            .await
            .unwrap();

        // Cache still has None (TTL hasn't expired with 30s TTL)
        // But a fresh lookup on a new key will hit DB
        let db2 = test_db_state().await;
        db2.store()
            .create_notification_channel("t1", "telegram", "main", r#"{"chat_id": "-555"}"#)
            .await
            .unwrap();
        let chat_id = db2.get_default_telegram_chat_id("t1").await.unwrap();
        assert_eq!(chat_id.as_deref(), Some("-555"));
    }
}
