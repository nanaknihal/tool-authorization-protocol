//! Agent API key authentication.

use sha2::{Sha256, Digest};

/// Authenticated agent info.
#[derive(Debug, Clone)]
pub struct AuthenticatedAgent {
    pub id: String,
    pub team_id: String,
}

/// Deterministic SHA-256 hash for API key lookup.
pub fn hash_api_key(api_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_hash_is_deterministic() {
        let h1 = hash_api_key("my-api-key-123");
        let h2 = hash_api_key("my-api-key-123");
        assert_eq!(h1, h2);
    }

    #[test]
    fn api_key_hash_different_keys_differ() {
        let h1 = hash_api_key("key-alpha");
        let h2 = hash_api_key("key-beta");
        assert_ne!(h1, h2);
    }
}
