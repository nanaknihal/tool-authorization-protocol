//! Telegram-specific configuration.

use agentsec_core::error::AgentSecError;

#[derive(Debug, Clone)]
pub struct TelegramConfig {
    pub bot_token: String,
    pub chat_id: String,
}

impl TelegramConfig {
    /// Load Telegram config from environment variables.
    pub fn from_env() -> Result<Self, AgentSecError> {
        let bot_token = std::env::var("TELEGRAM_BOT_TOKEN").map_err(|_| {
            AgentSecError::Config("Missing TELEGRAM_BOT_TOKEN environment variable".to_string())
        })?;

        if bot_token.is_empty() {
            return Err(AgentSecError::Config(
                "TELEGRAM_BOT_TOKEN must not be empty".to_string(),
            ));
        }

        let chat_id = std::env::var("TELEGRAM_CHAT_ID").map_err(|_| {
            AgentSecError::Config("Missing TELEGRAM_CHAT_ID environment variable".to_string())
        })?;

        if chat_id.is_empty() {
            return Err(AgentSecError::Config(
                "TELEGRAM_CHAT_ID must not be empty".to_string(),
            ));
        }

        Ok(Self { bot_token, chat_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Use a serial test approach by modifying env vars carefully
    fn with_env_vars<F: FnOnce()>(vars: &[(&str, Option<&str>)], f: F) {
        let originals: Vec<(&str, Option<String>)> = vars
            .iter()
            .map(|(k, _)| (*k, std::env::var(k).ok()))
            .collect();

        for (k, v) in vars {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }

        f();

        for (k, orig) in originals {
            match orig {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }

    #[test]
    fn config_from_env_valid() {
        with_env_vars(
            &[
                ("TELEGRAM_BOT_TOKEN", Some("123:ABC")),
                ("TELEGRAM_CHAT_ID", Some("-100123")),
            ],
            || {
                let config = TelegramConfig::from_env().unwrap();
                assert_eq!(config.bot_token, "123:ABC");
                assert_eq!(config.chat_id, "-100123");
            },
        );
    }

    #[test]
    fn config_missing_bot_token() {
        with_env_vars(
            &[
                ("TELEGRAM_BOT_TOKEN", None),
                ("TELEGRAM_CHAT_ID", Some("-100123")),
            ],
            || {
                let err = TelegramConfig::from_env().unwrap_err();
                assert!(err.to_string().contains("TELEGRAM_BOT_TOKEN"));
            },
        );
    }

    #[test]
    fn config_missing_chat_id() {
        with_env_vars(
            &[
                ("TELEGRAM_BOT_TOKEN", Some("123:ABC")),
                ("TELEGRAM_CHAT_ID", None),
            ],
            || {
                let err = TelegramConfig::from_env().unwrap_err();
                assert!(err.to_string().contains("TELEGRAM_CHAT_ID"));
            },
        );
    }

    #[test]
    fn config_empty_bot_token_rejected() {
        with_env_vars(
            &[
                ("TELEGRAM_BOT_TOKEN", Some("")),
                ("TELEGRAM_CHAT_ID", Some("-100123")),
            ],
            || {
                let err = TelegramConfig::from_env().unwrap_err();
                assert!(err.to_string().contains("TELEGRAM_BOT_TOKEN"));
            },
        );
    }
}
