//! `agentsec add` — interactive credential setup.
//!
//! Collects service info and writes to the database via ConfigStore.

use std::io::{self, Write};

/// Auth method as presented to the user.
#[derive(Debug, Clone, Copy)]
pub enum AuthMethod {
    ApiKey,
    OAuth2,
    OAuth1,
    Custom,
}

/// Result of the interactive flow.
pub struct AddResult {
    pub name: String,
    pub description: String,
    pub auth_method: AuthMethod,
    pub api_base: Option<String>,
}

/// Prompt for a line of input with a label.
fn prompt(label: &str) -> String {
    print!("{label}: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

/// Prompt with a default value.
fn prompt_default(label: &str, default: &str) -> String {
    print!("{label} [{default}]: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let val = input.trim();
    if val.is_empty() {
        default.to_string()
    } else {
        val.to_string()
    }
}

/// Run the interactive add flow. Returns None if user cancels.
pub fn interactive_add() -> Option<AddResult> {
    println!("Add a new service to AgentSec");
    println!("=============================\n");

    let name = prompt("Service name (e.g., google-workspace, telegram, my-api)");
    if name.is_empty() {
        eprintln!("Name is required.");
        return None;
    }

    let description = prompt("Description (e.g., Gmail + Calendar + Drive)");
    if description.is_empty() {
        eprintln!("Description is required.");
        return None;
    }

    println!("\nHow does this service authenticate?");
    println!("  1) API key or bearer token (paste a key, works forever)");
    println!("  2) OAuth 2.0 (Google, GitHub — sign in once, auto-refreshes)");
    println!("  3) OAuth 1.0a (Twitter — signed requests)");
    println!("  4) Custom protocol (Telegram, Discord — needs a connector)");

    let choice = prompt("\nChoice [1-4]");
    let auth_method = match choice.as_str() {
        "1" => AuthMethod::ApiKey,
        "2" => AuthMethod::OAuth2,
        "3" => AuthMethod::OAuth1,
        "4" => AuthMethod::Custom,
        _ => {
            eprintln!("Invalid choice.");
            return None;
        }
    };

    let api_base = match auth_method {
        AuthMethod::ApiKey => {
            let base = prompt("API base URL (e.g., https://api.example.com)");
            if base.is_empty() { None } else { Some(base) }
        }
        AuthMethod::OAuth2 => {
            Some(prompt_default(
                "OAuth2 refresher URL",
                "http://oauth2-refresher:8081",
            ))
        }
        AuthMethod::OAuth1 => {
            Some(prompt_default(
                "OAuth 1.0a signer URL",
                "http://oauth-signer:8080",
            ))
        }
        AuthMethod::Custom => {
            let url = prompt("Connector service URL (e.g., http://telegram-client:8082)");
            if url.is_empty() {
                eprintln!("URL is required for custom connectors.");
                return None;
            }
            Some(url)
        }
    };

    Some(AddResult {
        name,
        description,
        auth_method,
        api_base,
    })
}

/// Non-interactive add from CLI flags.
pub fn from_flags(
    name: String,
    description: String,
    auth: &str,
    api_base: Option<String>,
    _relative_target: bool,
) -> Option<AddResult> {
    let auth_method = match auth {
        "api-key" | "token" | "bearer" => AuthMethod::ApiKey,
        "oauth2" => AuthMethod::OAuth2,
        "oauth1" => AuthMethod::OAuth1,
        "custom" => AuthMethod::Custom,
        _ => {
            eprintln!("Unknown auth type: {auth}. Use: api-key, oauth2, oauth1, custom");
            return None;
        }
    };

    Some(AddResult {
        name,
        description,
        auth_method,
        api_base,
    })
}

/// Print post-add instructions.
pub fn print_instructions(result: &AddResult) {
    let env_name = result
        .name
        .to_uppercase()
        .replace('-', "_");

    println!("\n✓ Service '{}' configured\n", result.name);

    match result.auth_method {
        AuthMethod::ApiKey => {
            println!("Next steps:");
            println!("  1. Set the credential value:");
            println!("     AGENTSEC_CRED_{env_name}=<your-api-key>");
            println!("  2. Assign '{}' to agents via: agentsec agent create --credentials {}", result.name, result.name);
            println!("  3. Configure policies via the admin API");
            println!("  4. Restart agentsec (or it picks up DB changes automatically)");
        }
        AuthMethod::OAuth2 => {
            println!("Next steps:");
            println!("  1. Set the passthrough marker:");
            println!("     AGENTSEC_CRED_{env_name}=oauth2-refresher-passthrough");
            println!("  2. Add OAuth2 credentials to .env.oauth2-refresher:");
            println!("     GOOGLE_CRED_{env_name}_CLIENT_ID=...");
            println!("     GOOGLE_CRED_{env_name}_CLIENT_SECRET=...");
            println!("     GOOGLE_CRED_{env_name}_REFRESH_TOKEN=...");
            println!("  3. Run the token acquisition flow if needed");
            println!("  4. Assign '{}' to agents via: agentsec agent create --credentials {}", result.name, result.name);
            println!("  5. Restart agentsec + oauth2-refresher");
        }
        AuthMethod::OAuth1 => {
            println!("Next steps:");
            println!("  1. Set the passthrough marker:");
            println!("     AGENTSEC_CRED_{env_name}=oauth-signer-passthrough");
            println!("  2. Add OAuth1 credentials to .env.oauth-signer:");
            println!("     OAUTH_CRED_{env_name}_CONSUMER_KEY=...");
            println!("     OAUTH_CRED_{env_name}_CONSUMER_SECRET=...");
            println!("     OAUTH_CRED_{env_name}_ACCESS_TOKEN=...");
            println!("     OAUTH_CRED_{env_name}_ACCESS_TOKEN_SECRET=...");
            println!("  3. Assign '{}' to agents via: agentsec agent create --credentials {}", result.name, result.name);
            println!("  4. Restart agentsec + oauth-signer");
        }
        AuthMethod::Custom => {
            println!("Next steps:");
            println!("  1. Set the passthrough marker:");
            println!("     AGENTSEC_CRED_{env_name}=<connector>-passthrough");
            println!("  2. Ensure your connector service is running at:");
            println!("     {}", result.api_base.as_deref().unwrap_or("???"));
            println!("  3. Assign '{}' to agents via: agentsec agent create --credentials {}", result.name, result.name);
            println!("  4. Restart agentsec (or it picks up DB changes automatically)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_flags_api_key() {
        let r = from_flags(
            "test".to_string(),
            "Test".to_string(),
            "api-key",
            Some("https://api.example.com".to_string()),
            false,
        )
        .unwrap();
        assert!(matches!(r.auth_method, AuthMethod::ApiKey));
        assert_eq!(r.name, "test");
    }

    #[test]
    fn from_flags_oauth2() {
        let r = from_flags(
            "google".to_string(),
            "Google".to_string(),
            "oauth2",
            Some("http://oauth2-refresher:8081".to_string()),
            false,
        )
        .unwrap();
        assert!(matches!(r.auth_method, AuthMethod::OAuth2));
    }

    #[test]
    fn from_flags_unknown_auth_returns_none() {
        let r = from_flags(
            "test".to_string(),
            "Test".to_string(),
            "magic",
            None,
            false,
        );
        assert!(r.is_none());
    }

}
