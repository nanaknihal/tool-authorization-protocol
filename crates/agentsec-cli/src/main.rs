#![allow(dead_code)]

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod add;
mod agent_cmd;
mod init;
mod logs;
mod role_cmd;

#[derive(Parser)]
#[command(
    name = "tap",
    version = "0.1.0",
    about = "Tool Authorization Protocol — credential isolation for AI agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug, PartialEq)]
enum Commands {
    /// Check proxy health
    Status {
        /// Proxy URL to health-check
        #[arg(long, default_value = "http://localhost:3100")]
        proxy_url: String,
    },
    /// Tail and display audit log entries
    Logs {
        /// Path to audit log file
        #[arg(short, long, default_value = "./audit.jsonl")]
        log_file: PathBuf,
        /// Number of recent entries to show (0 = all)
        #[arg(short, long, default_value = "20")]
        tail: usize,
    },
    /// Add a new service/credential to the database
    Add {
        #[arg(long, default_value = "./agentsec.db")]
        db: PathBuf,
        #[arg(long, env = "AGENTSEC_ENCRYPTION_KEY")]
        encryption_key: String,
        /// Service name (interactive if omitted)
        #[arg(long)]
        name: Option<String>,
        /// Service description
        #[arg(long)]
        description: Option<String>,
        /// Auth type: api-key, oauth2, oauth1, custom
        #[arg(long)]
        auth: Option<String>,
        /// API base URL or sidecar URL
        #[arg(long)]
        api_base: Option<String>,
        /// Target is a relative path (for protocol translators like Telegram)
        #[arg(long)]
        relative_target: bool,
    },

    // -- SQLite-backed management commands (v0.2) --
    /// Manage agents (list, create, show, enable, disable, delete)
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
    /// Manage RBAC roles (list, create, add-credential, remove-credential, delete)
    Role {
        #[command(subcommand)]
        action: RoleAction,
    },
}

#[derive(Subcommand, Debug, PartialEq)]
enum AgentAction {
    /// List all agents
    List {
        #[arg(long, default_value = "./agentsec.db")]
        db: PathBuf,
        #[arg(long, env = "AGENTSEC_ENCRYPTION_KEY")]
        encryption_key: String,
    },
    /// Create a new agent
    Create {
        #[arg(long, default_value = "./agentsec.db")]
        db: PathBuf,
        #[arg(long, env = "AGENTSEC_ENCRYPTION_KEY")]
        encryption_key: String,
        /// Agent name/ID
        #[arg(long)]
        name: String,
        /// Description
        #[arg(long)]
        description: Option<String>,
        /// Comma-separated role names
        #[arg(long, value_delimiter = ',')]
        roles: Vec<String>,
        /// Comma-separated direct credential names
        #[arg(long, value_delimiter = ',')]
        credentials: Vec<String>,
        /// Rate limit per hour
        #[arg(long)]
        rate_limit: Option<i64>,
    },
    /// Show agent details and effective permissions
    Show {
        #[arg(long, default_value = "./agentsec.db")]
        db: PathBuf,
        #[arg(long, env = "AGENTSEC_ENCRYPTION_KEY")]
        encryption_key: String,
        /// Agent name/ID
        name: String,
    },
    /// Disable an agent (blocks all requests)
    Disable {
        #[arg(long, default_value = "./agentsec.db")]
        db: PathBuf,
        #[arg(long, env = "AGENTSEC_ENCRYPTION_KEY")]
        encryption_key: String,
        name: String,
    },
    /// Re-enable a disabled agent
    Enable {
        #[arg(long, default_value = "./agentsec.db")]
        db: PathBuf,
        #[arg(long, env = "AGENTSEC_ENCRYPTION_KEY")]
        encryption_key: String,
        name: String,
    },
    /// Delete an agent
    Delete {
        #[arg(long, default_value = "./agentsec.db")]
        db: PathBuf,
        #[arg(long, env = "AGENTSEC_ENCRYPTION_KEY")]
        encryption_key: String,
        name: String,
    },
}

#[derive(Subcommand, Debug, PartialEq)]
enum RoleAction {
    /// List all roles
    List {
        #[arg(long, default_value = "./agentsec.db")]
        db: PathBuf,
        #[arg(long, env = "AGENTSEC_ENCRYPTION_KEY")]
        encryption_key: String,
    },
    /// Create a new role
    Create {
        #[arg(long, default_value = "./agentsec.db")]
        db: PathBuf,
        #[arg(long, env = "AGENTSEC_ENCRYPTION_KEY")]
        encryption_key: String,
        /// Role name
        #[arg(long)]
        name: String,
        /// Description
        #[arg(long)]
        description: Option<String>,
        /// Comma-separated credential names
        #[arg(long, value_delimiter = ',')]
        credentials: Vec<String>,
        /// Rate limit per hour
        #[arg(long)]
        rate_limit: Option<i64>,
    },
    /// Add a credential to a role
    AddCredential {
        #[arg(long, default_value = "./agentsec.db")]
        db: PathBuf,
        #[arg(long, env = "AGENTSEC_ENCRYPTION_KEY")]
        encryption_key: String,
        /// Role name
        role: String,
        /// Credential name
        credential: String,
    },
    /// Remove a credential from a role
    RemoveCredential {
        #[arg(long, default_value = "./agentsec.db")]
        db: PathBuf,
        #[arg(long, env = "AGENTSEC_ENCRYPTION_KEY")]
        encryption_key: String,
        role: String,
        credential: String,
    },
    /// Delete a role
    Delete {
        #[arg(long, default_value = "./agentsec.db")]
        db: PathBuf,
        #[arg(long, env = "AGENTSEC_ENCRYPTION_KEY")]
        encryption_key: String,
        name: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status { proxy_url } => cmd_status(&proxy_url).await,
        Commands::Logs { log_file, tail } => cmd_logs(&log_file, tail),
        Commands::Add {
            db,
            encryption_key,
            name,
            description,
            auth,
            api_base,
            relative_target,
        } => {
            cmd_add(
                &db,
                &encryption_key,
                name,
                description,
                auth,
                api_base,
                relative_target,
            )
            .await
        }
        Commands::Agent { action } => cmd_agent(action).await,
        Commands::Role { action } => cmd_role(action).await,
    }
}

async fn open_store(db: &PathBuf, encryption_key: &str) -> ConfigStore {
    let key_bytes = match hex::decode(encryption_key) {
        Ok(b) if b.len() == 32 => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&b);
            k
        }
        _ => {
            eprintln!("Error: AGENTSEC_ENCRYPTION_KEY must be 64 hex chars (32 bytes)");
            std::process::exit(1);
        }
    };
    match ConfigStore::new(db.to_str().unwrap_or("agentsec.db"), None, key_bytes).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error opening database: {e}");
            std::process::exit(1);
        }
    }
}

use agentsec_core::store::ConfigStore;

const DEFAULT_TEAM_ID: &str = "default";

async fn cmd_agent(action: AgentAction) {
    match action {
        AgentAction::List { db, encryption_key } => {
            let store = open_store(&db, &encryption_key).await;
            agent_cmd::list(&store, DEFAULT_TEAM_ID).await;
        }
        AgentAction::Create {
            db,
            encryption_key,
            name,
            description,
            roles,
            credentials,
            rate_limit,
        } => {
            let store = open_store(&db, &encryption_key).await;
            agent_cmd::create(
                &store,
                DEFAULT_TEAM_ID,
                &name,
                description.as_deref(),
                &roles,
                &credentials,
                rate_limit,
            )
            .await;
        }
        AgentAction::Show {
            db,
            encryption_key,
            name,
        } => {
            let store = open_store(&db, &encryption_key).await;
            agent_cmd::show(&store, DEFAULT_TEAM_ID, &name).await;
        }
        AgentAction::Disable {
            db,
            encryption_key,
            name,
        } => {
            let store = open_store(&db, &encryption_key).await;
            agent_cmd::disable(&store, DEFAULT_TEAM_ID, &name).await;
        }
        AgentAction::Enable {
            db,
            encryption_key,
            name,
        } => {
            let store = open_store(&db, &encryption_key).await;
            agent_cmd::enable(&store, DEFAULT_TEAM_ID, &name).await;
        }
        AgentAction::Delete {
            db,
            encryption_key,
            name,
        } => {
            let store = open_store(&db, &encryption_key).await;
            agent_cmd::delete(&store, DEFAULT_TEAM_ID, &name).await;
        }
    }
}

async fn cmd_role(action: RoleAction) {
    match action {
        RoleAction::List { db, encryption_key } => {
            let store = open_store(&db, &encryption_key).await;
            role_cmd::list(&store, DEFAULT_TEAM_ID).await;
        }
        RoleAction::Create {
            db,
            encryption_key,
            name,
            description,
            credentials,
            rate_limit,
        } => {
            let store = open_store(&db, &encryption_key).await;
            role_cmd::create(
                &store,
                DEFAULT_TEAM_ID,
                &name,
                description.as_deref(),
                &credentials,
                rate_limit,
            )
            .await;
        }
        RoleAction::AddCredential {
            db,
            encryption_key,
            role,
            credential,
        } => {
            let store = open_store(&db, &encryption_key).await;
            role_cmd::add_credential(&store, DEFAULT_TEAM_ID, &role, &credential).await;
        }
        RoleAction::RemoveCredential {
            db,
            encryption_key,
            role,
            credential,
        } => {
            let store = open_store(&db, &encryption_key).await;
            role_cmd::remove_credential(&store, DEFAULT_TEAM_ID, &role, &credential).await;
        }
        RoleAction::Delete {
            db,
            encryption_key,
            name,
        } => {
            let store = open_store(&db, &encryption_key).await;
            role_cmd::delete(&store, DEFAULT_TEAM_ID, &name).await;
        }
    }
}

async fn cmd_status(proxy_url: &str) {
    println!("TAP Status");
    println!("===============");
    let health_url = format!("{proxy_url}/health");
    match reqwest::get(&health_url).await {
        Ok(resp) if resp.status().is_success() => {
            println!("  {health_url} -> OK");
        }
        Ok(resp) => {
            println!("  {health_url} -> HTTP {}", resp.status());
        }
        Err(e) => {
            println!("  {health_url} -> UNREACHABLE ({e})");
        }
    }
}

fn cmd_logs(log_file: &PathBuf, tail: usize) {
    let content = match std::fs::read_to_string(log_file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: cannot read {}: {e}", log_file.display());
            std::process::exit(1);
        }
    };

    let lines: Vec<&str> = content.lines().collect();
    let display_lines = if tail > 0 && lines.len() > tail {
        &lines[lines.len() - tail..]
    } else {
        &lines[..]
    };

    if display_lines.is_empty() {
        println!("No audit log entries found.");
        return;
    }

    for line in display_lines {
        match logs::parse_log_line(line) {
            Ok(entry) => println!("{}", logs::format_entry(&entry)),
            Err(_) => eprintln!("  (skipped malformed line)"),
        }
    }
}

async fn cmd_add(
    db: &PathBuf,
    encryption_key: &str,
    name: Option<String>,
    description: Option<String>,
    auth: Option<String>,
    api_base: Option<String>,
    relative_target: bool,
) {
    let result = if let (Some(name), Some(desc), Some(auth_type)) = (name, description, auth) {
        match add::from_flags(name, desc, &auth_type, api_base, relative_target) {
            Some(r) => r,
            None => std::process::exit(1),
        }
    } else {
        match add::interactive_add() {
            Some(r) => r,
            None => std::process::exit(1),
        }
    };

    let store = open_store(db, encryption_key).await;
    let connector = match result.auth_method {
        add::AuthMethod::ApiKey => "direct",
        _ => "sidecar",
    };
    match store
        .create_credential(
            DEFAULT_TEAM_ID,
            &result.name,
            &result.description,
            connector,
            result.api_base.as_deref(),
            relative_target,
            None,
            None,
        )
        .await
    {
        Ok(()) => add::print_instructions(&result),
        Err(e) => {
            eprintln!("Error creating credential: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_status_subcommand_parses() {
        let cli = Cli::try_parse_from(["tap", "status"]).unwrap();
        assert!(matches!(cli.command, Commands::Status { .. }));
    }

    #[test]
    fn cli_status_with_proxy_url_parses() {
        let cli = Cli::try_parse_from(["agentsec", "status", "--proxy-url", "http://proxy:3100"])
            .unwrap();
        match cli.command {
            Commands::Status { proxy_url } => {
                assert_eq!(proxy_url, "http://proxy:3100");
            }
            _ => panic!("Expected Status"),
        }
    }

    #[test]
    fn cli_logs_subcommand_parses() {
        let cli = Cli::try_parse_from(["tap", "logs"]).unwrap();
        assert!(matches!(cli.command, Commands::Logs { .. }));
    }

    #[test]
    fn cli_logs_with_tail_parses() {
        let cli = Cli::try_parse_from(["tap", "logs", "--tail", "50"]).unwrap();
        match cli.command {
            Commands::Logs { tail, .. } => assert_eq!(tail, 50),
            _ => panic!("Expected Logs"),
        }
    }

    #[test]
    fn cli_add_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "agentsec",
            "add",
            "--encryption-key",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ])
        .unwrap();
        assert!(matches!(cli.command, Commands::Add { .. }));
    }

    #[test]
    fn cli_add_with_flags_parses() {
        let cli = Cli::try_parse_from([
            "agentsec",
            "add",
            "--encryption-key",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--name",
            "my-api",
            "--description",
            "My API",
            "--auth",
            "api-key",
            "--api-base",
            "https://api.example.com",
        ])
        .unwrap();
        match cli.command {
            Commands::Add {
                name,
                description,
                auth,
                api_base,
                relative_target,
                ..
            } => {
                assert_eq!(name.unwrap(), "my-api");
                assert_eq!(description.unwrap(), "My API");
                assert_eq!(auth.unwrap(), "api-key");
                assert_eq!(api_base.unwrap(), "https://api.example.com");
                assert!(!relative_target);
            }
            _ => panic!("Expected Add"),
        }
    }

    #[test]
    fn cli_unknown_subcommand_errors() {
        let result = Cli::try_parse_from(["tap", "deploy"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_help_does_not_panic() {
        // --help causes clap to exit, so we just check try_parse doesn't panic
        let result = Cli::try_parse_from(["tap", "--help"]);
        // This returns Err because --help triggers early exit in clap
        assert!(result.is_err());
    }
}
