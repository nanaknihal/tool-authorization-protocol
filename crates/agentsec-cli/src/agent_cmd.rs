//! `agentsec agent` subcommands — manage agents via SQLite.

use agentsec_core::store::ConfigStore;
use colored::Colorize;

pub async fn list(store: &ConfigStore, team_id: &str) {
    match store.list_agents(team_id).await {
        Ok(agents) => {
            if agents.is_empty() {
                println!("No agents configured.");
                return;
            }
            println!(
                "{:<20} {:<10} {:<12} {}",
                "ID".bold(),
                "ENABLED".bold(),
                "RATE LIMIT".bold(),
                "DESCRIPTION".bold()
            );
            for a in agents {
                let enabled = if a.enabled {
                    "yes".green().to_string()
                } else {
                    "no".red().to_string()
                };
                let rate = a
                    .rate_limit_per_hour
                    .map(|r| format!("{}/hr", r))
                    .unwrap_or_else(|| "unlimited".to_string());
                println!(
                    "{:<20} {:<10} {:<12} {}",
                    a.id,
                    enabled,
                    rate,
                    a.description.unwrap_or_default()
                );
            }
        }
        Err(e) => eprintln!("Error: {e}"),
    }
}

pub async fn create(
    store: &ConfigStore,
    team_id: &str,
    name: &str,
    description: Option<&str>,
    roles: &[String],
    credentials: &[String],
    rate_limit: Option<i64>,
) {
    // Generate API key
    let api_key = crate::init::generate_api_key();
    let key_bytes = hex::decode(&api_key).unwrap_or_default();
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    key_bytes.hash(&mut hasher);
    let api_key_hash = format!("{:016x}", hasher.finish());

    if let Err(e) = store
        .create_agent(team_id, name, description, &api_key_hash, rate_limit)
        .await
    {
        eprintln!("Error creating agent: {e}");
        return;
    }

    for role in roles {
        if let Err(e) = store.assign_role_to_agent(team_id, name, role).await {
            eprintln!("Warning: failed to assign role '{role}': {e}");
        }
    }

    for cred in credentials {
        if let Err(e) = store.add_direct_credential(team_id, name, cred).await {
            eprintln!("Warning: failed to add credential '{cred}': {e}");
        }
    }

    println!("Agent '{}' created.", name);
    println!();
    println!("API key (save this — it won't be shown again):");
    println!("  {}", api_key.yellow());
    println!();
    println!("Set in agent's environment:");
    println!("  AGENTSEC_AGENT_KEY={api_key}");
}

pub async fn show(store: &ConfigStore, team_id: &str, name: &str) {
    match store.get_agent(team_id, name).await {
        Ok(Some(agent)) => {
            println!("Agent: {}", agent.id.bold());
            println!(
                "  Description: {}",
                agent.description.as_deref().unwrap_or("-")
            );
            println!(
                "  Enabled:     {}",
                if agent.enabled { "yes" } else { "no" }
            );
            println!(
                "  Rate limit:  {}",
                agent
                    .rate_limit_per_hour
                    .map(|r| format!("{}/hr", r))
                    .unwrap_or_else(|| "unlimited".to_string())
            );
            println!("  Created:     {}", agent.created_at);

            match store.get_agent_effective_credentials(team_id, name).await {
                Ok(creds) => {
                    let mut sorted: Vec<_> = creds.into_iter().collect();
                    sorted.sort();
                    println!(
                        "  Effective credentials ({}):",
                        sorted.len()
                    );
                    for c in sorted {
                        println!("    - {c}");
                    }
                }
                Err(e) => eprintln!("  Error loading credentials: {e}"),
            }
        }
        Ok(None) => eprintln!("Agent '{name}' not found."),
        Err(e) => eprintln!("Error: {e}"),
    }
}

pub async fn disable(store: &ConfigStore, team_id: &str, name: &str) {
    match store.disable_agent(team_id, name).await {
        Ok(()) => println!("Agent '{name}' disabled."),
        Err(e) => eprintln!("Error: {e}"),
    }
}

pub async fn enable(store: &ConfigStore, team_id: &str, name: &str) {
    match store.enable_agent(team_id, name).await {
        Ok(()) => println!("Agent '{name}' enabled."),
        Err(e) => eprintln!("Error: {e}"),
    }
}

pub async fn delete(store: &ConfigStore, team_id: &str, name: &str) {
    match store.delete_agent(team_id, name).await {
        Ok(()) => println!("Agent '{name}' deleted."),
        Err(e) => eprintln!("Error: {e}"),
    }
}
