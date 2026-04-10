//! Policy evaluation: auto-approve, require approval, rate limiting.

use agentsec_core::config::PolicyConfig;
use agentsec_core::error::AgentSecError;
use agentsec_core::types::HttpMethod;

/// Result of policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub requires_approval: bool,
    pub auto_approved: bool,
}

/// Evaluate whether a request requires human approval based on policy.
/// `target_url` is checked against `auto_approve_urls` for URL-pattern overrides.
pub fn evaluate_policy(
    method: &HttpMethod,
    policy: Option<&PolicyConfig>,
    target_url: Option<&str>,
) -> PolicyDecision {
    let policy = match policy {
        Some(p) => p,
        None => {
            // No explicit policy: auto-approve safe read methods (GET/HEAD),
            // require approval for everything else. Setting policies via the
            // dashboard is annoying enough that the default should "just work"
            // for the common case of reading data. Writes still require explicit
            // approval until the user opts in.
            let method_str = method_to_string(method);
            let safe = method_str == "GET" || method_str == "HEAD";
            return PolicyDecision {
                requires_approval: !safe,
                auto_approved: safe,
            };
        }
    };

    // Check URL-pattern overrides first (takes priority over method rules)
    if let Some(url) = target_url {
        if policy
            .auto_approve_urls
            .iter()
            .any(|pattern| url.contains(pattern))
        {
            return PolicyDecision {
                requires_approval: false,
                auto_approved: true,
            };
        }
    }

    let method_str = method_to_string(method);

    // HEAD follows GET policy (both are read-only)
    let check_method = if method_str == "HEAD" {
        "GET".to_string()
    } else {
        method_str.clone()
    };

    // Check auto-approve list
    if policy
        .auto_approve
        .iter()
        .any(|m| m.to_uppercase() == check_method)
    {
        return PolicyDecision {
            requires_approval: false,
            auto_approved: true,
        };
    }

    // Check require-approval list
    if policy
        .require_approval
        .iter()
        .any(|m| m.to_uppercase() == check_method)
    {
        return PolicyDecision {
            requires_approval: true,
            auto_approved: false,
        };
    }

    // Method not in either list — default to require approval (fail closed)
    PolicyDecision {
        requires_approval: true,
        auto_approved: false,
    }
}

fn method_to_string(method: &HttpMethod) -> String {
    match method {
        HttpMethod::Get => "GET".to_string(),
        HttpMethod::Post => "POST".to_string(),
        HttpMethod::Put => "PUT".to_string(),
        HttpMethod::Delete => "DELETE".to_string(),
        HttpMethod::Patch => "PATCH".to_string(),
        HttpMethod::Head => "HEAD".to_string(),
        HttpMethod::Options => "OPTIONS".to_string(),
    }
}

/// Check rate limit for an agent.
pub fn check_rate_limit(request_count: u64, limit_per_hour: u64) -> Result<(), AgentSecError> {
    if request_count >= limit_per_hour {
        return Err(AgentSecError::RateLimited(format!(
            "Rate limit exceeded: {request_count}/{limit_per_hour} requests in the last hour"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> PolicyConfig {
        PolicyConfig {
            auto_approve: vec!["GET".to_string()],
            require_approval: vec!["POST".to_string(), "PUT".to_string(), "DELETE".to_string()],
            auto_approve_urls: vec![],
            approval: None,
        }
    }

    #[test]
    fn get_request_auto_approved() {
        let policy = test_policy();
        let decision = evaluate_policy(&HttpMethod::Get, Some(&policy), None);
        assert!(decision.auto_approved);
        assert!(!decision.requires_approval);
    }

    #[test]
    fn post_request_requires_approval() {
        let policy = test_policy();
        let decision = evaluate_policy(&HttpMethod::Post, Some(&policy), None);
        assert!(decision.requires_approval);
        assert!(!decision.auto_approved);
    }

    #[test]
    fn delete_request_requires_approval() {
        let policy = test_policy();
        let decision = evaluate_policy(&HttpMethod::Delete, Some(&policy), None);
        assert!(decision.requires_approval);
        assert!(!decision.auto_approved);
    }

    #[test]
    fn head_request_auto_approved() {
        let policy = test_policy();
        let decision = evaluate_policy(&HttpMethod::Head, Some(&policy), None);
        assert!(decision.auto_approved);
        assert!(!decision.requires_approval);
    }

    #[test]
    fn url_pattern_overrides_method_policy() {
        let mut policy = test_policy();
        policy.auto_approve_urls = vec!["/v1/search".to_string()];

        // POST normally requires approval
        let decision = evaluate_policy(
            &HttpMethod::Post,
            Some(&policy),
            Some("https://api.notion.com/v1/search"),
        );
        assert!(decision.auto_approved);
        assert!(!decision.requires_approval);

        // POST to a different URL still requires approval
        let decision = evaluate_policy(
            &HttpMethod::Post,
            Some(&policy),
            Some("https://api.notion.com/v1/pages"),
        );
        assert!(decision.requires_approval);
    }

    #[test]
    fn rate_limit_under_threshold() {
        let result = check_rate_limit(5, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn rate_limit_exceeded() {
        let result = check_rate_limit(101, 100);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Rate limit exceeded"));
    }

    #[test]
    fn no_policy_auto_approves_get() {
        let decision = evaluate_policy(&HttpMethod::Get, None, None);
        assert!(decision.auto_approved);
        assert!(!decision.requires_approval);
    }

    #[test]
    fn no_policy_auto_approves_head() {
        let decision = evaluate_policy(&HttpMethod::Head, None, None);
        assert!(decision.auto_approved);
        assert!(!decision.requires_approval);
    }

    #[test]
    fn no_policy_requires_approval_for_post() {
        let decision = evaluate_policy(&HttpMethod::Post, None, None);
        assert!(decision.requires_approval);
        assert!(!decision.auto_approved);
    }

    #[test]
    fn no_policy_requires_approval_for_delete() {
        let decision = evaluate_policy(&HttpMethod::Delete, None, None);
        assert!(decision.requires_approval);
        assert!(!decision.auto_approved);
    }
}
