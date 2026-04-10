use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A proxy request from an agent, parsed from the incoming HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRequest {
    pub id: Uuid,
    pub agent_id: String,
    pub target_url: String,
    pub method: HttpMethod,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub content_type: Option<String>,
    /// Credential placeholders found in the request, with their positions.
    pub placeholders: Vec<Placeholder>,
    pub received_at: DateTime<Utc>,
}

/// Where a credential placeholder was found in the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Placeholder {
    pub credential_name: String,
    pub position: PlaceholderPosition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlaceholderPosition {
    /// In an HTTP header value (always allowed).
    Header(String),
    /// In the request body (only allowed if credential config opts in).
    Body,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
}

impl HttpMethod {
    pub fn is_read(&self) -> bool {
        matches!(self, Self::Get | Self::Head | Self::Options)
    }

    pub fn parse(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "PATCH" => Self::Patch,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            _ => Self::Post, // unknown methods require approval
        }
    }
}

/// The result of processing a proxy request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyResponse {
    pub request_id: Uuid,
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub sanitized: bool,
}

/// Status of an approval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Timeout,
}

/// An entry in the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub request_id: Uuid,
    pub agent_id: String,
    pub credential_names: Vec<String>,
    pub target_url: String,
    pub method: HttpMethod,
    pub approval_status: Option<ApprovalStatus>,
    pub upstream_status: Option<u16>,
    pub total_latency_ms: u64,
    pub approval_latency_ms: Option<u64>,
    pub upstream_latency_ms: Option<u64>,
    pub response_sanitized: bool,
    pub timestamp: DateTime<Utc>,
}

/// AI safety check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyCheckResult {
    pub passed: bool,
    pub risk_level: RiskLevel,
    pub concerns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
        }
    }
}
