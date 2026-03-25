use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub cve_id: Option<String>,
    pub component: String,
    pub severity: String,
    pub description: String,
    pub timestamp: String,
    pub source: String, // e.g., "falco", "trivy"
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RemediationAction {
    PatchImage(String),
    IsolateNetwork(String),
    KillAndReplace(String),
    AlertOnly(String),
}
