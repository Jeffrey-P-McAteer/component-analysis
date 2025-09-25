use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnalysisType {
    StaticAnalysis,
    CallGraph,
    Syscalls,
    Capabilities,
    DataFlow,
    TaintAnalysis,
    NetworkAnalysis,
}

impl std::fmt::Display for AnalysisType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnalysisType::StaticAnalysis => write!(f, "static_analysis"),
            AnalysisType::CallGraph => write!(f, "call_graph"),
            AnalysisType::Syscalls => write!(f, "syscalls"),
            AnalysisType::Capabilities => write!(f, "capabilities"),
            AnalysisType::DataFlow => write!(f, "data_flow"),
            AnalysisType::TaintAnalysis => write!(f, "taint_analysis"),
            AnalysisType::NetworkAnalysis => write!(f, "network_analysis"),
        }
    }
}

impl std::str::FromStr for AnalysisType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "static_analysis" => Ok(AnalysisType::StaticAnalysis),
            "call_graph" => Ok(AnalysisType::CallGraph),
            "syscalls" => Ok(AnalysisType::Syscalls),
            "capabilities" => Ok(AnalysisType::Capabilities),
            "data_flow" => Ok(AnalysisType::DataFlow),
            "taint_analysis" => Ok(AnalysisType::TaintAnalysis),
            "network_analysis" => Ok(AnalysisType::NetworkAnalysis),
            _ => Err(anyhow::anyhow!("Unknown analysis type: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub id: String,
    pub component_id: String,
    pub analysis_type: AnalysisType,
    pub results: serde_json::Value,
    pub confidence_score: Option<f64>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl AnalysisResult {
    pub fn new(
        component_id: String,
        analysis_type: AnalysisType,
        results: serde_json::Value,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            component_id,
            analysis_type,
            results,
            confidence_score: None,
            created_at: chrono::Utc::now(),
        }
    }

    pub fn with_confidence(mut self, score: f64) -> Self {
        self.confidence_score = Some(score);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum InvestigationType {
    Manual,
    Automated,
    Review,
    Annotation,
    Classification,
}

impl std::fmt::Display for InvestigationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvestigationType::Manual => write!(f, "manual"),
            InvestigationType::Automated => write!(f, "automated"),
            InvestigationType::Review => write!(f, "review"),
            InvestigationType::Annotation => write!(f, "annotation"),
            InvestigationType::Classification => write!(f, "classification"),
        }
    }
}

impl std::str::FromStr for InvestigationType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "manual" => Ok(InvestigationType::Manual),
            "automated" => Ok(InvestigationType::Automated),
            "review" => Ok(InvestigationType::Review),
            "annotation" => Ok(InvestigationType::Annotation),
            "classification" => Ok(InvestigationType::Classification),
            _ => Err(anyhow::anyhow!("Unknown investigation type: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Investigation {
    pub id: String,
    pub component_id: String,
    pub investigation_type: InvestigationType,
    pub findings: serde_json::Value,
    pub investigator: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl Investigation {
    pub fn new(
        component_id: String,
        investigation_type: InvestigationType,
        findings: serde_json::Value,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            component_id,
            investigation_type,
            findings,
            investigator: None,
            created_at: chrono::Utc::now(),
        }
    }

    pub fn with_investigator(mut self, investigator: String) -> Self {
        self.investigator = Some(investigator);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Syscall {
    pub name: String,
    pub address: u64,
    pub arguments: Vec<String>,
    pub return_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub name: String,
    pub description: String,
    pub risk_level: RiskLevel,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "low"),
            RiskLevel::Medium => write!(f, "medium"),
            RiskLevel::High => write!(f, "high"),
            RiskLevel::Critical => write!(f, "critical"),
        }
    }
}