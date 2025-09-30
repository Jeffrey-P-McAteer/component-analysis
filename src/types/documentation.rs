use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DocumentationType {
    StandardLibrary,
    WindowsAPI,
    LinuxAPI,
    POSIX,
    Manual,
    StackOverflow,
    Official,
}

impl std::fmt::Display for DocumentationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DocumentationType::StandardLibrary => write!(f, "standard_library"),
            DocumentationType::WindowsAPI => write!(f, "windows_api"),
            DocumentationType::LinuxAPI => write!(f, "linux_api"),
            DocumentationType::POSIX => write!(f, "posix"),
            DocumentationType::Manual => write!(f, "manual"),
            DocumentationType::StackOverflow => write!(f, "stackoverflow"),
            DocumentationType::Official => write!(f, "official"),
        }
    }
}

impl std::str::FromStr for DocumentationType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "standard_library" => Ok(DocumentationType::StandardLibrary),
            "windows_api" => Ok(DocumentationType::WindowsAPI),
            "linux_api" => Ok(DocumentationType::LinuxAPI),
            "posix" => Ok(DocumentationType::POSIX),
            "manual" => Ok(DocumentationType::Manual),
            "stackoverflow" => Ok(DocumentationType::StackOverflow),
            "official" => Ok(DocumentationType::Official),
            _ => Err(anyhow::anyhow!("Unknown documentation type: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDocumentation {
    pub id: String,
    pub function_name: String,
    pub platform: String,
    pub header: Option<String>,
    pub description: String,
    pub source_url: Option<String>,
    pub documentation_type: DocumentationType,
    pub quality_score: f64,
    pub lookup_timestamp: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl FunctionDocumentation {
    pub fn new(
        function_name: String,
        platform: String,
        description: String,
        documentation_type: DocumentationType,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            function_name,
            platform,
            header: None,
            description,
            source_url: None,
            documentation_type,
            quality_score: 0.0,
            lookup_timestamp: now,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn with_header(mut self, header: String) -> Self {
        self.header = Some(header);
        self
    }

    pub fn with_source_url(mut self, url: String) -> Self {
        self.source_url = Some(url);
        self
    }

    pub fn with_quality_score(mut self, score: f64) -> Self {
        self.quality_score = score;
        self
    }
}

#[derive(Debug, Clone)]
pub struct DocumentationLookupConfig {
    pub user_agent: String,
    pub timeout_seconds: u64,
    pub max_retries: u32,
    pub cache_duration_hours: u64,
    pub preferred_sources: Vec<DocumentationType>,
}

impl Default for DocumentationLookupConfig {
    fn default() -> Self {
        Self {
            user_agent: "component-analyzer/0.1.0".to_string(),
            timeout_seconds: 10,
            max_retries: 3,
            cache_duration_hours: 24 * 7, // 1 week
            preferred_sources: vec![
                DocumentationType::Official,
                DocumentationType::StandardLibrary,
                DocumentationType::WindowsAPI,
                DocumentationType::LinuxAPI,
                DocumentationType::POSIX,
                DocumentationType::Manual,
            ],
        }
    }
}

#[derive(Debug, Clone)]
pub struct DocumentationSearchResult {
    pub function_name: String,
    pub header: Option<String>,
    pub description: String,
    pub source_url: String,
    pub documentation_type: DocumentationType,
    pub quality_score: f64,
    pub platform: String,
}