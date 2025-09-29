use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ComponentType {
    Instruction,
    Function,
    Binary,
    Process,
    Host,
    Network,
}

impl std::fmt::Display for ComponentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComponentType::Instruction => write!(f, "instruction"),
            ComponentType::Function => write!(f, "function"),
            ComponentType::Binary => write!(f, "binary"),
            ComponentType::Process => write!(f, "process"),
            ComponentType::Host => write!(f, "host"),
            ComponentType::Network => write!(f, "network"),
        }
    }
}

impl std::str::FromStr for ComponentType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "instruction" => Ok(ComponentType::Instruction),
            "function" => Ok(ComponentType::Function),
            "binary" => Ok(ComponentType::Binary),
            "process" => Ok(ComponentType::Process),
            "host" => Ok(ComponentType::Host),
            "network" => Ok(ComponentType::Network),
            _ => Err(anyhow::anyhow!("Unknown component type: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    pub id: String,
    pub component_type: ComponentType,
    pub name: String,
    pub path: Option<String>,
    pub hash: Option<String>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl Component {
    pub fn new(component_type: ComponentType, name: String) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            component_type,
            name,
            path: None,
            hash: None,
            metadata: HashMap::new(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn with_full_details(
        id: String,
        component_type: ComponentType,
        name: String,
        path: Option<String>,
        metadata: serde_json::Value,
    ) -> Self {
        let metadata_map = match metadata {
            serde_json::Value::Object(map) => map.into_iter().collect(),
            _ => HashMap::new(),
        };
        
        let now = chrono::Utc::now();
        Self {
            id,
            component_type,
            name,
            path,
            hash: None,
            metadata: metadata_map,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn with_path(mut self, path: String) -> Self {
        self.path = Some(path);
        self
    }

    pub fn with_hash(mut self, hash: String) -> Self {
        self.hash = Some(hash);
        self
    }

    pub fn with_metadata(mut self, key: String, value: serde_json::Value) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RelationshipType {
    Calls,
    Imports,
    Contains,
    ConnectsTo,
    DependsOn,
    Executes,
    Reads,
    Writes,
    Uses,
}

impl std::fmt::Display for RelationshipType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelationshipType::Calls => write!(f, "calls"),
            RelationshipType::Imports => write!(f, "imports"),
            RelationshipType::Contains => write!(f, "contains"),
            RelationshipType::ConnectsTo => write!(f, "connects_to"),
            RelationshipType::DependsOn => write!(f, "depends_on"),
            RelationshipType::Executes => write!(f, "executes"),
            RelationshipType::Reads => write!(f, "reads"),
            RelationshipType::Writes => write!(f, "writes"),
            RelationshipType::Uses => write!(f, "uses"),
        }
    }
}

impl std::str::FromStr for RelationshipType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "calls" => Ok(RelationshipType::Calls),
            "imports" => Ok(RelationshipType::Imports),
            "contains" => Ok(RelationshipType::Contains),
            "connects_to" => Ok(RelationshipType::ConnectsTo),
            "depends_on" => Ok(RelationshipType::DependsOn),
            "executes" => Ok(RelationshipType::Executes),
            "reads" => Ok(RelationshipType::Reads),
            "writes" => Ok(RelationshipType::Writes),
            "uses" => Ok(RelationshipType::Uses),
            _ => Err(anyhow::anyhow!("Unknown relationship type: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    pub id: String,
    pub source_id: String,
    pub target_id: String,
    pub relationship_type: RelationshipType,
    pub metadata: HashMap<String, serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl Relationship {
    pub fn new(
        source_id: String,
        target_id: String,
        relationship_type: RelationshipType,
        metadata: serde_json::Value,
    ) -> Self {
        let metadata_map = match metadata {
            serde_json::Value::Object(map) => map.into_iter().collect(),
            _ => HashMap::new(),
        };
        
        Self {
            id: Uuid::new_v4().to_string(),
            source_id,
            target_id,
            relationship_type,
            metadata: metadata_map,
            created_at: chrono::Utc::now(),
        }
    }

    pub fn with_metadata(mut self, key: String, value: serde_json::Value) -> Self {
        self.metadata.insert(key, value);
        self
    }
}