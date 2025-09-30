use crate::types::{Component, Relationship, AnalysisResult, Investigation, ComponentType, RelationshipType, AnalysisType, InvestigationType, FunctionDocumentation, DocumentationType};
use anyhow::Result;
use rusqlite::{Connection, Row};
use serde_json;
use chrono;
use std::str::FromStr;

impl Component {
    #[allow(dead_code)]
    pub fn from_row(row: &Row) -> Result<Self, rusqlite::Error> {
        let metadata_str: String = row.get("metadata")?;
        let metadata = serde_json::from_str(&metadata_str).unwrap_or_default();
        
        let created_at_str: String = row.get("created_at")?;
        let updated_at_str: String = row.get("updated_at")?;
        
        let component_type_str: String = row.get("component_type")?;
        let component_type = ComponentType::from_str(&component_type_str)
            .map_err(|_| rusqlite::Error::InvalidColumnType(0, "component_type".to_string(), rusqlite::types::Type::Text))?;
            
        Ok(Component {
            id: row.get("id")?,
            component_type,
            name: row.get("name")?,
            path: row.get("path")?,
            hash: row.get("hash")?,
            metadata,
            created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
                .map_err(|_| rusqlite::Error::InvalidColumnType(0, "created_at".to_string(), rusqlite::types::Type::Text))?
                .with_timezone(&chrono::Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&updated_at_str)
                .map_err(|_| rusqlite::Error::InvalidColumnType(0, "updated_at".to_string(), rusqlite::types::Type::Text))?
                .with_timezone(&chrono::Utc),
        })
    }

    pub fn insert(&self, conn: &Connection) -> Result<()> {
        let metadata_str = serde_json::to_string(&self.metadata)?;
        
        conn.execute(
            "INSERT INTO components (id, component_type, name, path, hash, metadata, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                &self.id,
                &self.component_type.to_string(),
                &self.name,
                &self.path,
                &self.hash,
                &metadata_str,
                &self.created_at.to_rfc3339(),
                &self.updated_at.to_rfc3339(),
            ],
        )?;
        
        Ok(())
    }

    #[allow(dead_code)]
    pub fn update(&self, conn: &Connection) -> Result<()> {
        let metadata_str = serde_json::to_string(&self.metadata)?;
        
        conn.execute(
            "UPDATE components SET component_type = ?2, name = ?3, path = ?4, hash = ?5, 
             metadata = ?6, updated_at = ?7 WHERE id = ?1",
            rusqlite::params![
                &self.id,
                &self.component_type.to_string(),
                &self.name,
                &self.path,
                &self.hash,
                &metadata_str,
                &chrono::Utc::now().to_rfc3339(),
            ],
        )?;
        
        Ok(())
    }
}

impl Relationship {
    #[allow(dead_code)]
    pub fn from_row(row: &Row) -> Result<Self, rusqlite::Error> {
        let metadata_str: String = row.get("metadata")?;
        let metadata = serde_json::from_str(&metadata_str).unwrap_or_default();
        
        let created_at_str: String = row.get("created_at")?;
        
        let relationship_type_str: String = row.get("relationship_type")?;
        let relationship_type = RelationshipType::from_str(&relationship_type_str)
            .map_err(|_| rusqlite::Error::InvalidColumnType(0, "relationship_type".to_string(), rusqlite::types::Type::Text))?;
            
        Ok(Relationship {
            id: row.get("id")?,
            source_id: row.get("source_id")?,
            target_id: row.get("target_id")?,
            relationship_type,
            metadata,
            created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
                .map_err(|_| rusqlite::Error::InvalidColumnType(0, "created_at".to_string(), rusqlite::types::Type::Text))?
                .with_timezone(&chrono::Utc),
        })
    }

    pub fn insert(&self, conn: &Connection) -> Result<()> {
        let metadata_str = serde_json::to_string(&self.metadata)?;
        
        conn.execute(
            "INSERT INTO relationships (id, source_id, target_id, relationship_type, metadata, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                &self.id,
                &self.source_id,
                &self.target_id,
                &self.relationship_type.to_string(),
                &metadata_str,
                &self.created_at.to_rfc3339(),
            ],
        )?;
        
        Ok(())
    }
}

impl AnalysisResult {
    #[allow(dead_code)]
    pub fn from_row(row: &Row) -> Result<Self, rusqlite::Error> {
        let results_str: String = row.get("results")?;
        let results = serde_json::from_str(&results_str).unwrap_or(serde_json::Value::Null);
        
        let created_at_str: String = row.get("created_at")?;
        
        let analysis_type_str: String = row.get("analysis_type")?;
        let analysis_type = AnalysisType::from_str(&analysis_type_str)
            .map_err(|_| rusqlite::Error::InvalidColumnType(0, "analysis_type".to_string(), rusqlite::types::Type::Text))?;
            
        Ok(AnalysisResult {
            id: row.get("id")?,
            component_id: row.get("component_id")?,
            analysis_type,
            results,
            confidence_score: row.get("confidence_score")?,
            created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
                .map_err(|_| rusqlite::Error::InvalidColumnType(0, "created_at".to_string(), rusqlite::types::Type::Text))?
                .with_timezone(&chrono::Utc),
        })
    }

    pub fn insert(&self, conn: &Connection) -> Result<()> {
        let results_str = serde_json::to_string(&self.results)?;
        
        conn.execute(
            "INSERT INTO analysis_results (id, component_id, analysis_type, results, confidence_score, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                &self.id,
                &self.component_id,
                &self.analysis_type.to_string(),
                &results_str,
                &self.confidence_score,
                &self.created_at.to_rfc3339(),
            ],
        )?;
        
        Ok(())
    }
}

impl Investigation {
    #[allow(dead_code)]
    pub fn from_row(row: &Row) -> Result<Self, rusqlite::Error> {
        let findings_str: String = row.get("findings")?;
        let findings = serde_json::from_str(&findings_str).unwrap_or(serde_json::Value::Null);
        
        let created_at_str: String = row.get("created_at")?;
        
        let investigation_type_str: String = row.get("investigation_type")?;
        let investigation_type = InvestigationType::from_str(&investigation_type_str)
            .map_err(|_| rusqlite::Error::InvalidColumnType(0, "investigation_type".to_string(), rusqlite::types::Type::Text))?;
            
        Ok(Investigation {
            id: row.get("id")?,
            component_id: row.get("component_id")?,
            investigation_type,
            findings,
            investigator: row.get("investigator")?,
            created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
                .map_err(|_| rusqlite::Error::InvalidColumnType(0, "created_at".to_string(), rusqlite::types::Type::Text))?
                .with_timezone(&chrono::Utc),
        })
    }

    pub fn insert(&self, conn: &Connection) -> Result<()> {
        let findings_str = serde_json::to_string(&self.findings)?;
        
        conn.execute(
            "INSERT INTO investigations (id, component_id, investigation_type, findings, investigator, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                &self.id,
                &self.component_id,
                &self.investigation_type.to_string(),
                &findings_str,
                &self.investigator,
                &self.created_at.to_rfc3339(),
            ],
        )?;
        
        Ok(())
    }
}

impl FunctionDocumentation {
    #[allow(dead_code)]
    pub fn from_row(row: &Row) -> Result<Self, rusqlite::Error> {
        let created_at_str: String = row.get("created_at")?;
        let updated_at_str: String = row.get("updated_at")?;
        let lookup_timestamp_str: String = row.get("lookup_timestamp")?;
        
        let documentation_type_str: String = row.get("documentation_type")?;
        let documentation_type = DocumentationType::from_str(&documentation_type_str)
            .map_err(|_| rusqlite::Error::InvalidColumnType(0, "documentation_type".to_string(), rusqlite::types::Type::Text))?;
            
        Ok(FunctionDocumentation {
            id: row.get("id")?,
            function_name: row.get("function_name")?,
            platform: row.get("platform")?,
            header: row.get("header")?,
            description: row.get("description")?,
            source_url: row.get("source_url")?,
            documentation_type,
            quality_score: row.get("quality_score")?,
            lookup_timestamp: chrono::DateTime::parse_from_rfc3339(&lookup_timestamp_str)
                .map_err(|_| rusqlite::Error::InvalidColumnType(0, "lookup_timestamp".to_string(), rusqlite::types::Type::Text))?
                .with_timezone(&chrono::Utc),
            created_at: chrono::DateTime::parse_from_rfc3339(&created_at_str)
                .map_err(|_| rusqlite::Error::InvalidColumnType(0, "created_at".to_string(), rusqlite::types::Type::Text))?
                .with_timezone(&chrono::Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&updated_at_str)
                .map_err(|_| rusqlite::Error::InvalidColumnType(0, "updated_at".to_string(), rusqlite::types::Type::Text))?
                .with_timezone(&chrono::Utc),
        })
    }

    pub fn insert(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "INSERT INTO function_documentation (id, function_name, platform, header, description, source_url, documentation_type, quality_score, lookup_timestamp, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                &self.id,
                &self.function_name,
                &self.platform,
                &self.header,
                &self.description,
                &self.source_url,
                &self.documentation_type.to_string(),
                &self.quality_score,
                &self.lookup_timestamp.to_rfc3339(),
                &self.created_at.to_rfc3339(),
                &self.updated_at.to_rfc3339(),
            ],
        )?;
        
        Ok(())
    }

    #[allow(dead_code)]
    pub fn update(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "UPDATE function_documentation SET function_name = ?2, platform = ?3, header = ?4, description = ?5, 
             source_url = ?6, documentation_type = ?7, quality_score = ?8, lookup_timestamp = ?9, updated_at = ?10 WHERE id = ?1",
            rusqlite::params![
                &self.id,
                &self.function_name,
                &self.platform,
                &self.header,
                &self.description,
                &self.source_url,
                &self.documentation_type.to_string(),
                &self.quality_score,
                &self.lookup_timestamp.to_rfc3339(),
                &chrono::Utc::now().to_rfc3339(),
            ],
        )?;
        
        Ok(())
    }
}