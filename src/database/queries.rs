use crate::types::{Component, ComponentType, Relationship, RelationshipType, AnalysisResult, Investigation};
use anyhow::Result;
use rusqlite::{Connection, OptionalExtension};

pub struct ComponentQueries;

impl ComponentQueries {
    pub fn get_by_id(conn: &Connection, id: &str) -> Result<Option<Component>> {
        let mut stmt = conn.prepare(
            "SELECT id, component_type, name, path, hash, metadata, created_at, updated_at
             FROM components WHERE id = ?1"
        )?;

        let component = stmt.query_row([id], |row| Component::from_row(row))
            .optional()?;

        Ok(component)
    }

    pub fn get_by_type(conn: &Connection, component_type: ComponentType) -> Result<Vec<Component>> {
        let mut stmt = conn.prepare(
            "SELECT id, component_type, name, path, hash, metadata, created_at, updated_at
             FROM components WHERE component_type = ?1 ORDER BY name"
        )?;

        let rows = stmt.query_map([component_type.to_string()], |row| Component::from_row(row))?;

        let mut components = Vec::new();
        for component in rows {
            components.push(component?);
        }

        Ok(components)
    }

    pub fn get_by_name_pattern(conn: &Connection, pattern: &str) -> Result<Vec<Component>> {
        let mut stmt = conn.prepare(
            "SELECT id, component_type, name, path, hash, metadata, created_at, updated_at
             FROM components WHERE name LIKE ?1 ORDER BY name"
        )?;

        let search_pattern = format!("%{}%", pattern);
        let rows = stmt.query_map([search_pattern], |row| Component::from_row(row))?;

        let mut components = Vec::new();
        for component in rows {
            components.push(component?);
        }

        Ok(components)
    }

    pub fn get_by_id_pattern(conn: &Connection, pattern: &str) -> Result<Vec<Component>> {
        let mut stmt = conn.prepare(
            "SELECT id, component_type, name, path, hash, metadata, created_at, updated_at
             FROM components WHERE id LIKE ?1 ORDER BY name"
        )?;

        let search_pattern = format!("%{}%", pattern);
        let rows = stmt.query_map([search_pattern], |row| Component::from_row(row))?;

        let mut components = Vec::new();
        for component in rows {
            components.push(component?);
        }

        Ok(components)
    }

    pub fn get_all(conn: &Connection) -> Result<Vec<Component>> {
        let mut stmt = conn.prepare(
            "SELECT id, component_type, name, path, hash, metadata, created_at, updated_at
             FROM components ORDER BY component_type, name"
        )?;

        let rows = stmt.query_map([], |row| Component::from_row(row))?;

        let mut components = Vec::new();
        for component in rows {
            components.push(component?);
        }

        Ok(components)
    }

    pub fn count_by_type(conn: &Connection) -> Result<std::collections::HashMap<String, i64>> {
        let mut stmt = conn.prepare(
            "SELECT component_type, COUNT(*) as count FROM components GROUP BY component_type"
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>("component_type")?, row.get::<_, i64>("count")?))
        })?;

        let mut counts = std::collections::HashMap::new();
        for row in rows {
            let (component_type, count) = row?;
            counts.insert(component_type, count);
        }

        Ok(counts)
    }
}

pub struct RelationshipQueries;

impl RelationshipQueries {
    pub fn get_by_source(conn: &Connection, source_id: &str) -> Result<Vec<Relationship>> {
        let mut stmt = conn.prepare(
            "SELECT id, source_id, target_id, relationship_type, metadata, created_at
             FROM relationships WHERE source_id = ?1"
        )?;

        let rows = stmt.query_map([source_id], |row| Relationship::from_row(row))?;

        let mut relationships = Vec::new();
        for relationship in rows {
            relationships.push(relationship?);
        }

        Ok(relationships)
    }

    pub fn get_by_target(conn: &Connection, target_id: &str) -> Result<Vec<Relationship>> {
        let mut stmt = conn.prepare(
            "SELECT id, source_id, target_id, relationship_type, metadata, created_at
             FROM relationships WHERE target_id = ?1"
        )?;

        let rows = stmt.query_map([target_id], |row| Relationship::from_row(row))?;

        let mut relationships = Vec::new();
        for relationship in rows {
            relationships.push(relationship?);
        }

        Ok(relationships)
    }

    pub fn get_by_type(conn: &Connection, relationship_type: RelationshipType) -> Result<Vec<Relationship>> {
        let mut stmt = conn.prepare(
            "SELECT id, source_id, target_id, relationship_type, metadata, created_at
             FROM relationships WHERE relationship_type = ?1"
        )?;

        let rows = stmt.query_map([relationship_type.to_string()], |row| Relationship::from_row(row))?;

        let mut relationships = Vec::new();
        for relationship in rows {
            relationships.push(relationship?);
        }

        Ok(relationships)
    }

    pub fn get_all(conn: &Connection) -> Result<Vec<Relationship>> {
        let mut stmt = conn.prepare(
            "SELECT id, source_id, target_id, relationship_type, metadata, created_at
             FROM relationships ORDER BY created_at"
        )?;

        let rows = stmt.query_map([], |row| Relationship::from_row(row))?;

        let mut relationships = Vec::new();
        for relationship in rows {
            relationships.push(relationship?);
        }

        Ok(relationships)
    }
}

pub struct AnalysisQueries;

impl AnalysisQueries {
    pub fn get_by_component(conn: &Connection, component_id: &str) -> Result<Vec<AnalysisResult>> {
        let mut stmt = conn.prepare(
            "SELECT id, component_id, analysis_type, results, confidence_score, created_at
             FROM analysis_results WHERE component_id = ?1 ORDER BY created_at DESC"
        )?;

        let rows = stmt.query_map([component_id], |row| AnalysisResult::from_row(row))?;

        let mut results = Vec::new();
        for result in rows {
            results.push(result?);
        }

        Ok(results)
    }

    pub fn get_latest_by_component_and_type(
        conn: &Connection,
        component_id: &str,
        analysis_type: &str,
    ) -> Result<Option<AnalysisResult>> {
        let mut stmt = conn.prepare(
            "SELECT id, component_id, analysis_type, results, confidence_score, created_at
             FROM analysis_results WHERE component_id = ?1 AND analysis_type = ?2
             ORDER BY created_at DESC LIMIT 1"
        )?;

        let result = stmt.query_row([component_id, analysis_type], |row| AnalysisResult::from_row(row))
            .optional()?;

        Ok(result)
    }
}

pub struct InvestigationQueries;

impl InvestigationQueries {
    pub fn get_by_component(conn: &Connection, component_id: &str) -> Result<Vec<Investigation>> {
        let mut stmt = conn.prepare(
            "SELECT id, component_id, investigation_type, findings, investigator, created_at
             FROM investigations WHERE component_id = ?1 ORDER BY created_at DESC"
        )?;

        let rows = stmt.query_map([component_id], |row| Investigation::from_row(row))?;

        let mut investigations = Vec::new();
        for investigation in rows {
            investigations.push(investigation?);
        }

        Ok(investigations)
    }
}