use crate::database::{open_database, ComponentQueries};
use anyhow::Result;
use log::info;
use std::path::Path;

pub fn init(db_path: &Path) -> Result<()> {
    let db = open_database(db_path)?;
    db.init_schema()?;
    info!("Database schema initialized successfully");
    Ok(())
}

pub fn stats(db_path: &Path) -> Result<()> {
    let db = open_database(db_path)?;
    let conn = db.connection();

    // Get component counts by type
    let type_counts = ComponentQueries::count_by_type(conn)?;
    
    println!("Database Statistics:");
    println!("==================");
    
    let mut total_components = 0;
    for (component_type, count) in &type_counts {
        println!("{}: {}", component_type, count);
        total_components += count;
    }
    
    println!("==================");
    println!("Total components: {}", total_components);

    // Get relationship count
    let relationship_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM relationships",
        [],
        |row| row.get(0)
    )?;
    println!("Total relationships: {}", relationship_count);

    // Get analysis results count
    let analysis_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM analysis_results",
        [],
        |row| row.get(0)
    )?;
    println!("Total analysis results: {}", analysis_count);

    // Get investigation count
    let investigation_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM investigations",
        [],
        |row| row.get(0)
    )?;
    println!("Total investigations: {}", investigation_count);

    Ok(())
}

pub fn export(db_path: &Path, export_path: &Path) -> Result<()> {
    let db = open_database(db_path)?;
    let conn = db.connection();

    // Get all data
    let components = ComponentQueries::get_all(conn)?;
    let relationships = crate::database::RelationshipQueries::get_all(conn)?;
    let analysis_results = conn.prepare("SELECT * FROM analysis_results")?
        .query_map([], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, String>("id")?,
                "component_id": row.get::<_, String>("component_id")?,
                "analysis_type": row.get::<_, String>("analysis_type")?,
                "results": row.get::<_, String>("results")?,
                "confidence_score": row.get::<_, Option<f64>>("confidence_score")?,
                "created_at": row.get::<_, String>("created_at")?
            }))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let investigations = conn.prepare("SELECT * FROM investigations")?
        .query_map([], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, String>("id")?,
                "component_id": row.get::<_, String>("component_id")?,
                "investigation_type": row.get::<_, String>("investigation_type")?,
                "findings": row.get::<_, String>("findings")?,
                "investigator": row.get::<_, Option<String>>("investigator")?,
                "created_at": row.get::<_, String>("created_at")?
            }))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    // Create export data structure
    let export_data = serde_json::json!({
        "export_timestamp": chrono::Utc::now().to_rfc3339(),
        "components": components,
        "relationships": relationships,
        "analysis_results": analysis_results,
        "investigations": investigations
    });

    // Write to file
    std::fs::write(export_path, serde_json::to_string_pretty(&export_data)?)?;
    
    info!("Data exported successfully to {}", export_path.display());
    Ok(())
}

pub fn import(db_path: &Path, import_path: &Path) -> Result<()> {
    let db = open_database(db_path)?;
    let conn = db.connection();

    // Read import file
    let import_data: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(import_path)?
    )?;

    // Import components
    if let Some(components) = import_data["components"].as_array() {
        for component_data in components {
            let component: crate::types::Component = serde_json::from_value(component_data.clone())?;
            component.insert(conn)?;
        }
    }

    // Import relationships
    if let Some(relationships) = import_data["relationships"].as_array() {
        for relationship_data in relationships {
            let relationship: crate::types::Relationship = serde_json::from_value(relationship_data.clone())?;
            relationship.insert(conn)?;
        }
    }

    // Import analysis results
    if let Some(analysis_results) = import_data["analysis_results"].as_array() {
        for result_data in analysis_results {
            let analysis_result: crate::types::AnalysisResult = serde_json::from_value(result_data.clone())?;
            analysis_result.insert(conn)?;
        }
    }

    // Import investigations
    if let Some(investigations) = import_data["investigations"].as_array() {
        for investigation_data in investigations {
            let investigation: crate::types::Investigation = serde_json::from_value(investigation_data.clone())?;
            investigation.insert(conn)?;
        }
    }

    info!("Data imported successfully from {}", import_path.display());
    Ok(())
}