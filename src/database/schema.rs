use anyhow::Result;
use rusqlite::Connection;

pub fn create_tables(conn: &Connection) -> Result<()> {
    // Components table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS components (
            id TEXT PRIMARY KEY,
            component_type TEXT NOT NULL,
            name TEXT NOT NULL,
            path TEXT,
            hash TEXT,
            metadata TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )",
        [],
    )?;

    // Relationships table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS relationships (
            id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            target_id TEXT NOT NULL,
            relationship_type TEXT NOT NULL,
            metadata TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (source_id) REFERENCES components(id),
            FOREIGN KEY (target_id) REFERENCES components(id)
        )",
        [],
    )?;

    // Investigations table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS investigations (
            id TEXT PRIMARY KEY,
            component_id TEXT NOT NULL,
            investigation_type TEXT NOT NULL,
            findings TEXT NOT NULL,
            investigator TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (component_id) REFERENCES components(id)
        )",
        [],
    )?;

    // Analysis results table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS analysis_results (
            id TEXT PRIMARY KEY,
            component_id TEXT NOT NULL,
            analysis_type TEXT NOT NULL,
            results TEXT NOT NULL,
            confidence_score REAL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (component_id) REFERENCES components(id)
        )",
        [],
    )?;

    // Create indexes for performance
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_components_type ON components(component_type)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_components_name ON components(name)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_relationships_source ON relationships(source_id)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_relationships_target ON relationships(target_id)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_relationships_type ON relationships(relationship_type)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_analysis_component ON analysis_results(component_id)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_analysis_type ON analysis_results(analysis_type)",
        [],
    )?;

    Ok(())
}