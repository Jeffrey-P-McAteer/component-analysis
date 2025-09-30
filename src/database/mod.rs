pub mod models;
pub mod schema;
pub mod queries;

use anyhow::Result;
use rusqlite::Connection;
use std::path::Path;

pub use queries::*;

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        
        // Enable foreign key support
        conn.execute("PRAGMA foreign_keys = ON", [])?;
        
        Ok(Self { conn })
    }

    pub fn init_schema(&self) -> Result<()> {
        schema::create_tables(&self.conn)
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }
}

pub fn open_database<P: AsRef<Path>>(path: P) -> Result<Database> {
    Database::new(path)
}