pub mod elf;
pub mod pe;
pub mod common;

use crate::types::{Component, ComponentType, Function};
use anyhow::{Result, anyhow};
use goblin::Object;
use std::fs;
use std::path::Path;

pub use common::*;

pub struct BinaryParser {
    pub path: String,
    pub data: Vec<u8>,
}

impl BinaryParser {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        let data = fs::read(&path)?;

        Ok(Self {
            path: path_str,
            data,
        })
    }

    pub fn get_format(&self) -> BinaryFormat {
        match Object::parse(&self.data) {
            Ok(Object::Elf(_)) => BinaryFormat::Elf,
            Ok(Object::PE(_)) => BinaryFormat::Pe,
            Ok(Object::Mach(_)) => BinaryFormat::MachO,
            Ok(Object::Archive(_)) => BinaryFormat::Archive,
            Ok(Object::Unknown(_)) => BinaryFormat::Unknown,
            Ok(_) => BinaryFormat::Unknown,
            Err(_) => BinaryFormat::Unknown,
        }
    }

    pub fn extract_metadata(&self) -> Result<BinaryMetadata> {
        let object = Object::parse(&self.data)?;
        match object {
            Object::Elf(elf) => elf::extract_metadata(&elf, &self.data),
            Object::PE(pe) => pe::extract_metadata(&pe, &self.data),
            _ => Err(anyhow!("Unsupported binary format for metadata extraction")),
        }
    }

    pub fn get_binary_base(&self) -> Result<u64> {
        let object = Object::parse(&self.data)?;
        match object {
            Object::Elf(elf) => Ok(elf.entry),
            Object::PE(pe) => Ok(pe.image_base as u64),
            _ => Err(anyhow!("Unsupported binary format for base address")),
        }
    }

    pub fn extract_functions(&self) -> Result<Vec<Function>> {
        let object = Object::parse(&self.data)?;
        match object {
            Object::Elf(elf) => elf::extract_functions(&elf, &self.data),
            Object::PE(pe) => pe::extract_functions(&pe, &self.data),
            _ => Err(anyhow!("Unsupported binary format for function extraction")),
        }
    }

    pub fn create_binary_component(&self) -> Result<Component> {
        let metadata = self.extract_metadata()?;
        let hash = calculate_file_hash(&self.data);
        
        let filename = Path::new(&self.path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        let mut component = Component::new(ComponentType::Binary, filename)
            .with_path(self.path.clone())
            .with_hash(hash);

        // Add metadata
        component = component.with_metadata("format".to_string(), serde_json::json!(self.get_format().to_string()));
        component = component.with_metadata("architecture".to_string(), serde_json::json!(metadata.architecture));
        component = component.with_metadata("entry_point".to_string(), serde_json::json!(metadata.entry_point));
        component = component.with_metadata("imports".to_string(), serde_json::json!(metadata.imports));
        component = component.with_metadata("exports".to_string(), serde_json::json!(metadata.exports));

        Ok(component)
    }

    pub fn get_imported_functions(&self) -> Result<Vec<String>> {
        let object = Object::parse(&self.data)?;
        match object {
            Object::Elf(elf) => elf::get_imports(&elf),
            Object::PE(pe) => pe::get_imports(&pe),
            _ => Ok(Vec::new()),
        }
    }

    pub fn get_exported_functions(&self) -> Result<Vec<String>> {
        let object = Object::parse(&self.data)?;
        match object {
            Object::Elf(elf) => elf::get_exports(&elf),
            Object::PE(pe) => pe::get_exports(&pe),
            _ => Ok(Vec::new()),
        }
    }
}