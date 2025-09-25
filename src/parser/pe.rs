use crate::parser::common::{BinaryMetadata, SectionInfo, get_architecture_string};
use crate::types::Function;
use anyhow::Result;
use goblin::pe::{PE, characteristic::{IMAGE_FILE_EXECUTABLE_IMAGE, IMAGE_FILE_DLL}};

pub fn extract_metadata(pe: &PE, _data: &[u8]) -> Result<BinaryMetadata> {
    let architecture = get_architecture_string(pe.header.coff_header.machine);
    let is_64bit = pe.is_64;
    let entry_point = Some(pe.header.optional_header.unwrap().standard_fields.address_of_entry_point as u64);

    let is_executable = pe.header.coff_header.characteristics 
        & IMAGE_FILE_EXECUTABLE_IMAGE != 0;
    let is_shared_library = pe.header.coff_header.characteristics 
        & IMAGE_FILE_DLL != 0;

    // Extract sections
    let mut sections = Vec::new();
    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();
        
        let section_info = SectionInfo::new(
            name,
            section.virtual_address as u64,
            section.virtual_size as u64,
        ).with_permissions(
            section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0,
            section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE != 0,
            section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_READ != 0,
        );
        sections.push(section_info);
    }

    // Extract imports and exports
    let imports = get_imports(pe)?;
    let exports = get_exports(pe)?;

    Ok(BinaryMetadata {
        architecture,
        entry_point,
        imports,
        exports,
        sections,
        file_size: 0, // Will be filled by caller
        is_64bit,
        is_executable,
        is_shared_library,
    })
}

pub fn extract_functions(pe: &PE, _data: &[u8]) -> Result<Vec<Function>> {
    let mut functions = Vec::new();

    // Extract functions from exports
    for export in &pe.exports {
        if let Some(name) = &export.name {
            let function = Function::new(export.rva as u64)
                .with_name(name.to_string());
            functions.push(function);
        }
    }

    // Note: PE format doesn't have a symbol table like ELF by default
    // For more comprehensive function extraction, we would need to:
    // 1. Parse debug information (PDB files)
    // 2. Use heuristics to identify function boundaries
    // 3. Analyze call patterns

    Ok(functions)
}

pub fn get_imports(pe: &PE) -> Result<Vec<String>> {
    let mut imports = Vec::new();

    for import in &pe.imports {
        imports.push(import.name.to_string());
    }

    imports.sort();
    imports.dedup();
    Ok(imports)
}

pub fn get_exports(pe: &PE) -> Result<Vec<String>> {
    let mut exports = Vec::new();

    for export in &pe.exports {
        if let Some(name) = &export.name {
            exports.push(name.to_string());
        }
    }

    exports.sort();
    exports.dedup();
    Ok(exports)
}