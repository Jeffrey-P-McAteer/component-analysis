use crate::parser::common::{BinaryMetadata, SectionInfo};
use crate::types::Function;
use anyhow::Result;
use goblin::elf::Elf;

pub fn extract_metadata(elf: &Elf, _data: &[u8]) -> Result<BinaryMetadata> {
    let architecture = match elf.header.e_machine {
        goblin::elf::header::EM_386 => "i386",
        goblin::elf::header::EM_X86_64 => "x86_64",
        goblin::elf::header::EM_ARM => "arm",
        goblin::elf::header::EM_AARCH64 => "aarch64",
        goblin::elf::header::EM_MIPS => "mips",
        goblin::elf::header::EM_RISCV => "riscv",
        _ => "unknown",
    }.to_string();

    let is_64bit = elf.is_64;
    let entry_point = if elf.header.e_entry == 0 {
        None
    } else {
        Some(elf.header.e_entry)
    };

    let is_executable = elf.header.e_type == goblin::elf::header::ET_EXEC;
    let is_shared_library = elf.header.e_type == goblin::elf::header::ET_DYN;

    // Extract sections
    let mut sections = Vec::new();
    for section in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
            let section_info = SectionInfo::new(
                name.to_string(),
                section.sh_addr,
                section.sh_size,
            ).with_permissions(
                section.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 != 0,
                section.sh_flags & goblin::elf::section_header::SHF_WRITE as u64 != 0,
                true, // Most sections are readable by default
            );
            sections.push(section_info);
        }
    }

    // Extract imports and exports
    let imports = get_imports(elf)?;
    let exports = get_exports(elf)?;

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

pub fn extract_functions(elf: &Elf, _data: &[u8]) -> Result<Vec<Function>> {
    let mut functions = Vec::new();

    // Extract functions from symbol table
    for sym in &elf.syms {
        if sym.st_type() == goblin::elf::sym::STT_FUNC && sym.st_value != 0 {
            let name = elf.strtab.get_at(sym.st_name)
                .map(|s| s.to_string());

            let function = Function::new(sym.st_value)
                .with_name(name.unwrap_or_else(|| format!("func_{:x}", sym.st_value)))
                .with_size(sym.st_size);

            functions.push(function);
        }
    }

    // Also check dynamic symbol table
    for sym in &elf.dynsyms {
        if sym.st_type() == goblin::elf::sym::STT_FUNC && sym.st_value != 0 {
            let name = elf.dynstrtab.get_at(sym.st_name)
                .map(|s| s.to_string());

            let function = Function::new(sym.st_value)
                .with_name(name.unwrap_or_else(|| format!("dyn_func_{:x}", sym.st_value)))
                .with_size(sym.st_size);

            functions.push(function);
        }
    }

    // Remove duplicates based on address
    functions.sort_by_key(|f| f.address);
    functions.dedup_by_key(|f| f.address);

    Ok(functions)
}

pub fn get_imports(elf: &Elf) -> Result<Vec<String>> {
    let mut imports = Vec::new();

    // Get imports from dynamic symbols (undefined symbols)
    for sym in &elf.dynsyms {
        if sym.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize && sym.st_name != 0 {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                imports.push(name.to_string());
            }
        }
    }

    // PLT entries would require additional parsing
    // This is a placeholder for future PLT analysis

    imports.sort();
    imports.dedup();
    Ok(imports)
}

pub fn get_exports(elf: &Elf) -> Result<Vec<String>> {
    let mut exports = Vec::new();

    // Get exports from dynamic symbols (defined symbols)
    for sym in &elf.dynsyms {
        if sym.st_shndx != goblin::elf::section_header::SHN_UNDEF as usize
            && sym.st_bind() == goblin::elf::sym::STB_GLOBAL 
            && sym.st_name != 0 {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                exports.push(name.to_string());
            }
        }
    }

    // Also check regular symbol table for exported functions
    for sym in &elf.syms {
        if sym.st_shndx != goblin::elf::section_header::SHN_UNDEF as usize
            && sym.st_bind() == goblin::elf::sym::STB_GLOBAL 
            && sym.st_type() == goblin::elf::sym::STT_FUNC
            && sym.st_name != 0 {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                exports.push(name.to_string());
            }
        }
    }

    exports.sort();
    exports.dedup();
    Ok(exports)
}