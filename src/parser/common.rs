use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
    Archive,
    Unknown,
}

impl std::fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryFormat::Elf => write!(f, "ELF"),
            BinaryFormat::Pe => write!(f, "PE"),
            BinaryFormat::MachO => write!(f, "Mach-O"),
            BinaryFormat::Archive => write!(f, "Archive"),
            BinaryFormat::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryMetadata {
    pub architecture: String,
    pub entry_point: Option<u64>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub sections: Vec<SectionInfo>,
    pub file_size: u64,
    pub is_64bit: bool,
    pub is_executable: bool,
    pub is_shared_library: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub is_executable: bool,
    pub is_writable: bool,
    pub is_readable: bool,
}

impl SectionInfo {
    pub fn new(name: String, address: u64, size: u64) -> Self {
        Self {
            name,
            address,
            size,
            is_executable: false,
            is_writable: false,
            is_readable: true,
        }
    }

    pub fn with_permissions(mut self, executable: bool, writable: bool, readable: bool) -> Self {
        self.is_executable = executable;
        self.is_writable = writable;
        self.is_readable = readable;
        self
    }
}

pub fn calculate_file_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

pub fn get_architecture_string(machine: u16) -> String {
    match machine {
        0x014c => "i386".to_string(),
        0x8664 => "x86_64".to_string(),
        0x01c0 => "arm".to_string(),
        0xaa64 => "aarch64".to_string(),
        0x0266 => "mips".to_string(),
        0xf30c => "riscv".to_string(),
        _ => format!("unknown(0x{:04x})", machine),
    }
}