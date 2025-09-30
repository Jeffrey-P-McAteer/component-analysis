use crate::types::{Instruction, Function, CallType, CallEdge};
use anyhow::{Result, anyhow};
use capstone::prelude::*;
use capstone::{Arch, Mode, arch};

pub struct DisassemblyEngine {
    capstone: Capstone,
    arch: ArchInfo,
}

#[derive(Debug, Clone)]
pub struct ArchInfo {
    pub arch: Arch,
    pub mode: Mode,
    pub is_64bit: bool,
}

impl DisassemblyEngine {
    pub fn new(arch: Arch, mode: Mode) -> Result<Self> {
        let capstone = match arch {
            Arch::X86 => {
                let mut builder = Capstone::new().x86();
                builder = match mode {
                    Mode::Mode32 => builder.mode(arch::x86::ArchMode::Mode32),
                    Mode::Mode64 => builder.mode(arch::x86::ArchMode::Mode64),
                    _ => return Err(anyhow!("Unsupported X86 mode: {:?}", mode)),
                };
                builder.detail(true).build()
            }
            Arch::ARM => {
                let mut builder = Capstone::new().arm();
                builder = match mode {
                    Mode::Arm => builder.mode(arch::arm::ArchMode::Arm),
                    Mode::Thumb => builder.mode(arch::arm::ArchMode::Thumb),
                    _ => return Err(anyhow!("Unsupported ARM mode: {:?}", mode)),
                };
                builder.detail(true).build()
            }
            Arch::ARM64 => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(true)
                .build(),
            _ => return Err(anyhow!("Unsupported architecture: {:?}", arch)),
        }.map_err(|e| anyhow!("Failed to initialize Capstone: {:?}", e))?;

        let is_64bit = matches!(mode, Mode::Mode64);

        Ok(Self {
            capstone,
            arch: ArchInfo { arch, mode, is_64bit },
        })
    }

    pub fn from_goblin_elf(elf: &goblin::elf::Elf) -> Result<Self> {
        let (arch, mode) = match elf.header.e_machine {
            goblin::elf::header::EM_386 => (Arch::X86, Mode::Mode32),
            goblin::elf::header::EM_X86_64 => (Arch::X86, Mode::Mode64),
            goblin::elf::header::EM_ARM => (Arch::ARM, Mode::Arm),
            goblin::elf::header::EM_AARCH64 => (Arch::ARM64, Mode::Arm),
            _ => return Err(anyhow!("Unsupported architecture: {}", elf.header.e_machine)),
        };

        Self::new(arch, mode)
    }

    pub fn from_goblin_pe(pe: &goblin::pe::PE) -> Result<Self> {
        let (arch, mode) = match pe.header.coff_header.machine {
            0x014c => (Arch::X86, Mode::Mode32), // IMAGE_FILE_MACHINE_I386
            0x8664 => (Arch::X86, Mode::Mode64), // IMAGE_FILE_MACHINE_AMD64
            0x01c0 => (Arch::ARM, Mode::Arm),    // IMAGE_FILE_MACHINE_ARM
            0xaa64 => (Arch::ARM64, Mode::Arm),  // IMAGE_FILE_MACHINE_ARM64
            _ => return Err(anyhow!("Unsupported architecture: {:#x}", pe.header.coff_header.machine)),
        };

        Self::new(arch, mode)
    }

    pub fn disassemble_bytes(&self, bytes: &[u8], start_address: u64) -> Result<Vec<Instruction>> {
        let instructions = self.capstone
            .disasm_all(bytes, start_address)
            .map_err(|e| anyhow!("Disassembly failed: {:?}", e))?;

        let mut result = Vec::new();
        for insn in instructions.iter() {
            let operands = if let Some(op_str) = insn.op_str() {
                op_str.split(',').map(|s| s.trim().to_string()).collect()
            } else {
                Vec::new()
            };

            let instruction = Instruction::new(
                insn.address(),
                insn.mnemonic().unwrap_or("unknown").to_string(),
                operands,
                insn.bytes().to_vec(),
            );
            result.push(instruction);
        }

        Ok(result)
    }

    pub fn disassemble_function(&self, bytes: &[u8], function: &Function, binary_base: u64) -> Result<Function> {
        let function_offset = function.address.saturating_sub(binary_base);
        let function_size = function.size.unwrap_or(0x1000) as usize; // Default to 4KB if size unknown
        
        if function_offset as usize >= bytes.len() {
            return Err(anyhow!("Function offset beyond binary bounds"));
        }

        let end_offset = std::cmp::min(
            (function_offset as usize) + function_size,
            bytes.len()
        );
        
        let function_bytes = &bytes[function_offset as usize..end_offset];
        let instructions = self.disassemble_bytes(function_bytes, function.address)?;

        let mut enhanced_function = function.clone();
        enhanced_function.instructions = instructions;

        Ok(enhanced_function)
    }

    pub fn analyze_calls(&self, instructions: &[Instruction]) -> Vec<CallEdge> {
        let mut call_edges = Vec::new();

        for instruction in instructions {
            let call_type = self.classify_call_instruction(&instruction.mnemonic);
            if let Some(call_type) = call_type {
                if let Some(target) = self.extract_call_target(instruction) {
                    let call_edge = CallEdge::new(
                        instruction.address,
                        target,
                        call_type,
                        instruction.address,
                    );
                    call_edges.push(call_edge);
                }
            }
        }

        call_edges
    }

    fn classify_call_instruction(&self, mnemonic: &str) -> Option<CallType> {
        match self.arch.arch {
            Arch::X86 => {
                match mnemonic {
                    "call" => Some(CallType::Direct),
                    "jmp" => Some(CallType::Tail),
                    _ if mnemonic.starts_with("call") => Some(CallType::Indirect),
                    _ => None,
                }
            }
            Arch::ARM | Arch::ARM64 => {
                match mnemonic {
                    "bl" | "blx" => Some(CallType::Direct),
                    "b" | "bx" => Some(CallType::Tail),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn extract_call_target(&self, instruction: &Instruction) -> Option<u64> {
        if instruction.operands.is_empty() {
            return None;
        }

        let operand = &instruction.operands[0];
        
        // Try to parse as hex address
        if operand.starts_with("0x") {
            if let Ok(addr) = u64::from_str_radix(&operand[2..], 16) {
                return Some(addr);
            }
        }

        // Try to parse as decimal
        if let Ok(addr) = operand.parse::<u64>() {
            return Some(addr);
        }

        // For relative addresses, we'd need more context
        // This is a simplified implementation
        None
    }

    pub fn find_syscalls(&self, instructions: &[Instruction]) -> Vec<SyscallInfo> {
        let mut syscalls = Vec::new();

        for instruction in instructions {
            if let Some(syscall_info) = self.analyze_syscall_instruction(instruction) {
                syscalls.push(syscall_info);
            }
        }

        syscalls
    }

    fn analyze_syscall_instruction(&self, instruction: &Instruction) -> Option<SyscallInfo> {
        match self.arch.arch {
            Arch::X86 => {
                match instruction.mnemonic.as_str() {
                    "int" if instruction.operands.get(0) == Some(&"0x80".to_string()) => {
                        Some(SyscallInfo {
                            address: instruction.address,
                            syscall_type: SyscallType::LinuxX86,
                            instruction: instruction.clone(),
                        })
                    }
                    "syscall" => {
                        Some(SyscallInfo {
                            address: instruction.address,
                            syscall_type: SyscallType::LinuxX64,
                            instruction: instruction.clone(),
                        })
                    }
                    "sysenter" => {
                        Some(SyscallInfo {
                            address: instruction.address,
                            syscall_type: SyscallType::LinuxSysenter,
                            instruction: instruction.clone(),
                        })
                    }
                    _ => None,
                }
            }
            Arch::ARM | Arch::ARM64 => {
                match instruction.mnemonic.as_str() {
                    "svc" => {
                        Some(SyscallInfo {
                            address: instruction.address,
                            syscall_type: SyscallType::ArmSvc,
                            instruction: instruction.clone(),
                        })
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SyscallInfo {
    pub address: u64,
    pub syscall_type: SyscallType,
    pub instruction: Instruction,
}

#[derive(Debug, Clone)]
pub enum SyscallType {
    LinuxX86,
    LinuxX64,
    LinuxSysenter,
    ArmSvc,
    #[allow(dead_code)]
    WindowsNtdll,
}

impl std::fmt::Display for SyscallType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyscallType::LinuxX86 => write!(f, "linux_x86"),
            SyscallType::LinuxX64 => write!(f, "linux_x64"),
            SyscallType::LinuxSysenter => write!(f, "linux_sysenter"),
            SyscallType::ArmSvc => write!(f, "arm_svc"),
            SyscallType::WindowsNtdll => write!(f, "windows_ntdll"),
        }
    }
}

pub fn create_disassembler_for_binary(binary_data: &[u8]) -> Result<DisassemblyEngine> {
    match goblin::Object::parse(binary_data)? {
        goblin::Object::Elf(elf) => DisassemblyEngine::from_goblin_elf(&elf),
        goblin::Object::PE(pe) => DisassemblyEngine::from_goblin_pe(&pe),
        _ => Err(anyhow!("Unsupported binary format for disassembly")),
    }
}