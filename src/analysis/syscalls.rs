use crate::analysis::disassembly::{SyscallInfo, SyscallType};
use crate::analysis::call_graph::{SyscallPath, CallGraphBuilder};
use crate::types::{Syscall, RiskLevel, Instruction};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use log::{debug, info, warn};

pub struct SyscallAnalyzer {
    syscall_db: SyscallDatabase,
}

impl SyscallAnalyzer {
    pub fn new() -> Self {
        Self {
            syscall_db: SyscallDatabase::new(),
        }
    }

    pub fn analyze_syscalls(&self, syscall_paths: Vec<SyscallPath>) -> Result<SyscallAnalysisReport> {
        info!("Analyzing {} syscall paths", syscall_paths.len());
        
        let mut report = SyscallAnalysisReport::new();
        
        for syscall_path in syscall_paths {
            let analysis = self.analyze_single_syscall_path(&syscall_path)?;
            report.add_syscall_analysis(analysis);
        }
        
        report.compute_summary();
        
        info!("Syscall analysis complete: {} unique syscalls, {} high-risk paths", 
              report.unique_syscalls.len(),
              report.high_risk_paths);
        
        Ok(report)
    }

    fn analyze_single_syscall_path(&self, path: &SyscallPath) -> Result<SyscallAnalysis> {
        let syscall_number = self.extract_syscall_number(&path.syscall_info)?;
        let syscall_info = self.syscall_db.get_syscall_info(&path.syscall_info.syscall_type, syscall_number);
        
        let risk_level = self.assess_risk_level(&syscall_info, &path.call_path);
        let capabilities = self.infer_capabilities(&syscall_info);
        
        Ok(SyscallAnalysis {
            syscall_info: path.syscall_info.clone(),
            syscall_details: syscall_info,
            call_path: path.call_path.clone(),
            function_address: path.function_address,
            risk_level,
            capabilities,
            analysis_notes: self.generate_analysis_notes(&path.syscall_info, &path.call_path),
        })
    }

    fn extract_syscall_number(&self, syscall_info: &SyscallInfo) -> Result<u32> {
        // For different syscall types, the syscall number is passed in different registers
        // This would typically require register value tracking
        
        match syscall_info.syscall_type {
            SyscallType::LinuxX86 => {
                // On x86 Linux, syscall number is in EAX
                // We'd need to trace back to find the value loaded into EAX
                self.trace_register_value(&syscall_info.instruction, "eax")
            }
            SyscallType::LinuxX64 => {
                // On x64 Linux, syscall number is in RAX
                self.trace_register_value(&syscall_info.instruction, "rax")
            }
            SyscallType::ArmSvc => {
                // On ARM, syscall number can be in the SVC instruction or in r7
                if let Some(operand) = syscall_info.instruction.operands.get(0) {
                    Ok(operand.parse::<u32>().unwrap_or(0))
                } else {
                    Ok(0) // Would need to trace r7 register
                }
            }
            _ => Ok(0), // Default/unknown
        }
    }

    fn trace_register_value(&self, _instruction: &Instruction, _register: &str) -> Result<u32> {
        // This would implement backward data flow analysis to find the value
        // loaded into the specified register before the syscall
        // For now, return 0 as placeholder
        Ok(0)
    }

    fn assess_risk_level(&self, syscall_info: &Option<KnownSyscall>, call_path: &[u64]) -> RiskLevel {
        if let Some(syscall) = syscall_info {
            // Base risk from the syscall itself
            let mut risk = match syscall.base_risk {
                RiskLevel::Critical => 4,
                RiskLevel::High => 3,
                RiskLevel::Medium => 2,
                RiskLevel::Low => 1,
            };
            
            // Increase risk based on call path depth (deeper calls are more suspicious)
            if call_path.len() > 10 {
                risk += 1;
            }
            
            // Check for suspicious patterns
            if syscall.categories.contains(&SyscallCategory::Network) && 
               syscall.categories.contains(&SyscallCategory::FileSystem) {
                risk += 1; // Network + file access together is suspicious
            }
            
            match risk {
                1 => RiskLevel::Low,
                2 => RiskLevel::Medium,
                3 => RiskLevel::High,
                _ => RiskLevel::Critical,
            }
        } else {
            RiskLevel::Medium // Unknown syscalls are medium risk by default
        }
    }

    fn infer_capabilities(&self, syscall_info: &Option<KnownSyscall>) -> Vec<String> {
        if let Some(syscall) = syscall_info {
            syscall.capabilities.clone()
        } else {
            vec!["unknown_capability".to_string()]
        }
    }

    fn generate_analysis_notes(&self, syscall_info: &SyscallInfo, call_path: &[u64]) -> Vec<String> {
        let mut notes = Vec::new();
        
        notes.push(format!("Syscall type: {}", syscall_info.syscall_type));
        notes.push(format!("Call depth: {} functions", call_path.len()));
        
        if call_path.len() > 15 {
            notes.push("Deep call chain may indicate obfuscation".to_string());
        }
        
        if call_path.len() == 1 {
            notes.push("Direct syscall from single function".to_string());
        }
        
        notes
    }

    pub fn detect_syscall_patterns(&self, report: &SyscallAnalysisReport) -> Vec<SyscallPattern> {
        let mut patterns = Vec::new();
        
        // Look for common malware patterns
        patterns.extend(self.detect_network_exfiltration_pattern(report));
        patterns.extend(self.detect_file_encryption_pattern(report));
        patterns.extend(self.detect_privilege_escalation_pattern(report));
        patterns.extend(self.detect_persistence_pattern(report));
        
        patterns
    }

    fn detect_network_exfiltration_pattern(&self, report: &SyscallAnalysisReport) -> Vec<SyscallPattern> {
        let mut patterns = Vec::new();
        
        let has_file_read = report.syscall_analyses.iter()
            .any(|a| a.capabilities.iter().any(|c| c.contains("file_read")));
        let has_network_send = report.syscall_analyses.iter()
            .any(|a| a.capabilities.iter().any(|c| c.contains("network_send")));
        
        if has_file_read && has_network_send {
            patterns.push(SyscallPattern {
                name: "Potential Data Exfiltration".to_string(),
                description: "Program reads files and sends network data".to_string(),
                risk_level: RiskLevel::High,
                indicators: vec![
                    "File read operations detected".to_string(),
                    "Network send operations detected".to_string(),
                ],
                mitigation: "Monitor file access and network traffic".to_string(),
            });
        }
        
        patterns
    }

    fn detect_file_encryption_pattern(&self, report: &SyscallAnalysisReport) -> Vec<SyscallPattern> {
        let mut patterns = Vec::new();
        
        let file_operations = report.syscall_analyses.iter()
            .filter(|a| a.capabilities.iter().any(|c| c.contains("file")))
            .count();
        
        if file_operations > 10 {
            patterns.push(SyscallPattern {
                name: "High Volume File Operations".to_string(),
                description: "Program performs many file operations".to_string(),
                risk_level: RiskLevel::Medium,
                indicators: vec![
                    format!("{} file operations detected", file_operations),
                ],
                mitigation: "Monitor file system activity for encryption patterns".to_string(),
            });
        }
        
        patterns
    }

    fn detect_privilege_escalation_pattern(&self, report: &SyscallAnalysisReport) -> Vec<SyscallPattern> {
        let mut patterns = Vec::new();
        
        let has_setuid = report.syscall_analyses.iter()
            .any(|a| a.capabilities.iter().any(|c| c.contains("setuid") || c.contains("privilege")));
        
        if has_setuid {
            patterns.push(SyscallPattern {
                name: "Privilege Escalation Attempt".to_string(),
                description: "Program attempts to change user privileges".to_string(),
                risk_level: RiskLevel::Critical,
                indicators: vec![
                    "Privilege modification syscalls detected".to_string(),
                ],
                mitigation: "Restrict execution privileges and monitor privilege changes".to_string(),
            });
        }
        
        patterns
    }

    fn detect_persistence_pattern(&self, report: &SyscallAnalysisReport) -> Vec<SyscallPattern> {
        let mut patterns = Vec::new();
        
        let has_file_create = report.syscall_analyses.iter()
            .any(|a| a.capabilities.iter().any(|c| c.contains("file_create")));
        let has_process_create = report.syscall_analyses.iter()
            .any(|a| a.capabilities.iter().any(|c| c.contains("process_create")));
        
        if has_file_create || has_process_create {
            patterns.push(SyscallPattern {
                name: "Potential Persistence Mechanism".to_string(),
                description: "Program creates files or processes".to_string(),
                risk_level: RiskLevel::Medium,
                indicators: vec![
                    if has_file_create { "File creation detected" } else { "" }.to_string(),
                    if has_process_create { "Process creation detected" } else { "" }.to_string(),
                ].into_iter().filter(|s| !s.is_empty()).collect(),
                mitigation: "Monitor created files and processes for persistence indicators".to_string(),
            });
        }
        
        patterns
    }
}

impl Default for SyscallAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct SyscallAnalysisReport {
    pub syscall_analyses: Vec<SyscallAnalysis>,
    pub unique_syscalls: HashMap<u32, KnownSyscall>,
    pub high_risk_paths: usize,
    pub total_paths: usize,
    pub risk_distribution: HashMap<RiskLevel, usize>,
}

impl SyscallAnalysisReport {
    pub fn new() -> Self {
        Self {
            syscall_analyses: Vec::new(),
            unique_syscalls: HashMap::new(),
            high_risk_paths: 0,
            total_paths: 0,
            risk_distribution: HashMap::new(),
        }
    }

    pub fn add_syscall_analysis(&mut self, analysis: SyscallAnalysis) {
        if matches!(analysis.risk_level, RiskLevel::High | RiskLevel::Critical) {
            self.high_risk_paths += 1;
        }
        
        self.total_paths += 1;
        *self.risk_distribution.entry(analysis.risk_level.clone()).or_insert(0) += 1;
        
        self.syscall_analyses.push(analysis);
    }

    pub fn compute_summary(&mut self) {
        // Extract unique syscalls
        for analysis in &self.syscall_analyses {
            if let Some(syscall_details) = &analysis.syscall_details {
                self.unique_syscalls.insert(syscall_details.number, syscall_details.clone());
            }
        }
    }
}

impl Default for SyscallAnalysisReport {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct SyscallAnalysis {
    pub syscall_info: SyscallInfo,
    pub syscall_details: Option<KnownSyscall>,
    pub call_path: Vec<u64>,
    pub function_address: u64,
    pub risk_level: RiskLevel,
    pub capabilities: Vec<String>,
    pub analysis_notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct KnownSyscall {
    pub number: u32,
    pub name: String,
    pub description: String,
    pub parameters: Vec<SyscallParameter>,
    pub categories: Vec<SyscallCategory>,
    pub capabilities: Vec<String>,
    pub base_risk: RiskLevel,
}

#[derive(Debug, Clone)]
pub struct SyscallParameter {
    pub name: String,
    pub param_type: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SyscallCategory {
    FileSystem,
    Network,
    Process,
    Memory,
    Security,
    System,
    IPC,
}

#[derive(Debug, Clone)]
pub struct SyscallPattern {
    pub name: String,
    pub description: String,
    pub risk_level: RiskLevel,
    pub indicators: Vec<String>,
    pub mitigation: String,
}

struct SyscallDatabase {
    linux_x86_syscalls: HashMap<u32, KnownSyscall>,
    linux_x64_syscalls: HashMap<u32, KnownSyscall>,
}

impl SyscallDatabase {
    pub fn new() -> Self {
        let mut db = Self {
            linux_x86_syscalls: HashMap::new(),
            linux_x64_syscalls: HashMap::new(),
        };
        
        db.initialize_linux_syscalls();
        db
    }

    fn initialize_linux_syscalls(&mut self) {
        // Linux x64 syscalls
        self.linux_x64_syscalls.insert(0, KnownSyscall {
            number: 0,
            name: "read".to_string(),
            description: "Read from file descriptor".to_string(),
            parameters: vec![
                SyscallParameter { name: "fd".to_string(), param_type: "int".to_string(), description: "File descriptor".to_string() },
                SyscallParameter { name: "buf".to_string(), param_type: "void*".to_string(), description: "Buffer".to_string() },
                SyscallParameter { name: "count".to_string(), param_type: "size_t".to_string(), description: "Bytes to read".to_string() },
            ],
            categories: vec![SyscallCategory::FileSystem],
            capabilities: vec!["file_read".to_string()],
            base_risk: RiskLevel::Low,
        });

        self.linux_x64_syscalls.insert(1, KnownSyscall {
            number: 1,
            name: "write".to_string(),
            description: "Write to file descriptor".to_string(),
            parameters: vec![
                SyscallParameter { name: "fd".to_string(), param_type: "int".to_string(), description: "File descriptor".to_string() },
                SyscallParameter { name: "buf".to_string(), param_type: "const void*".to_string(), description: "Buffer".to_string() },
                SyscallParameter { name: "count".to_string(), param_type: "size_t".to_string(), description: "Bytes to write".to_string() },
            ],
            categories: vec![SyscallCategory::FileSystem],
            capabilities: vec!["file_write".to_string()],
            base_risk: RiskLevel::Low,
        });

        self.linux_x64_syscalls.insert(41, KnownSyscall {
            number: 41,
            name: "socket".to_string(),
            description: "Create network socket".to_string(),
            parameters: vec![
                SyscallParameter { name: "domain".to_string(), param_type: "int".to_string(), description: "Communication domain".to_string() },
                SyscallParameter { name: "type".to_string(), param_type: "int".to_string(), description: "Socket type".to_string() },
                SyscallParameter { name: "protocol".to_string(), param_type: "int".to_string(), description: "Protocol".to_string() },
            ],
            categories: vec![SyscallCategory::Network],
            capabilities: vec!["network_create".to_string()],
            base_risk: RiskLevel::Medium,
        });

        self.linux_x64_syscalls.insert(42, KnownSyscall {
            number: 42,
            name: "connect".to_string(),
            description: "Connect to network address".to_string(),
            parameters: vec![
                SyscallParameter { name: "sockfd".to_string(), param_type: "int".to_string(), description: "Socket descriptor".to_string() },
                SyscallParameter { name: "addr".to_string(), param_type: "struct sockaddr*".to_string(), description: "Address".to_string() },
                SyscallParameter { name: "addrlen".to_string(), param_type: "socklen_t".to_string(), description: "Address length".to_string() },
            ],
            categories: vec![SyscallCategory::Network],
            capabilities: vec!["network_connect".to_string()],
            base_risk: RiskLevel::Medium,
        });

        self.linux_x64_syscalls.insert(57, KnownSyscall {
            number: 57,
            name: "fork".to_string(),
            description: "Create child process".to_string(),
            parameters: vec![],
            categories: vec![SyscallCategory::Process],
            capabilities: vec!["process_create".to_string()],
            base_risk: RiskLevel::Medium,
        });

        self.linux_x64_syscalls.insert(59, KnownSyscall {
            number: 59,
            name: "execve".to_string(),
            description: "Execute program".to_string(),
            parameters: vec![
                SyscallParameter { name: "filename".to_string(), param_type: "const char*".to_string(), description: "Program path".to_string() },
                SyscallParameter { name: "argv".to_string(), param_type: "char* const[]".to_string(), description: "Arguments".to_string() },
                SyscallParameter { name: "envp".to_string(), param_type: "char* const[]".to_string(), description: "Environment".to_string() },
            ],
            categories: vec![SyscallCategory::Process],
            capabilities: vec!["process_execute".to_string()],
            base_risk: RiskLevel::High,
        });

        self.linux_x64_syscalls.insert(105, KnownSyscall {
            number: 105,
            name: "setuid".to_string(),
            description: "Set user ID".to_string(),
            parameters: vec![
                SyscallParameter { name: "uid".to_string(), param_type: "uid_t".to_string(), description: "User ID".to_string() },
            ],
            categories: vec![SyscallCategory::Security],
            capabilities: vec!["setuid".to_string(), "privilege_change".to_string()],
            base_risk: RiskLevel::Critical,
        });

        // Add some Linux x86 syscalls (different numbers)
        self.linux_x86_syscalls.insert(3, self.linux_x64_syscalls[&0].clone()); // read
        self.linux_x86_syscalls.insert(4, self.linux_x64_syscalls[&1].clone()); // write
        // ... more would be added in a complete implementation
    }

    pub fn get_syscall_info(&self, syscall_type: &SyscallType, number: u32) -> Option<KnownSyscall> {
        match syscall_type {
            SyscallType::LinuxX64 | SyscallType::LinuxSysenter => {
                self.linux_x64_syscalls.get(&number).cloned()
            }
            SyscallType::LinuxX86 => {
                self.linux_x86_syscalls.get(&number).cloned()
            }
            _ => None, // ARM and Windows syscalls would be added here
        }
    }
}