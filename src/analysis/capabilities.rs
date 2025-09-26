use crate::analysis::syscalls::{SyscallAnalysisReport, SyscallPattern};
use crate::types::{Capability, RiskLevel};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use log::{info, debug};

pub struct CapabilityAnalyzer {
    capability_rules: Vec<CapabilityRule>,
}

impl CapabilityAnalyzer {
    pub fn new() -> Self {
        Self {
            capability_rules: Self::initialize_capability_rules(),
        }
    }

    pub fn analyze_binary_capabilities(
        &self,
        syscall_report: &SyscallAnalysisReport,
        imports: &[String],
        exports: &[String],
    ) -> Result<CapabilityAnalysisReport> {
        info!("Analyzing binary capabilities from {} syscalls and {} imports", 
              syscall_report.syscall_analyses.len(), imports.len());

        let mut report = CapabilityAnalysisReport::new();

        // Analyze syscall-based capabilities
        let syscall_capabilities = self.extract_syscall_capabilities(syscall_report);
        report.add_capabilities(syscall_capabilities);

        // Analyze import-based capabilities  
        let import_capabilities = self.extract_import_capabilities(imports);
        report.add_capabilities(import_capabilities);

        // Analyze export-based capabilities
        let export_capabilities = self.extract_export_capabilities(exports);
        report.add_capabilities(export_capabilities);

        // Infer higher-level behaviors
        let behavioral_capabilities = self.infer_behavioral_capabilities(&report);
        report.add_capabilities(behavioral_capabilities);

        // Assess overall risk
        report.assess_risk();

        info!("Capability analysis complete: {} capabilities identified", 
              report.capabilities.len());

        Ok(report)
    }

    fn extract_syscall_capabilities(&self, syscall_report: &SyscallAnalysisReport) -> Vec<Capability> {
        let mut capabilities = Vec::new();
        let mut capability_evidence = HashMap::new();

        // Collect evidence from syscall analyses
        for analysis in &syscall_report.syscall_analyses {
            for capability_name in &analysis.capabilities {
                let evidence = capability_evidence.entry(capability_name.clone())
                    .or_insert_with(|| Vec::new());
                evidence.push(format!("Syscall at 0x{:x}", analysis.function_address));
            }
        }

        // Create capability objects
        for (capability_name, evidence) in capability_evidence {
            let risk_level = self.assess_capability_risk(&capability_name, &evidence);
            let description = self.get_capability_description(&capability_name);

            capabilities.push(Capability {
                name: capability_name.clone(),
                category: self.get_capability_category(&capability_name),
                description,
                risk_level,
                evidence,
            });
        }

        capabilities
    }

    fn extract_import_capabilities(&self, imports: &[String]) -> Vec<Capability> {
        let mut capabilities = Vec::new();
        let mut grouped_capabilities = HashMap::new();

        for import in imports {
            if let Some(capability_info) = self.match_import_to_capability(import) {
                let evidence = grouped_capabilities.entry(capability_info.name.clone())
                    .or_insert_with(|| Vec::new());
                evidence.push(format!("Import: {}", import));
            }
        }

        for (name, evidence) in grouped_capabilities {
            let risk_level = self.assess_capability_risk(&name, &evidence);
            let description = self.get_capability_description(&name);

            capabilities.push(Capability {
                name: name.clone(),
                category: self.get_capability_category(&name),
                description,
                risk_level,
                evidence,
            });
        }

        capabilities
    }

    fn extract_export_capabilities(&self, exports: &[String]) -> Vec<Capability> {
        let mut capabilities = Vec::new();

        // Check for potentially dangerous exports
        let suspicious_exports = exports.iter()
            .filter(|export| self.is_suspicious_export(export))
            .collect::<Vec<_>>();

        if !suspicious_exports.is_empty() {
            capabilities.push(Capability {
                name: "export_suspicious_functions".to_string(),
                category: "General".to_string(),
                description: "Binary exports functions that may be used by other processes".to_string(),
                risk_level: RiskLevel::Medium,
                evidence: suspicious_exports.iter()
                    .map(|exp| format!("Export: {}", exp))
                    .collect(),
            });
        }

        capabilities
    }

    fn infer_behavioral_capabilities(&self, report: &CapabilityAnalysisReport) -> Vec<Capability> {
        let mut behavioral_capabilities = Vec::new();

        // Check for malware behavior patterns
        behavioral_capabilities.extend(self.detect_data_exfiltration_behavior(report));
        behavioral_capabilities.extend(self.detect_persistence_behavior(report));
        behavioral_capabilities.extend(self.detect_evasion_behavior(report));
        behavioral_capabilities.extend(self.detect_credential_harvesting_behavior(report));

        behavioral_capabilities
    }

    fn detect_data_exfiltration_behavior(&self, report: &CapabilityAnalysisReport) -> Vec<Capability> {
        let mut capabilities = Vec::new();
        
        let has_file_read = report.has_capability("file_read");
        let has_network_send = report.has_capability("network_send") || 
                              report.has_capability("network_connect");
        let has_crypto = report.has_capability("cryptography") || 
                        report.has_capability("encryption");

        if has_file_read && has_network_send {
            let mut evidence = vec![
                "Can read files from disk".to_string(),
                "Can send data over network".to_string(),
            ];
            
            if has_crypto {
                evidence.push("Has cryptographic capabilities".to_string());
            }

            capabilities.push(Capability {
                name: "data_exfiltration".to_string(),
                category: "Data Exfiltration".to_string(),
                description: "May exfiltrate data by reading files and sending over network".to_string(),
                risk_level: if has_crypto { RiskLevel::Critical } else { RiskLevel::High },
                evidence,
            });
        }

        capabilities
    }

    fn detect_persistence_behavior(&self, report: &CapabilityAnalysisReport) -> Vec<Capability> {
        let mut capabilities = Vec::new();

        let has_file_write = report.has_capability("file_write");
        let has_registry = report.has_capability("registry_modify");
        let has_service = report.has_capability("service_control");
        let has_process_create = report.has_capability("process_create");

        if has_file_write || has_registry || has_service || has_process_create {
            let mut evidence = Vec::new();
            if has_file_write { evidence.push("Can write files".to_string()); }
            if has_registry { evidence.push("Can modify registry".to_string()); }
            if has_service { evidence.push("Can control services".to_string()); }
            if has_process_create { evidence.push("Can create processes".to_string()); }

            capabilities.push(Capability {
                name: "persistence_mechanism".to_string(),
                category: "Persistence".to_string(),
                description: "May establish persistence through file/registry/service modifications".to_string(),
                risk_level: RiskLevel::High,
                evidence,
            });
        }

        capabilities
    }

    fn detect_evasion_behavior(&self, report: &CapabilityAnalysisReport) -> Vec<Capability> {
        let mut capabilities = Vec::new();

        let has_process_enum = report.has_capability("process_enumerate");
        let has_debug_detect = report.has_capability("debug_detection");
        let has_vm_detect = report.has_capability("vm_detection");
        let has_sleep = report.has_capability("delay_execution");

        if has_process_enum || has_debug_detect || has_vm_detect || has_sleep {
            let mut evidence = Vec::new();
            if has_process_enum { evidence.push("Can enumerate processes".to_string()); }
            if has_debug_detect { evidence.push("May detect debuggers".to_string()); }
            if has_vm_detect { evidence.push("May detect virtual machines".to_string()); }
            if has_sleep { evidence.push("Can delay execution".to_string()); }

            capabilities.push(Capability {
                name: "evasion_techniques".to_string(),
                category: "Evasion".to_string(),
                description: "May use techniques to evade analysis or detection".to_string(),
                risk_level: RiskLevel::High,
                evidence,
            });
        }

        capabilities
    }

    fn detect_credential_harvesting_behavior(&self, report: &CapabilityAnalysisReport) -> Vec<Capability> {
        let mut capabilities = Vec::new();

        let has_memory_access = report.has_capability("memory_read");
        let has_keyboard_hook = report.has_capability("keyboard_hook");
        let has_browser_access = report.has_capability("browser_data");
        let has_clipboard = report.has_capability("clipboard_access");

        if has_memory_access || has_keyboard_hook || has_browser_access || has_clipboard {
            let mut evidence = Vec::new();
            if has_memory_access { evidence.push("Can read process memory".to_string()); }
            if has_keyboard_hook { evidence.push("Can hook keyboard input".to_string()); }
            if has_browser_access { evidence.push("Can access browser data".to_string()); }
            if has_clipboard { evidence.push("Can access clipboard".to_string()); }

            capabilities.push(Capability {
                name: "credential_harvesting".to_string(),
                category: "Credential Access".to_string(),
                description: "May harvest credentials through various methods".to_string(),
                risk_level: RiskLevel::Critical,
                evidence,
            });
        }

        capabilities
    }

    fn match_import_to_capability(&self, import: &str) -> Option<CapabilityInfo> {
        for rule in &self.capability_rules {
            if rule.matches_import(import) {
                return Some(CapabilityInfo {
                    name: rule.capability_name.clone(),
                    risk_level: rule.risk_level.clone(),
                });
            }
        }
        None
    }

    fn is_suspicious_export(&self, export: &str) -> bool {
        let suspicious_patterns = [
            "hook", "inject", "patch", "bypass", "crack",
            "keylog", "steal", "dump", "extract", "decrypt",
        ];
        
        let export_lower = export.to_lowercase();
        suspicious_patterns.iter().any(|pattern| export_lower.contains(pattern))
    }

    fn assess_capability_risk(&self, capability_name: &str, evidence: &[String]) -> RiskLevel {
        // Base risk assessment
        let base_risk = match capability_name {
            name if name.contains("privilege") || name.contains("setuid") => RiskLevel::Critical,
            name if name.contains("network") => RiskLevel::Medium,
            name if name.contains("file_write") => RiskLevel::Medium,
            name if name.contains("process_create") => RiskLevel::Medium,
            name if name.contains("file_read") => RiskLevel::Low,
            _ => RiskLevel::Low,
        };

        // Adjust based on evidence count
        let evidence_count = evidence.len();
        match (base_risk.clone(), evidence_count) {
            (RiskLevel::Low, count) if count > 5 => RiskLevel::Medium,
            (RiskLevel::Medium, count) if count > 3 => RiskLevel::High,
            (RiskLevel::High, count) if count > 2 => RiskLevel::Critical,
            _ => base_risk,
        }
    }

    fn get_capability_category(&self, capability_name: &str) -> String {
        match capability_name {
            name if name.contains("file") => "File System".to_string(),
            name if name.contains("network") || name.contains("socket") => "Network".to_string(),
            name if name.contains("process") => "Process Control".to_string(),
            name if name.contains("registry") => "Registry".to_string(),
            name if name.contains("debug") => "Debugging".to_string(),
            name if name.contains("memory") => "Memory".to_string(),
            name if name.contains("crypto") || name.contains("encrypt") => "Cryptography".to_string(),
            name if name.contains("hook") || name.contains("keyboard") || name.contains("mouse") => "Input Capture".to_string(),
            _ => "General".to_string(),
        }
    }

    fn get_capability_description(&self, capability_name: &str) -> String {
        match capability_name {
            "file_read" => "Can read files from the filesystem".to_string(),
            "file_write" => "Can write or modify files on the filesystem".to_string(),
            "file_create" => "Can create new files".to_string(),
            "file_delete" => "Can delete files".to_string(),
            "network_connect" => "Can establish network connections".to_string(),
            "network_send" => "Can send data over the network".to_string(),
            "network_receive" => "Can receive data from the network".to_string(),
            "process_create" => "Can create new processes".to_string(),
            "process_terminate" => "Can terminate processes".to_string(),
            "memory_read" => "Can read process memory".to_string(),
            "memory_write" => "Can write to process memory".to_string(),
            "registry_read" => "Can read Windows registry".to_string(),
            "registry_write" => "Can modify Windows registry".to_string(),
            "privilege_change" => "Can change user privileges".to_string(),
            "setuid" => "Can change user ID".to_string(),
            "cryptography" => "Has cryptographic capabilities".to_string(),
            "compression" => "Can compress or decompress data".to_string(),
            _ => format!("Unknown capability: {}", capability_name),
        }
    }

    fn initialize_capability_rules() -> Vec<CapabilityRule> {
        vec![
            // File system operations
            CapabilityRule::new("file_read", vec!["fopen", "read", "fread", "ReadFile"], RiskLevel::Low),
            CapabilityRule::new("file_write", vec!["fwrite", "write", "WriteFile", "fprintf"], RiskLevel::Medium),
            CapabilityRule::new("file_create", vec!["creat", "CreateFile"], RiskLevel::Medium),
            CapabilityRule::new("file_delete", vec!["unlink", "remove", "DeleteFile"], RiskLevel::Medium),
            
            // Network operations
            CapabilityRule::new("network_connect", vec!["connect", "WSAConnect"], RiskLevel::Medium),
            CapabilityRule::new("network_send", vec!["send", "sendto", "WSASend"], RiskLevel::Medium),
            CapabilityRule::new("network_receive", vec!["recv", "recvfrom", "WSARecv"], RiskLevel::Low),
            CapabilityRule::new("network_create", vec!["socket", "WSASocket"], RiskLevel::Medium),
            
            // Process operations
            CapabilityRule::new("process_create", vec!["fork", "exec", "CreateProcess", "system"], RiskLevel::Medium),
            CapabilityRule::new("process_terminate", vec!["kill", "TerminateProcess"], RiskLevel::High),
            CapabilityRule::new("process_enumerate", vec!["EnumProcesses", "CreateToolhelp32Snapshot"], RiskLevel::Medium),
            
            // Memory operations
            CapabilityRule::new("memory_read", vec!["ReadProcessMemory", "ptrace"], RiskLevel::High),
            CapabilityRule::new("memory_write", vec!["WriteProcessMemory"], RiskLevel::Critical),
            CapabilityRule::new("memory_allocate", vec!["VirtualAlloc", "malloc"], RiskLevel::Low),
            
            // Registry operations (Windows)
            CapabilityRule::new("registry_read", vec!["RegOpenKey", "RegQueryValue"], RiskLevel::Low),
            CapabilityRule::new("registry_write", vec!["RegSetValue", "RegCreateKey"], RiskLevel::High),
            
            // Security/privilege operations
            CapabilityRule::new("privilege_change", vec!["SetTokenInformation", "AdjustTokenPrivileges"], RiskLevel::Critical),
            CapabilityRule::new("service_control", vec!["CreateService", "OpenService", "ControlService"], RiskLevel::High),
            
            // Cryptography
            CapabilityRule::new("cryptography", vec!["CryptGenRandom", "BCrypt", "openssl", "crypto"], RiskLevel::Medium),
            CapabilityRule::new("encryption", vec!["AES", "RSA", "encrypt", "decrypt"], RiskLevel::Medium),
            
            // Input/UI operations
            CapabilityRule::new("keyboard_hook", vec!["SetWindowsHookEx", "GetAsyncKeyState"], RiskLevel::Critical),
            CapabilityRule::new("mouse_hook", vec!["SetCapture", "GetCursorPos"], RiskLevel::High),
            CapabilityRule::new("clipboard_access", vec!["GetClipboardData", "SetClipboardData"], RiskLevel::Medium),
            
            // Timing/delay
            CapabilityRule::new("delay_execution", vec!["Sleep", "usleep", "nanosleep"], RiskLevel::Low),
        ]
    }

    pub fn analyze_imports(&self, imports: &[String]) -> CapabilityAnalysisReport {
        let mut report = CapabilityAnalysisReport::new();
        let import_capabilities = self.extract_import_capabilities(imports);
        report.add_capabilities(import_capabilities);
        
        // Infer behavioral capabilities from imports
        let behavioral_capabilities = self.infer_behavioral_capabilities(&report);
        report.add_capabilities(behavioral_capabilities);
        
        report.assess_risk();
        report
    }

    pub fn get_network_capabilities(&self) -> Vec<Capability> {
        // Return network-related capability rules
        self.capability_rules.iter()
            .filter(|rule| {
                rule.capability_name.contains("network") || 
                rule.capability_name.contains("socket") ||
                rule.capability_name.contains("http") ||
                rule.capability_name.contains("dns")
            })
            .map(|rule| Capability {
                name: rule.capability_name.clone(),
                category: self.get_capability_category(&rule.capability_name),
                description: self.get_capability_description(&rule.capability_name),
                risk_level: rule.risk_level.clone(),
                evidence: Vec::new(),
            })
            .collect()
    }
}

impl Default for CapabilityAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct CapabilityAnalysisReport {
    pub capabilities: Vec<Capability>,
    pub behavioral_capabilities: Vec<Capability>,
    pub overall_risk: RiskLevel,
    pub capability_summary: HashMap<String, usize>,
    pub risk_score: f64,
    pub detected_behaviors: Vec<DetectedBehavior>,
}

#[derive(Debug, Clone)]
pub struct DetectedBehavior {
    pub behavior_type: String,
    pub confidence: f64,
    pub evidence: Vec<String>,
}

impl CapabilityAnalysisReport {
    pub fn new() -> Self {
        Self {
            capabilities: Vec::new(),
            behavioral_capabilities: Vec::new(),
            overall_risk: RiskLevel::Low,
            capability_summary: HashMap::new(),
            risk_score: 0.0,
            detected_behaviors: Vec::new(),
        }
    }

    pub fn add_capabilities(&mut self, mut capabilities: Vec<Capability>) {
        for capability in &capabilities {
            *self.capability_summary.entry(capability.name.clone()).or_insert(0) += 1;
        }
        self.capabilities.append(&mut capabilities);
    }

    pub fn has_capability(&self, capability_name: &str) -> bool {
        self.capabilities.iter()
            .any(|cap| cap.name.contains(capability_name))
    }

    pub fn assess_risk(&mut self) {
        let mut risk_score = 0;
        let mut capability_count = 0;

        for capability in &self.capabilities {
            capability_count += 1;
            risk_score += match capability.risk_level {
                RiskLevel::Low => 1,
                RiskLevel::Medium => 2,
                RiskLevel::High => 3,
                RiskLevel::Critical => 4,
            };
        }

        if capability_count > 0 {
            let average_risk = risk_score as f64 / capability_count as f64;
            self.risk_score = average_risk;
            self.overall_risk = match average_risk {
                x if x >= 3.5 => RiskLevel::Critical,
                x if x >= 2.5 => RiskLevel::High,
                x if x >= 1.5 => RiskLevel::Medium,
                _ => RiskLevel::Low,
            };
        }

        // Adjust for specific high-risk combinations
        if self.has_capability("privilege_change") || 
           self.has_capability("memory_write") ||
           self.has_capability("keyboard_hook") {
            self.overall_risk = RiskLevel::Critical;
        }
    }

    pub fn get_high_risk_capabilities(&self) -> Vec<&Capability> {
        self.capabilities.iter()
            .filter(|cap| matches!(cap.risk_level, RiskLevel::High | RiskLevel::Critical))
            .collect()
    }
}

impl Default for CapabilityAnalysisReport {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct CapabilityRule {
    capability_name: String,
    import_patterns: Vec<String>,
    risk_level: RiskLevel,
}

impl CapabilityRule {
    fn new(capability_name: &str, import_patterns: Vec<&str>, risk_level: RiskLevel) -> Self {
        Self {
            capability_name: capability_name.to_string(),
            import_patterns: import_patterns.into_iter().map(|s| s.to_string()).collect(),
            risk_level,
        }
    }

    fn matches_import(&self, import: &str) -> bool {
        let import_lower = import.to_lowercase();
        self.import_patterns.iter()
            .any(|pattern| import_lower.contains(&pattern.to_lowercase()))
    }
}

#[derive(Debug, Clone)]
struct CapabilityInfo {
    name: String,
    risk_level: RiskLevel,
}