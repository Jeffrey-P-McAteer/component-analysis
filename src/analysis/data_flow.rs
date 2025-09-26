use crate::types::{Function, Instruction, CallGraph, Component, AnalysisResult, AnalysisType, RiskLevel};
use crate::analysis::disassembly::DisassemblyEngine;
use anyhow::Result;
use std::collections::{HashMap, HashSet, VecDeque};
use log::{debug, info};

#[derive(Debug, Clone)]
pub struct DataFlowAnalyzer {
    functions: HashMap<u64, Function>,
    call_graph: CallGraph,
    taint_sources: Vec<TaintSource>,
    taint_sinks: Vec<TaintSink>,
}

#[derive(Debug, Clone)]
pub struct TaintSource {
    pub source_type: TaintSourceType,
    pub function_pattern: String,
    pub instruction_pattern: String,
    pub description: String,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone)]
pub enum TaintSourceType {
    UserInput,
    NetworkInput,
    FileInput,
    EnvironmentInput,
    CommandLineInput,
    RegistryInput,
}

#[derive(Debug, Clone)]
pub struct TaintSink {
    pub sink_type: TaintSinkType,
    pub function_pattern: String,
    pub instruction_pattern: String,
    pub description: String,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone)]
pub enum TaintSinkType {
    SystemCall,
    NetworkOutput,
    FileOutput,
    ProcessExecution,
    MemoryWrite,
    RegistryWrite,
}

#[derive(Debug, Clone)]
pub struct TaintPath {
    pub source: TaintSource,
    pub sink: TaintSink,
    pub path: Vec<TaintFlowNode>,
    pub risk_level: RiskLevel,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
pub struct TaintFlowNode {
    pub function_address: u64,
    pub instruction_address: u64,
    pub operation_type: FlowOperationType,
    pub registers_affected: Vec<String>,
    pub memory_affected: Vec<MemoryRegion>,
}

#[derive(Debug, Clone)]
pub enum FlowOperationType {
    Assignment,
    Arithmetic,
    Comparison,
    Branch,
    Call,
    Return,
    Load,
    Store,
}

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base_address: Option<u64>,
    pub offset: Option<i64>,
    pub size: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct DataFlowReport {
    pub taint_paths: Vec<TaintPath>,
    pub data_dependencies: Vec<DataDependency>,
    pub control_dependencies: Vec<ControlDependency>,
    pub overall_risk: RiskLevel,
    pub summary: DataFlowSummary,
}

#[derive(Debug, Clone)]
pub struct DataDependency {
    pub from_instruction: u64,
    pub to_instruction: u64,
    pub dependency_type: DataDependencyType,
    pub data_flow_type: String,
}

#[derive(Debug, Clone)]
pub enum DataDependencyType {
    DirectFlow,
    IndirectFlow,
    ControlFlow,
    MemoryAlias,
}

#[derive(Debug, Clone)]
pub struct ControlDependency {
    pub control_instruction: u64,
    pub dependent_instruction: u64,
    pub condition_type: String,
}

#[derive(Debug, Clone)]
pub struct DataFlowSummary {
    pub total_paths: usize,
    pub high_risk_paths: usize,
    pub source_count: HashMap<TaintSourceType, usize>,
    pub sink_count: HashMap<TaintSinkType, usize>,
}

impl DataFlowAnalyzer {
    pub fn new() -> Self {
        let mut analyzer = Self {
            functions: HashMap::new(),
            call_graph: CallGraph::new(),
            taint_sources: Vec::new(),
            taint_sinks: Vec::new(),
        };
        
        analyzer.initialize_taint_definitions();
        analyzer
    }

    pub fn set_call_graph(&mut self, call_graph: CallGraph) {
        // Extract functions from call graph
        for (address, function) in &call_graph.functions {
            self.functions.insert(*address, function.clone());
        }
        self.call_graph = call_graph;
    }

    pub fn analyze_data_flow(&self) -> Result<DataFlowReport> {
        info!("Starting data flow analysis");
        
        let mut taint_paths = Vec::new();
        let mut data_dependencies = Vec::new();
        let mut control_dependencies = Vec::new();

        // Find all potential taint sources in the analyzed functions
        let sources = self.find_taint_sources()?;
        info!("Found {} potential taint sources", sources.len());

        // Find all potential taint sinks
        let sinks = self.find_taint_sinks()?;
        info!("Found {} potential taint sinks", sinks.len());

        // Perform taint propagation analysis
        for source_location in &sources {
            let paths = self.trace_taint_propagation(source_location, &sinks)?;
            taint_paths.extend(paths);
        }

        info!("Found {} taint propagation paths", taint_paths.len());

        // Analyze data dependencies within functions
        for function in self.functions.values() {
            let deps = self.analyze_function_data_dependencies(function)?;
            data_dependencies.extend(deps);
        }

        // Analyze control dependencies
        for function in self.functions.values() {
            let deps = self.analyze_function_control_dependencies(function)?;
            control_dependencies.extend(deps);
        }

        let overall_risk = self.calculate_overall_risk(&taint_paths);
        let summary = self.generate_summary(&taint_paths);

        Ok(DataFlowReport {
            taint_paths,
            data_dependencies,
            control_dependencies,
            overall_risk,
            summary,
        })
    }

    fn initialize_taint_definitions(&mut self) {
        // Initialize common taint sources
        self.taint_sources = vec![
            TaintSource {
                source_type: TaintSourceType::UserInput,
                function_pattern: "scanf|gets|fgets|read|recv".to_string(),
                instruction_pattern: "call.*".to_string(),
                description: "User input from stdin or console".to_string(),
                risk_level: RiskLevel::Medium,
            },
            TaintSource {
                source_type: TaintSourceType::NetworkInput,
                function_pattern: "recv|recvfrom|accept|read".to_string(),
                instruction_pattern: "call.*".to_string(),
                description: "Network input data".to_string(),
                risk_level: RiskLevel::High,
            },
            TaintSource {
                source_type: TaintSourceType::FileInput,
                function_pattern: "fread|read|ReadFile".to_string(),
                instruction_pattern: "call.*".to_string(),
                description: "File input data".to_string(),
                risk_level: RiskLevel::Medium,
            },
            TaintSource {
                source_type: TaintSourceType::CommandLineInput,
                function_pattern: "getopt|GetCommandLine".to_string(),
                instruction_pattern: "call.*".to_string(),
                description: "Command line arguments".to_string(),
                risk_level: RiskLevel::Low,
            },
        ];

        // Initialize common taint sinks
        self.taint_sinks = vec![
            TaintSink {
                sink_type: TaintSinkType::SystemCall,
                function_pattern: "system|exec|execve|CreateProcess".to_string(),
                instruction_pattern: "call.*|syscall|int.*".to_string(),
                description: "System command execution".to_string(),
                risk_level: RiskLevel::Critical,
            },
            TaintSink {
                sink_type: TaintSinkType::NetworkOutput,
                function_pattern: "send|sendto|write".to_string(),
                instruction_pattern: "call.*".to_string(),
                description: "Network data transmission".to_string(),
                risk_level: RiskLevel::High,
            },
            TaintSink {
                sink_type: TaintSinkType::FileOutput,
                function_pattern: "fwrite|write|WriteFile".to_string(),
                instruction_pattern: "call.*".to_string(),
                description: "File write operation".to_string(),
                risk_level: RiskLevel::Medium,
            },
            TaintSink {
                sink_type: TaintSinkType::ProcessExecution,
                function_pattern: "fork|CreateThread|CreateProcess".to_string(),
                instruction_pattern: "call.*".to_string(),
                description: "Process or thread creation".to_string(),
                risk_level: RiskLevel::High,
            },
        ];
    }

    fn find_taint_sources(&self) -> Result<Vec<(u64, u64, TaintSource)>> {
        let mut sources = Vec::new();
        
        for function in self.functions.values() {
            for instruction in &function.instructions {
                for source in &self.taint_sources {
                    if self.instruction_matches_pattern(instruction, &source.function_pattern, &source.instruction_pattern) {
                        sources.push((function.address, instruction.address, source.clone()));
                        debug!("Found taint source at {}:0x{:x}", function.address, instruction.address);
                    }
                }
            }
        }
        
        Ok(sources)
    }

    fn find_taint_sinks(&self) -> Result<Vec<(u64, u64, TaintSink)>> {
        let mut sinks = Vec::new();
        
        for function in self.functions.values() {
            for instruction in &function.instructions {
                for sink in &self.taint_sinks {
                    if self.instruction_matches_pattern(instruction, &sink.function_pattern, &sink.instruction_pattern) {
                        sinks.push((function.address, instruction.address, sink.clone()));
                        debug!("Found taint sink at {}:0x{:x}", function.address, instruction.address);
                    }
                }
            }
        }
        
        Ok(sinks)
    }

    fn instruction_matches_pattern(&self, instruction: &Instruction, function_pattern: &str, instruction_pattern: &str) -> bool {
        // Simple pattern matching - would use regex in production
        let mnemonic = instruction.mnemonic.to_lowercase();
        let operands = instruction.operands.join(" ").to_lowercase();
        
        // Check if instruction mnemonic matches
        if instruction_pattern.contains(&mnemonic) {
            return true;
        }

        // Check if any operand contains function pattern keywords
        for keyword in function_pattern.split('|') {
            if operands.contains(keyword) {
                return true;
            }
        }

        false
    }

    fn trace_taint_propagation(
        &self, 
        source: &(u64, u64, TaintSource), 
        sinks: &[(u64, u64, TaintSink)]
    ) -> Result<Vec<TaintPath>> {
        let mut paths = Vec::new();
        let (source_func, source_addr, source_def) = source;

        // Use a simplified taint propagation algorithm
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        
        queue.push_back((*source_func, *source_addr, Vec::new()));

        while let Some((current_func, current_addr, path)) = queue.pop_front() {
            if visited.contains(&(current_func, current_addr)) {
                continue;
            }
            visited.insert((current_func, current_addr));

            // Check if current location is a sink
            for (sink_func, sink_addr, sink_def) in sinks {
                if current_func == *sink_func && current_addr == *sink_addr {
                    let taint_path = TaintPath {
                        source: source_def.clone(),
                        sink: sink_def.clone(),
                        path: path.clone(),
                        risk_level: self.calculate_path_risk(&source_def.risk_level, &sink_def.risk_level),
                        confidence: self.calculate_path_confidence(&path),
                    };
                    paths.push(taint_path);
                    continue;
                }
            }

            // Follow control flow and data flow
            if let Some(function) = self.functions.get(&current_func) {
                for instruction in &function.instructions {
                    if instruction.address > current_addr {
                        let mut new_path = path.clone();
                        new_path.push(TaintFlowNode {
                            function_address: current_func,
                            instruction_address: instruction.address,
                            operation_type: self.classify_operation(&instruction.mnemonic),
                            registers_affected: self.extract_registers(&instruction.operands),
                            memory_affected: self.extract_memory_regions(&instruction.operands),
                        });

                        if new_path.len() < 50 { // Prevent infinite loops
                            queue.push_back((current_func, instruction.address, new_path));
                        }
                    }
                }
            }

            // Follow function calls
            for call_edge in self.call_graph.get_callees(current_func) {
                if let Some(callee_function) = self.functions.get(&call_edge.callee) {
                    let mut new_path = path.clone();
                    new_path.push(TaintFlowNode {
                        function_address: call_edge.callee,
                        instruction_address: callee_function.address,
                        operation_type: FlowOperationType::Call,
                        registers_affected: Vec::new(),
                        memory_affected: Vec::new(),
                    });

                    if new_path.len() < 50 {
                        queue.push_back((call_edge.callee, callee_function.address, new_path));
                    }
                }
            }
        }

        Ok(paths)
    }

    fn analyze_function_data_dependencies(&self, function: &Function) -> Result<Vec<DataDependency>> {
        let mut dependencies = Vec::new();
        
        // Simplified data dependency analysis
        for (i, instruction) in function.instructions.iter().enumerate() {
            let write_regs = self.get_write_registers(&instruction.mnemonic, &instruction.operands);
            
            // Look for subsequent instructions that read these registers
            for (j, later_instruction) in function.instructions.iter().enumerate().skip(i + 1) {
                let read_regs = self.get_read_registers(&later_instruction.mnemonic, &later_instruction.operands);
                
                for write_reg in &write_regs {
                    if read_regs.contains(write_reg) {
                        dependencies.push(DataDependency {
                            from_instruction: instruction.address,
                            to_instruction: later_instruction.address,
                            dependency_type: DataDependencyType::DirectFlow,
                            data_flow_type: format!("register_{}", write_reg),
                        });
                    }
                }
            }
        }
        
        Ok(dependencies)
    }

    fn analyze_function_control_dependencies(&self, function: &Function) -> Result<Vec<ControlDependency>> {
        let mut dependencies = Vec::new();
        
        for instruction in &function.instructions {
            if self.is_branch_instruction(&instruction.mnemonic) {
                // Find instructions that are control-dependent on this branch
                let target_addr = self.extract_branch_target(instruction);
                if let Some(target) = target_addr {
                    dependencies.push(ControlDependency {
                        control_instruction: instruction.address,
                        dependent_instruction: target,
                        condition_type: instruction.mnemonic.clone(),
                    });
                }
            }
        }
        
        Ok(dependencies)
    }

    fn classify_operation(&self, mnemonic: &str) -> FlowOperationType {
        match mnemonic.to_lowercase().as_str() {
            "mov" | "movq" | "movl" => FlowOperationType::Assignment,
            "add" | "sub" | "mul" | "div" => FlowOperationType::Arithmetic,
            "cmp" | "test" => FlowOperationType::Comparison,
            "jmp" | "je" | "jne" | "jz" | "jnz" => FlowOperationType::Branch,
            "call" => FlowOperationType::Call,
            "ret" => FlowOperationType::Return,
            "ld" | "ldr" | "load" => FlowOperationType::Load,
            "st" | "str" | "store" => FlowOperationType::Store,
            _ => FlowOperationType::Assignment,
        }
    }

    fn extract_registers(&self, operands: &[String]) -> Vec<String> {
        let mut registers = Vec::new();
        for operand in operands {
            if operand.starts_with('%') || operand.starts_with('r') || operand.starts_with('e') {
                registers.push(operand.clone());
            }
        }
        registers
    }

    fn extract_memory_regions(&self, operands: &[String]) -> Vec<MemoryRegion> {
        let mut regions = Vec::new();
        for operand in operands {
            if operand.contains('[') && operand.contains(']') {
                regions.push(MemoryRegion {
                    base_address: None,
                    offset: None,
                    size: None,
                });
            }
        }
        regions
    }

    fn get_write_registers(&self, mnemonic: &str, operands: &[String]) -> Vec<String> {
        match mnemonic.to_lowercase().as_str() {
            "mov" | "movq" | "movl" | "add" | "sub" => {
                if !operands.is_empty() {
                    vec![operands[0].clone()]
                } else {
                    Vec::new()
                }
            }
            _ => Vec::new(),
        }
    }

    fn get_read_registers(&self, mnemonic: &str, operands: &[String]) -> Vec<String> {
        match mnemonic.to_lowercase().as_str() {
            "mov" | "movq" | "movl" => {
                if operands.len() > 1 {
                    vec![operands[1].clone()]
                } else {
                    Vec::new()
                }
            }
            "add" | "sub" | "cmp" => {
                operands.iter().cloned().collect()
            }
            _ => operands.iter().cloned().collect(),
        }
    }

    fn is_branch_instruction(&self, mnemonic: &str) -> bool {
        matches!(mnemonic.to_lowercase().as_str(), 
            "jmp" | "je" | "jne" | "jz" | "jnz" | "jg" | "jl" | "jge" | "jle" |
            "ja" | "jb" | "jae" | "jbe" | "jo" | "jno" | "js" | "jns" |
            "b" | "beq" | "bne" | "bgt" | "blt" | "bge" | "ble"
        )
    }

    fn extract_branch_target(&self, instruction: &Instruction) -> Option<u64> {
        if instruction.operands.is_empty() {
            return None;
        }

        let operand = &instruction.operands[0];
        if operand.starts_with("0x") {
            u64::from_str_radix(&operand[2..], 16).ok()
        } else {
            operand.parse::<u64>().ok()
        }
    }

    fn calculate_path_risk(&self, source_risk: &RiskLevel, sink_risk: &RiskLevel) -> RiskLevel {
        match (source_risk, sink_risk) {
            (RiskLevel::Critical, _) | (_, RiskLevel::Critical) => RiskLevel::Critical,
            (RiskLevel::High, RiskLevel::High) => RiskLevel::Critical,
            (RiskLevel::High, _) | (_, RiskLevel::High) => RiskLevel::High,
            (RiskLevel::Medium, RiskLevel::Medium) => RiskLevel::High,
            (RiskLevel::Medium, _) | (_, RiskLevel::Medium) => RiskLevel::Medium,
            _ => RiskLevel::Low,
        }
    }

    fn calculate_path_confidence(&self, path: &[TaintFlowNode]) -> f64 {
        // Simple confidence calculation based on path length and complexity
        let base_confidence = 0.8;
        let length_penalty = (path.len() as f64) * 0.02;
        (base_confidence - length_penalty).max(0.1)
    }

    fn calculate_overall_risk(&self, paths: &[TaintPath]) -> RiskLevel {
        if paths.is_empty() {
            return RiskLevel::Low;
        }

        let high_risk_count = paths.iter()
            .filter(|p| matches!(p.risk_level, RiskLevel::High | RiskLevel::Critical))
            .count();

        if high_risk_count > 0 {
            RiskLevel::High
        } else {
            RiskLevel::Medium
        }
    }

    fn generate_summary(&self, paths: &[TaintPath]) -> DataFlowSummary {
        let mut source_count = HashMap::new();
        let mut sink_count = HashMap::new();
        let high_risk_paths = paths.iter()
            .filter(|p| matches!(p.risk_level, RiskLevel::High | RiskLevel::Critical))
            .count();

        for path in paths {
            *source_count.entry(path.source.source_type.clone()).or_insert(0) += 1;
            *sink_count.entry(path.sink.sink_type.clone()).or_insert(0) += 1;
        }

        DataFlowSummary {
            total_paths: paths.len(),
            high_risk_paths,
            source_count,
            sink_count,
        }
    }

    pub fn create_analysis_result(&self, component_id: String, report: DataFlowReport) -> AnalysisResult {
        let results = serde_json::json!({
            "total_taint_paths": report.taint_paths.len(),
            "high_risk_paths": report.summary.high_risk_paths,
            "data_dependencies": report.data_dependencies.len(),
            "control_dependencies": report.control_dependencies.len(),
            "overall_risk": report.overall_risk,
            "taint_paths": report.taint_paths.iter().map(|path| {
                serde_json::json!({
                    "source_type": format!("{:?}", path.source.source_type),
                    "sink_type": format!("{:?}", path.sink.sink_type),
                    "risk_level": path.risk_level,
                    "confidence": path.confidence,
                    "path_length": path.path.len(),
                })
            }).collect::<Vec<_>>(),
        });

        AnalysisResult::new(component_id, AnalysisType::DataFlow, results)
    }
}

impl Default for DataFlowAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// Implement Display for various types
impl std::fmt::Display for TaintSourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaintSourceType::UserInput => write!(f, "User Input"),
            TaintSourceType::NetworkInput => write!(f, "Network Input"),
            TaintSourceType::FileInput => write!(f, "File Input"),
            TaintSourceType::EnvironmentInput => write!(f, "Environment Input"),
            TaintSourceType::CommandLineInput => write!(f, "Command Line Input"),
            TaintSourceType::RegistryInput => write!(f, "Registry Input"),
        }
    }
}

impl std::fmt::Display for TaintSinkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaintSinkType::SystemCall => write!(f, "System Call"),
            TaintSinkType::NetworkOutput => write!(f, "Network Output"),
            TaintSinkType::FileOutput => write!(f, "File Output"),
            TaintSinkType::ProcessExecution => write!(f, "Process Execution"),
            TaintSinkType::MemoryWrite => write!(f, "Memory Write"),
            TaintSinkType::RegistryWrite => write!(f, "Registry Write"),
        }
    }
}