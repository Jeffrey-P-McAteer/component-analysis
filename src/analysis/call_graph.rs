use crate::types::{CallGraph, Function, CallEdge, CallType, Instruction};
use crate::analysis::disassembly::{DisassemblyEngine, SyscallInfo};
use anyhow::Result;
use std::collections::{HashMap, HashSet, VecDeque};
use log::{debug, warn, info};

pub struct CallGraphBuilder<'a> {
    disassembler: &'a DisassemblyEngine,
    functions: HashMap<u64, Function>,
    call_graph: CallGraph,
    binary_base: u64,
    binary_data: Vec<u8>,
}

impl<'a> CallGraphBuilder<'a> {
    pub fn new(disassembler: &'a DisassemblyEngine, binary_base: u64, binary_data: Vec<u8>) -> Self {
        Self {
            disassembler,
            functions: HashMap::new(),
            call_graph: CallGraph::new(),
            binary_base,
            binary_data,
        }
    }

    pub fn add_function(&mut self, function: Function) {
        self.functions.insert(function.address, function.clone());
        self.call_graph.add_function(function.address, function);
    }

    pub fn build_call_graph(&mut self) -> Result<&CallGraph> {
        info!("Building call graph for {} functions", self.functions.len());

        // First pass: disassemble all functions and collect their instructions
        self.disassemble_all_functions()?;

        // Second pass: analyze call instructions and build edges
        self.analyze_call_relationships()?;

        // Third pass: resolve indirect calls where possible
        self.resolve_indirect_calls()?;

        info!("Call graph construction complete: {} functions, {} edges", 
              self.call_graph.functions.len(), 
              self.call_graph.edges.len());

        Ok(&self.call_graph)
    }

    fn disassemble_all_functions(&mut self) -> Result<()> {
        let function_addresses: Vec<u64> = self.functions.keys().copied().collect();
        
        for &address in &function_addresses {
            if let Some(function) = self.functions.get(&address).cloned() {
                match self.disassembler.disassemble_function(&self.binary_data, &function, self.binary_base) {
                    Ok(enhanced_function) => {
                        debug!("Disassembled function at 0x{:x}: {} instructions", 
                               address, enhanced_function.instructions.len());
                        self.functions.insert(address, enhanced_function.clone());
                        self.call_graph.add_function(address, enhanced_function);
                    }
                    Err(e) => {
                        warn!("Failed to disassemble function at 0x{:x}: {}", address, e);
                    }
                }
            }
        }

        Ok(())
    }

    fn analyze_call_relationships(&mut self) -> Result<()> {
        let mut total_calls = 0;

        for function in self.functions.values() {
            let call_edges = self.disassembler.analyze_calls(&function.instructions);
            
            for call_edge in call_edges {
                // Verify the target function exists or is an import
                if self.is_valid_call_target(call_edge.callee) {
                    self.call_graph.add_call(call_edge);
                    total_calls += 1;
                }
            }
        }

        debug!("Analyzed {} call relationships", total_calls);
        Ok(())
    }

    fn is_valid_call_target(&self, target: u64) -> bool {
        // Check if target is a known function
        if self.functions.contains_key(&target) {
            return true;
        }

        // Check if target could be an import (typically in PLT section)
        // This is a simplified check - in practice you'd verify against PLT addresses
        true // For now, assume all targets are valid
    }

    fn resolve_indirect_calls(&mut self) -> Result<()> {
        // This is a complex analysis that would involve:
        // 1. Tracking register values
        // 2. Analyzing jump tables
        // 3. Following function pointers
        // 4. Resolving virtual function calls
        
        // For now, implement a basic version that looks for common patterns
        debug!("Attempting to resolve indirect calls");
        
        let mut resolved_calls = 0;
        
        let functions: Vec<Function> = self.functions.values().cloned().collect();
        for function in functions {
            resolved_calls += self.resolve_function_indirect_calls(&function)?;
        }

        debug!("Resolved {} indirect calls", resolved_calls);
        Ok(())
    }

    fn resolve_function_indirect_calls(&mut self, function: &Function) -> Result<usize> {
        let mut resolved = 0;
        
        // Look for common indirect call patterns
        for (i, instruction) in function.instructions.iter().enumerate() {
            if self.is_indirect_call_instruction(&instruction.mnemonic) {
                // Try to resolve the target by looking at previous instructions
                if let Some(target) = self.analyze_indirect_call_target(function, i) {
                    let call_edge = CallEdge::new(
                        instruction.address,
                        target,
                        CallType::Indirect,
                        instruction.address,
                    );
                    
                    if self.is_valid_call_target(target) {
                        self.call_graph.add_call(call_edge);
                        resolved += 1;
                    }
                }
            }
        }
        
        Ok(resolved)
    }

    fn is_indirect_call_instruction(&self, mnemonic: &str) -> bool {
        matches!(mnemonic, "call" | "jmp") && 
        // Additional logic would check if the operand is indirect (e.g., memory reference)
        true // Simplified for now
    }

    fn analyze_indirect_call_target(&self, function: &Function, call_index: usize) -> Option<u64> {
        // This would implement pattern matching to resolve indirect calls
        // For example:
        // mov rax, [address]  ; Load function pointer
        // call rax           ; Indirect call
        
        // Look back a few instructions for patterns
        let start_index = call_index.saturating_sub(5);
        
        for i in start_index..call_index {
            if let Some(instruction) = function.instructions.get(i) {
                // Look for mov instructions that load addresses
                if instruction.mnemonic == "mov" && instruction.operands.len() >= 2 {
                    // Try to extract the address from the second operand
                    if let Some(addr) = self.extract_address_from_operand(&instruction.operands[1]) {
                        return Some(addr);
                    }
                }
            }
        }
        
        None
    }

    fn extract_address_from_operand(&self, operand: &str) -> Option<u64> {
        // Try to parse various address formats
        // [0x401000], 0x401000, etc.
        
        let cleaned = operand.trim_matches(|c| c == '[' || c == ']');
        
        if cleaned.starts_with("0x") {
            u64::from_str_radix(&cleaned[2..], 16).ok()
        } else {
            cleaned.parse::<u64>().ok()
        }
    }

    pub fn find_syscall_paths(&self) -> Result<Vec<SyscallPath>> {
        let mut syscall_paths = Vec::new();
        
        // Find all functions that contain syscalls
        let syscall_functions = self.find_syscall_functions();
        
        // For each syscall function, find all paths from main/entry points
        for (func_addr, syscalls) in syscall_functions {
            let paths = self.find_paths_to_function(func_addr)?;
            
            for syscall in syscalls {
                for path in &paths {
                    syscall_paths.push(SyscallPath {
                        syscall_info: syscall.clone(),
                        call_path: path.clone(),
                        function_address: func_addr,
                    });
                }
            }
        }
        
        Ok(syscall_paths)
    }

    fn find_syscall_functions(&self) -> HashMap<u64, Vec<SyscallInfo>> {
        let mut syscall_functions = HashMap::new();
        
        for function in self.functions.values() {
            let syscalls = self.disassembler.find_syscalls(&function.instructions);
            if !syscalls.is_empty() {
                syscall_functions.insert(function.address, syscalls);
            }
        }
        
        syscall_functions
    }

    fn find_paths_to_function(&self, target: u64) -> Result<Vec<Vec<u64>>> {
        let mut paths = Vec::new();
        
        // Find entry points (functions not called by others or main function)
        let entry_points = self.find_entry_points();
        
        for entry_point in entry_points {
            let mut path_queue = VecDeque::new();
            let mut visited = HashSet::new();
            
            path_queue.push_back(vec![entry_point]);
            
            while let Some(current_path) = path_queue.pop_front() {
                let current_func = *current_path.last().unwrap();
                
                if current_func == target {
                    paths.push(current_path);
                    continue;
                }
                
                if visited.contains(&current_func) || current_path.len() > 20 {
                    continue; // Avoid cycles and overly long paths
                }
                
                visited.insert(current_func);
                
                // Find all functions called by the current function
                for call_edge in self.call_graph.get_callees(current_func) {
                    let mut new_path = current_path.clone();
                    new_path.push(call_edge.callee);
                    path_queue.push_back(new_path);
                }
            }
        }
        
        Ok(paths)
    }

    fn find_entry_points(&self) -> Vec<u64> {
        let mut called_functions = HashSet::new();
        
        // Collect all functions that are called by others
        for edge in &self.call_graph.edges {
            called_functions.insert(edge.callee);
        }
        
        // Entry points are functions that exist but are not called by others
        let mut entry_points = Vec::new();
        for &func_addr in self.functions.keys() {
            if !called_functions.contains(&func_addr) {
                entry_points.push(func_addr);
            }
        }
        
        // Also add main function if we can identify it
        if let Some(main_addr) = self.find_main_function() {
            if !entry_points.contains(&main_addr) {
                entry_points.push(main_addr);
            }
        }
        
        entry_points
    }

    fn find_main_function(&self) -> Option<u64> {
        // Look for function named "main" or the entry point
        for function in self.functions.values() {
            if let Some(name) = &function.name {
                if name == "main" {
                    return Some(function.address);
                }
            }
        }
        
        // Could also check the entry point from the binary header
        None
    }

    pub fn get_call_graph(&self) -> &CallGraph {
        &self.call_graph
    }

    pub fn get_function_call_count(&self, address: u64) -> usize {
        self.call_graph.get_callees(address).len()
    }

    pub fn get_function_caller_count(&self, address: u64) -> usize {
        self.call_graph.get_callers(address).len()
    }

    pub fn analyze_function_complexity(&self, address: u64) -> Option<FunctionComplexity> {
        let function = self.functions.get(&address)?;
        
        let instruction_count = function.instructions.len();
        let call_count = self.get_function_call_count(address);
        let caller_count = self.get_function_caller_count(address);
        
        // Calculate cyclomatic complexity (simplified)
        let branches = self.count_branch_instructions(function);
        let cyclomatic_complexity = branches + 1;
        
        Some(FunctionComplexity {
            address,
            instruction_count,
            call_count,
            caller_count,
            cyclomatic_complexity,
            has_loops: self.detect_loops_in_function(function),
        })
    }

    fn count_branch_instructions(&self, function: &Function) -> usize {
        function.instructions.iter()
            .filter(|inst| self.is_branch_instruction(&inst.mnemonic))
            .count()
    }

    fn is_branch_instruction(&self, mnemonic: &str) -> bool {
        matches!(mnemonic, 
            "jmp" | "je" | "jne" | "jz" | "jnz" | "jg" | "jl" | "jge" | "jle" |
            "ja" | "jb" | "jae" | "jbe" | "jo" | "jno" | "js" | "jns" |
            "b" | "beq" | "bne" | "bgt" | "blt" | "bge" | "ble" | "bl" | "blx"
        )
    }

    fn detect_loops_in_function(&self, function: &Function) -> bool {
        // Simple loop detection by looking for backward jumps
        for instruction in &function.instructions {
            if self.is_branch_instruction(&instruction.mnemonic) {
                if let Some(target) = self.extract_branch_target(instruction) {
                    if target < instruction.address {
                        return true; // Backward jump indicates a loop
                    }
                }
            }
        }
        false
    }

    fn extract_branch_target(&self, instruction: &Instruction) -> Option<u64> {
        // Similar to call target extraction but for branches
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
}

#[derive(Debug, Clone)]
pub struct SyscallPath {
    pub syscall_info: SyscallInfo,
    pub call_path: Vec<u64>,
    pub function_address: u64,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct FunctionComplexity {
    pub address: u64,
    pub instruction_count: usize,
    pub call_count: usize,
    pub caller_count: usize,
    pub cyclomatic_complexity: usize,
    pub has_loops: bool,
}