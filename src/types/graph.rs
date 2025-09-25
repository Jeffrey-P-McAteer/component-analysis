use crate::types::{Component, Relationship};
use petgraph::{Graph, Directed};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type ComponentGraph = Graph<Component, Relationship, Directed>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraph {
    pub functions: HashMap<u64, Function>,
    pub edges: Vec<CallEdge>,
}

impl CallGraph {
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
            edges: Vec::new(),
        }
    }

    pub fn add_function(&mut self, address: u64, function: Function) {
        self.functions.insert(address, function);
    }

    pub fn add_call(&mut self, edge: CallEdge) {
        self.edges.push(edge);
    }

    pub fn get_function(&self, address: &u64) -> Option<&Function> {
        self.functions.get(address)
    }

    pub fn get_callers(&self, target: u64) -> Vec<&CallEdge> {
        self.edges.iter().filter(|e| e.callee == target).collect()
    }

    pub fn get_callees(&self, source: u64) -> Vec<&CallEdge> {
        self.edges.iter().filter(|e| e.caller == source).collect()
    }
}

impl Default for CallGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    pub address: u64,
    pub name: Option<String>,
    pub size: Option<u64>,
    pub instructions: Vec<Instruction>,
    pub local_variables: Vec<Variable>,
    pub parameters: Vec<Parameter>,
    pub return_type: Option<String>,
}

impl Function {
    pub fn new(address: u64) -> Self {
        Self {
            address,
            name: None,
            size: None,
            instructions: Vec::new(),
            local_variables: Vec::new(),
            parameters: Vec::new(),
            return_type: None,
        }
    }

    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEdge {
    pub caller: u64,
    pub callee: u64,
    pub call_type: CallType,
    pub instruction_address: u64,
}

impl CallEdge {
    pub fn new(caller: u64, callee: u64, call_type: CallType, instruction_address: u64) -> Self {
        Self {
            caller,
            callee,
            call_type,
            instruction_address,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CallType {
    Direct,
    Indirect,
    Import,
    Tail,
}

impl std::fmt::Display for CallType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallType::Direct => write!(f, "direct"),
            CallType::Indirect => write!(f, "indirect"),
            CallType::Import => write!(f, "import"),
            CallType::Tail => write!(f, "tail"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub address: u64,
    pub mnemonic: String,
    pub operands: Vec<String>,
    pub bytes: Vec<u8>,
    pub size: u32,
}

impl Instruction {
    pub fn new(address: u64, mnemonic: String, operands: Vec<String>, bytes: Vec<u8>) -> Self {
        let size = bytes.len() as u32;
        Self {
            address,
            mnemonic,
            operands,
            bytes,
            size,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variable {
    pub name: String,
    pub var_type: String,
    pub offset: Option<i32>,
    pub size: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub param_type: String,
    pub register: Option<String>,
    pub offset: Option<i32>,
}