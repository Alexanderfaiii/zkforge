//! ZKForge Compiler — AST definitions and core types.
//!
//! This module defines the Abstract Syntax Tree that represents
//! a ZK proof program after parsing the DSL.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A complete ZK proof program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Program {
    pub name: String,
    pub statements: Vec<Statement>,
    pub source_info: SourceInfo,
}

/// A top-level statement in the DSL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Statement {
    ProveBlock(ProveBlock),
    Import(String),
    Comment(String),
}

/// A `prove { ... }` block — the core unit of a ZK program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveBlock {
    pub name: Option<String>,
    pub inputs: Vec<InputDecl>,
    pub assertions: Vec<AssertStmt>,
    pub outputs: Vec<OutputDecl>,
}

/// An input signal declaration.
/// `prove { input age: Private<u8>; }`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDecl {
    pub name: String,
    pub privacy: Privacy,
    pub ty: DataType,
}

/// Privacy level of an input signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Privacy {
    /// Private input — part of the witness, not revealed on-chain
    Private,
    /// Public input — part of the instance, revealed on-chain
    Public,
}

/// Supported data types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataType {
    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    Bool,
    Address,
}

impl DataType {
    /// Bit width of the type.
    pub fn bits(&self) -> u32 {
        match self {
            DataType::U8 => 8,
            DataType::U16 => 16,
            DataType::U32 => 32,
            DataType::U64 => 64,
            DataType::U128 => 128,
            DataType::U256 => 256,
            DataType::Bool => 1,
            DataType::Address => 160,
        }
    }

    /// Circom signal type name.
    pub fn to_circom_signal(&self) -> &'static str {
        match self {
            DataType::U8 | DataType::U16 | DataType::U32 => "signal",
            DataType::U64 | DataType::U128 | DataType::U256 => "signal",
            DataType::Bool => "signal",
            DataType::Address => "signal",
        }
    }
}

impl fmt::Display for DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataType::U8 => write!(f, "u8"),
            DataType::U16 => write!(f, "u16"),
            DataType::U32 => write!(f, "u32"),
            DataType::U64 => write!(f, "u64"),
            DataType::U128 => write!(f, "u128"),
            DataType::U256 => write!(f, "u256"),
            DataType::Bool => write!(f, "bool"),
            DataType::Address => write!(f, "address"),
        }
    }
}

/// An assertion statement.
/// `assert age >= 18;`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertStmt {
    pub expr: Expression,
}

/// An output signal declaration.
/// `output valid<bool>;`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputDecl {
    pub name: String,
    pub ty: DataType,
}

/// Expressions that can appear in assertions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Expression {
    /// A binary comparison: `age >= 18`
    Comparison {
        left: Box<Expression>,
        op: ComparisonOp,
        right: Box<Expression>,
    },
    /// A variable reference
    Variable(String),
    /// A numeric literal
    Number(String), // Stored as string to handle u256
    /// A boolean literal
    Bool(bool),
    /// Arithmetic: a + b, a * b, etc.
    Arithmetic {
        left: Box<Expression>,
        op: ArithmeticOp,
        right: Box<Expression>,
    },
    /// Function call: `merkle_verify(root, path, leaf)`
    FunctionCall {
        name: String,
        args: Vec<Expression>,
    },
    /// Parenthesized expression
    Paren(Box<Expression>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComparisonOp {
    Gt,
    GtEq,
    Lt,
    LtEq,
    Eq,
    NotEq,
}

impl fmt::Display for ComparisonOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComparisonOp::Gt => write!(f, ">"),
            ComparisonOp::GtEq => write!(f, ">="),
            ComparisonOp::Lt => write!(f, "<"),
            ComparisonOp::LtEq => write!(f, "<="),
            ComparisonOp::Eq => write!(f, "=="),
            ComparisonOp::NotEq => write!(f, "!="),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArithmeticOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
}

/// Source location information for error reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceInfo {
    pub file: String,
    /// Line number → column position
    pub spans: Vec<Span>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Span {
    pub line: usize,
    pub col: usize,
    pub len: usize,
}

/// Type-checking and semantic analysis of a ProveBlock.
impl ProveBlock {
    /// Returns the set of private signals (they become witness inputs).
    pub fn private_signals(&self) -> Vec<&InputDecl> {
        self.inputs
            .iter()
            .filter(|i| i.privacy == Privacy::Private)
            .collect()
    }

    /// Returns the set of public signals (they become instance inputs).
    pub fn public_signals(&self) -> Vec<&InputDecl> {
        self.inputs
            .iter()
            .filter(|i| i.privacy == Privacy::Public)
            .collect()
    }

    /// All signal names in order of declaration.
    pub fn all_signal_names(&self) -> Vec<&str> {
        self.inputs.iter().map(|i| i.name.as_str()).collect()
    }

    /// Count the total number of assertions.
    pub fn assertion_count(&self) -> usize {
        self.assertions.len()
    }

    /// Estimate circuit complexity (rough constraint count without optimization).
    pub fn estimated_constraints(&self) -> usize {
        let mut count = 0;
        for a in &self.assertions {
            count += a.expr.estimated_constraints(&self.inputs);
        }
        count
    }
}

impl Expression {
    /// Rough constraint estimation.
    pub fn estimated_constraints(&self, inputs: &[InputDecl]) -> usize {
        match self {
            Expression::Comparison { left, right, .. } => {
                // Find the type of the compared variables
                let ty = self.resolve_type(inputs);
                let base = left.estimated_constraints(inputs) + right.estimated_constraints(inputs);
                match ty {
                    Some(DataType::U256) | Some(DataType::U128) => base + 256, // full range check
                    Some(DataType::U64) => base + 64,
                    Some(DataType::U32) => base + 32,
                    _ => base + 16,
                }
            }
            Expression::Arithmetic { left, right, .. } => {
                left.estimated_constraints(inputs) + right.estimated_constraints(inputs) + 1
            }
            Expression::FunctionCall { name, args } => {
                let args_cost: usize = args.iter().map(|a| a.estimated_constraints(inputs)).sum();
                match name.as_str() {
                    "merkle_verify" => args_cost + 256 * 20, // ~20 levels * 256-bit hash
                    "hash" | "poseidon" => args_cost + 250,
                    "ecdsa_verify" => args_cost + 20_000,
                    "signature_verify" => args_cost + 15_000,
                    _ => args_cost + 100, // unknown function
                }
            }
            Expression::Paren(inner) => inner.estimated_constraints(inputs),
            Expression::Variable(_) | Expression::Number(_) | Expression::Bool(_) => 0,
        }
    }

    /// Try to resolve the type of this expression.
    pub fn resolve_type(&self, inputs: &[InputDecl]) -> Option<DataType> {
        match self {
            Expression::Variable(name) => {
                inputs.iter().find(|i| i.name == *name).map(|i| i.ty)
            }
            Expression::Comparison { left, right, .. } => {
                left.resolve_type(inputs).or(right.resolve_type(inputs))
            }
            Expression::Arithmetic { left, right, .. } => {
                left.resolve_type(inputs).or(right.resolve_type(inputs))
            }
            Expression::FunctionCall { .. } => Some(DataType::Bool),
            Expression::Paren(inner) => inner.resolve_type(inputs),
            Expression::Number(_) => None,
            Expression::Bool(_) => Some(DataType::Bool),
        }
    }
}
