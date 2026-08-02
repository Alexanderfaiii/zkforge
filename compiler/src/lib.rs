#![allow(dead_code)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::obfuscated_if_else)]
#![allow(clippy::type_complexity)]

//! ZKForge Compiler — No-Code ZK Circuit Generator
//!
//! # Overview
//!
//! ZKForge compiles a high-level DSL into zero-knowledge proof circuits.
//! Users describe what they want to prove in a simple language,
//! and ZKForge generates the complete circuit, prover, verifier,
//! and deployment scripts.
//!
//! # Architecture
//!
//! 1. **Parser** — Parses `.zkf` files into AST
//! 2. **Constraint Synthesizer** — Converts AST into R1CS constraints
//! 3. **Code Generator** — Emits circom/Solidity/Foundry code
//!
//! # Example
//!
//! ```text
//! prove {
//!     input age: Private<u8>;
//!     input threshold: Public<u8>;
//!     assert age >= 18;
//!     output valid<bool>;
//! }
//! ```

pub mod ast;
pub mod auto_shield;
pub mod codegen;
pub mod constraints;
pub mod crypto;
pub mod crypto_primitives;
pub mod deployment;
pub mod groth16_native;
pub mod nl_translator;
pub mod parser;
pub mod plonk_prover;
pub mod prover;
pub mod r1cs;
pub mod recursive_prover;
pub mod signature;
pub mod solidity_verifier;
pub mod zkml;

/// Compile a ZKF source file into all output artifacts.
#[derive(Debug)]
pub struct CompileOutput {
    /// Name of the circuit
    pub name: String,
    /// Circom circuit source code
    pub circom: String,
    /// Solidity verifier contract source code
    pub verifier: String,
    /// Circuit metadata
    pub info: constraints::CircuitInfo,
    /// Raw constraint system (for native proving)
    pub cs: Option<constraints::ConstraintSystem>,
}

/// Compile a ZKF source string.
pub fn compile(source: &str, filename: &str) -> Result<CompileOutput, parser::ParseError> {
    // 1. Parse
    let program = parser::parse(source, filename)?;

    // Extract the first ProveBlock (skip comments and imports)
    let block = program
        .statements
        .iter()
        .find_map(|s| match s {
            ast::Statement::ProveBlock(b) => Some(b),
            _ => None,
        })
        .ok_or_else(|| parser::ParseError::TypeError("No prove block found in source".into()))?;

    // 2. Synthesize constraints
    let cs = constraints::ConstraintSystem::synthesize(block);

    // 3. Select proof system
    let ps = constraints::ProofSystem::select(cs.constraints.len(), block.public_signals().len());

    // 4. Generate circom
    let circom = codegen::circom::generate(&cs, ps);

    // 5. Generate verifier
    let verifier = codegen::verifier::generate(&cs, ps);

    // 6. Build info
    let info = constraints::CircuitInfo {
        name: program.name.clone(),
        num_inputs: cs
            .signals
            .iter()
            .filter(|s| s.kind == constraints::SignalKind::Input)
            .count(),
        num_private: block.private_signals().len(),
        num_public: block.public_signals().len(),
        num_constraints: cs.constraints.len(),
        num_signals: cs.signals.len(),
        proof_system: ps,
    };

    Ok(CompileOutput {
        name: program.name,
        circom,
        verifier,
        info,
        cs: Some(cs),
    })
}
