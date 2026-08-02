# ZKForge Architecture

This document explains how ZKForge works under the hood — from `.zkf` DSL to a deployed Solidity verifier on an EVM chain.

## Pipeline Overview

```
.zkf Source File
      │
      ▼
┌─────────────┐
│   Parser    │  compiler/src/parser.rs (~640 LoC)
│   Lexer →   │  Hand-written recursive descent parser. No dependencies.
│   AST       │  Produces a typed AST with ProveBlock, Expr, VarKind nodes.
└──────┬──────┘
       │ AST
       ▼
┌──────────────────┐
│    Constraint    │  compiler/src/constraints.rs (~870 LoC)
│   Synthesizer    │  Walks the AST, emits R1CS constraints.
│                  │  Handles: comparisons (>, <, >=, <=, ==, !=),
│                  │           arithmetic, merkle proofs, signatures.
└──────┬───────────┘
       │ Sparse R1CS Constraints (BigUint, BN254 scalar field)
       ▼
┌──────────────────┐
│      R1CS        │  compiler/src/r1cs.rs (~550 LoC)
│  Constraint      │  Custom R1CS with public/private separation.
│    System        │  Witness solver using modular arithmetic
│  + Solver        │  (mod_add, mod_sub, mod_mul, mod_inv).
└──────┬───────────┘
       │ Witness values + R1CS structure
       ▼
┌──────────────────────────────────────────────┐
│              Proving Backends                 │
│                                               │
│  ┌─────────────────┐  ┌────────────────────┐ │
│  │  Groth16 Native  │  │    PLONK Prover     │ │
│  │  groth16_native  │  │   plonk_prover.rs   │ │
│  │      .rs         │  │   (~400 LoC)        │ │
│  │  (~510 LoC)      │  │                     │ │
│  │                  │  │  KZG polynomial      │ │
│  │  arkworks BN254   │  │  commitments         │ │
│  │  EIP-197 compat  │  │  3-gate universal    │ │
│  └────────┬────────┘  └──────────┬─────────┘ │
└───────────┼──────────────────────┼───────────┘
            │                      │
            ▼                      ▼
     ┌──────────────────────────────────┐
     │       Solidity Verifier           │
     │   compiler/src/solidity_verifier  │  (~200 LoC)
     │           .rs                     │
     │                                   │
     │  Generates EIP-197 compatible     │
     │  Solidity verifier contract       │
     │  (solc 0.8.x)                     │
     └──────────────┬───────────────────┘
                    │
                    ▼
     ┌──────────────────────────────────┐
     │     Foundry Deployment Package    │
     │   compiler/src/deployment.rs      │
     │                                   │
     │  One command:                     │
     │  zkforge deploy circuit.zkf       │
     │  --chain-id 11155111              │
     │                                   │
     │  Output:                          │
     │  ├── src/Verifier.sol             │
     │  ├── script/Deploy.s.sol          │
     │  ├── foundry.toml                 │
     │  └── verify_input.json            │
     └──────────────────────────────────┘
```

## Module Deep-Dive

### 1. Parser (`compiler/src/parser.rs`)

The parser is hand-written (recursive descent) with zero external dependencies. Why no parser generator? ZKForge's DSL is intentionally minimal — writing a hand-crafted parser is simpler, faster, and gives us full control over error messages.

**Input:** A `.zkf` file:

```
prove {
    input age: Private<u8>;
    input min_age: Public<u8>;
    assert age >= min_age;
    output valid<bool>;
}
```

**Output:** An AST (`ProveBlock`) containing:
- Input declarations with types and visibility (Private/Public)
- Assert statements with comparison expressions
- Output declarations

**Key types:**
- `ast::ProveBlock` — the top-level circuit definition
- `ast::VarKind` — `Private<T>`, `Public<T>`, `Constant`
- `ast::Expr` — `Var`, `Literal`, `BinaryOp`, `Not`

### 2. Constraint Synthesizer (`compiler/src/constraints.rs`)

This is the heart of the compiler. It traverses the AST and emits R1CS constraints.

**Core Logic:**

For each `assert` statement, the synthesizer generates constraints that mathematically enforce the condition. Example for `assert age >= min_age`:

1. Compute `diff = age - min_age` (modular subtraction in BN254 field)
2. Perform bit decomposition of `diff` (binary representation)
3. Generate range-check constraints for each bit
4. The comparison passes iff `diff >= 0` in the field sense (i.e., `diff < field_order / 2`)

**Supported operations:**
- Comparisons: `>`, `<`, `>=`, `<=`, `==`, `!=`
- Arithmetic: `+`, `-`, `*`
- Binary operations
- Constant equality

**Security note:** All comparison constraints were independently verified with adversarial tests. Wrong inputs produce rejected proofs — never silent passes. See `SECURITY.md` for the full audit report.

### 3. R1CS System (`compiler/src/r1cs.rs`)

The R1CS (Rank-1 Constraint System) is the mathematical core of zero-knowledge proofs. Each constraint enforces:

```
(a₁·z₁ + a₂·z₂ + ...) · (b₁·z₁ + b₂·z₂ + ...) = (c₁·z₁ + c₂·z₂ + ...)
```

Where `z` is the witness vector and `a, b, c` are coefficient vectors.

**Key features:**
- **Public/Private separation:** Track which witness values the verifier sees
- **BN254 scalar field:** All arithmetic modulo the BN254 curve order (~254-bit prime)
- **Modular arithmetic:** `mod_add`, `mod_sub`, `mod_mul`, `mod_inv` — never plain BigUint division
- **Witness solver:** Multi-pass forward propagation that solves for unknown witness values

**Witness Solver Algorithm:**

The solver uses an iterative multi-pass approach:

1. Apply user-provided assignments (known witness values)
2. Iterative constraint propagation (up to 200 rounds):
   - **ReLU handling:** For `relu = bit * dense`, determine sign from dense value
   - **Generic solver:** Solve for single unknowns in `A·B = C`
   - **Zero-check:** Handle `A·B = 0` constraints correctly
   - **Side solving:** Solve unknowns on A-side or B-side when other two known
3. Post-pass bit decomposition from known signal values
4. Collect all resolved witness values

### 4. Groth16 Prover (`compiler/src/groth16_native.rs`)

Native Groth16 implementation using arkworks libraries.

**Flow:**
1. **Setup:** Generate proving key (pk) and verification key (vk) from R1CS
2. **Prove:** Compute the three Groth16 proof elements (A, B, C) using the witness
3. **Verify:** Check the pairing equation: `e(A, B) = e(α, β) · e(Σ inputs, γ) · e(C, δ)`

**Technical details:**
- Curve: BN254 (EIP-197 precompile)
- Proof size: 128 bytes (constant)
- Proving time: ~0.03s for simple circuits
- Verification: ~5ms (on-chain via EIP-197)

### 5. PLONK Prover (`compiler/src/plonk_prover.rs`)

PLONK (Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge) implementation.

**Key components:**
- **KZG commitments:** Polynomial commitments using bilinear pairings
- **3-gate structure:** Addition, multiplication, and constant gates encoded in one universal circuit
- **Permutation argument:** Ensures correct wiring via grand product check
- **Fiat-Shamir transform:** Makes the protocol non-interactive (hash-based challenges)

**Current status:** Functional for trusted-setup scenarios. Fiat-Shamir challenges currently use fixed values (documented in security audit as Low finding L2). Production-ready Fiat-Shamir transform is in the roadmap.

### 6. Solidity Verifier (`compiler/src/solidity_verifier.rs`)

Generates EIP-197 compliant Solidity verifier contracts.

The verifier contract contains:
- **Pairing precompile calls:** Uses `Pairing` precompile at address `0x08`
- **Input encoding:** Correct ABI encoding of proof elements and public inputs
- **Proof verification:** On-chain verification using the EIP-197 pairing check
- **Gas optimization:** Minimized storage reads and calldata copies

### 7. Deployment (`compiler/src/deployment.rs`)

One-command deployment to any EVM chain.

**Output structure:**
```
deployments/<circuit_name>/
├── src/<circuit_name>Verifier.sol    # Solidity verifier contract
├── script/Deploy.s.sol               # Foundry deployment script
├── foundry.toml                      # Foundry configuration
└── verify_input.json                 # Deployment parameters
```

**Usage:**
```bash
zkforge deploy my_circuit.zkf --chain-id 11155111
forge script script/Deploy.s.sol --broadcast --rpc-url $RPC
```

## Advanced Modules

### Recursive Prover (`compiler/src/recursive_prover.rs`)

Composes multiple proofs into one. Key for:
- **Proof aggregation:** Combine N proofs into a single, constant-size proof
- **IVC (Incrementally Verifiable Computation):** Chain proofs over long computations

### zkML (`compiler/src/zkml.rs`)

Zero-knowledge neural network inference. Proves `f(x) = y` without revealing model weights `f` or input `x`.

**Architecture:**
1. **Model Ingestion:** Load quantized MLP/CNN weights from JSON
2. **Arithmetization:** Convert forward pass to R1CS constraints
3. **Witness Generation:** Execute inference, record intermediate values
4. **Proof Generation:** Prove correctness with Groth16

**Supported layers:** Dense (Fully Connected), ReLU, Softmax
**Quantization:** 8-bit fixed-point with configurable scale factor

### Auto-Shielding (`compiler/src/auto_shield.rs`)

Automatically wraps any Solidity contract with ZK privacy. Generates:
- Circuit definition for private state transitions
- Shielded wrapper contract with nullifier-based replay protection
- Proof verification integration

## Data Flow Summary

| Step | Module | Input | Output |
|------|--------|-------|--------|
| 1 | `parser.rs` | `.zkf` DSL text | AST (`ProveBlock`) |
| 2 | `constraints.rs` | AST | Sparse R1CS constraints |
| 3 | `r1cs.rs` | Constraints + witness | R1CS witness vector |
| 4a | `groth16_native.rs` | R1CS + witness | Groth16 proof (128 B) |
| 4b | `plonk_prover.rs` | R1CS + witness | PLONK proof |
| 5 | `solidity_verifier.rs` | Proving key | Solidity verifier contract |
| 6 | `deployment.rs` | Verifier contract | Foundry deploy package |

## Key Design Decisions

1. **Pure Rust, no circom, no snarkjs, no Node.js** — Single language, single binary. Faster to install, faster to run, fewer dependency issues.

2. **Custom R1CS, not circom's** — Full control over field arithmetic (BN254, BigUint) and public/private separation. Enables the adversarial test pattern.

3. **Hand-written parser, not LALRPOP/pest** — The DSL is simple by design. A hand-written parser is faster, produces better errors, and has zero dependencies.

4. **Multi-pass witness solver** — Instead of a single symbolic pass, we iterate. This handles complex constraint graphs (ReLU, bit decompositions) that single-pass solvers can't.

5. **Both Groth16 and PLONK** — Different tradeoffs. Groth16: smaller proofs, universal setup. PLONK: universal circuit, no circuit-specific trusted setup needed.

## Constraints per Circuit

| Circuit | Constraints | Why |
|---------|------------|-----|
| Age Verify | 12 | 1 comparison + bit decomposition |
| Credit Score | 36 | Multiple comparisons + arithmetic |
| Token Balance | 72 | Balance checks + transfer validation |
| NFT Ownership | 4 | Simple ownership check |
| MNIST Inference | ~50 | 3 Dense layers + ReLU + Softmax |
