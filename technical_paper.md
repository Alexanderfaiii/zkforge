# ZKForge: A Self-Contained Zero-Knowledge Proof Compiler in Pure Rust

**Technical Report — Q3 2026**  
**Repository:** [github.com/zkarchitect/zkforge](https://github.com/zkarchitect/zkforge)  
**License:** Apache 2.0

---

## Abstract

ZKForge is a self-contained zero-knowledge proof compiler written entirely in Rust. Unlike existing toolchains that depend on JavaScript runtimes (circom + snarkjs) or complex multi-language build pipelines (Noir + nargo + Barretenberg), ZKForge compiles a high-level DSL into non-interactive zero-knowledge proofs within a single binary. The system supports both Groth16 and PLONK proving backends over the BN254 curve, generates EIP-197-compatible Solidity verifiers, and provides built-in support for zero-knowledge machine learning inference, recursive proof composition, and automatic contract shielding.

This report documents the architecture, the cryptographic protocols implemented, the security review methodology, and the three critical bugs discovered and fixed during internal review.

---

## 1. Introduction

Zero-knowledge proofs have transitioned from theoretical cryptography to production infrastructure. Ethereum rollups process billions of dollars through ZK validity proofs. Private transactions, identity systems, and machine learning verification increasingly rely on ZK circuits.

However, the developer tooling remains fragmented. The dominant toolchain — circom + snarkjs — requires Node.js, npm, and a multi-step pipeline: compile DSL → generate R1CS → trusted setup ceremony → compute witness → generate proof → export verifier. Each step is a different tool with different dependencies.

ZKForge collapses this pipeline into a single Rust binary. The design philosophy is:

1. **One binary, no runtime dependencies.** No Node.js, no circom, no snarkjs, no npm.
2. **Compile-time security.** Constraints are synthesized at circuit construction, not deferred to witness computation.
3. **Verifiable correctness.** Every push triggers 128 adversarial tests and an end-to-end proof verification on CI.
4. **Honest about limitations.** Stub functions return `false`, not `true`. Unaudited components are clearly documented.

---

## 2. Architecture

### 2.1 Compiler Pipeline

```
.zkf Source File
      │
      ▼
┌─────────────┐
│   Parser    │  compiler/src/parser.rs
│   Lexer →   │  Hand-written recursive descent parser.
│   AST       │  Produces typed AST with ProveBlock, Expr, VarKind.
└──────┬──────┘
       │ AST
       ▼
┌──────────────────┐
│    Constraint    │  compiler/src/constraints.rs
│   Synthesizer    │  Walks AST, emits R1CS constraints.
│                  │  Handles comparisons (>, <, >=, <=, ==, !=),
│                  │  arithmetic, Merkle proofs, ECDSA.
└──────┬───────────┘
       │ Sparse R1CS Constraints
       ▼
┌──────────────────┐
│      R1CS        │  compiler/src/r1cs.rs
│  System +        │  Custom R1CS with public/private separation.
│  Witness Solver  │  Witness solver using modular arithmetic
│                  │  (mod_add, mod_sub, mod_mul, mod_inv).
└──────┬───────────┘
       │ R1CS Instance + Witness
       ▼
┌──────────────────┐
│   Prover Layer   │
│                  │
│ ┌──────────────┐ │
│ │ Groth16      │ │  compiler/src/groth16_native.rs
│ │ (arkworks)   │ │  BN254, EIP-197 compatible.
│ └──────────────┘ │
│ ┌──────────────┐ │
│ │ PLONK        │ │  compiler/src/plonk_prover.rs
│ │ (KZG + F-S)  │ │  KZG commitments, Fiat-Shamir via Poseidon.
│ └──────────────┘ │
└──────┬───────────┘
       │ Proof + Verifier
       ▼
┌──────────────────┐
│   Codegen        │
│                  │
│ ┌──────────────┐ │
│ │ Solidity      │ │  compiler/src/codegen/verifier.rs
│ │ Verifier      │ │  EIP-197 pairing check, compilable.
│ └──────────────┘ │
│ ┌──────────────┐ │
│ │ Foundry       │ │  compiler/src/deployment.rs
│ │ Deploy        │ │  One-command deploy to any EVM chain.
│ └──────────────┘ │
└──────────────────┘
```

### 2.2 Module Breakdown

| Module | Lines | Description |
|--------|-------|-------------|
| `parser` | ~1,500 | Recursive descent parser for `.zkf` DSL |
| `constraints` | ~1,200 | Constraint synthesis, comparison gates, Merkle, ECDSA |
| `r1cs` | ~1,000 | R1CS system, witness solver, public/private separation |
| `groth16_native` | ~1,000 | Groth16 prover/verifier via arkworks, BN254 |
| `plonk_prover` | ~1,400 | PLONK prover/verifier, KZG commitments, permutation argument |
| `crypto` | ~600 | Poseidon hash (73 rounds, SHAKE256 constants), Transcript (Fiat-Shamir) |
| `crypto_primitives` | ~350 | MiMC hash, Merkle tree construction |
| `codegen/circom` | ~180 | circom compatibility output |
| `codegen/verifier` | ~320 | EIP-197 Solidity verifier generation |
| `auto_shield` | ~1,500 | Automatic wrapping of Solidity contracts with ZK privacy |
| `zkml` | ~700 | Zero-knowledge neural network inference |
| `recursive_prover` | ~1,000 | Proof folding and batch verification |
| `signature` | ~300 | ECDSA verification with k256 + Poseidon commitment |
| `deployment` | ~100 | Foundry deployment script generation |
| `nl_translator` | ~1,000 | Natural language (Arabic + English) to `.zkf` translator |
| **Total** | **~12,000** | |

---

## 3. Cryptographic Protocols

### 3.1 Groth16 over BN254

ZKForge implements the Groth16 proving system using the arkworks library over the BN254 curve. This is the same curve used by Ethereum precompiles (EIP-197), making all proofs directly verifiable on-chain.

**Proving cost:** O(n) group operations where n is the number of constraints. For a typical circuit (13-74 constraints), proving takes <0.1-0.3 seconds.

**Proof size:** 128 bytes (2 G₁ points + 1 G₁ point), the theoretical minimum for Groth16.

**Verification:** 3 pairing checks via EIP-197 precompile. Constant gas cost (~170K).

### 3.2 PLONK with Fiat-Shamir

The PLONK implementation uses:

- **KZG polynomial commitments** over BN254
- **3-gate universal circuit** (add, mul, constant)
- **Permutation argument** enforcing cross-gate variable consistency via product check
- **Fiat-Shamir transform** using Poseidon-based transcript

**Fiat-Shamir implementation details:**

```
Prover transcript order:
  1. Absorb wire commitments: a_comm, b_comm, c_comm
  2. Challenge: beta, gamma (permutation challenges)
  3. Compute permutation product z
  4. Absorb: z_comm, t_lo_comm, t_mid_comm, t_hi_comm
  5. Challenge: zeta (evaluation point), v (opening challenge)
  6. Compute evaluations at zeta
  7. KZG batch opening

Verifier reconstructs the same challenges in the same order,
ensuring soundness under the random oracle model.
```

**Critical fix:** In the pre-audit codebase, beta and gamma were hardcoded constants (5 and 7). This meant the PLONK prover was not truly non-interactive — challenges did not depend on the statement being proved. The fix derives beta and gamma from the transcript after absorbing wire commitments, making the protocol secure under the random oracle model.

### 3.3 Poseidon Hash (73 Rounds)

ZKForge implements a production-grade Poseidon hash function with:

- **73 rounds:** 8 full rounds → 57 partial rounds → 8 full rounds
- **S-box:** x⁵ power function
- **MDS matrix:** 3×3 maximum distance separable matrix
- **Round constants:** SHAKE256-derived (matching the reference implementation)
- **State width:** 3 field elements

The constraint synthesizer generates all 73 rounds as R1CS constraints, using 3 multiplication constraints per full-round S-box and 1 per partial-round S-box.

### 3.4 Poseidon Transcript

The Fiat-Shamir transcript is built on top of Poseidon:

1. Initialize with domain-separated label hash
2. Absorb commitments by hashing serialized G₁/G₂ points into field elements
3. Generate challenges by hashing accumulated state with round counter

This provides domain separation between different challenge types and prevents cross-protocol attacks.

---

## 4. Security Review

### 4.1 Methodology

An internal security review was conducted following the "adversarial test-driven review" protocol:

1. For every assertion type (comparison, equality, inequality, range check), construct a witness that should FAIL and verify that proof generation rejects it.
2. For every proof system, tamper with the proof or witness and verify rejection.
3. For every public/private signal separation, verify that public inputs are checked and private inputs are not exposed.
4. Stubs are explicitly identified and documented.

### 4.2 Critical Findings

#### C1: Comparison Constraints Silent Pass (FIXED)

The comparison constraint synthesis (`>=`, `>`, `<=`, `<`) hardcoded the result term to `-1` (always true) instead of computing the actual comparison via bit decomposition.

**Impact:** `assert age >= 18` succeeded when `age = 3`. All comparison-based proofs were trivially forgeable.

**Root cause:** The constraint synthesizer bypassed bit decomposition in favor of a hardcoded constant, treating the comparison result as always true.

**Fix:** Replaced hardcoded constant with proper bit decomposition of `left - right`, generating a full range check via binary decomposition. This ensures the assertion only passes when the comparison is mathematically satisfied.

**Verification:** 5 independent adversarial tests confirm the fix:
- `age=3, assert age≥18` → proof REJECTED ✅
- `age=25, assert age≥18` → proof ACCEPTED ✅
- Tampered witness → proof REJECTED ✅

#### C2: Plonk Witness Bypass (FIXED)

The Plonk prover assigned domain elements as wire values instead of reading actual witness values from the R1CS solver.

**Impact:** Any Plonk proof verified successfully regardless of input — the system produced structurally valid proofs that enforced no real constraints.

**Root cause:** The `var_map` (HashMap mapping variable names to witness indices) was populated by the solver but never read by the prover. Domain elements were used as placeholders.

**Fix:** Replaced domain-element loop with actual witness value extraction via `var_map`. Each wire now receives the correct field element from the R1CS solver.

**Verification:** `assert x>10` with `x=3` → proof REJECTED. `x=15` → ACCEPTED.

#### C3: Inequality Constraint Inversion (FIXED)

The inequality constraint (`!=`) encoded the check as `diff * inv = -1` instead of `diff * inv = 1`.

**Impact:** The constraint could not be satisfied for legitimate inequality cases, making `!=` essentially non-functional.

**Root cause:** Used `-1` instead of `1` for the multiplicative inverse witness. The correct ZK encoding for "diff is nonzero" is `diff * inv = 1` — if `diff` has a multiplicative inverse, it cannot be zero.

**Fix:** Corrected constraint to `diff * inv = 1`.

**Verification:** `x!=5` with `x=10` → ACCEPTED. `x!=5` with `x=5` → REJECTED.

### 4.3 Medium Findings

| Finding | Status |
|---------|--------|
| M1: Equality bypass via zero result (`diff*result=0` → prover sets `result=0`) | FIXED |
| M2: Integer division instead of modular inverse in witness solver | FIXED |
| M3: `make_public` called after `add_constraint` (public vars remained private) | FIXED |
| M4: Nullifier derivation not ZK-verifiable (on-chain only) | NOTED |

### 4.4 Known Limitations

| Component | Status | Details |
|-----------|--------|---------|
| ECDSA verification | ⚠️ Partial | k256 verification runs outside circuit. Only Poseidon commitment is constrained. |
| Fiat-Shamir security proof | ⚠️ Not formalized | The transcript construction follows the standard pattern but lacks a formal security reduction. |
| Unimplemented builtins | ❌ Fail-safe | Unknown functions produce `result=0` (false), preventing silent proof forgery. |
| Merkle proofs | ✅ Verified | 73-round Poseidon constraints with proper sibling/index handling. |

---

## 5. Performance

Measured on Windows 11, Rust 1.x release mode, BN254 curve, via `cargo run --release -- bench examples/`.

### 5.1 Compilation Speed

| Circuit | Constraints | Signals | Compile Time |
|---------|------------|---------|-------------|
| age_verify | 13 | 14 | 314μs |
| credit_score | 37 | 38 | ~600μs |
| token_balance | 74 | 75 | ~1,200μs |
| nft_ownership | 7 | 9 | ~800μs |
| merkle_proof | 18 | 20 | ~700μs |

**Total:** 5 circuits, 149 constraints, ~5.5ms compilation (average 1.1ms/circuit).

### 5.2 Groth16 Proving

| Circuit | Setup | Prove | Proof Size |
|---------|-------|-------|-------------|
| age_verify (13) | 0.01s | 0.02s | 128 B |
| credit_score (36) | ~0.01s | ~0.03s | 128 B |
| token_balance (74) | ~0.01s | ~0.04s | 128 B |

### 5.3 Gas Cost (Ethereum)

| Metric | Value |
|--------|-------|
| Verifier bytecode | ~5,200 B |
| Deploy gas | ~296K |
| Verify gas | ~170K |
| **Total per proof** | **~466K** |

---

## 6. Testing Infrastructure

### 6.1 Test Suite

128 tests across 17 modules, including:

- **Parser:** valid and invalid `.zkf` inputs, edge cases
- **Constraint synthesis:** all comparison types, arithmetic, composite expressions
- **R1CS:** witness solving with modular arithmetic, public/private separation
- **Groth16:** full pipeline (setup → prove → verify), tampered proof rejection, zero-knowledge property
- **PLONK:** single-gate, three-gate, permutation, tampered rejection
- **Crypto:** Poseidon determinism, Merkle tamper resistance, transcript consistency
- **Recursive:** folding, batch verification, invalid input rejection
- **zkML:** inference determinism, privacy guarantee, dimension mismatch
- **Natural language:** Arabic + English translation, threshold extraction

### 6.2 Continuous Integration

Two CI workflows run on every push:

**CI:** Tests on Ubuntu + Windows, Clippy (zero warnings), Rustfmt, Benchmarks.

**Verifiable CI:** Full test suite + Clippy + Format + Release build + End-to-end prove (age_verify with witness) → Audit Summary.

---

## 7. Comparison with Existing Tools

ZKForge is not a replacement for circom, Noir, or Halo2. Each tool has years of development, external audits, and production deployment. ZKForge's contributions are:

1. **Zero-runtime-dependency architecture:** A single Rust binary that requires no Node.js, no npm, no WASM runtime, and no multi-language toolchain.
2. **Built-in ZKML:** Zero-knowledge neural network inference with ReLU, softmax, and field-aware arithmetic — not available in circom or Noir without custom circuit implementation.
3. **Auto-shielding:** Automatic wrapping of any Solidity contract with ZK privacy, including circuit generation, verifier deployment, and nullifier tracking.
4. **Honest security posture:** All limitations are documented. Stub functions fail loudly, not silently.

A rigorous cross-tool benchmark requires circom 2.x (Rust compiler) with circomlib for equivalent constraint semantics. This data is pending.

---

## 8. Future Work

1. **Fiat-Shamir security proof:** A formal security reduction for the Poseidon-based transcript construction.
2. **ECDSA circuit integration:** Full secp256k1 verification inside the R1CS constraint system.
3. **External security audit:** A third-party review of the constraint synthesizer and proving backends.
4. **Circom compatibility layer:** Direct execution of existing circom circuits within ZKForge.
5. **Nova folding scheme:** Incrementally verifiable computation for long proof chains.
6. **WASM target:** Browser-based ZK proving.

---

## 9. Conclusion

ZKForge demonstrates that a production-capable ZK proof compiler can be built as a single, self-contained Rust binary. The system implements Groth16 and PLONK proving over BN254 with Fiat-Shamir via Poseidon, generates EIP-197-compatible Solidity verifiers, and includes unique features like built-in ZKML and auto-shielding.

The internal security review identified and fixed three critical bugs that would have made all proofs forgeable. This review process, combined with 128 adversarial tests running on every push, provides a foundation of verifiable correctness.

ZKForge is not yet production-ready — it lacks external audit and has known limitations in ECDSA verification and Fiat-Shamir formalization. But it is honest about these limitations, and its architecture provides a clean foundation for community audit, contribution, and eventual production deployment.

---

## References

- [Groth16] J. Groth. "On the Size of Pairing-Based Non-interactive Arguments." EUROCRYPT 2016.
- [PLONK] A. Gabizon, Z. J. Williamson, O. Ciobotaru. "PLONK: Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge." 2019.
- [Poseidon] L. Grassi et al. "Poseidon: A New Hash Function for Zero-Knowledge Proof Systems." USENIX 2021.
- [EIP-197] V. Buterin. "Precompiled contracts for optimal ate pairing check on the elliptic curve alt_bn128." Ethereum Improvement Proposal 197.
- [arkworks] arkworks.rs — A Rust ecosystem for zkSNARK programming.
