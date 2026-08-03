# ZKForge — Pure Rust ZK Compiler

## Benchmark Summary

Measured via `cargo run --release -- bench examples/`. Results vary by hardware.

### Native Groth16 Proving

| Circuit | DSL Constraints | R1CS Vars | Prove Time | Proof Size | Status |
|---------|----------------|-----------|------------|------------|--------|
| Age Verification | 13 | 15 | <0.1s | 128 B | PASS |
| Credit Score | 37 | 39 | <0.2s | 128 B | PASS |
| Token Balance | 74 | 75 | <0.3s | 128 B | PASS |
| NFT Ownership | 7 | 9 | <0.1s | 128 B | PASS |

### Gas Cost (Ethereum EIP-197)

| Metric | ZKForge |
|--------|---------|
| Verifier bytecode | ~5,200 B |
| Deploy gas | ~296K |
| Verify gas | ~170K |
| **Total** | **~466K** |

### Test Suite

128 tests passing across all modules (parser, AST, constraint synthesis, R1CS witness solver, Groth16 native, PLONK, crypto primitives, recursive prover, auto-shield, zkML, NL translator, signature, deployment). Adversarial counterexample tests verify that tampered inputs and forged proofs are correctly rejected.

### Architecture

```
.zkf DSL → Hand-written Parser (~640 lines)
          → Constraint Synthesizer (~870 lines)
          → Custom R1CS (~550 lines, BigUint, BN254 field)
          → Native Groth16 (~510 lines, arkworks, BN254)
          → Solidity Verifier (~200 lines, EIP-197, compilable)
          → Deploy Package (Foundry)
```

Zero circom. Zero snarkjs. Zero Node.js in core path.
