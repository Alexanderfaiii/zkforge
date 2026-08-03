# ZKForge — Pure Rust ZK Compiler

## Benchmark Summary

Measured via `cargo run --release -- bench examples/`. Results vary by hardware.

### Native Groth16 Proving

| Circuit | DSL Constraints | R1CS Vars | Prove Time | Proof Size | Status |
|---------|----------------|-----------|------------|------------|--------|
| Age Verification | 12 | 64 | <0.1s | 128 B | PASS |
| Credit Score | 36 | 232 | <0.2s | 128 B | PASS |
| Token Balance | 72 | 428 | <0.3s | 128 B | PASS |
| NFT Ownership | 4 | 15 | <0.1s | 128 B | PASS |

### Gas Cost (Ethereum EIP-197)

| Metric | ZKForge | circom/snarkjs | Delta |
|--------|---------|---------------|-------|
| Verifier bytecode | 6,986 B | ~6,900 B | +1.2% |
| Deploy gas | ~296K | ~290K | +2% |
| Verify gas | ~170K | ~170K | 0% |
| Total | ~466K | ~460K | <2% |

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
