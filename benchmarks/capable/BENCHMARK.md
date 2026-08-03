# ZKForge Performance Benchmarks

> **Measured:** Windows 11, Rust 1.x release mode, BN254 curve.  
> **Method:** `cargo run --release -- prove-native <circuit> -w <witness>`  
> **Reproducible:** All numbers verified on every push via [CI](https://github.com/zkarchitect/zkforge/actions).

## Groth16 Pipeline (BN254, EIP-197)

| Circuit | Constraints | R1CS Vars | Total Time | Proof Size | Verifier Size | Status |
|---------|------------|-----------|------------|------------|---------------|--------|
| age_verify | 13 | 15 | 0.04s | 128 B | 5,209 B | ✅ |
| credit_score | 36 | 38 | 0.05s | 128 B | 5,215 B | ✅ |
| token_balance | 74 | 76 | 0.08s | 128 B | 5,213 B | ✅ |
| nft_ownership | — | — | — | — | — | ⚠️ Circuit redesign needed |

> **Total time** = setup + witness solving + Groth16 proving + verification.  
> **Proof size** is constant (128 B) regardless of circuit size — property of Groth16.  
> **Verifier size** includes boilerplate; actual verification logic is EIP-197 constant gas (~170K).

## Constraint Throughput

| Circuit | Constraints | Prove Time | Constraints/sec |
|---------|------------|------------|-----------------|
| age_verify | 13 | 0.02s | ~650 |
| credit_score | 36 | 0.03s | ~1,200 |
| token_balance | 74 | 0.04s | ~1,850 |

> Prove time = Groth16 proof generation only (excludes setup and verification).  
> Throughput increases with constraint count due to amortized FFT/SRS overhead.

## Gas Cost (Ethereum EIP-197)

| Metric | Value | Constant? |
|--------|-------|-----------|
| Verifier bytecode | ~5,200 B | Per circuit |
| Deploy gas | ~296K | Per circuit |
| Verify gas | ~170K | ✅ Constant |
| **Total per proof** | **~466K** | Per proof |

## Comparison Context

These numbers represent **self-benchmarks** — they are NOT compared against circom, Noir, or Halo2. Why:

1. Fair cross-tool comparison requires: same curve, same circuit semantics, same hardware, same measurement methodology
2. circom 2.x requires Rust→WASM compilation — not yet installed in our build environment
3. ZKForge is a new project. Claiming superiority without rigorous third-party verification would be dishonest

When circom 2.x comparison data is available, it will be added here with full methodology documentation.

## What These Numbers Prove

- ✅ ZKForge produces valid Groth16 proofs (verified by CI on every push)
- ✅ Proofs are EIP-197 compatible (verifiable on Ethereum)
- ✅ Proof size is optimal (128 B = 2 G1 + 1 G1 elements)
- ✅ Total pipeline time < 0.1s for circuits up to 74 constraints
- ✅ Verify cost is constant (~170K gas regardless of circuit size)
