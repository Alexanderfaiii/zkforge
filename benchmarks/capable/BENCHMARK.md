# ZKForge vs circom — Benchmark Comparison

> **Last updated:** Q3 2026  
> **Status:** ⚠️ Preliminary — circom 2.x comparison pending

## ⚠️ Important Caveats

This benchmark compares **ZKForge v1.0.0** against **circom 0.5.46** (JavaScript, 2018). Key differences that affect fairness:

1. **circom 0.5.46 is obsolete.** circom 2.x uses a Rust compiler compiled to WASM, which is significantly faster. This benchmark is NOT a fair comparison against the current circom.
2. **Different curves.** circom 0.5.46 uses bn-128. ZKForge uses BN254. Different security levels.
3. **circomlib not used.** A real circom developer would use `Num2Bits` + `LessThan` from circomlib for comparison gates — producing constraint counts similar to ZKForge. This benchmark uses minimal `<--` operators which are NOT production-quality.
4. **Only compile time measured.** Proving time, verification time, and memory usage are more important metrics for real-world use and are NOT yet compared.
5. **Single-machine measurements.** Both platforms measured on the same Windows 11 machine to control for hardware variance.

**This benchmark is a work in progress.** A fair comparison requires:
- circom 2.x (Rust compiler)
- circomlib-based circuits with proper comparison gates
- Groth16 proving + verification time on both platforms
- Same curve (BN254) for both

## Compile Time (preliminary, circom 0.5.46)

| Circuit | ZKForge | circom 0.5.46 | Notes |
|---------|---------|---------------|-------|
| age_verify | 742μs | 812ms | circom includes ~600ms Node.js startup |
| credit_score | 718μs | 818ms | Same overhead pattern |
| token_balance | 1239μs | ~1200ms | Larger circuit, both scale linearly |
| nft_ownership | 825μs | ~1100ms | Comparable constraint complexity |

> **Honest interpretation**: ZKForge is faster at end-to-end compilation because it avoids Node.js entirely. The circom 0.5.46 numbers are dominated by JS startup overhead (~600ms). circom 2.x (Rust→WASM) would likely reduce this gap to ~10-50× rather than ~1000×. A direct circom 2.x comparison is pending.

## Constraint Count (preliminary)

| Circuit | ZKForge | circom 0.5.46 (minimal) | circom 2.x (est. with circomlib) |
|---------|---------|-------------------------|----------------------------------|
| age_verify | 13 | 2 | ~15-25 |
| credit_score | 37 | 2 | ~40-60 |
| token_balance | 74 | 4 | ~80-120 |
| nft_ownership | 7 | 9 | ~7-12 |

> **Honest interpretation**: ZKForge produces production-quality constraints with bit-decomposition and field-aware arithmetic. circom 0.5.46 numbers use simplified `<--` operators that are NOT safe for production. circom 2.x with circomlib would produce comparable constraint counts. The constraint quality gap vanishes when both use proper comparison synthesis.

## What We Actually Prove

| Claim | Status | Evidence |
|-------|--------|----------|
| ZKForge compiles ZK circuits | ✅ | 128 tests, CI, e2e proof |
| ZKForge is faster to install | ✅ | `cargo install --git` vs `npm install -g circom snarkjs` |
| ZKForge avoids Node.js | ✅ | Pure Rust binary |
| ZKForge has fewer dependencies | ✅ | 1 binary vs 170 npm packages |
| ZKForge is 1000× faster than circom | ❌ | Only true against circom 0.5.46 (obsolete). circom 2.x pending. |

## What We Don't Prove (Yet)

- [ ] ZKForge is faster at Groth16 proving than circom 2.x
- [ ] ZKForge produces smaller proofs
- [ ] ZKForge verifier is cheaper on-chain
- [ ] ZKForge is more secure (we found bugs, circom has had external audits)
- [ ] ZKForge is production-ready (no external audit yet)

## Bottom Line (Honest)

ZKForge offers a simpler developer experience: one Rust binary, no Node.js, no npm. For developers who value this, the toolchain simplicity is real. For benchmarking claims against circom: **we need circom 2.x data before making speed comparisons.** This document will be updated when that data is available.
