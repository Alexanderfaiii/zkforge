# ZKForge vs circom — Benchmark Comparison

> **Measured:** Windows 11, Rust 1.x, Node.js v22, circom v0.5.46, ZKForge v1.0.0  
> **Method:** Same logical circuits on both platforms. 5 iterations, warm run.  
> **Reproducible:** All ZKForge numbers verified on every push via [CI](https://github.com/zkarchitect/zkforge/actions).

## Compile Time

| Circuit | ZKForge | circom | Speedup |
|---------|---------|--------|---------|
| age_verify | 742μs | 812ms | **1094×** |
| credit_score | 718μs | 818ms | **1139×** |
| token_balance | 1239μs | ~1200ms | **968×** |
| nft_ownership | 825μs | ~1100ms | **1333×** |

> ZKForge: `cargo run --release -- bench examples/` (native Rust).  
> circom: `time circom file.circom -o file.r1cs` (Node.js + JavaScript compiler).  
> circom times include Node.js startup (~600ms); actual constraint generation is fast but the end-to-end experience includes this overhead.

## Constraint Count

| Circuit | ZKForge | circom 0.5 | Notes |
|---------|---------|------------|-------|
| age_verify | 13 | 2 | ZKForge: full bit-decomposition + range check. circom 0.5: simplified `<--` operator. |
| credit_score | 37 | 2 | Same difference in comparison gate synthesis. |
| token_balance | 74 | 4 | Two comparisons, each requires bit-decomp. circom minimal. |
| nft_ownership | 7 | 9 | ZKForge uses Poseidon with S-box optimization. |

> **Note on constraint counts**: circom 0.5.46 uses bn-128 (not BN254) and lacks field-aware comparison synthesis. ZKForge produces more constraints because it enforces soundness: every comparison is verified via bit decomposition, not just tagged with `<--`. This is a correctness tradeoff, not a performance one — fewer constraints ≠ more secure.

## End-to-End Pipeline

| Metric | ZKForge | circom + snarkjs |
|--------|---------|-----------------|
| Install | `cargo install --git` | `npm install -g circom snarkjs` |
| Language | Pure Rust | JavaScript (circom 0.5) / Rust→WASM→JS (circom 2.x) |
| Compile to R1CS | Built-in | circom compiler |
| Setup (Groth16) | Built-in (arkworks) | snarkjs powers of tau |
| Prove | Built-in (native) | snarkjs groth16 prove |
| Verify | Built-in (EIP-197) | snarkjs groth16 verify |
| Solidity verifier | Auto-generated | snarkjs export |
| Foundry deploy | One command | Manual |
| zkML | Built-in | Not available |
| PLONK | Built-in (Fiat-Shamir) | snarkjs plonk |
| Recursive proofs | Native | Not available |

## Gas Cost (Ethereum)

| Metric | ZKForge | circom/snarkjs |
|--------|---------|---------------|
| Verifier bytecode | 6,986 B | ~6,900 B |
| Deploy gas | ~296K | ~290K |
| Verify gas | ~170K | ~170K |
| **Total** | **~466K** | **~460K** |

Gas costs are nearly identical — both use EIP-197 pairing precompile. The ~6K difference is in boilerplate.

## Bottom Line

1. **Compile speed**: ZKForge is ~1000× faster end-to-end because it has zero Node.js startup overhead
2. **Constraint quality**: ZKForge produces more rigorous constraints (bit-decomposition vs `<--`)
3. **Gas cost**: Identical (both EIP-197)
4. **Developer experience**: ZKForge = one binary, no Node.js, no npm, no snarkjs
5. **Advanced features**: zkML, auto-shielding, recursive proofs — only in ZKForge

> The circom 0.5.46 compiler (JavaScript) is obsolete. circom 2.x uses a Rust compiler compiled to WASM, which should narrow the compile-time gap but still incurs WASM + JS bridge overhead. A direct circom 2.x comparison requires additional setup and will be added in a future benchmark.
