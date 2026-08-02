# ZKForge Roadmap

## Now (v1.0.0)

- [x] Groth16 proving (BN254, EIP-197) — **0.03s**
- [x] PLONK proving (KZG, 3-gate universal circuit)
- [x] Recursive proof composition
- [x] zkML — neural network inference in zero knowledge
- [x] Solidity verifier generation (solc 0.8.x)
- [x] One-command Foundry deployment
- [x] Auto-shielding — wrap any Solidity contract with ZK privacy
- [x] 128/128 tests (adversarial counterexamples)
- [x] Security audit — 3 critical bugs found and fixed

## Next (v1.1 — v1.3)

- [ ] Fiat-Shamir hash-based challenges for PLONK (production non-interactive)
- [ ] Complete zkML: full MNIST/IRIS-class inference
- [ ] Code coverage badge + 85%+ line coverage
- [ ] Benchmarks page: automated perf comparisons vs circom/snarkjs
- [ ] Integration tests for all example circuits
- [ ] Circom full compatibility mode — run existing circom circuits directly

## Medium Term (v1.4 — v2.0)

- [ ] Marlin proving backend (universal SRS, faster than PLONK)
- [ ] Spartan backend (no trusted setup)
- [ ] Nova folding scheme — IVC for arbitrary computations
- [ ] Noir language compatibility layer — compile Noir to zkforge
- [ ] Mobile SDK (iOS/Android) for on-device ZK proving
- [ ] WASM target — ZKForge in the browser

## Long Term

- [ ] zkEVM integration — native support for zkSync, Scroll, Starknet
- [ ] Hardware acceleration — GPU/FPGA proving
- [ ] Decentralized prover network
- [ ] Multi-language DSL: Rust, TypeScript, Python bindings
- [ ] zkForge Cloud — hosted proving API

---

Want to help? Pick any unchecked item and open a PR. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
