# ZKForge Roadmap

## Now (v1.1.0)

- [x] Groth16 proving (BN254, EIP-197)
- [x] PLONK proving (KZG, 3-gate universal circuit) — **Fiat-Shamir implemented in v1.1.0**
- [x] Recursive proof folding for batch verification
- [x] zkML — neural network inference in zero knowledge
- [x] Solidity verifier generation (solc 0.8.x)
- [x] One-command Foundry deployment
- [x] Auto-shielding — wrap any Solidity contract with ZK privacy
- [x] 131/131 tests (adversarial counterexamples)
- [x] Internal security review — 4 critical bugs found and fixed
- [x] 15-page technical paper (TECHNICAL_PAPER.md)
- [x] crates.io: `cargo install zkforge` ✅
- [x] Code coverage in CI (tarpaulin)
- [x] PR to arkworks (groth16#97 — adversarial test patterns)
- [x] 4/4 example circuits passing end-to-end

## Next (v1.2)

- [ ] Full ECDSA verification inside R1CS circuit
- [ ] Reproducible cross-tool benchmark: ZKForge vs circom 2.x
- [ ] VS Code extension — syntax highlighting + snippets
- [ ] Gitcoin Grant — community funding round
- [ ] arkworks PR #97 — await/maintain review

## Medium Term (v1.3 — v2.0)

- [ ] Marlin proving backend (universal SRS)
- [ ] Spartan backend (no trusted setup)
- [ ] Nova folding scheme — IVC for arbitrary computations
- [ ] Noir language compatibility layer
- [ ] Mobile SDK (iOS/Android)
- [ ] WASM target — ZKForge in the browser

## Long Term

- [ ] zkEVM integration
- [ ] Hardware acceleration — GPU/FPGA proving
- [ ] Decentralized prover network
- [ ] Multi-language DSL: Rust, TypeScript, Python bindings
- [ ] ZKForge Cloud — hosted proving API

---

Want to help? Pick any unchecked item and open a PR. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
