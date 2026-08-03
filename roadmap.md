# ZKForge Roadmap

## Now (v1.1.0)

- [x] Groth16 proving (BN254, EIP-197)
- [x] PLONK proving (KZG, 3-gate universal circuit) — **Fiat-Shamir added in v1.1.0**
- [x] Recursive proof folding for batch verification
- [x] zkML — neural network inference in zero knowledge
- [x] Solidity verifier generation (solc 0.8.x)
- [x] One-command Foundry deployment
- [x] Auto-shielding — wrap any Solidity contract with ZK privacy
- [x] 128/128 tests (adversarial counterexamples)
- [x] Internal security review — 3 critical bugs found and fixed
- [x] 15-page technical paper (TECHNICAL_PAPER.md)
- [x] Grant proposal (GRANT_PROPOSAL.md)

## Next (v1.2)

- [ ] Fix comparison constraints with literal operands
- [ ] Fix remaining example circuits (credit_score, token_balance, nft_ownership)
- [ ] Extend CI: prove-native all 6 circuits on every push
- [ ] Code coverage badge + 85%+ line coverage
- [ ] Reproducible cross-tool benchmark: ZKForge vs circom 2.x
- [ ] Full ECDSA verification inside R1CS circuit

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
