<div align="center">
  <img src="https://raw.githubusercontent.com/zkarchitect/zkforge/main/assets/logo.svg" alt="ZKForge" width="320" />
  <p><strong>Pure Rust ZK Compiler — No circom. No snarkjs. No Node.js.</strong></p>
  
  <p>
    <a href="https://crates.io/crates/zkforge"><img src="https://img.shields.io/crates/v/zkforge?style=flat-square&color=orange" alt="crates.io" /></a>
    <a href="https://github.com/zkarchitect/zkforge/actions"><img src="https://img.shields.io/github/actions/workflow/status/zkarchitect/zkforge/verifiable-ci.yml?branch=main&style=flat-square" alt="CI" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square" alt="License" /></a>
    <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.80%2B-orange.svg?style=flat-square" alt="Rust" /></a>
    <img src="https://img.shields.io/badge/tests-131%2F131-brightgreen?style=flat-square" alt="Tests" />
    <img src="https://img.shields.io/badge/proof%20speed-<0.1s_(age_verify)-red?style=flat-square" alt="Speed" />
    <img src="https://img.shields.io/badge/proof%20systems-Groth16%20%7C%20PLONK-blueviolet?style=flat-square" alt="Proof Systems" />
  </p>
</div>

---

ZKForge compiles a high-level DSL into zero-knowledge proof circuits — entirely in Rust. No circom toolchain, no snarkjs, no Node.js dependency. Generate Groth16 or PLONK proofs in under a second, get an EIP-197 Solidity verifier, and deploy with Foundry — all from a single binary.

## 🔥 Why ZKForge?

|  | ZKForge | circom + snarkjs |
|---|---|---|
| **Language** | Pure Rust 🦀 | Rust DSL + JavaScript runtime |
| **Install** | `cargo install zkforge` | Node.js + npm + circom + snarkjs |
| **Prove time** (simple) | **<0.1s** ⚡ | ~0.3s (with Node.js) |
| **Proof size** | 128 B | ~128 B |
| **Verifier** | Solidity (EIP-197) + Foundry deploy | Solidity (manual deploy) |
| **Proof systems** | Groth16 + PLONK | Groth16 + PLONK |
| **zkML** | ✅ Built-in | ❌ |
| **Auto-shielding** | ✅ Automatic | ❌ |
| **Recursive proofs** | ✅ Native | ❌ |

## 🚀 Quick Start

```bash
# Install from crates.io
cargo install zkforge

# Or from GitHub
cargo install --git https://github.com/zkarchitect/zkforge.git

# Write a circuit
cat > prove_age.zkf << 'EOF'
prove {
    input age: Private<u8>;
    input min_age: Public<u8>;
    assert age >= min_age;
    output valid<bool>;
}
EOF

# Generate a proof
zkforge prove-native prove_age.zkf -w witness.json

# Deploy verifier to any EVM chain
zkforge deploy prove_age.zkf --chain-id 11155111
```

## 📊 Benchmarks

| Circuit | Constraints | R1CS Vars | Prove Time | Proof Size | Gas (verify) |
|---------|------------|-----------|------------|------------|--------------|
| Age Verify | 13 | 15 | <0.1s | 128 B | ~170K | ✅ |
| Credit Score | 36 | 38 | <0.1s | 128 B | ~170K | ✅ |
| Token Balance | 74 | 76 | <0.1s | 128 B | ~170K | ✅ |
| NFT Ownership | 5 | 7 | <0.1s | 128 B | ~170K | ✅ |
| Merkle Proof | 18 | 23 | <0.1s | 128 B | ~170K | ✅ |
| **ECDSA Verify** | **3,041** | **3,045** | **<0.8s** | **128 B** | **~290K** | ✅ |

## 🏗 Architecture

```
.zkf DSL → Parser (~770 LoC)
        → Constraint Synthesizer (~1,380 LoC)
        → R1CS (BigUint, BN254 field, ~630 LoC)
        → Native Groth16 (arkworks, BN254, ~630 LoC)
        → PLONK (KZG, 3-gate, ~500 LoC)
        → Solidity Verifier (EIP-197, ~320 LoC)
        → Foundry Deploy Package
```

**Zero circom. Zero snarkjs. Zero Node.js in the core path.**

## 📦 Features

- **Groth16 Proving** — Native arkworks backend, BN254 curve, EIP-197 compatible
- **PLONK Proving** — KZG polynomial commitments, 3-gate universal circuit, Fiat-Shamir
- **Recursive Proofs** — Fold multiple proofs into one for batch verification
- **zkML** — Zero-knowledge neural network inference (ReLU, softmax, field-aware)
- **Solidity Verifier** — Auto-generated, EIP-197, compilable with solc 0.8.x
- **Foundry Deploy** — One command: verifier + deployment script + test
- **Auto-Shielding** — Wrap any Solidity contract with ZK privacy
- **ECDSA Verification** — Signature checks via k256, committed in-circuit via Poseidon
- **Merkle Proofs** — Tree membership via 73-round Poseidon hash chain
- **Crypto Primitives** — Poseidon hashing, field arithmetic

## 📂 Project Structure

```
zkforge/
├── compiler/          # Core compiler (17 Rust modules, ~10,200 LoC)
├── cli/               # CLI binary
├── examples/          # 6 .zkf example circuits (all passing e2e)
├── assets/            # Logo and assets
└── .github/           # CI workflows, templates, security review
```

## 🔐 Security

Internal security review completed. 3 critical bugs found and fixed:

1. **Comparison constraints** — `assert age >= 18` was silently passing for `age = 3`
2. **Plonk witness bypass** — prover used domain elements instead of real witness values  
3. **Inequality inversion** — `!=` check used `-1` instead of `1` for the witness

All fixes verified with adversarial tests (131/131 passing). [Full audit report →](SECURITY_AUDIT.md)

## 🧪 Testing

```
131 tests passing — parser, AST, constraint synthesis, R1CS, Groth16, 
PLONK, crypto primitives, recursive prover, auto-shield, zkML, deployment.
```

Many tests include adversarial counterexamples: wrong inputs produce rejected proofs.

## 👥 Community

- 📣 [Introducing ZKForge: A Pure Rust ZK Compiler](https://github.com/zkarchitect/zkforge/discussions/14) — start here!
- 🐛 [Bug Reports](https://github.com/zkarchitect/zkforge/issues/new?template=bug_report.yml)
- 💡 [Feature Requests](https://github.com/zkarchitect/zkforge/issues/new?template=feature_request.yml)
- 🔬 [Technical Paper](TECHNICAL_PAPER.md) — Architecture, protocols, security review

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=zkarchitect/zkforge&type=Date)](https://star-history.com/#zkarchitect/zkforge&Date)

## 📄 License

Apache 2.0 — see [LICENSE](LICENSE)

## 🌟 Contributing

ZKForge is open source and welcomes contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

