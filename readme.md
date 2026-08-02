<div align="center">
  <img src="https://raw.githubusercontent.com/zkarchitect/zkforge/main/assets/logo.svg" alt="ZKForge" width="320" />
  <p><strong>Pure Rust ZK Compiler — No circom. No snarkjs. No Node.js.</strong></p>
  
  <p>
    <a href="https://github.com/zkarchitect/zkforge/actions"><img src="https://img.shields.io/github/actions/workflow/status/zkarchitect/zkforge/ci.yml?branch=main&style=flat-square" alt="CI" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square" alt="License" /></a>
    <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.80%2B-orange.svg?style=flat-square" alt="Rust" /></a>
    <img src="https://img.shields.io/badge/tests-128%2F128-brightgreen?style=flat-square" alt="Tests" />
    <img src="https://img.shields.io/badge/proof%20speed-0.03s-red?style=flat-square" alt="Speed" />
    <img src="https://img.shields.io/badge/proof%20systems-Groth16%20%7C%20PLONK-blueviolet?style=flat-square" alt="Proof Systems" />
  </p>
</div>

---

ZKForge compiles a high-level DSL into zero-knowledge proof circuits — entirely in Rust. No circom toolchain, no snarkjs, no Node.js dependency. Generate Groth16 or PLONK proofs in **0.03 seconds**, get an EIP-197 Solidity verifier, and deploy with Foundry — all from a single binary.

## 🔥 Why ZKForge?

|  | ZKForge | circom + snarkjs |
|---|---|---|
| **Language** | Pure Rust 🦀 | Rust DSL + JavaScript runtime |
| **Install** | `cargo install zkforge` | Node.js + npm + circom + snarkjs |
| **Prove time** (simple) | **0.03s** ⚡ | ~0.3s |
| **Proof size** | 128 B | ~128 B |
| **Verifier** | Solidity (EIP-197) + Foundry deploy | Solidity (manual deploy) |
| **Proof systems** | Groth16 + PLONK | Groth16 + PLONK |
| **zkML** | ✅ Built-in | ❌ |
| **Auto-shielding** | ✅ Automatic | ❌ |
| **Recursive proofs** | ✅ Native | ❌ |

## 🚀 Quick Start

```bash
# Install (30 seconds)
cargo install zkforge

# Write a circuit
cat > prove_age.zkf << 'EOF'
prove {
    input age: Private<u8>;
    input min_age: Public<u8>;
    assert age >= min_age;
    output valid<bool>;
}
EOF

# Generate a proof (0.03s)
zkforge prove prove_age.zkf

# Deploy verifier to any EVM chain
zkforge deploy prove_age.zkf --chain-id 11155111
```

## 📊 Benchmarks

| Circuit | Constraints | R1CS Vars | Prove Time | Proof Size | Gas (verify) |
|---------|------------|-----------|------------|------------|--------------|
| Age Verify | 12 | 64 | 0.03s | 128 B | ~170K |
| Credit Score | 36 | 232 | 0.06s | 128 B | ~170K |
| Token Balance | 72 | 428 | 0.08s | 128 B | ~170K |
| NFT Ownership | 4 | 15 | 0.03s | 128 B | ~170K |

## 🏗 Architecture

```
.zkf DSL → Parser (~640 LoC)
        → Constraint Synthesizer (~870 LoC)
        → R1CS (BigUint, BN254 field, ~550 LoC)
        → Native Groth16 (arkworks, BN254, ~510 LoC)
        → PLONK (KZG, 3-gate, ~400 LoC)
        → Solidity Verifier (EIP-197, ~200 LoC)
        → Foundry Deploy Package
```

**Zero circom. Zero snarkjs. Zero Node.js in the core path.**

## 📦 Features

- **Groth16 Proving** — Native arkworks backend, BN254 curve, EIP-197 compatible
- **PLONK Proving** — KZG polynomial commitments, 3-gate universal circuit
- **Recursive Proofs** — Compose proofs natively
- **zkML** — Zero-knowledge neural network inference (ReLU, softmax, field-aware)
- **Solidity Verifier** — Auto-generated, EIP-197, compilable with solc 0.8.x
- **Foundry Deploy** — One command: verifier + deployment script + test
- **Auto-Shielding** — Wrap any Solidity contract with ZK privacy
- **ECDSA Verification** — Native signature checks in-circuit
- **Merkle Proofs** — Tree membership without revealing the path
- **Crypto Primitives** — Poseidon hashing, field arithmetic

## 📂 Project Structure

```
zkforge/
├── compiler/          # Core compiler (17 Rust modules)
├── cli/               # CLI binary + benchmarks
├── examples/          # 6 .zkf example circuits
├── deployments/       # 12 Foundry deployment packages
├── proofs/            # 41 proven circuits with artifacts
├── output/            # Generated circom, Solidity, zkML outputs
├── shielded/          # Auto-Shield examples
├── shield_test/       # Shield test contracts
└── circom-backend/    # circom compatibility proofs
```

## 🔐 Security

Full security audit completed (Q3 2026). 3 critical bugs found and fixed:

1. **Comparison constraints** — `assert age >= 18` was silently passing for `age = 3`
2. **Plonk witness bypass** — prover used domain elements instead of real witness values  
3. **Inequality inversion** — `!=` check used `-1` instead of `1` for the witness

All fixes verified with independent adversarial tests (128/128 passing). [Full audit report →](security_audit.md)

## 🧪 Testing

```
128 tests passing — parser, AST, constraint synthesis, R1CS, Groth16, 
PLONK, crypto primitives, recursive prover, auto-shield, zkML, deployment.
```

Every test includes adversarial counterexamples: wrong inputs produce rejected proofs.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=zkarchitect/zkforge&type=Date)](https://star-history.com/#zkarchitect/zkforge&Date)

## 📄 License

Apache 2.0 — see [LICENSE](LICENSE)

## 🌟 Contributing

ZKForge is open source and welcomes contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

