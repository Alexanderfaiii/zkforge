# Contributing to ZKForge

Thanks for your interest in contributing! This document covers how to get started.

## Setup

```bash
git clone https://github.com/zkarchitect/zkforge.git
cd zkforge
cargo build --release
cargo test
```

## Project Structure

| Crate | Purpose |
|-------|---------|
| `compiler/` | Core compiler: parser, AST, constraints, R1CS, Groth16, PLONK, zkML |
| `cli/` | CLI binary + benchmark commands |

## Development

```bash
# Run all tests (should be 131/131)
cargo test

# Run with verbose output
cargo test -- --nocapture

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt --all -- --check

# Build release
cargo build --release
```

## Pull Requests

1. Fork the repo
2. Create a branch: `git checkout -b fix/something` or `feat/new-feature`
3. Make your changes
4. Run `cargo test` and `cargo clippy`
5. Push and open a PR

### Commit Messages

Use conventional commits:
- `feat: add X`
- `fix: correct Y`
- `perf: optimize Z`
- `test: add adversarial test for W`
- `docs: update README`

## Testing Guidelines

Every new feature must include adversarial tests: wrong inputs must produce rejected proofs, not silently accepted ones. See `compiler/src/constraints.rs` for examples of the adversarial test pattern used throughout the codebase.

## Code Style

- Rust 2021 edition
- All `pub` items must have doc comments
- Use `anyhow::Result` for fallible operations
- Field arithmetic always via `mod_add`/`mod_sub`/`mod_mul`/`mod_inv` — never plain operators

## Getting Help

Open a [Discussion](https://github.com/zkarchitect/zkforge/discussions) or comment on an issue.
