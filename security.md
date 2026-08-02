# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in ZKForge, please **do not** open a public issue. 

Open a private security advisory on GitHub: https://github.com/zkarchitect/zkforge/security/advisories/new

We take ZK circuit correctness extremely seriously. Every report will be investigated promptly.

## Audit History

| Date | Auditor | Findings | Status |
|------|---------|----------|--------|
| Q3 2026 | Internal | 3 Critical, 4 Medium, 4 Low | All critical & medium fixed |

See [security_audit.md](security_audit.md) for the full audit report.

## Responsible Disclosure

- Acknowledgment within 48 hours
- Fix within 7 days for critical issues
- Public disclosure after fix is released
- Credit in release notes for reporters

## Scope

All code in this repository is in scope:
- `compiler/src/` — compiler core (parser, constraints, R1CS, provers)
- `cli/src/` — CLI interface
- `circom-backend/` — circom compatibility layer
- `shielded/` — auto-shielding logic

The following are out of scope:
- Example circuits (`examples/`) — they are demonstrations, not production
- Generated artifacts (`output/`, `proofs/`) — they are compiler outputs
- Stub functions (Merkle, ECDSA, Poseidon — documented as not production-ready)
