# Privacy Report: ShieldedToken

Original contract: **Token**

## What is Private

- **6 state variables** are now hidden (stored as commitments)
- **All function arguments** are private (inside ZK proof)
- **State transition logic** is private (verified in ZK)
- Only commitments + nullifiers are stored on-chain

## Shielded Functions

- **2 functions** now require ZK proofs
- Each call: submit proof + nullifier → contract updates state
- Replay protection: nullifiers are tracked on-chain

## Gas Estimates

| Operation | Gas |
|-----------|-----|
| Shielded call | ~250K |
| Proof verification | ~170K |
| State update | ~30K |
| **Total per call** | **~450K** |

## Security

- ✅ EIP-197 pairing precompile for proof verification
- ✅ Nullifier-based replay protection
- ✅ Poseidon hash for commitment binding
- ✅ Every state transition is ZK-proven on-chain
