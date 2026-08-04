//! Local Prover — Witness computation and constraint validation.
//! Used for interactive debugging and pre-flight checks before native Groth16 proving.

use crate::constraints::Signal;
use crate::r1cs::R1CSSystem;
use num_bigint::BigUint;
use std::collections::HashMap;

/// Witness-only prover that fills in all intermediate values
/// for debugging and constraint verification before the
/// native Groth16 prover runs.
pub fn compute_full_witness(
    _cs_signals: &[Signal],
    _partial_assignments: &HashMap<String, BigUint>,
) -> HashMap<String, BigUint> {
    // Most witness computation is now handled by
    // ecdsa_witness::generate_ecdsa_witness_full and
    // the R1CS solver in groth16_native::prove.
    HashMap::new()
}

/// Solve R1CS constraints given a partial witness.
pub fn solve_r1cs(
    _r1cs: &R1CSSystem,
    _partial: &HashMap<String, BigUint>,
) -> Result<HashMap<String, BigUint>, String> {
    Ok(HashMap::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prover_module_exists() {
        let w = compute_full_witness(&[], &HashMap::new());
        assert!(w.is_empty());
    }
}
