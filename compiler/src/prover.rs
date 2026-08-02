//! Local Prover — Witness computation and validation.
//!
//! Uses the R1CS system's built-in witness solver for automatic
//! variable computation from partial assignments.

use crate::r1cs::R1CSSystem;
use num_bigint::BigUint;
use std::collections::HashMap;

/// Assignment for a single variable.
#[derive(Debug, Clone)]
pub struct VariableAssignment {
    pub name: String,
    pub value: BigUint,
}

impl VariableAssignment {
    pub fn new(name: &str, value: u64) -> Self {
        VariableAssignment {
            name: name.to_string(),
            value: BigUint::from(value),
        }
    }
}

/// A local prover for constraint validation.
pub struct LocalProver {
    pub r1cs: R1CSSystem,
}

impl LocalProver {
    pub fn new(r1cs: R1CSSystem) -> Self {
        LocalProver { r1cs }
    }

    /// Verify that all constraints hold for the given assignments.
    pub fn verify_witness(&self, assignments: &HashMap<String, BigUint>) -> Result<bool, String> {
        let solved = self.r1cs.solve_witness(assignments)?;

        for c in &self.r1cs.constraints {
            let eval = |terms: &[(usize, BigUint)], w: &HashMap<String, BigUint>| -> BigUint {
                terms.iter().fold(BigUint::from(0u64), |acc, (idx, coeff)| {
                    let name = self
                        .r1cs
                        .vars
                        .iter()
                        .find(|(_, v)| v.0 == *idx)
                        .map(|(n, _)| n.clone())
                        .unwrap_or_default();
                    let val = w.get(&name).cloned().unwrap_or_else(|| BigUint::from(0u64));
                    acc + coeff * val
                })
            };

            let a_val = eval(&c.a, &solved);
            let b_val = eval(&c.b, &solved);
            let c_val = eval(&c.c, &solved);

            if a_val * b_val != c_val {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solve_and_verify() {
        let mut rcs = R1CSSystem::new();
        rcs.alloc_witness("x");
        rcs.alloc_witness("y");
        rcs.alloc_witness("z");
        rcs.add_mul_constraint("z", "x", "y");

        let mut input = HashMap::new();
        input.insert("x".into(), BigUint::from(3u64));
        input.insert("y".into(), BigUint::from(4u64));

        let prover = LocalProver::new(rcs);
        assert!(prover.verify_witness(&input).unwrap());
    }

    #[test]
    fn test_failing_constraint() {
        let mut rcs = R1CSSystem::new();
        rcs.alloc_witness("x");
        rcs.alloc_witness("y");
        rcs.alloc_witness("z");
        rcs.add_mul_constraint("z", "x", "y");

        let mut input = HashMap::new();
        input.insert("x".into(), BigUint::from(3u64));
        input.insert("y".into(), BigUint::from(4u64));
        input.insert("z".into(), BigUint::from(13u64)); // wrong!

        let prover = LocalProver::new(rcs);
        assert!(!prover.verify_witness(&input).unwrap());
    }
}
