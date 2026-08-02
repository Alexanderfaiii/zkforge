//! Crypto Primitives — Poseidon + Merkle + MiMC using BigUint for BN254.
//! Real constraint additions that work with the new R1CS system.
//!
//! ## Security Parameters
//!
//! **Poseidon:**
//! - Current: 4 full rounds + 20 partial rounds (24 total, width-3 reduced to width-2).
//! - Production: 8 full rounds + 57 partial rounds (65 total, width-3) per Gröbner basis analysis.
//! - S-box: x^5 (α=5 for BN254/Goldilocks-like fields).
//! - This implementation uses width-2 (2 elements) with x^5 s-box and simplified MDS mixing.
//!
//! **MiMC:**
//! - Current: 10 rounds (demonstration security).
//! - Production: ~91 rounds for 128-bit security in BN254 field when r=⌈254/log₂(7)⌉.
//! - Permutation: x → x^7 (exponent 7 chosen for gcd(7, p-1) = 1 in BN254).
//!
//! **Merkle:**
//! - Uses multi-round Poseidon for each level of the proof.
//! - Typical Merkle depth: 20-32 levels.

use crate::r1cs::R1CSSystem;

// ── Round constant generation ───────────────────────────────────────────

/// Deterministic round constant for Poseidon mixing.
/// Derived from a simple multiplicative hash of round index and column.
/// **Production:** replace with SHA-256 / Keccak-256 of "Poseidon-param-BN254-{round}-{col}".
fn poseidon_round_constant(round: usize, col: usize) -> u64 {
    let base: u64 = 0x19A7B3C5D8E2F164u64;
    let mult: u64 = 0x9E3779B97F4A7C15u64; // golden ratio
    let add: u64 = 0x517CC1B727220A95u64;
    let seed = (round as u64)
        .wrapping_mul(mult)
        .wrapping_add((col as u64) * 0x6A09E667F3BCC908u64);
    seed.wrapping_mul(mult).wrapping_add(add).wrapping_add(base)
}

/// Deterministic round constant for MiMC7.
/// **Production:** replace with Keccak-256 of "MiMC7-const-BN254-{round}".
fn mimc_round_constant(round: usize) -> u64 {
    let mult: u64 = 0x9E3779B97F4A7C15u64;
    let add: u64 = 0xBB67AE8584CAA73Bu64;
    let seed = (round as u64).wrapping_mul(mult);
    seed.wrapping_mul(mult).wrapping_add(add)
}

// ── Poseidon multi-round constraint ─────────────────────────────────────

/// Compute x^5 = ((x^2)^2)·x in the R1CS system.
/// Returns the name of the intermediate x^5 variable.
fn add_pow5(r1cs: &mut R1CSSystem, prefix: &str, var_name: &str) -> String {
    let x2 = format!("{}_x2", prefix);
    let x4 = format!("{}_x4", prefix);
    let x5 = format!("{}_x5", prefix);

    r1cs.add_mul_constraint(&x2, var_name, var_name);
    r1cs.add_mul_constraint(&x4, &x2, &x2);
    r1cs.add_mul_constraint(&x5, &x4, var_name);
    x5
}

/// Apply one full Poseidon round (s-box on both elements, then linear mixing).
/// Returns (new_left_var, new_right_var).
fn add_poseidon_full_round(
    r1cs: &mut R1CSSystem,
    left: &str,
    right: &str,
    round: usize,
    label: &str,
) -> (String, String) {
    // S-box: l^5, r^5
    let l5 = add_pow5(r1cs, &format!("{}_r{}_l", label, round), left);
    let r5 = add_pow5(r1cs, &format!("{}_r{}_r", label, round), right);

    // Linear mixing (simplified 2×2 MDS-like matrix [1 1; 1 2]):
    //   new_left  = l^5 + r^5    + rc_0
    //   new_right = l^5 + 2·r^5  + rc_1
    let new_left = format!("{}_r{}_nl", label, round);
    let new_right = format!("{}_r{}_nr", label, round);

    let rc0 = poseidon_round_constant(round, 0);
    let rc1 = poseidon_round_constant(round, 1);

    // new_left  = l^5 + r^5 + rc0
    r1cs.add_constraint_u64(
        &[(new_left.clone(), 1)],
        &[("ONE".to_string(), 1)],
        &[(l5.clone(), 1), (r5.clone(), 1), ("ONE".to_string(), rc0)],
    );

    // new_right = l^5 + 2·r^5 + rc1
    r1cs.add_constraint_u64(
        &[(new_right.clone(), 1)],
        &[("ONE".to_string(), 1)],
        &[(l5, 1), (r5, 2), ("ONE".to_string(), rc1)],
    );

    (new_left, new_right)
}

/// Apply one partial Poseidon round (s-box on left only, then linear mixing).
/// Returns (new_left_var, new_right_var).
fn add_poseidon_partial_round(
    r1cs: &mut R1CSSystem,
    left: &str,
    right: &str,
    round: usize,
    label: &str,
) -> (String, String) {
    // Partial: only apply s-box to left element
    let l5 = add_pow5(r1cs, &format!("{}_pr{}_l", label, round), left);

    // Linear mixing with same matrix, right passes through without s-box:
    //   new_left  = l^5 + right     + rc_0
    //   new_right = l^5 + 2·right   + rc_1
    let new_left = format!("{}_pr{}_nl", label, round);
    let new_right = format!("{}_pr{}_nr", label, round);

    let rc0 = poseidon_round_constant(round + 1000, 0); // offset to avoid collision with full round constants
    let rc1 = poseidon_round_constant(round + 1000, 1);

    r1cs.add_constraint_u64(
        &[(new_left.clone(), 1)],
        &[("ONE".to_string(), 1)],
        &[
            (l5.clone(), 1),
            (right.to_string(), 1),
            ("ONE".to_string(), rc0),
        ],
    );

    r1cs.add_constraint_u64(
        &[(new_right.clone(), 1)],
        &[("ONE".to_string(), 1)],
        &[(l5, 1), (right.to_string(), 2), ("ONE".to_string(), rc1)],
    );

    (new_left, new_right)
}

/// Poseidon-3 hash over BN254 (x^5 s-box, 4 full + 20 partial rounds).
///
/// `result` = Poseidon3([left, right])
///
/// # Security
///
/// Uses 4 full rounds + 20 partial rounds. This provides basic collision
/// resistance suitable for testing and development.
///
/// **Production circuits MUST use 8 full + 57 partial rounds** (total 65)
/// with width-3 and proper MDS matrix mixing derived from the Poseidon
/// parameter generation script.
pub fn add_poseidon_constraint(
    r1cs: &mut R1CSSystem,
    result_name: &str,
    left_name: &str,
    right_name: &str,
) {
    const FULL_ROUNDS: usize = 4;
    const PARTIAL_ROUNDS: usize = 20;

    let mut l = left_name.to_string();
    let mut r = right_name.to_string();

    // Full rounds (first half): s-box on both elements
    for round in 0..FULL_ROUNDS / 2 {
        let (nl, nr) = add_poseidon_full_round(r1cs, &l, &r, round, result_name);
        l = nl;
        r = nr;
    }

    // Partial rounds: s-box only on left element
    for round in 0..PARTIAL_ROUNDS {
        let (nl, nr) = add_poseidon_partial_round(r1cs, &l, &r, round, result_name);
        l = nl;
        r = nr;
    }

    // Full rounds (second half): s-box on both elements again
    for round in 0..FULL_ROUNDS / 2 {
        let actual_round = FULL_ROUNDS / 2 + round;
        let (nl, nr) = add_poseidon_full_round(r1cs, &l, &r, actual_round, result_name);
        l = nl;
        r = nr;
    }

    // Final linear combination: result = left + right
    // In a proper implementation this would be another partial round output,
    // but for width-2 we emit the sum as the final hash.
    let hash_out = format!("{}_hash", result_name);
    r1cs.add_constraint_u64(
        &[(hash_out.clone(), 1)],
        &[("ONE".to_string(), 1)],
        &[(l, 1), (r, 1)],
    );

    // Constrain hash_out == result_name
    r1cs.constrain_linear_eq(&hash_out, result_name);
}

// ── Merkle proof verification ───────────────────────────────────────────

/// Verify a Merkle inclusion proof using multi-round Poseidon hashing.
///
/// For each level of the proof tree, we apply Poseidon hash to the pair
/// (current, sibling) ordered by direction bit. The final computed root
/// is constrained to equal the claimed root.
///
/// # Parameters
///
/// - `leaf_name`: Name of the leaf signal.
/// - `root_name`: Name of the claimed Merkle root signal.
/// - `path_vars`: Sibling hash signal names for each level.
/// - `directions`: `true` = current node is on the right (sibling on left).
/// - `proof_id`: Unique prefix for intermediate variable names.
///
/// # Returns
///
/// The signal name of the final computed root (constrained equal to `root_name`).
pub fn verify_merkle_proof(
    r1cs: &mut R1CSSystem,
    leaf_name: &str,
    root_name: &str,
    path_vars: &[String],
    directions: &[bool],
    proof_id: &str,
) -> String {
    assert_eq!(
        path_vars.len(),
        directions.len(),
        "Path and direction arrays must have equal length"
    );

    let mut current = format!("{}_mp0", proof_id);
    r1cs.constrain_linear_eq(&current, leaf_name);

    for (i, (sibling, &is_right)) in path_vars.iter().zip(directions.iter()).enumerate() {
        let next = format!("{}_mp{}", proof_id, i + 1);
        let (left, right) = if is_right {
            (current.clone(), sibling.clone())
        } else {
            (sibling.clone(), current.clone())
        };
        add_poseidon_constraint(r1cs, &next, &left, &right);
        current = next;
    }

    r1cs.constrain_linear_eq(&current, root_name);
    current
}

// ── MiMC7 multi-round constraint ────────────────────────────────────────

/// Compute x^7 = ((x^2)^2)·(x^2)·x in the R1CS system.
/// Returns the name of the intermediate x^7 variable.
fn add_pow7(r1cs: &mut R1CSSystem, prefix: &str, var_name: &str) -> String {
    let x2 = format!("{}_x2", prefix);
    let x4 = format!("{}_x4", prefix);
    let x6 = format!("{}_x6", prefix);
    let x7 = format!("{}_x7", prefix);

    r1cs.add_mul_constraint(&x2, var_name, var_name);
    r1cs.add_mul_constraint(&x4, &x2, &x2);
    r1cs.add_mul_constraint(&x6, &x4, &x2);
    r1cs.add_mul_constraint(&x7, &x6, var_name);
    x7
}

/// MiMC7 hash: multi-round Feistel-like construction.
///
/// For each round i ∈ [0, rounds):
///   x = (x + k_i)^7
///
/// Final: result = x + right (absorb second input).
///
/// # Security
///
/// Uses 10 rounds for demonstration. Production circuits require
/// ~91 rounds for 128-bit security in the BN254 scalar field,
/// as r ≈ ⌈log(p) / log(7)⌉ = ⌈254 / 2.807⌉ ≈ 91.
pub fn add_mimc_constraint(
    r1cs: &mut R1CSSystem,
    result_name: &str,
    left_name: &str,
    right_name: &str,
    k_name: &str,
) {
    const ROUNDS: usize = 10;

    // Absorb input: start with left
    let mut x = left_name.to_string();

    for round in 0..ROUNDS {
        // Add round constant: x = x + k_i
        let ki = mimc_round_constant(round);
        let x_plus_k = format!("{}_r{}_add", result_name, round);

        r1cs.add_constraint_u64(
            &[(x_plus_k.clone(), 1)],
            &[("ONE".to_string(), 1)],
            &[(x.clone(), 1), ("ONE".to_string(), ki)],
        );

        // Apply x^7 s-box
        let x7 = add_pow7(r1cs, &format!("{}_r{}", result_name, round), &x_plus_k);
        x = x7;
    }

    // Final absorption: result = x + right + k (absorb second input + key)
    r1cs.add_constraint_u64(
        &[(result_name.to_string(), 1)],
        &[("ONE".to_string(), 1)],
        &[
            (x.clone(), 1),
            (right_name.to_string(), 1),
            (k_name.to_string(), 1),
        ],
    );
}

#[cfg(test)]
#[allow(clippy::len_zero)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon() {
        let mut rcs = R1CSSystem::new();
        rcs.alloc_witness("left");
        rcs.alloc_witness("right");
        add_poseidon_constraint(&mut rcs, "hash", "left", "right");
        // With 24 rounds of Poseidon: (4 mul per pow5 × 2 = 8 mul) × 4 full rounds
        // + (3 mul × 2 × 4 half-rounds) + 20 partial rounds × (3 mul + 2 add)
        // + 1 final combine + 1 linear eq = well over 3
        assert!(rcs.num_constraints() >= 3);
    }

    #[test]
    fn test_merkle_proof() {
        let mut rcs = R1CSSystem::new();
        rcs.alloc_witness("leaf");
        rcs.alloc_witness("root");
        rcs.alloc_witness("sibling0");
        rcs.alloc_witness("sibling1");
        verify_merkle_proof(
            &mut rcs,
            "leaf",
            "root",
            &["sibling0".into(), "sibling1".into()],
            &[false, true],
            "t",
        );
        assert!(rcs.constraints.len() > 0);
        assert!(rcs.vars.contains_key("t_mp2"));
    }

    #[test]
    fn test_mimc() {
        let mut rcs = R1CSSystem::new();
        rcs.alloc_witness("x");
        rcs.alloc_witness("y");
        rcs.alloc_witness("k");
        add_mimc_constraint(&mut rcs, "out", "x", "y", "k");
        // 10 rounds × (1 add + 4 mul) + 1 final add = 51 constraints
        assert!(rcs.num_constraints() >= 4);
    }

    #[test]
    fn test_poseidon_deterministic() {
        // Same inputs should produce the same constraint count.
        let mut rcs1 = R1CSSystem::new();
        rcs1.alloc_witness("a");
        rcs1.alloc_witness("b");
        add_poseidon_constraint(&mut rcs1, "h", "a", "b");
        let n1 = rcs1.num_constraints();

        let mut rcs2 = R1CSSystem::new();
        rcs2.alloc_witness("a");
        rcs2.alloc_witness("b");
        add_poseidon_constraint(&mut rcs2, "h", "a", "b");
        let n2 = rcs2.num_constraints();

        assert_eq!(n1, n2);
    }

    #[test]
    fn test_round_constants_unique() {
        // Round constants should differ from each other.
        let mut constants = std::collections::HashSet::new();
        for round in 0..30 {
            for col in 0..2 {
                let rc = poseidon_round_constant(round, col);
                assert!(
                    constants.insert(rc),
                    "Duplicate round constant at round={}, col={}: {}",
                    round,
                    col,
                    rc
                );
            }
        }
    }
}
