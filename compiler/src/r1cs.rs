//! Pure Rust R1CS — Proper field-aware constraint system for ZKForge
//!
//! Fixes the three critical flaws:
//!  1. u64 → BigUint: 254-bit field support (BN254 compatible)
//!  2. Public/Private: track which variables the verifier sees
//!  3. Witness solving: automatic forward-propagation of witness values
//!
//! : Modular field arithmetic for witness solving (M2 fix).
//! All witness-solving operations are performed modulo BN254 scalar field order.
//! Plain BigUint division is replaced with modular inverse multiplication.
//!
//! R1CS: (A·z) ∘ (B·z) = (C·z), Variable 0 = ONE constant

use num_bigint::BigUint;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

/// BN254 scalar field order (the same as Fr modulus in ark-bn254).
/// All witness arithmetic must be done modulo this value.
pub const BN254_SCALAR_FIELD: &str =
    "21888242871839275222246405745257275088696311157297823662689037894645226208583";

/// Get the field modulus as BigUint (cached).
pub fn field_modulus() -> BigUint {
    BigUint::from_str(BN254_SCALAR_FIELD).unwrap()
}

/// Add two BigUints modulo the BN254 scalar field.
fn mod_add(a: &BigUint, b: &BigUint) -> BigUint {
    (a + b) % field_modulus()
}

/// Subtract two BigUints modulo the BN254 scalar field.
fn mod_sub(a: &BigUint, b: &BigUint) -> BigUint {
    let m = field_modulus();
    if a >= b {
        (a - b) % &m
    } else {
        (a + &m - b) % &m
    }
}

/// Multiply two BigUints modulo the BN254 scalar field.
fn mod_mul(a: &BigUint, b: &BigUint) -> BigUint {
    (a * b) % field_modulus()
}

/// Modular inverse of a BigUint modulo the BN254 scalar field.
/// Uses extended Euclidean algorithm. Returns None if a ≡ 0 (mod field).
fn mod_inv(a: &BigUint) -> Option<BigUint> {
    let m = field_modulus();
    if *a == BigUint::from(0u64) || a % &m == BigUint::from(0u64) {
        return None;
    }
    // Extended Euclidean Algorithm: find x such that a*x ≡ 1 (mod m)
    let (gcd, x, _) = egcd(a, &m);
    if gcd != BigUint::from(1u64) {
        return None;
    }
    let result = x % &m;
    Some(result)
}

/// Extended Euclidean algorithm: returns (gcd, x, y) where ax + by = gcd.
fn egcd(a: &BigUint, b: &BigUint) -> (BigUint, BigUint, BigUint) {
    let (mut old_r, mut r) = (a.clone(), b.clone());
    let (mut old_s, mut s) = (BigUint::from(1u64), BigUint::from(0u64));
    let (mut old_t, mut t) = (BigUint::from(0u64), BigUint::from(1u64));

    while r != BigUint::from(0u64) {
        let quotient = &old_r / &r;
        let new_r = &old_r - &quotient * &r;
        old_r = r;
        r = new_r;
        let new_s = mod_sub(&old_s, &mod_mul(&quotient, &s));
        old_s = s;
        s = new_s;
        let new_t = mod_sub(&old_t, &mod_mul(&quotient, &t));
        old_t = t;
        t = new_t;
    }
    (old_r, old_s, old_t)
}

/// A variable index in the R1CS witness vector. 0 = ONE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct R1CSVar(pub usize);

/// Sparse R1CS constraint: Σ a_i·z_i * Σ b_i·z_i = Σ c_i·z_i
/// Coefficients are BigUint for full field compatibility.
#[derive(Debug, Clone)]
pub struct SparseConstraint {
    pub a: Vec<(usize, BigUint)>,
    pub b: Vec<(usize, BigUint)>,
    pub c: Vec<(usize, BigUint)>,
}

/// The R1CS constraint system with public/private separation.
#[derive(Debug, Clone)]
pub struct R1CSSystem {
    pub vars: HashMap<String, R1CSVar>,
    /// Variable indices that are public (verifier sees them)
    pub public_vars: HashSet<usize>,
    pub constraints: Vec<SparseConstraint>,
    next_var: usize,
}

fn one() -> BigUint {
    BigUint::from(1u64)
}
pub(crate) fn zero() -> BigUint {
    BigUint::from(0u64)
}
pub(crate) fn coeff(c: u64) -> BigUint {
    BigUint::from(c)
}

impl Default for R1CSSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl R1CSSystem {
    pub fn new() -> Self {
        let mut s = R1CSSystem {
            vars: HashMap::new(),
            public_vars: HashSet::new(),
            constraints: Vec::new(),
            next_var: 0,
        };
        // Variable 0 = ONE is always public
        s.vars.insert("ONE".to_string(), R1CSVar(0));
        s.public_vars.insert(0);
        s.next_var = 1;
        s
    }

    /// Allocate a private witness variable.
    pub fn alloc_witness(&mut self, name: &str) -> R1CSVar {
        if let Some(v) = self.vars.get(name) {
            return *v;
        }
        let idx = self.next_var;
        self.next_var += 1;
        let var = R1CSVar(idx);
        self.vars.insert(name.to_string(), var);
        var
    }

    /// Allocate a public input variable (verifier sees this).
    pub fn alloc_public(&mut self, name: &str) -> R1CSVar {
        let var = self.alloc_witness(name);
        self.public_vars.insert(var.0);
        var
    }

    /// Change an existing variable to public.
    pub fn make_public(&mut self, name: &str) {
        if let Some(var) = self.vars.get(name) {
            self.public_vars.insert(var.0);
        }
    }

    pub fn is_public(&self, var: &R1CSVar) -> bool {
        self.public_vars.contains(&var.0)
    }

    pub fn add_constraint(
        &mut self,
        a: &[(String, BigUint)],
        b: &[(String, BigUint)],
        c: &[(String, BigUint)],
    ) {
        let a_vec: Vec<(usize, BigUint)> = a
            .iter()
            .map(|(n, coeff)| (self.alloc_witness(n).0, coeff.clone()))
            .collect();
        let b_vec: Vec<(usize, BigUint)> = b
            .iter()
            .map(|(n, coeff)| (self.alloc_witness(n).0, coeff.clone()))
            .collect();
        let c_vec: Vec<(usize, BigUint)> = c
            .iter()
            .map(|(n, coeff)| (self.alloc_witness(n).0, coeff.clone()))
            .collect();
        self.constraints.push(SparseConstraint {
            a: a_vec,
            b: b_vec,
            c: c_vec,
        });
    }

    pub fn add_constraint_u64(
        &mut self,
        a: &[(String, u64)],
        b: &[(String, u64)],
        c: &[(String, u64)],
    ) {
        self.add_constraint(
            &a.iter()
                .map(|(n, c)| (n.clone(), coeff(*c)))
                .collect::<Vec<_>>(),
            &b.iter()
                .map(|(n, c)| (n.clone(), coeff(*c)))
                .collect::<Vec<_>>(),
            &c.iter()
                .map(|(n, c)| (n.clone(), coeff(*c)))
                .collect::<Vec<_>>(),
        );
    }

    pub fn add_mul_constraint(&mut self, c_name: &str, a_name: &str, b_name: &str) {
        self.add_constraint_u64(
            &[(a_name.to_string(), 1)],
            &[(b_name.to_string(), 1)],
            &[(c_name.to_string(), 1)],
        );
    }

    pub fn constrain_binary(&mut self, var_name: &str) {
        self.add_constraint_u64(
            &[(var_name.to_string(), 1)],
            &[(var_name.to_string(), 1)],
            &[(var_name.to_string(), 1)],
        );
    }

    pub fn constrain_eq_constant(&mut self, var_name: &str, k: u64) {
        let field = field_modulus();
        let k_biguint = BigUint::from(k);
        if k_biguint >= field {
            panic!(
                "constrain_eq_constant: constant {} exceeds BN254 scalar field order {}",
                k, BN254_SCALAR_FIELD
            );
        }
        self.add_constraint_u64(
            &[(var_name.to_string(), 1)],
            &[("ONE".to_string(), 1)],
            &[("ONE".to_string(), k)],
        );
    }

    pub fn constrain_linear_eq(&mut self, a_name: &str, b_name: &str) {
        self.add_constraint_u64(
            &[(a_name.to_string(), 1)],
            &[("ONE".to_string(), 1)],
            &[(b_name.to_string(), 1)],
        );
    }

    pub fn num_vars(&self) -> usize {
        self.next_var
    }
    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    /// Solve the witness: given concrete assignments to some variables,
    /// compute all unknown witness values by forward propagation.
    ///
    /// Phases:
    ///  1. Apply user assignments
    ///  2. Multi-pass constraint propagation:
    ///     a. ReLU: bit * dense = relu (dense known from forward pass)
    ///     b. Generic: solve for single unknowns in A*B=C
    ///     c. Bit-decomposition: signal = Σ(bit_i * 2^i) after bits are resolved
    ///  3. Post-pass bit-decomp for stubborn constraints
    ///  4. Collect results
    pub fn solve_witness(
        &self,
        assignments: &HashMap<String, BigUint>,
    ) -> Result<HashMap<String, BigUint>, String> {
        let mut w: Vec<BigUint> = vec![zero(); self.num_vars()];
        let mut known: HashSet<usize> = HashSet::new();
        let field = field_modulus();
        let half = &field / BigUint::from(2u64);

        // Set ONE = 1
        w[0] = one();
        known.insert(0);

        // ===== Phase 1: Apply user assignments =====
        for (name, val) in assignments {
            if let Some(var) = self.vars.get(name) {
                w[var.0] = val.clone();
                known.insert(var.0);
            }
        }

        // ===== Phase 2: Constraint propagation (iterative, multi-pass) =====
        let mut changed = true;
        for _round in 0..200 {
            if !changed {
                break;
            }
            changed = false;

            for c in &self.constraints {
                // --- Skip self-loops (x*x=x pattern from constrain_binary) ---
                if c.a.len() == 1
                    && c.b.len() == 1
                    && c.c.len() == 1
                    && c.a[0].0 == c.b[0].0
                    && c.a[0].0 == c.c[0].0
                {
                    continue;
                }

                // --- ReLU: add_mul_constraint(relu, bit, dense)
                //   a=[(bit,1)], b=[(dense,1)], c=[(relu,1)]
                if c.a.len() == 1
                    && c.b.len() == 1
                    && c.c.len() == 1
                    && c.a[0].1 == one()
                    && c.b[0].1 == one()
                    && c.c[0].1 == one()
                {
                    let bit_i = c.a[0].0;
                    let dense_i = c.b[0].0;
                    let relu_i = c.c[0].0;
                    // These are the same variable (x*x=x), handled above
                    // Only skip true self-loops (x*x=x, which was handled above)
                    if bit_i == dense_i && bit_i == relu_i {
                        continue;
                    }
                    // Skip constraints where b-side is ONE (linear-eq pattern: y*ONE=x).
                    // ReLU requires dense to be a real forward-pass value, never a constant.
                    if dense_i == 0 {
                        // fall through to generic solver
                    } else {
                        let dense_kn = known.contains(&dense_i);
                        let bit_kn = known.contains(&bit_i);
                        let relu_kn = known.contains(&relu_i);

                        // Core ReLU: dense known, bit unknown -> determine sign
                        if dense_kn && !bit_kn {
                            let dv = &w[dense_i] % &field;
                            let is_neg = dv > half;
                            w[bit_i] = if is_neg { zero() } else { one() };
                            known.insert(bit_i);
                            if !relu_kn {
                                w[relu_i] = if is_neg { zero() } else { dv.clone() };
                                known.insert(relu_i);
                            }
                            changed = true;
                            continue;
                        }

                        // bit=0 => relu=0
                        if bit_kn && w[bit_i] == zero() && !relu_kn {
                            w[relu_i] = zero();
                            known.insert(relu_i);
                            changed = true;
                            continue;
                        }
                    } // end else dense_i != 0
                } // end ReLU handler

                // --- Evaluate constraint sides ---
                let ev = |t: &[(usize, BigUint)]| -> (BigUint, bool) {
                    let mut s = zero();
                    let mut all = true;
                    for (idx, coeff) in t {
                        if known.contains(idx) {
                            s = mod_add(&s, &mod_mul(coeff, &w[*idx]));
                        } else {
                            all = false;
                        }
                    }
                    (s, all)
                };
                let (av, ak) = ev(&c.a);
                let (bv, bk) = ev(&c.b);
                let (cv, ck) = ev(&c.c);

                // --- Zero-check: a*b == 0 (c is empty or (ONE,0)) ---
                // IMPORTANT: if one side is zero, the other can be ANYTHING (0*x=0).
                // Only set unknown to zero when the KNOWN side is NON-ZERO.
                let c_is_zero =
                    c.c.is_empty() || (c.c.len() == 1 && c.c[0].1 == zero() && c.c[0].0 == 0);
                if c_is_zero {
                    if c.a.len() == 1 && c.b.len() == 1 {
                        // Known A != 0, unknown B → B must be 0
                        if ak && !bk && w[c.a[0].0] != zero() {
                            w[c.b[0].0] = zero();
                            known.insert(c.b[0].0);
                            changed = true;
                        // Known B != 0, unknown A → A must be 0
                        } else if bk && !ak && w[c.b[0].0] != zero() {
                            w[c.a[0].0] = zero();
                            known.insert(c.a[0].0);
                            changed = true;
                        }
                        // If known side IS zero, leave the other side alone (0*x=0 ∀x)
                    }
                    continue;
                }

                // --- Solve for one unknown on C side (both A and B known) ---
                if ak && bk {
                    let mut uk: Option<usize> = None;
                    for (idx, _) in &c.c {
                        if !known.contains(idx) {
                            if uk.is_some() {
                                uk = None;
                                break;
                            }
                            uk = Some(*idx);
                        }
                    }
                    if let Some(ci) = uk {
                        let tgt = mod_mul(&av, &bv);
                        let rest: BigUint =
                            c.c.iter()
                                .filter(|(idx, _)| *idx != ci)
                                .fold(zero(), |acc, (idx, tc)| {
                                    mod_add(&acc, &mod_mul(tc, &w[*idx]))
                                });
                        let num = mod_sub(&tgt, &rest);
                        let cc =
                            c.c.iter()
                                .find(|(idx, _)| *idx == ci)
                                .map(|(_, c)| c.clone())
                                .unwrap_or(one());
                        if cc == one() {
                            w[ci] = num;
                            known.insert(ci);
                            changed = true;
                        } else if let Some(inv) = mod_inv(&cc) {
                            w[ci] = mod_mul(&num, &inv);
                            known.insert(ci);
                            changed = true;
                        }
                    }
                }

                // --- Solve for one unknown on A side (B and C known, B ≠ 0) ---
                if bk && ck && bv != zero() {
                    let mut uk: Option<usize> = None;
                    for (idx, _) in &c.a {
                        if !known.contains(idx) {
                            if uk.is_some() {
                                uk = None;
                                break;
                            }
                            uk = Some(*idx);
                        }
                    }
                    if let Some(ai) = uk {
                        let rest: BigUint =
                            c.a.iter()
                                .filter(|(idx, _)| *idx != ai)
                                .fold(zero(), |acc, (idx, tc)| {
                                    mod_add(&acc, &mod_mul(tc, &w[*idx]))
                                });
                        let ca =
                            c.a.iter()
                                .find(|(idx, _)| *idx == ai)
                                .map(|(_, c)| c.clone())
                                .unwrap_or(one());
                        if let Some(b_inv) = mod_inv(&bv) {
                            let tgt = mod_mul(&cv, &b_inv);
                            let num = mod_sub(&tgt, &rest);
                            if ca == one() {
                                w[ai] = num;
                                known.insert(ai);
                                changed = true;
                            } else if let Some(inv) = mod_inv(&ca) {
                                w[ai] = mod_mul(&num, &inv);
                                known.insert(ai);
                                changed = true;
                            }
                        }
                    }
                }

                // --- Solve for one unknown on B side (A and C known, A ≠ 0) ---
                if ak && ck && av != zero() {
                    let mut uk: Option<usize> = None;
                    for (idx, _) in &c.b {
                        if !known.contains(idx) {
                            if uk.is_some() {
                                uk = None;
                                break;
                            }
                            uk = Some(*idx);
                        }
                    }
                    if let Some(bi) = uk {
                        let rest: BigUint =
                            c.b.iter()
                                .filter(|(idx, _)| *idx != bi)
                                .fold(zero(), |acc, (idx, tc)| {
                                    mod_add(&acc, &mod_mul(tc, &w[*idx]))
                                });
                        let cb =
                            c.b.iter()
                                .find(|(idx, _)| *idx == bi)
                                .map(|(_, c)| c.clone())
                                .unwrap_or(one());
                        if let Some(a_inv) = mod_inv(&av) {
                            let tgt = mod_mul(&cv, &a_inv);
                            let num = mod_sub(&tgt, &rest);
                            if cb == one() {
                                w[bi] = num;
                                known.insert(bi);
                                changed = true;
                            } else if let Some(inv) = mod_inv(&cb) {
                                w[bi] = mod_mul(&num, &inv);
                                known.insert(bi);
                                changed = true;
                            }
                        }
                    }
                }
            }
        }

        // ===== Phase 3: Post-pass — bit-decomposition from known signal =====
        // Pattern: signal * 1 = Σ(bit_i * 2^i)
        // Only trigger when ALL C-side coefficients are powers of 2.
        for c in &self.constraints {
            if c.a.len() != 1 || c.a[0].1 != one() {
                continue;
            }
            if c.b.len() != 1 || c.b[0].0 != 0 || c.b[0].1 != one() {
                continue;
            }
            if c.c.len() <= 1 {
                continue;
            }

            let sig_i = c.a[0].0;
            if !known.contains(&sig_i) {
                continue;
            }

            // Verify ALL C coefficients are exact powers of 2
            let all_pow2 = c.c.iter().all(|(_, coeff)| {
                let c_val = coeff % &field;
                c_val == zero() || (c_val != zero() && (c_val == one() || c_val.count_ones() == 1))
            });
            if !all_pow2 {
                continue;
            }

            let mut sorted_c: Vec<(usize, BigUint)> = c.c.clone();
            sorted_c.sort_by_key(|(_, coeff)| coeff.clone());

            let sig_val = &w[sig_i] % &field;
            let mut remaining = sig_val.clone();

            for (bit_i, coeff) in &sorted_c {
                let weight = coeff % &field;
                // Allow overwriting — generic solver may have assigned wrong values
                if remaining >= weight {
                    w[*bit_i] = one();
                    remaining = mod_sub(&remaining, &weight);
                } else {
                    w[*bit_i] = zero();
                }
                known.insert(*bit_i);
            }
        }

        // ===== Phase 4: Collect results =====
        let mut result = HashMap::new();
        for (name, var) in &self.vars {
            if known.contains(&var.0) {
                result.insert(name.clone(), w[var.0].clone());
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bu(n: u64) -> BigUint {
        BigUint::from(n)
    }

    #[test]
    fn test_basic_mul() {
        let mut s = R1CSSystem::new();
        s.add_mul_constraint("c", "a", "b");
        assert_eq!(s.num_vars(), 4);
        assert_eq!(s.num_constraints(), 1);
    }

    #[test]
    fn test_binary() {
        let mut s = R1CSSystem::new();
        s.constrain_binary("x");
        assert_eq!(s.num_constraints(), 1);
    }

    #[test]
    fn test_linear_eq() {
        let mut s = R1CSSystem::new();
        s.constrain_linear_eq("x", "y");
        assert_eq!(s.num_constraints(), 1);
    }

    #[test]
    fn test_solve_witness_mul() {
        let mut s = R1CSSystem::new();
        s.alloc_witness("x");
        s.alloc_witness("y");
        s.alloc_witness("z");
        s.add_mul_constraint("z", "x", "y");

        let mut input = HashMap::new();
        input.insert("x".into(), bu(3));
        input.insert("y".into(), bu(4));

        let result = s.solve_witness(&input).unwrap();
        assert_eq!(result.get("z").unwrap(), &bu(12));
    }

    #[test]
    fn test_solve_linear_eq() {
        let mut s = R1CSSystem::new();
        s.constrain_linear_eq("a", "b");

        let mut input = HashMap::new();
        input.insert("a".into(), bu(42));

        let result = s.solve_witness(&input).unwrap();
        assert_eq!(result.get("b").unwrap(), &bu(42));
    }

    #[test]
    fn test_public_private() {
        let mut s = R1CSSystem::new();
        let pk = s.alloc_public("public_key");
        let sk = s.alloc_witness("secret_key");
        assert!(s.is_public(&pk));
        assert!(!s.is_public(&sk));
    }

    #[test]
    fn test_large_field_values() {
        // Test values beyond u64 range
        let mut s = R1CSSystem::new();
        s.alloc_witness("big_a");
        s.alloc_witness("big_b");
        s.alloc_witness("big_c");
        s.add_mul_constraint("big_c", "big_a", "big_b");

        let large = BigUint::from(1_000_000_000_000_000_000u64) * BigUint::from(1_000_000u64);
        let mut input = HashMap::new();
        input.insert("big_a".into(), large.clone());
        input.insert("big_b".into(), bu(2));

        let result = s.solve_witness(&input).unwrap();
        assert_eq!(result.get("big_c").unwrap(), &(large * bu(2)));
    }
}
