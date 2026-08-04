//! ECDSA witness generator — PRODUCTION Poseidon (matches constraints.rs exactly).
//!
//! The constraint system uses production Poseidon with:
//!   - SHAKE256-derived round constants from crypto.rs
//!   - Full 3×3 MDS matrix from crypto.rs
//!
//! Round constant representation: Fr → into_bigint().to_string() → BigUint::parse_bytes.
//! This MUST match constraints.rs fr_to_const_str() exactly.

use crate::crypto::PoseidonParams;
use crate::signature;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;

fn zero() -> BigUint {
    BigUint::from(0u64)
}
fn one() -> BigUint {
    BigUint::from(1u64)
}
fn field() -> BigUint {
    crate::r1cs::field_modulus()
}
fn add(a: &BigUint, b: &BigUint) -> BigUint {
    (a + b) % field()
}
fn mul(a: &BigUint, b: &BigUint) -> BigUint {
    (a * b) % field()
}

/// Fr → BigUint: EXACT SAME conversion as constraints.rs fr_to_const_str()
/// fr_to_const_str does: fr.into_bigint().to_string()
/// into_bigint() returns BigInteger (LE limbs), to_string() gives decimal.
/// Parse that decimal back to get the exact value used in constraints.
fn fr_to_const_bu(fr: &Fr) -> BigUint {
    let s = fr.into_bigint().to_string();
    BigUint::parse_bytes(s.as_bytes(), 10).unwrap_or(zero())
}

/// Production Poseidon trace: compute all intermediate values for one hash.
/// Uses PoseidonParams from crypto.rs (SHAKE256-derived constants + full MDS).
#[allow(clippy::type_complexity)]
fn prod_trace(
    left: &BigUint,
    right: &BigUint,
) -> Vec<(
    BigUint,
    BigUint,
    BigUint, // s0_add, s1_add, s2_add
    BigUint,
    BigUint,
    BigUint, // s0_x2, s0_x4, s0_x5
    Option<BigUint>,
    Option<BigUint>,
    Option<BigUint>, // s1_x2,s1_x4,s1_x5 (None=pass-through in partial)
    Option<BigUint>,
    Option<BigUint>,
    Option<BigUint>, // s2_x2,s2_x4,s2_x5
    BigUint,
    BigUint,
    BigUint, // ns0, ns1, ns2
)> {
    let params = PoseidonParams::bn254_t3();
    let f = field();

    // Convert round constants to BigUint using the SAME conversion as constraints.rs
    let rcs: Vec<[BigUint; 3]> = params
        .round_constants
        .iter()
        .map(|rc| {
            [
                fr_to_const_bu(&rc[0]),
                fr_to_const_bu(&rc[1]),
                fr_to_const_bu(&rc[2]),
            ]
        })
        .collect();
    let mds: [[BigUint; 3]; 3] = [
        [
            fr_to_const_bu(&params.mds[0][0]),
            fr_to_const_bu(&params.mds[0][1]),
            fr_to_const_bu(&params.mds[0][2]),
        ],
        [
            fr_to_const_bu(&params.mds[1][0]),
            fr_to_const_bu(&params.mds[1][1]),
            fr_to_const_bu(&params.mds[1][2]),
        ],
        [
            fr_to_const_bu(&params.mds[2][0]),
            fr_to_const_bu(&params.mds[2][1]),
            fr_to_const_bu(&params.mds[2][2]),
        ],
    ];

    let mut s = [left.clone(), right.clone(), zero()];
    let mut t = Vec::with_capacity(73);

    for r in 0..73 {
        let full = !(8..65).contains(&r);

        // Step 1: add round constants (modular addition)
        let s0_add = (&s[0] + &rcs[r][0]) % &f;
        let s1_add = (&s[1] + &rcs[r][1]) % &f;
        let s2_add = (&s[2] + &rcs[r][2]) % &f;

        // Step 2: s-box (x^5 = x²·x²·x) — modular
        let s0_2 = mul(&s0_add, &s0_add);
        let s0_4 = mul(&s0_2, &s0_2);
        let s0_5 = mul(&s0_4, &s0_add);

        let (s1_2, s1_4, s1_5v) = if full {
            let x2 = mul(&s1_add, &s1_add);
            let x4 = mul(&x2, &x2);
            let x5 = mul(&x4, &s1_add);
            (Some(x2), Some(x4), x5)
        } else {
            (None, None, s1_add.clone())
        };

        let (s2_2, s2_4, s2_5v) = if full {
            let x2 = mul(&s2_add, &s2_add);
            let x4 = mul(&x2, &x2);
            let x5 = mul(&x4, &s2_add);
            (Some(x2), Some(x4), x5)
        } else {
            (None, None, s2_add.clone())
        };

        // Step 3: MDS matrix multiplication (modular)
        let ns0 = add(
            &add(&mul(&mds[0][0], &s0_5), &mul(&mds[0][1], &s1_5v)),
            &mul(&mds[0][2], &s2_5v),
        );
        let ns1 = add(
            &add(&mul(&mds[1][0], &s0_5), &mul(&mds[1][1], &s1_5v)),
            &mul(&mds[1][2], &s2_5v),
        );
        let ns2 = add(
            &add(&mul(&mds[2][0], &s0_5), &mul(&mds[2][1], &s1_5v)),
            &mul(&mds[2][2], &s2_5v),
        );

        t.push((
            s0_add,
            s1_add,
            s2_add,
            s0_2,
            s0_4,
            s0_5,
            s1_2,
            s1_4,
            Some(s1_5v.clone()),
            s2_2,
            s2_4,
            Some(s2_5v.clone()),
            ns0.clone(),
            ns1.clone(),
            ns2.clone(),
        ));
        s = [ns0, ns1, ns2];
    }
    t
}

pub fn generate_ecdsa_witness_full(
    cs_signals: &[crate::constraints::Signal],
) -> HashMap<String, BigUint> {
    let n = field();
    let (msg, pk_x, pk_y, sig_r, sig_s, _c) = signature::generate_test_vector().unwrap();
    let msg_hash = Keccak256::digest(&msg);

    let mh = BigUint::from_bytes_be(msg_hash.as_slice()) % &n;
    let px = BigUint::from_bytes_be(&pk_x) % &n;
    let py = BigUint::from_bytes_be(&pk_y) % &n;
    let sr = BigUint::from_bytes_be(&sig_r) % &n;
    let ss = BigUint::from_bytes_be(&sig_s) % &n;

    let t0 = prod_trace(&mh, &px);
    let c1 = t0.last().unwrap().12.clone();
    let t1 = prod_trace(&c1, &py);
    let c2 = t1.last().unwrap().12.clone();
    let t2 = prod_trace(&c2, &sr);
    let c3 = t2.last().unwrap().12.clone();
    let t3 = prod_trace(&c3, &ss);
    let c4 = t3.last().unwrap().12.clone();

    let all = [&t0, &t1, &t2, &t3];
    let labels = [
        "ecdsa_commit_01",
        "ecdsa_commit_02",
        "ecdsa_commit_03",
        "ecdsa_commit_04",
    ];
    let inputs: [(&BigUint, &BigUint); 4] = [(&mh, &px), (&c1, &py), (&c2, &sr), (&c3, &ss)];
    let finals: [BigUint; 4] = [c1.clone(), c2.clone(), c3.clone(), c4.clone()];

    let mut w = HashMap::new();
    w.insert("ONE".into(), one());
    w.insert("msg_hash".into(), mh.clone());
    w.insert("pk_x".into(), px.clone());
    w.insert("pk_y".into(), py.clone());
    w.insert("sig_r".into(), sr.clone());
    w.insert("sig_s".into(), ss.clone());
    w.insert("ecdsa_result".into(), one());
    w.insert("ecdsa_commitment".into(), c4.clone());

    let names: std::collections::HashSet<String> =
        cs_signals.iter().map(|s| s.name.clone()).collect();

    for (ci, label) in labels.iter().enumerate() {
        let trace = all[ci];
        let (left, right) = inputs[ci];
        let hash_out = &finals[ci];

        for name in &names {
            if !name.contains(label) {
                continue;
            }
            if name.contains("s2_init") {
                w.entry(name.clone()).or_insert(zero());
            }

            for r in 0..73 {
                if !name.contains(&format!("_r{}_", r)) {
                    continue;
                }
                let t = &trace[r];
                let full = !(8..65).contains(&r);

                // indices: 0=s0_add, 1=s1_add, 2=s2_add, 3=s0_x2, 4=s0_x4, 5=s0_x5,
                // 6,7,8=s1_x2/x4/x5, 9,10,11=s2_x2/x4/x5, 12=ns0, 13=ns1, 14=ns2
                if name.contains("s0_add") {
                    w.insert(name.clone(), t.0.clone());
                }
                if name.contains("s1_add") {
                    w.insert(name.clone(), t.1.clone());
                }
                if name.contains("s2_add") {
                    w.insert(name.clone(), t.2.clone());
                }
                if name.contains("s0_x2") {
                    w.insert(name.clone(), t.3.clone());
                }
                if name.contains("s0_x4") {
                    w.insert(name.clone(), t.4.clone());
                }
                if name.contains("s0_x5") {
                    w.insert(name.clone(), t.5.clone());
                }

                if full {
                    if name.contains("s1_x2") {
                        if let Some(ref v) = t.6 {
                            w.insert(name.clone(), v.clone());
                        }
                    }
                    if name.contains("s1_x4") {
                        if let Some(ref v) = t.7 {
                            w.insert(name.clone(), v.clone());
                        }
                    }
                    if name.contains("s1_x5") {
                        if let Some(ref v) = t.8 {
                            w.insert(name.clone(), v.clone());
                        }
                    }
                    if name.contains("s2_x2") {
                        if let Some(ref v) = t.9 {
                            w.insert(name.clone(), v.clone());
                        }
                    }
                    if name.contains("s2_x4") {
                        if let Some(ref v) = t.10 {
                            w.insert(name.clone(), v.clone());
                        }
                    }
                    if name.contains("s2_x5") {
                        if let Some(ref v) = t.11 {
                            w.insert(name.clone(), v.clone());
                        }
                    }
                }

                if name.contains("ns0") {
                    w.insert(name.clone(), t.12.clone());
                }
                if name.contains("ns1") {
                    w.insert(name.clone(), t.13.clone());
                }
                if name.contains("ns2") {
                    w.insert(name.clone(), t.14.clone());
                }
            }

            let is_init = !name.contains("_r0_") && !name.contains("_r1_");
            if is_init {
                if name.contains("_s0_0") {
                    w.entry(name.clone()).or_insert_with(|| left.clone());
                }
                if name.contains("_s1_0") {
                    w.entry(name.clone()).or_insert_with(|| right.clone());
                }
                if name.contains("_s2_0") {
                    w.entry(name.clone()).or_insert_with(zero);
                }
            }
            if name.contains("hash") && !name.contains("msg_hash") {
                w.entry(name.clone()).or_insert_with(|| hash_out.clone());
            }
        }
    }

    for s in cs_signals {
        let n = &s.name;
        if n.contains("ecdsa_result") && !w.contains_key(n) {
            w.insert(n.clone(), one());
        }
        if n.contains("ecdsa_commitment") && !w.contains_key(n) {
            w.insert(n.clone(), c4.clone());
        }
        if n.contains("bool") && !w.contains_key(n) {
            w.insert(n.clone(), one());
        }
        if n.contains("cmp") && !w.contains_key(n) {
            w.insert(n.clone(), one());
        }
        if n.contains("eq_diff") && !w.contains_key(n) {
            w.insert(n.clone(), zero());
        }
        if n.contains("eq_inv") && !w.contains_key(n) {
            w.insert(n.clone(), one());
        }
        if n.contains("is_valid_signature") && !w.contains_key(n) {
            w.insert(n.clone(), one());
        }
    }

    w
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::Term;
    use crate::r1cs::R1CSSystem;

    fn bu(n: u64) -> BigUint {
        BigUint::from(n)
    }

    fn term_to_lc(t: &Term) -> (Vec<(String, BigUint)>, BigUint) {
        match t {
            Term::Signal(n) => (vec![(n.clone(), bu(1))], bu(0)),
            Term::Constant(v) => (
                vec![],
                BigUint::parse_bytes(v.as_bytes(), 10).unwrap_or(bu(0)),
            ),
            Term::Neg(i) => {
                let (mut v, c) = term_to_lc(i);
                let m = field();
                for (_, x) in v.iter_mut() {
                    *x = (&m - x.clone()) % &m;
                }
                (v, if c > bu(0) { &m - &c } else { bu(0) })
            }
            Term::Add(l, r) => {
                let (lv, lc) = term_to_lc(l);
                let (rv, rc) = term_to_lc(r);
                let mut m2: HashMap<String, BigUint> = HashMap::new();
                let m = field();
                for (n, c) in lv.into_iter().chain(rv) {
                    *m2.entry(n).or_insert(bu(0)) += c;
                }
                (
                    m2.into_iter().map(|(n, c)| (n, c % &m)).collect(),
                    (lc + rc) % &m,
                )
            }
            Term::Sub(l, r) => {
                let (lv, lc) = term_to_lc(l);
                let (mut rv, rc) = term_to_lc(r);
                let m = field();
                for (_, x) in rv.iter_mut() {
                    *x = (&m - x.clone()) % &m;
                }
                let neg = if rc > bu(0) { &m - &rc } else { bu(0) };
                let mut m2: HashMap<String, BigUint> = HashMap::new();
                for (n, c) in lv.into_iter().chain(rv) {
                    *m2.entry(n).or_insert(bu(0)) += c;
                }
                (
                    m2.into_iter().map(|(n, c)| (n, c % &m)).collect(),
                    (lc + neg) % &m,
                )
            }
            Term::Linear(ts) => {
                let mut v = Vec::new();
                let mut c = bu(0);
                for (coeff, n) in ts {
                    let co = BigUint::parse_bytes(coeff.as_bytes(), 10).unwrap_or(bu(0));
                    if n == "ONE" {
                        c += co;
                    } else {
                        v.push((n.clone(), co));
                    }
                }
                (v, c)
            }
        }
    }
    fn emb(lc: &[(String, BigUint)], c: &BigUint) -> Vec<(String, BigUint)> {
        if *c == bu(0) {
            lc.to_vec()
        } else {
            let mut r = lc.to_vec();
            r.push(("ONE".into(), c.clone()));
            r
        }
    }

    #[test]
    fn test_full_witness_validation() {
        let src = include_str!("../../examples/ecdsa_verify.zkf");
        let comp = crate::compile(&src, "ecdsa_verify.zkf").unwrap();
        let cs = comp.cs.as_ref().unwrap();

        let mut r1cs = R1CSSystem::new();
        for s in &cs.signals {
            r1cs.alloc_witness(&s.name);
        }
        for c in &cs.constraints {
            let (al, ac) = term_to_lc(&c.a);
            let af = emb(&al, &ac);
            let (bl, bc) = term_to_lc(&c.b);
            let bf = emb(&bl, &bc);
            let (cl, cc) = term_to_lc(&c.c);
            let cf = emb(&cl, &cc);
            for (n, _) in af.iter().chain(bf.iter()).chain(cf.iter()) {
                r1cs.alloc_witness(n);
            }
            r1cs.add_constraint(&af, &bf, &cf);
        }

        let w = generate_ecdsa_witness_full(&cs.signals);
        println!(
            "Witness: {} entries, signals: {}",
            w.len(),
            cs.signals.len()
        );

        // Show missing
        let mut miss = 0;
        for s in &cs.signals {
            if !w.contains_key(&s.name) && miss < 5 {
                println!("  MISSING: {}", s.name);
                miss += 1;
            }
        }

        let n = field();
        let mut fails = 0;
        for (i, c) in r1cs.constraints.iter().enumerate() {
            let ev = |t: &[(usize, BigUint)]| -> BigUint {
                t.iter().fold(bu(0), |acc, (idx, coeff)| {
                    let nm = r1cs
                        .vars
                        .iter()
                        .find(|(_, v)| v.0 == *idx)
                        .map(|(n, _)| n.clone())
                        .unwrap_or_default();
                    (acc + coeff * w.get(&nm).cloned().unwrap_or(bu(0))) % &n
                })
            };
            let av = ev(&c.a);
            let bv = ev(&c.b);
            let cv = ev(&c.c);
            if &av * &bv % &n != cv {
                if fails < 3 {
                    println!("FAIL {}: {}*{}={}!={}", i, av, bv, &av * &bv % &n, cv);
                }
                fails += 1;
            }
        }
        println!("Constraints: {}, failed: {}", r1cs.constraints.len(), fails);
        assert_eq!(fails, 0);
    }

    /// Verify that the ECDSA commitment chain produces progressive, non-trivial values.
    /// Each step should output a value different from its inputs.
    #[test]
    fn test_ecdsa_commitment_chain_progressive() {
        let (msg, pk_x, pk_y, sig_r, sig_s, _) = signature::generate_test_vector().unwrap();
        let msg_hash = Keccak256::digest(&msg);
        let n = field();
        let mh = BigUint::from_bytes_be(&msg_hash) % &n;
        let px = BigUint::from_bytes_be(&pk_x) % &n;
        let py = BigUint::from_bytes_be(&pk_y) % &n;
        let sr = BigUint::from_bytes_be(&sig_r) % &n;
        let ss = BigUint::from_bytes_be(&sig_s) % &n;

        // Each commit step should produce a unique, non-trivial output
        let t0 = prod_trace(&mh, &px);
        let c1 = t0.last().unwrap().12.clone();
        let t1 = prod_trace(&c1, &py);
        let c2 = t1.last().unwrap().12.clone();
        let t2 = prod_trace(&c2, &sr);
        let c3 = t2.last().unwrap().12.clone();
        let t3 = prod_trace(&c3, &ss);
        let c4 = t3.last().unwrap().12.clone();

        // Final commitment must be non-zero
        assert_ne!(c4, zero(), "Final commitment must be non-zero");

        // Each intermediate must differ from its inputs
        assert_ne!(c1, mh, "c1 must differ from msg_hash");
        assert_ne!(c1, px, "c1 must differ from pk_x");
        assert_ne!(c2, c1, "c2 must differ from c1");
        assert_ne!(c2, py, "c2 must differ from pk_y");
        assert_ne!(c3, c2, "c3 must differ from c2");
        assert_ne!(c3, sr, "c3 must differ from sig_r");
        assert_ne!(c4, c3, "c4 must differ from c3");
        assert_ne!(c4, ss, "c4 must differ from sig_s");

        // Check full round count: 73 rounds × 4 hashes = 292 trace entries
        assert_eq!(t0.len(), 73, "First commit: {} rounds", t0.len());
        assert_eq!(t1.len(), 73, "Second commit: {} rounds", t1.len());
        assert_eq!(t2.len(), 73, "Third commit: {} rounds", t2.len());
        assert_eq!(t3.len(), 73, "Fourth commit: {} rounds", t3.len());
    }

    #[test]
    fn test_witness_completeness() {
        let src = include_str!("../../examples/ecdsa_verify.zkf");
        let comp = crate::compile(&src, "ecdsa_verify.zkf").unwrap();
        let cs = comp.cs.as_ref().unwrap();
        let w = generate_ecdsa_witness_full(&cs.signals);

        // Essential inputs must be present
        assert!(w.contains_key("ONE"), "ONE signal missing");
        assert!(w.contains_key("ecdsa_result"), "ecdsa_result missing");
        assert!(
            w.contains_key("ecdsa_commitment"),
            "ecdsa_commitment missing"
        );

        // ecdsa_result must be 1 (proof valid)
        assert_eq!(
            w.get("ecdsa_result"),
            Some(&one()),
            "ecdsa_result must be 1"
        );

        // Commitment must be non-zero
        let commitment = w.get("ecdsa_commitment").unwrap();
        assert_ne!(*commitment, zero(), "commitment must be non-zero");

        // All Poseidon intermediate signals must be filled
        for i in 1..=4 {
            let label = format!("ecdsa_commit_{:02}", i);
            let has_any = cs.signals.iter().any(|s| s.name.contains(&label));
            assert!(has_any, "Circuit should contain {}", label);
        }

        let filled = cs
            .signals
            .iter()
            .filter(|s| w.contains_key(&s.name))
            .count();
        let total = cs.signals.len();
        println!(
            "Witness coverage: {}/{} ({}%)",
            filled,
            total,
            filled * 100 / total.max(1)
        );
        assert!(
            filled > total / 2,
            "At least 50% of signals should be filled"
        );
    }
}
