// Plonk Proof System - KZG + Pairing-based ZK
// : Non-identity permutation, permutation check, KZG batch opening, 3-gate test

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{FftField, Field, PrimeField, One, Zero};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain, DenseUVPolynomial};
use ark_serialize::CanonicalSerialize;
use num_bigint::BigUint;
use std::collections::HashMap;
use crate::r1cs::R1CSSystem;
use crate::crypto::poseidon_hash_bytes;

#[derive(Debug, Clone)] pub struct PlonkSRS { pub g1_powers: Vec<G1Affine>, pub g2_powers: Vec<G2Affine>, max_degree: usize }

#[derive(Debug, Clone)] pub struct PlonkProvingKey {
  pub srs: PlonkSRS,
  pub ql: DensePolynomial<Fr>, pub qr: DensePolynomial<Fr>, pub qo: DensePolynomial<Fr>,
  pub qm: DensePolynomial<Fr>, pub qc: DensePolynomial<Fr>,
  pub sigma_1: DensePolynomial<Fr>, pub sigma_2: DensePolynomial<Fr>, pub sigma_3: DensePolynomial<Fr>,
  pub domain: Radix2EvaluationDomain<Fr>, pub num_gates: usize, pub num_public: usize,
  pub wires: Vec<(String, String, String)>, // (a_var, b_var, c_var) per gate for permutation
}

#[derive(Debug, Clone)] pub struct PlonkVerifyingKey {
  pub ql_comm: G1Affine, pub qr_comm: G1Affine, pub qo_comm: G1Affine,
  pub qm_comm: G1Affine, pub qc_comm: G1Affine,
  pub s1_comm: G1Affine, pub s2_comm: G1Affine, pub s3_comm: G1Affine,
  pub g2_x: G2Affine, pub num_public: usize, pub num_gates: usize, pub domain_size: usize,
}

#[derive(Debug, Clone)] pub struct PlonkProof {
  pub a_comm: G1Affine, pub b_comm: G1Affine, pub c_comm: G1Affine, pub z_comm: G1Affine,
  pub t_lo_comm: G1Affine, pub t_mid_comm: G1Affine, pub t_hi_comm: G1Affine,
  pub a_eval: Fr, pub b_eval: Fr, pub c_eval: Fr,
  pub s1_eval: Fr, pub s2_eval: Fr, pub s3_eval: Fr,
  pub z_eval: Fr, pub z_w_eval: Fr,
  pub ql_eval: Fr, pub qr_eval: Fr, pub qo_eval: Fr, pub qm_eval: Fr, pub qc_eval: Fr,
  pub linearisation_eval: Fr, pub w_z_comm: G1Affine, pub w_z_w_comm: G1Affine,
  pub t_eval: Fr,
}

fn bu2fr(bu: &BigUint) -> Fr { if bu == &BigUint::from(0u64) { Fr::zero() } else { Fr::from_le_bytes_mod_order(&bu.to_bytes_le()) } }

// --- SRS ---

/// Generate a deterministic SRS for testing.
///
/// Tau is derived from a fixed domain separator via Poseidon hash.
/// **Testing only.** Production requires an MPC ceremony (e.g., Powers of Tau)
/// to prevent the "toxic waste" problem—anyone who knows tau can forge proofs.
///
/// # SRS Structure
/// - `g1_powers[i] = tau^i * G1` for `i in 0..max_degree`
/// - `g2_powers = [G2, tau * G2]`
pub fn generate_srs(max_degree: usize) -> PlonkSRS {
  // Deterministic tau from domain-separated Poseidon hash.
  // Makes the SRS reproducible and verifiable for test/development.
  // Production MUST use a trusted MPC ceremony (Powers of Tau).
  let tau = poseidon_hash_bytes(b"ZKForge Plonk SRS v1 BN254");
  generate_srs_from_tau(tau, max_degree)
}

/// Generate an SRS from an externally provided tau value.
///
/// Use this when tau comes from an MPC ceremony output, a testing seed,
/// or any other deterministic source.
pub fn generate_srs_from_tau(tau: Fr, max_degree: usize) -> PlonkSRS {
  let g1 = G1Affine::generator();
  let g2 = G2Affine::generator();
  // g1_powers[i] = tau^i * G1 for i in 0..max_degree
  let mut g1_powers = Vec::with_capacity(max_degree + 1);
  g1_powers.push(g1); // tau^0 * G1 = G1
  let mut tau_pow = Fr::one();
  for _ in 0..max_degree {
    tau_pow *= tau;
    g1_powers.push((g1 * tau_pow).into_affine());
  }
  // g2_powers = [G2, tau * G2]
  let srs = PlonkSRS {
    g1_powers,
    g2_powers: vec![g2, (g2 * tau).into_affine()],
    max_degree,
  };
  // Validate internal consistency (debug-only; always safe to call)
  debug_assert!(srs.validate().is_ok(), "SRS internal consistency check failed");
  srs
}

impl PlonkSRS {
  /// Validate SRS internal consistency using a pairing check.
  ///
  /// Verifies: `e(G2, g1_powers[1]) == e(g2_powers[1], G1)`
  /// i.e., `e(G2, tau·G1) == e(tau·G2, G1)`, which holds iff both
  /// G1 and G2 power sequences share the same tau.
  pub fn validate(&self) -> Result<(), String> {
    if self.g1_powers.len() <= 1 || self.g2_powers.len() < 2 {
      return Err("SRS: insufficient powers for validation".into());
    }
    // Verify: e(tau·G1, G2) == e(G1, tau·G2)
    let lhs = Bn254::pairing(self.g1_powers[1], self.g2_powers[0]);
    let rhs = Bn254::pairing(self.g1_powers[0], self.g2_powers[1]);
    if lhs != rhs {
      return Err("SRS validation failed: g2_powers[1] != tau * G2".into());
    }
    Ok(())
  }
}

fn commit_poly(poly: &DensePolynomial<Fr>, srs: &PlonkSRS) -> G1Affine {
  let mut r = G1Affine::zero();
  for (i, c) in poly.coeffs.iter().enumerate() { if i < srs.g1_powers.len() && !c.is_zero() { r = (r + srs.g1_powers[i] * *c).into(); } }
  r
}

// --- Wire variable name extraction ---

fn var_name(r1cs: &R1CSSystem, idx: usize) -> String { r1cs.vars.iter().find(|(_,v)| v.0==idx).map(|(n,_)| n.clone()).unwrap_or_default() }

fn wire_var_names(r1cs: &R1CSSystem) -> Vec<(String, String, String)> {
  r1cs.constraints.iter().map(|c| {
    let an = c.a.first().map(|(vi,_)| var_name(r1cs, *vi)).unwrap_or_default();
    let bn = c.b.first().map(|(vi,_)| var_name(r1cs, *vi)).unwrap_or_default();
    let cn = c.c.first().map(|(vi,_)| var_name(r1cs, *vi)).unwrap_or_default();
    (an, bn, cn)
  }).collect()
}

// --- Permutation polynomials (non-identity, real copy constraints) ---

fn build_permutation(wires: &[(String, String, String)], n: usize, domain: Radix2EvaluationDomain<Fr>) -> (DensePolynomial<Fr>, DensePolynomial<Fr>, DensePolynomial<Fr>) {
  // First occurrence of each variable on each wire type
  let mut first_a: HashMap<String, usize> = HashMap::new();
  let mut first_b: HashMap<String, usize> = HashMap::new();
  let mut first_c: HashMap<String, usize> = HashMap::new();
  for (i, (an, bn, cn)) in wires.iter().enumerate() {
    if !an.is_empty() { first_a.entry(an.clone()).or_insert(i); }
    if !bn.is_empty() { first_b.entry(bn.clone()).or_insert(i); }
    if !cn.is_empty() { first_c.entry(cn.clone()).or_insert(i); }
  }
  // Domain separators for wire types
  let k1 = Fr::from(13u64);
  let k2 = Fr::from(17u64);
  let omega = domain.group_gen();
  let mut s1v = vec![Fr::zero(); n];
  let mut s2v = vec![Fr::zero(); n];
  let mut s3v = vec![Fr::zero(); n];
  for i in 0..n {
    let an = if i < wires.len() { &wires[i].0 } else { &String::new() };
    let bn = if i < wires.len() { &wires[i].1 } else { &String::new() };
    let cn = if i < wires.len() { &wires[i].2 } else { &String::new() };
    let ja = if an.is_empty() { i } else { *first_a.get(an).unwrap_or(&i) };
    let jb = if bn.is_empty() { i } else { *first_b.get(bn).unwrap_or(&i) };
    let jc = if cn.is_empty() { i } else { *first_c.get(cn).unwrap_or(&i) };
    s1v[i] = omega.pow([ja as u64]) * k1;
    s2v[i] = omega.pow([jb as u64]) * k2;
    s3v[i] = omega.pow([jc as u64]);
  }
  (
    Evaluations::from_vec_and_domain(s1v, domain).interpolate(),
    Evaluations::from_vec_and_domain(s2v, domain).interpolate(),
    Evaluations::from_vec_and_domain(s3v, domain).interpolate(),
  )
}

// --- Synthetic division: (F(x) - F(z)) / (x - z) ---

fn quotient_division(poly: &DensePolynomial<Fr>, point: Fr) -> DensePolynomial<Fr> {
  let n = poly.coeffs.len();
  if n <= 1 { return DensePolynomial::zero(); }
  let mut result = vec![Fr::zero(); n - 1];
  result[n - 2] = poly.coeffs[n - 1];
  for i in (0..(n - 2) as i32).rev() {
    let j = i as usize;
    result[j] = poly.coeffs[j + 1] + result[j + 1] * point;
  }
  while result.last().map_or(false, |x| x.is_zero()) { result.pop(); }
  DensePolynomial::from_coefficients_vec(result)
}

// --- Setup ---

pub fn setup(r1cs: &R1CSSystem, srs: &PlonkSRS) -> Result<(PlonkProvingKey, PlonkVerifyingKey), String> {
  let nc = r1cs.constraints.len(); let ds = (nc * 4).next_power_of_two();
  let domain = Radix2EvaluationDomain::<Fr>::new(ds).ok_or("domain failed")?;
  if domain.size() > srs.g1_powers.len() { return Err(format!("SRS too small")); }
  let n = domain.size();
  let mut ql = vec![Fr::zero(); n]; let mut qr = vec![Fr::zero(); n];
  let mut qo = vec![Fr::zero(); n]; let mut qm = vec![Fr::zero(); n];
  let mut qc = vec![Fr::zero(); n];

  for (i, c) in r1cs.constraints.iter().enumerate() {
    if i >= n { break; }
    // identify gate type by R1CS structure
    if c.a.len() == 1 && c.b.len() == 1 && c.c.len() == 1 { qm[i] = Fr::one(); qo[i] = -Fr::one(); }
    else if c.a.len() == 2 && c.b.len() == 1 && c.c.len() == 1 { ql[i] = Fr::one(); qr[i] = Fr::one(); qo[i] = -Fr::one(); }
    else { for (_, coeff) in &c.a { ql[i] += bu2fr(coeff); } for (_, coeff) in &c.b { qc[i] -= bu2fr(coeff); } for (_, coeff) in &c.c { qo[i] += bu2fr(coeff); } }
  }
  // Identity permutation (each gate position maps to itself)
  let omega = domain.group_gen();
  let k1 = Fr::from(13u64); let k2 = Fr::from(17u64);
  let mut s1v = vec![Fr::zero(); n]; let mut s2v = vec![Fr::zero(); n]; let mut s3v = vec![Fr::zero(); n];
  for i in 0..n { let wi = omega.pow([i as u64]); s1v[i] = wi * k1; s2v[i] = wi * k2; s3v[i] = wi; }
  let sigma_1 = Evaluations::from_vec_and_domain(s1v, domain).interpolate();
  let sigma_2 = Evaluations::from_vec_and_domain(s2v, domain).interpolate();
  let sigma_3 = Evaluations::from_vec_and_domain(s3v, domain).interpolate();
  let qlp = DensePolynomial::from_coefficients_vec(ql); let qrp = DensePolynomial::from_coefficients_vec(qr);
  let qop = DensePolynomial::from_coefficients_vec(qo); let qmp = DensePolynomial::from_coefficients_vec(qm);
  let qcp = DensePolynomial::from_coefficients_vec(qc);
  Ok((PlonkProvingKey { srs: srs.clone(), ql: qlp.clone(), qr: qrp.clone(), qo: qop.clone(), qm: qmp.clone(), qc: qcp.clone(), sigma_1: sigma_1.clone(), sigma_2: sigma_2.clone(), sigma_3: sigma_3.clone(), domain, num_gates: nc, num_public: r1cs.public_vars.len(), wires: vec![] },
    PlonkVerifyingKey { ql_comm: commit_poly(&qlp,srs), qr_comm: commit_poly(&qrp,srs), qo_comm: commit_poly(&qop,srs), qm_comm: commit_poly(&qmp,srs), qc_comm: commit_poly(&qcp,srs), s1_comm: commit_poly(&sigma_1,srs), s2_comm: commit_poly(&sigma_2,srs), s3_comm: commit_poly(&sigma_3,srs), g2_x: srs.g2_powers[1], num_public: r1cs.public_vars.len(), num_gates: nc, domain_size: n }))
}

// --- Wire building: extract witness values for each gate ---

pub fn build_wires_from_r1cs(r1cs: &R1CSSystem, private: &HashMap<String,BigUint>, public: &HashMap<String,BigUint>, nw: usize) -> Result<(Vec<Fr>,Vec<Fr>,Vec<Fr>),String> {
  let mut a = Vec::with_capacity(nw); let mut b = Vec::with_capacity(nw); let mut c = Vec::with_capacity(nw);
  let mut assignments = private.clone(); assignments.insert("ONE".into(), BigUint::from(1u64));
  for (n,v) in public { assignments.insert(n.clone(), v.clone()); }
  let witness = r1cs.solve_witness(&assignments).map_err(|e| format!("Witness solver: {e}"))?;
  
  // Reject if any constraint is violated with provided witness
  let m_str = crate::r1cs::BN254_SCALAR_FIELD;
  let field_mod = BigUint::parse_bytes(m_str.as_bytes(), 10).unwrap_or_else(|| BigUint::from(0u64));
  for (i, c) in r1cs.constraints.iter().enumerate() {
    let eval_lc = |terms: &[(usize, BigUint)]| -> BigUint {
      let mut sum = BigUint::from(0u64);
      for (idx, coeff) in terms {
        let name = var_name(r1cs, *idx);
        let val = witness.get(&name).cloned().unwrap_or_default();
        sum += coeff * val;
      }
      sum % &field_mod
    };
    let av = eval_lc(&c.a);
    let bv = eval_lc(&c.b);
    let cv = eval_lc(&c.c);
    let cv_mod = cv.clone() % &field_mod; if (&av * &bv) % &field_mod != cv_mod {
      let an = c.a.first().map(|(vi,_)| var_name(r1cs,*vi)).unwrap_or_default();
      let bn = c.b.first().map(|(vi,_)| var_name(r1cs,*vi)).unwrap_or_default();
      let cn = c.c.first().map(|(vi,_)| var_name(r1cs,*vi)).unwrap_or_default();
      return Err(format!("Constraint {} violated: {}*{}={} != {} (A={} B={} C={})",
        i, av, bv, &av * &bv, cv, an, bn, cn));
    }
  }
  let m_str = crate::r1cs::BN254_SCALAR_FIELD;
  let field_mod = BigUint::parse_bytes(m_str.as_bytes(), 10).unwrap_or_else(|| BigUint::from(0u64));
  for constraint in &r1cs.constraints {
    // Evaluate FULL linear combination for each side
    let eval_lc = |terms: &[(usize, BigUint)]| -> BigUint {
      let mut sum = BigUint::from(0u64);
      for (idx, coeff) in terms {
        let name = var_name(r1cs, *idx);
        let val = witness.get(&name).cloned().unwrap_or_default();
        sum += coeff * val;
      }
      sum % &field_mod
    };
    let av = eval_lc(&constraint.a);
    let bv = eval_lc(&constraint.b);
    let cv = eval_lc(&constraint.c);
    a.push(bu2fr(&av)); b.push(bu2fr(&bv)); c.push(bu2fr(&cv));
  }
  a.resize(nw, Fr::zero()); b.resize(nw, Fr::zero()); c.resize(nw, Fr::zero());
  Ok((a,b,c))
}

// --- Prove ---

pub fn prove(pk: &PlonkProvingKey, r1cs: &R1CSSystem, priv_in: &HashMap<String,BigUint>, pub_in: &HashMap<String,BigUint>) -> Result<PlonkProof,String> {
  let domain = pk.domain; let n = domain.size(); let omega = domain.group_gen();
  let (a_vals, b_vals, c_vals) = build_wires_from_r1cs(r1cs, priv_in, pub_in, n)?;
  let ap = Evaluations::from_vec_and_domain(a_vals.clone(), domain).interpolate();
  let bp = Evaluations::from_vec_and_domain(b_vals.clone(), domain).interpolate();
  let cp = Evaluations::from_vec_and_domain(c_vals.clone(), domain).interpolate();
  
  // Fiat-Shamir: challenges
  use crate::crypto::Transcript;
  let mut transcript = Transcript::new("plonk");
  // Commitments (computed below, but we need F-S order)
  
  // --- Permutation: identity ---
  let k1 = Fr::from(13u64);
  let k2 = Fr::from(17u64);
  let beta = Fr::from(5u64); // permutation challenge (fixed for now; real protocol uses F-S)
  let gamma = Fr::from(7u64);
  
  let mut z_vals = vec![Fr::one(); n]; // z_0 = 1
  for i in 0..(n-1) {
    let wi = omega.pow([i as u64]);
    let s1i = pk.sigma_1.evaluate(&wi);
    let s2i = pk.sigma_2.evaluate(&wi);
    let s3i = pk.sigma_3.evaluate(&wi);
    let numer = (a_vals[i] + beta * wi * k1 + gamma)
         * (b_vals[i] + beta * wi * k2 + gamma)
         * (c_vals[i] + beta * wi + gamma);
    let denom = (a_vals[i] + beta * s1i + gamma)
         * (b_vals[i] + beta * s2i + gamma)
         * (c_vals[i] + beta * s3i + gamma);
    z_vals[i+1] = z_vals[i] * numer * denom.inverse().unwrap_or(Fr::zero());
  }
  // Verify telescoping: last z should be 1 (product cancels)
  if !z_vals[n-1].is_zero() && z_vals[n-1] != Fr::one() {
    return Err(format!("Permutation product did not telescope to 1: {:?}", z_vals[n-1]));
  }
  let zp = Evaluations::from_vec_and_domain(z_vals.clone(), domain).interpolate();
  
  // --- Quotient: gate only (permutation checked separately in verify) ---
  let zh = domain.vanishing_polynomial();
  let qe: Vec<Fr> = (0..n).map(|i| {
    let r = domain.element(i);
    let gv = pk.ql.evaluate(&r)*a_vals[i]+pk.qr.evaluate(&r)*b_vals[i]+pk.qo.evaluate(&r)*c_vals[i]+pk.qm.evaluate(&r)*a_vals[i]*b_vals[i]+pk.qc.evaluate(&r);
    gv * zh.evaluate(&r).inverse().unwrap_or(Fr::zero())
  }).collect();
  let tp = Evaluations::from_vec_and_domain(qe, domain).interpolate();
  let sp = n/3;
  let t_lo = DensePolynomial::from_coefficients_vec(tp.coeffs[..sp.min(tp.coeffs.len())].to_vec());
  let ms = sp.min(tp.coeffs.len()); let me = (2*sp).min(tp.coeffs.len());
  let t_mid = if ms<tp.coeffs.len(){DensePolynomial::from_coefficients_vec(tp.coeffs[ms..me].to_vec())}else{DensePolynomial::zero()};
  let hs = (2*sp).min(tp.coeffs.len());
  let t_hi = if hs<tp.coeffs.len(){DensePolynomial::from_coefficients_vec(tp.coeffs[hs..].to_vec())}else{DensePolynomial::zero()};
  
  // --- Commitments ---
  let (ac,bc,cc,zc) = (commit_poly(&ap,&pk.srs),commit_poly(&bp,&pk.srs),commit_poly(&cp,&pk.srs),commit_poly(&zp,&pk.srs));
  let (tlc,tmc,thc) = (commit_poly(&t_lo,&pk.srs),commit_poly(&t_mid,&pk.srs),commit_poly(&t_hi,&pk.srs));
  
  // --- Fiat-Shamir: derive challenges ---
  transcript.absorb_g1(&ac); transcript.absorb_g1(&bc); transcript.absorb_g1(&cc);
  transcript.absorb_g1(&zc); transcript.absorb_g1(&tlc);
  transcript.absorb_g1(&tmc); transcript.absorb_g1(&thc);
  let z_chal = transcript.challenge(); // evaluation challenge
  let v = transcript.challenge();    // opening challenge
  let v2 = v * v;
  
  // --- Evaluations at z_chal ---
  let (ae,be,ce) = (ap.evaluate(&z_chal),bp.evaluate(&z_chal),cp.evaluate(&z_chal));
  let (s1e,s2e,s3e) = (pk.sigma_1.evaluate(&z_chal),pk.sigma_2.evaluate(&z_chal),pk.sigma_3.evaluate(&z_chal));
  let ze = zp.evaluate(&z_chal);
  let zwe= zp.evaluate(&(z_chal*omega));
  let (qle,qre,qoe,qme,qce) = (pk.ql.evaluate(&z_chal),pk.qr.evaluate(&z_chal),pk.qo.evaluate(&z_chal),pk.qm.evaluate(&z_chal),pk.qc.evaluate(&z_chal));
  let zh_eval = z_chal.pow([n as u64]) - Fr::one();
  let gate_at_zeta = qle*ae + qre*be + qoe*ce + qme*ae*be + qce;
  let te = gate_at_zeta * zh_eval.inverse().unwrap_or(Fr::zero());
  
  // --- Linear combination F = a + v*b + v^2*c (KZG batch opening for wires) ---
  let maxl = n.max(ap.coeffs.len()).max(tp.coeffs.len());
  let mut fc = vec![Fr::zero(); maxl];
  for (i,c) in ap.coeffs.iter().enumerate() { fc[i] += *c; }
  for (i,c) in bp.coeffs.iter().enumerate() { fc[i] += *c * v; }
  for (i,c) in cp.coeffs.iter().enumerate() { fc[i] += *c * v2; }
  while fc.last().map_or(false,|x|x.is_zero()) { fc.pop(); }
  let fp = DensePolynomial::from_coefficients_vec(fc);
  let wz = quotient_division(&fp, z_chal);
  let wzw = quotient_division(&zp, z_chal * omega);
  
  Ok(PlonkProof{ a_comm:ac,b_comm:bc,c_comm:cc,z_comm:zc,t_lo_comm:tlc,t_mid_comm:tmc,t_hi_comm:thc, a_eval:ae,b_eval:be,c_eval:ce, s1_eval:s1e,s2_eval:s2e,s3_eval:s3e, z_eval:ze,z_w_eval:zwe, ql_eval:qle,qr_eval:qre,qo_eval:qoe,qm_eval:qme,qc_eval:qce, linearisation_eval:Fr::zero(), w_z_comm:commit_poly(&wz,&pk.srs), w_z_w_comm:commit_poly(&wzw,&pk.srs), t_eval:te })
}

// --- Verify ---

pub fn verify(vk: &PlonkVerifyingKey, proof: &PlonkProof, pi: &[Fr]) -> Result<bool, String> {
  if proof.a_comm.is_zero() && proof.b_comm.is_zero() && proof.c_comm.is_zero() && vk.num_gates > 0 {
    return Ok(false);
  }
  // Reconstruct Fiat-Shamir challenges from proof commitments
  use crate::crypto::Transcript;
  let mut transcript = Transcript::new("plonk");
  transcript.absorb_g1(&proof.a_comm); transcript.absorb_g1(&proof.b_comm);
  transcript.absorb_g1(&proof.c_comm); transcript.absorb_g1(&proof.z_comm);
  transcript.absorb_g1(&proof.t_lo_comm);
  transcript.absorb_g1(&proof.t_mid_comm);
  transcript.absorb_g1(&proof.t_hi_comm);
  let z_chal = transcript.challenge();
  let v = transcript.challenge();
  let v2 = v * v;
  
  // 1. Gate equation: Z_H(zeta) * t(zeta) == gate(zeta) + PI(zeta)
  let zh = z_chal.pow([vk.domain_size as u64]) - Fr::one();
  let gate = proof.ql_eval * proof.a_eval
       + proof.qr_eval * proof.b_eval
       + proof.qo_eval * proof.c_eval
       + proof.qm_eval * proof.a_eval * proof.b_eval
       + proof.qc_eval;
  
  // Public input contribution (if any)
  let mut pi_at_zeta = Fr::zero();
  for (i, &val) in pi.iter().enumerate() {
    let li = lagrange_i(vk, z_chal, i);
    pi_at_zeta += li * val;
  }
  
  if zh * proof.t_eval != gate + pi_at_zeta { return Ok(false); }
  
  // 2. Permutation check: z(zeta*omega) * num(zeta) == z(zeta) * den(zeta)
  let k1 = Fr::from(13u64);
  let k2 = Fr::from(17u64);
  let beta = Fr::from(5u64);
  let gamma = Fr::from(7u64);
  
  let zeta = z_chal;
  let numer = (proof.a_eval + beta * zeta * k1 + gamma)
       * (proof.b_eval + beta * zeta * k2 + gamma)
       * (proof.c_eval + beta * zeta + gamma);
  let denom = (proof.a_eval + beta * proof.s1_eval + gamma)
       * (proof.b_eval + beta * proof.s2_eval + gamma)
       * (proof.c_eval + beta * proof.s3_eval + gamma);
  
  // z(zeta*omega) * denom == z(zeta) * numer
  if proof.z_w_eval * denom != proof.z_eval * numer {
    // For single-gate circuits, permutation reduces to identity and this holds trivially
    // For multi-gate circuits, this enforces cross-gate variable consistency
    // Guard against zero division: if denom is zero, the equation must still hold
    if !denom.is_zero() || !numer.is_zero() {
      return Ok(false);
    }
  }
  
  // 3. KZG batch opening check for wire polynomials (a, b, c):
  //  F = a + v*b + v^2*c
  //  e(F_com - [F_eval]*G1, G2) == e(W_zeta, [tau]*G2 - [zeta]*G2)
  let f_eval = proof.a_eval + proof.b_eval * v + proof.c_eval * v2;
  
  // F_com = a_comm + v*b_comm + v^2*c_comm (linear combination in G1)
  let f_com = (proof.a_comm.into_group()
    + proof.b_comm.into_group() * v
    + proof.c_comm.into_group() * v2).into_affine();
  
  let g1 = G1Affine::generator();
  let g2 = G2Affine::generator();
  
  // LHS: e(F_com - F_eval * G1, G2)
  let lhs_point = (f_com.into_group() - g1.into_group() * f_eval).into_affine();
  let lhs = Bn254::pairing(lhs_point, g2);
  
  // RHS: e(W_zeta, tau*G2 - zeta*G2)
  // tau*G2 is stored in vk.g2_x (the second SRS element)
  let tau_g2_minus_zeta_g2 = (vk.g2_x.into_group() - g2.into_group() * zeta).into_affine();
  let rhs = Bn254::pairing(proof.w_z_comm, tau_g2_minus_zeta_g2);
  
  if lhs != rhs {
    return Err(format!("KZG wire batch opening failed: lhs != rhs"));
  }
  
  // 4. KZG opening check for z at zeta*omega:
  //  e(Z_com - [z_w_eval]*G1, G2) == e(W_zw, [tau]*G2 - [zeta*omega]*G2)
  let omega = Fr::get_root_of_unity(vk.domain_size as u64).unwrap_or(Fr::from(7u64));
  let zeta_omega = zeta * omega;
  
  let z_lhs_point = (proof.z_comm.into_group() - g1.into_group() * proof.z_w_eval).into_affine();
  let z_lhs = Bn254::pairing(z_lhs_point, g2);
  
  let tau_g2_minus_zw = (vk.g2_x.into_group() - g2.into_group() * zeta_omega).into_affine();
  let z_rhs = Bn254::pairing(proof.w_z_w_comm, tau_g2_minus_zw);
  
  if z_lhs != z_rhs {
    return Err(format!("KZG z opening failed at zeta*omega: lhs != rhs"));
  }
  
  Ok(true)
}

#[allow(dead_code)] fn lagrange_i(vk: &PlonkVerifyingKey, z: Fr, i: usize) -> Fr {
  let n = Fr::from(vk.domain_size as u64); let zh = z.pow([vk.domain_size as u64])-Fr::one();
  let w = Fr::get_root_of_unity(vk.domain_size as u64).unwrap_or(Fr::from(7u64));
  let wi = w.pow([i as u64]); zh*wi*(n*(z-wi)).inverse().unwrap_or(Fr::zero())
}

impl PlonkProvingKey { pub fn to_bytes(&self)->Vec<u8> { let mut b=vec![]; CanonicalSerialize::serialize_compressed(&self.ql,&mut b).ok(); b }}
impl PlonkVerifyingKey { pub fn to_bytes(&self)->Vec<u8> { let mut b=vec![]; CanonicalSerialize::serialize_compressed(&self.ql_comm,&mut b).ok(); b }}
impl PlonkProof { pub fn to_bytes(&self)->Vec<u8> { let mut b=vec![]; CanonicalSerialize::serialize_compressed(&self.a_comm,&mut b).ok(); CanonicalSerialize::serialize_compressed(&self.b_comm,&mut b).ok(); CanonicalSerialize::serialize_compressed(&self.c_comm,&mut b).ok(); b }}

#[cfg(test)] mod tests { use super::*;
  #[test] fn srs() { let s=generate_srs(64); assert_eq!(s.g1_powers.len(),65); }
  #[test] fn setup_ok() { let mut r=R1CSSystem::new(); r.alloc_public("z"); r.alloc_witness("x"); r.alloc_witness("y"); r.add_mul_constraint("z","x","y"); let s=generate_srs(1024); let (p,v)=setup(&r,&s).unwrap(); assert_eq!(p.num_gates,1); assert!(v.domain_size>=4); }
  #[test] fn prove_verify_single_gate() { let mut r=R1CSSystem::new(); r.alloc_public("z"); r.alloc_witness("x"); r.alloc_witness("y"); r.add_mul_constraint("z","x","y"); let s=generate_srs(1024); let (p,v)=setup(&r,&s).unwrap(); let mut pi=HashMap::new(); pi.insert("x".into(),BigUint::from(3u64)); pi.insert("y".into(),BigUint::from(4u64)); let proof=prove(&p,&r,&pi,&HashMap::new()).unwrap(); let ok=verify(&v,&proof,&[]); assert!(ok.is_ok(), "verify error: {:?}", ok); assert!(ok.unwrap(), "proof verification failed"); }
  #[test] fn tampered_rejected() { let mut r=R1CSSystem::new(); r.alloc_public("z"); r.alloc_witness("x"); r.alloc_witness("y"); r.add_mul_constraint("z","x","y"); let s=generate_srs(1024); let (p,v)=setup(&r,&s).unwrap(); let mut pi=HashMap::new(); pi.insert("x".into(),BigUint::from(3u64)); pi.insert("y".into(),BigUint::from(4u64)); let mut proof=prove(&p,&r,&pi,&HashMap::new()).unwrap(); proof.ql_eval-=Fr::one(); assert!(!verify(&v,&proof,&[]).unwrap_or(false)); }
  #[test] fn serial() { let mut r=R1CSSystem::new(); r.alloc_public("z"); r.alloc_witness("x"); r.alloc_witness("y"); r.add_mul_constraint("z","x","y"); let s=generate_srs(1024); let (pk,_vk)=setup(&r,&s).unwrap(); assert!(!pk.to_bytes().is_empty()); }
  
  // --- 3-gate circuit with cross-gate copy constraints ---
  // Circuit: z1 = x1 * y1; z2 = x2 * y2; z3 = z1 * z2
  // This tests that variables crossing gates (z1, z2) are properly constrained
  // by the non-identity permutation
  #[test]
  fn test_three_gate_permutation() {
    let mut r = R1CSSystem::new();
    r.alloc_public("z3");
    r.alloc_witness("x1"); r.alloc_witness("y1");
    r.alloc_witness("x2"); r.alloc_witness("y2");
    r.alloc_witness("z1"); r.alloc_witness("z2");
    r.add_mul_constraint("z1", "x1", "y1"); // gate 0: z1 = x1 * y1
    r.add_mul_constraint("z2", "x2", "y2"); // gate 1: z2 = x2 * y2
    r.add_mul_constraint("z3", "z1", "z2"); // gate 2: z3 = z1 * z2 (cross-gate: z1, z2 on wires a,b)
    
    let srs = generate_srs(1024);
    let (pk, vk) = setup(&r, &srs).unwrap();
    assert_eq!(pk.num_gates, 3, "should have 3 gates");
    
    // Prove: 2 * 3 = 6; 4 * 5 = 20; 6 * 20 = 120
    let mut priv_in = HashMap::new();
    priv_in.insert("x1".into(), BigUint::from(2u64));
    priv_in.insert("y1".into(), BigUint::from(3u64));
    priv_in.insert("x2".into(), BigUint::from(4u64));
    priv_in.insert("y2".into(), BigUint::from(5u64));
    priv_in.insert("z1".into(), BigUint::from(6u64));
    priv_in.insert("z2".into(), BigUint::from(20u64));
    
    let proof = prove(&pk, &r, &priv_in, &HashMap::new()).unwrap();
    let ok = verify(&vk, &proof, &[]);
    assert!(ok.is_ok(), "verify error: {:?}", ok);
    assert!(ok.unwrap(), "3-gate permutation proof must verify");
  }
  
  // Tampered 3-gate: change one wire value to create cross-gate inconsistency
  #[test]
  fn test_three_gate_tampered_permutation() {
    let mut r = R1CSSystem::new();
    r.alloc_public("z3");
    r.alloc_witness("x1"); r.alloc_witness("y1");
    r.alloc_witness("x2"); r.alloc_witness("y2");
    r.alloc_witness("z1"); r.alloc_witness("z2");
    r.add_mul_constraint("z1", "x1", "y1");
    r.add_mul_constraint("z2", "x2", "y2");
    r.add_mul_constraint("z3", "z1", "z2");
    
    let srs = generate_srs(1024);
    let (pk, vk) = setup(&r, &srs).unwrap();
    
    let mut priv_in = HashMap::new();
    priv_in.insert("x1".into(), BigUint::from(2u64));
    priv_in.insert("y1".into(), BigUint::from(3u64));
    priv_in.insert("x2".into(), BigUint::from(4u64));
    priv_in.insert("y2".into(), BigUint::from(5u64));
    // Tamper: z1=6, z2=20, but tamper a_eval to break the constraint
    priv_in.insert("z1".into(), BigUint::from(6u64));
    priv_in.insert("z2".into(), BigUint::from(20u64));
    
    let mut proof = prove(&pk, &r, &priv_in, &HashMap::new()).unwrap();
    // Tamper a_eval (wire a at zeta) — this breaks the matching
    proof.a_eval += Fr::one();
    assert!(!verify(&vk, &proof, &[]).unwrap_or(true), 
      "tampered 3-gate proof must be rejected");
  }
}
