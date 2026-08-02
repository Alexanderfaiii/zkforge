//! ECDSA Signature Verification - Production-grade for ZKForge 
//! Architecture: native k256 verification + Poseidon commitment over Keccak256 hash in ZK.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use k256::{
  ecdsa::{Signature, SigningKey, VerifyingKey},
  elliptic_curve::sec1::ToSec1Point,
  PublicKey, SecretKey,
};
use num_bigint::BigUint;
use std::str::FromStr;
use crate::crypto::poseidon_hash;

#[derive(Debug, Clone)]
pub struct EcdsaCommitmentProof {
  pub signature_valid: bool,
  /// Poseidon commitment over Keccak256(message)
  pub commitment: Fr,
}

pub fn verify_ecdsa_with_commitment(
  raw_message: &[u8],
  pk_x_bytes: &[u8; 32],
  pk_y_bytes: &[u8; 32],
  sig_r_bytes: &[u8; 32],
  sig_s_bytes: &[u8; 32],
) -> Result<EcdsaCommitmentProof, String> {
  // Compute Keccak256 for the Poseidon commitment (Ethereum standard)
  use sha3::{Digest, Keccak256};
  let msg_hash = Keccak256::digest(raw_message);
  let mf = bytes_to_fr(msg_hash.as_slice().try_into().unwrap());
  let px = bytes_to_fr(pk_x_bytes);
  let py = bytes_to_fr(pk_y_bytes);
  let sr = bytes_to_fr(sig_r_bytes);
  let ss = bytes_to_fr(sig_s_bytes);

  let c01 = poseidon_hash(&mf, &px);
  let c012 = poseidon_hash(&c01, &py);
  let c0123= poseidon_hash(&c012, &sr);
  let commitment = poseidon_hash(&c0123, &ss);

  let valid = native_verify(raw_message, pk_x_bytes, pk_y_bytes, sig_r_bytes, sig_s_bytes);
  Ok(EcdsaCommitmentProof { signature_valid: valid, commitment })
}

fn native_verify(
  raw_msg: &[u8], px: &[u8; 32], py: &[u8; 32], sr: &[u8; 32], ss: &[u8; 32],
) -> bool {
  use k256::ecdsa::signature::Verifier;

  let mut pk = [0u8; 65]; pk[0] = 0x04;
  pk[1..33].copy_from_slice(px); pk[33..65].copy_from_slice(py);
  let vk = match VerifyingKey::from_sec1_bytes(&pk) { Ok(v) => v, Err(_) => return false };

  let mut sb = [0u8; 64]; sb[..32].copy_from_slice(sr); sb[32..].copy_from_slice(ss);
  let sig = match Signature::from_slice(&sb) { Ok(s) => s, Err(_) => return false };

  // k256's Verifier uses SHA-256 by default - we verify the raw message
  vk.verify(raw_msg, &sig).is_ok()
}

fn bytes_to_fr(b: &[u8; 32]) -> Fr { Fr::from_be_bytes_mod_order(b) }

pub fn hex_to_bytes32(hex_str: &str) -> Result<[u8; 32], String> {
  let s = hex_str.strip_prefix("0x").unwrap_or(hex_str);
  let bytes = hex::decode(s).map_err(|e| format!("Invalid hex: {}", e))?;
  if bytes.len() > 32 { return Err(format!("Hex too long: {} bytes", bytes.len())); }
  let mut out = [0u8; 32]; let start = 32 - bytes.len();
  out[start..].copy_from_slice(&bytes); Ok(out)
}

pub fn biguint_to_bytes32(val: &str) -> Result<[u8; 32], String> {
  let bu = BigUint::from_str(val).map_err(|e| format!("Invalid BigUint: {}", e))?;
  let bytes = bu.to_bytes_be();
  if bytes.len() > 32 { return Err("Value > 32 bytes".to_string()); }
  let mut out = [0u8; 32]; let start = 32 - bytes.len();
  out[start..].copy_from_slice(&bytes); Ok(out)
}

/// Generate a valid ECDSA test vector.
/// Uses k256's built-in SHA-256 signing + Keccak256 for the ZK commitment.
pub fn generate_test_vector(
) -> Result<(Vec<u8>, [u8; 32], [u8; 32], [u8; 32], [u8; 32], Fr), String> {
  use k256::ecdsa::signature::Signer;

  let sk_bytes: [u8; 32] = [
    0x8b,0x4a,0x3f,0x17,0x2d,0x5b,0x6e,0x89,0x7c,0x3f,0x2a,0xbb,0x9e,0x1d,0x4f,0x06,
    0xcd,0x8a,0x2d,0x7e,0x3b,0x5c,0x1f,0x42,0xaa,0x8b,0x6e,0x3d,0xc5,0x9f,0x2a,0x11,
  ];
  let sk = SecretKey::from_slice(&sk_bytes).unwrap();
  let signing_key = SigningKey::from(&sk);
  let pk = PublicKey::from(&sk);

  let msg = b"ZKForge ECDSA test message";
  let sig: Signature = signing_key.sign(msg); // SHA-256 internally (k256 default)

  let ep = pk.to_sec1_point(false);
  let pk_bytes = ep.as_ref();
  let pk_x: [u8; 32] = pk_bytes[1..33].try_into().unwrap();
  let pk_y: [u8; 32] = pk_bytes[33..65].try_into().unwrap();

  let mut sig_r = [0u8; 32]; let mut sig_s = [0u8; 32];
  let rb = sig.r().to_bytes(); let sb = sig.s().to_bytes();
  sig_r[32 - rb.len()..].copy_from_slice(&rb);
  sig_s[32 - sb.len()..].copy_from_slice(&sb);

  let proof = verify_ecdsa_with_commitment(msg, &pk_x, &pk_y, &sig_r, &sig_s)?;
  Ok((msg.to_vec(), pk_x, pk_y, sig_r, sig_s, proof.commitment))
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test] fn test_valid() {
    let (msg, px, py, sr, ss, c) = generate_test_vector().unwrap();
    let p = verify_ecdsa_with_commitment(&msg, &px, &py, &sr, &ss).unwrap();
    assert!(p.signature_valid); assert_eq!(p.commitment, c);
  }
  #[test] fn test_tamper_msg() {
    let (msg, px, py, sr, ss, _) = generate_test_vector().unwrap();
    let bad = b"tampered message";
    assert!(!verify_ecdsa_with_commitment(bad, &px, &py, &sr, &ss).unwrap().signature_valid);
  }
  #[test] fn test_tamper_sig() {
    let (msg, px, py, mut sr, ss, _) = generate_test_vector().unwrap();
    sr[0] ^= 0x01;
    assert!(!verify_ecdsa_with_commitment(&msg, &px, &py, &sr, &ss).unwrap().signature_valid);
  }
  #[test] fn test_wrong_key() {
    let sk2b: [u8; 32] = [
      0x11,0x2a,0x9f,0xc5,0x3d,0x6e,0x8b,0xaa,0x42,0x1f,0x5c,0x3b,0x7e,0x2d,0x8a,0xcd,
      0x06,0x4f,0x1d,0x9e,0xbb,0x2a,0x3f,0x7c,0x89,0x6e,0x5b,0x2d,0x17,0x3f,0x4a,0x8b,
    ];
    let sk2 = SecretKey::from_slice(&sk2b).unwrap();
    let pk2 = PublicKey::from(&sk2);
    let ep = pk2.to_sec1_point(false); let pb = ep.as_ref();
    let opx: [u8; 32] = pb[1..33].try_into().unwrap();
    let opy: [u8; 32] = pb[33..65].try_into().unwrap();
    let (msg, _, _, sr, ss, _) = generate_test_vector().unwrap();
    assert!(!verify_ecdsa_with_commitment(&msg, &opx, &opy, &sr, &ss).unwrap().signature_valid);
  }
  #[test] fn test_deterministic() {
    let (msg, px, py, sr, ss, _) = generate_test_vector().unwrap();
    let p1 = verify_ecdsa_with_commitment(&msg, &px, &py, &sr, &ss).unwrap();
    let p2 = verify_ecdsa_with_commitment(&msg, &px, &py, &sr, &ss).unwrap();
    assert_eq!(p1.commitment, p2.commitment);
  }
  #[test] fn test_hex32() {
    let b = hex_to_bytes32("0xabcdef").unwrap();
    assert_eq!(b[29], 0xab); assert_eq!(b[30], 0xcd); assert_eq!(b[31], 0xef);
  }
  #[test] fn test_bu32() {
    assert_eq!(biguint_to_bytes32("42").unwrap()[31], 42);
  }
}
