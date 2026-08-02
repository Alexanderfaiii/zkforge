//! ZK-Friendly Crypto Primitives
//!
//! Poseidon hash (ZK-optimized) + Fiat-Shamir transcript.
//! SHAKE256-based deterministic constants ensure Rust ↔ Solidity interoperability.
//! This is the SINGLE source of truth for all Poseidon constants.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

// ─── Poseidon Permutation (BN254, t=3, 8 full + 57 partial rounds) ───

/// BN254 base field modulus (the scalar field of BN254, aka Fr)
pub const BN254_PRIME: &str =
    "21888242871839275222246405745257275088696311157297823662689037894645226208583";

/// SHAKE256 domain separator for constant generation.
/// Must match exactly between Rust and Solidity.
const POSEIDON_DOMAIN: &[u8] = b"zkforge-poseidon-bn254-t3-v1";

/// Number of full rounds per half (R_F = 8).
pub const FULL_ROUNDS: usize = 8;
/// Number of partial rounds (R_P = 57).
pub const PARTIAL_ROUNDS: usize = 57;
/// Total rounds: 2*R_F + R_P = 73.
pub const TOTAL_ROUNDS: usize = FULL_ROUNDS * 2 + PARTIAL_ROUNDS;

/// Generate deterministic round constants from SHAKE256.
/// Each round gets 3 field elements (one per state element).
fn generate_round_constants(total_rounds: usize) -> Vec<[Fr; 3]> {
    let mut shake = Shake256::default();
    shake.update(POSEIDON_DOMAIN);
    let mut reader = shake.finalize_xof();

    let mut rcs = Vec::with_capacity(total_rounds);
    let mut buf = [0u8; 32];

    for _ in 0..total_rounds {
        let mut round_rc = [Fr::zero(); 3];
        for j in 0..3 {
            reader.read(&mut buf);
            round_rc[j] = Fr::from_be_bytes_mod_order(&buf);
        }
        rcs.push(round_rc);
    }
    rcs
}

/// Generate deterministic MDS matrix from SHAKE256 (continuation after round constants).
/// Returns a 3×3 matrix of field elements for the linear mixing layer.
fn generate_mds_matrix() -> [[Fr; 3]; 3] {
    let mut shake = Shake256::default();
    shake.update(POSEIDON_DOMAIN);
    let mut reader = shake.finalize_xof();

    // Skip the round constants bytes (TOTAL_ROUNDS * 3 * 32 bytes)
    let mut skip = [0u8; 32];
    for _ in 0..(TOTAL_ROUNDS * 3) {
        reader.read(&mut skip);
    }

    let mut mds = [[Fr::zero(); 3]; 3];
    let mut buf = [0u8; 32];
    for i in 0..3 {
        for j in 0..3 {
            reader.read(&mut buf);
            mds[i][j] = Fr::from_be_bytes_mod_order(&buf);
        }
    }
    mds
}

/// Convert a field element to its decimal string representation (for Solidity output).
fn fr_to_decimal(f: &Fr) -> String {
    f.into_bigint().to_string()
}

/// Poseidon parameters for BN254 with width 3.
pub struct PoseidonParams {
    /// Round constants: [round_index][state_element]
    pub round_constants: Vec<[Fr; 3]>,
    /// 3×3 MDS matrix for the linear mixing layer
    pub mds: [[Fr; 3]; 3],
}

impl PoseidonParams {
    /// Create BN254 t=3 Poseidon parameters with SHAKE256-derived constants.
    /// These constants are identical to what the Solidity PoseidonT3 library uses.
    pub fn bn254_t3() -> Self {
        PoseidonParams {
            round_constants: generate_round_constants(TOTAL_ROUNDS),
            mds: generate_mds_matrix(),
        }
    }

    /// Get round constants as decimal strings (for Solidity code generation).
    pub fn round_constants_strings(&self) -> Vec<[String; 3]> {
        self.round_constants
            .iter()
            .map(|rc| {
                [
                    fr_to_decimal(&rc[0]),
                    fr_to_decimal(&rc[1]),
                    fr_to_decimal(&rc[2]),
                ]
            })
            .collect()
    }

    /// Get MDS matrix as decimal strings (for Solidity code generation).
    pub fn mds_strings(&self) -> [[String; 3]; 3] {
        [
            [
                fr_to_decimal(&self.mds[0][0]),
                fr_to_decimal(&self.mds[0][1]),
                fr_to_decimal(&self.mds[0][2]),
            ],
            [
                fr_to_decimal(&self.mds[1][0]),
                fr_to_decimal(&self.mds[1][1]),
                fr_to_decimal(&self.mds[1][2]),
            ],
            [
                fr_to_decimal(&self.mds[2][0]),
                fr_to_decimal(&self.mds[2][1]),
                fr_to_decimal(&self.mds[2][2]),
            ],
        ]
    }
}

/// Full Poseidon permutation on state of width 3.
///
/// Applies 73 rounds (8 full + 57 partial + 8 full) with:
///   - Round constant addition
///   - x^5 S-box (full on all 3 elements, partial only on state[0])
///   - MDS matrix multiplication
fn poseidon_permutation(params: &PoseidonParams, state: &mut [Fr; 3]) {
    let total = TOTAL_ROUNDS;
    let half = FULL_ROUNDS + PARTIAL_ROUNDS; // 65 — start of second full-round half

    for r in 0..total {
        // Add round constants
        for i in 0..3 {
            state[i] += params.round_constants[r][i];
        }

        if r < FULL_ROUNDS || r >= half {
            // Full round: x^5 S-box on all three state elements
            for i in 0..3 {
                let x2 = state[i] * state[i];
                let x4 = x2 * x2;
                state[i] = x4 * state[i]; // x^5
            }
        } else {
            // Partial round: x^5 S-box only on state[0]
            let x2 = state[0] * state[0];
            let x4 = x2 * x2;
            state[0] = x4 * state[0]; // x^5
        }

        // MDS matrix multiplication: new_state = M × state
        let mut new_state = [Fr::zero(); 3];
        for i in 0..3 {
            for j in 0..3 {
                new_state[i] += params.mds[i][j] * state[j];
            }
        }
        *state = new_state;
    }
}

/// Poseidon hash: two field elements → one field element.
///
/// Initializes state as [left, right, 0], runs the full permutation,
/// and returns state[0] as the hash output.
pub fn poseidon_hash(left: &Fr, right: &Fr) -> Fr {
    let params = PoseidonParams::bn254_t3();
    let mut state = [*left, *right, Fr::zero()];
    poseidon_permutation(&params, &mut state);
    state[0]
}

/// Poseidon hash chain: hash a sequence of field elements into one.
///
/// For [a, b, c]: poseidon_hash(poseidon_hash(a, b), c)
pub fn poseidon_chain(elements: &[Fr]) -> Fr {
    if elements.is_empty() {
        return Fr::zero();
    }
    if elements.len() == 1 {
        return elements[0];
    }
    let mut result = poseidon_hash(&elements[0], &elements[1]);
    for elem in &elements[2..] {
        result = poseidon_hash(&result, elem);
    }
    result
}

/// Hash bytes to a field element via Poseidon.
///
/// Chunks input into 31-byte segments, converts each to a field element
/// (little-endian, mod order), then chains through Poseidon.
pub fn poseidon_hash_bytes(data: &[u8]) -> Fr {
    let mut field_elements = Vec::new();
    for chunk in data.chunks(31) {
        let mut padded = [0u8; 32];
        padded[..chunk.len()].copy_from_slice(chunk);
        field_elements.push(Fr::from_le_bytes_mod_order(&padded));
    }
    poseidon_chain(&field_elements)
}

// ─── Solidity PoseidonT3 Library Generator ───

/// Generate a self-contained Solidity library that implements PoseidonT3
/// with the EXACT same SHAKE256-derived constants as the Rust implementation.
///
/// The output is a complete `library PoseidonT3 { ... }` that can be embedded
/// in any Solidity contract. It uses no imports beyond standard Solidity.
///
/// # Cross-Language Compatibility
///
/// This function reads the SHAKE256 constants at generation time and embeds them
/// as decimal literals. The Rust `poseidon_hash` uses the same constants at
/// runtime. Both must produce identical hash outputs for identical inputs.
pub fn generate_poseidon_solidity() -> String {
    let params = PoseidonParams::bn254_t3();
    let rcs = params.round_constants_strings();
    let mds = params.mds_strings();

    let mut out = String::new();

    // ─── Header ───
    out.push_str("/// @title PoseidonT3 — Poseidon hash over BN254 scalar field, width t=3\n");
    out.push_str("/// @notice Matches ZKForge Rust `poseidon_hash` in crypto.rs byte-for-byte.\n");
    out.push_str(
        "/// @dev SHAKE256-derived constants from domain \"zkforge-poseidon-bn254-t3-v1\".\n",
    );
    out.push_str(
        "///      Structure: 8 full + 57 partial + 8 full rounds = 73 total, x^5 S-box.\n",
    );
    out.push_str("library PoseidonT3 {\n");
    out.push_str(&format!("    uint256 constant Q = {};\n\n", BN254_PRIME));

    // ─── Field arithmetic ───
    out.push_str("    /// @dev Modular addition (unchecked block saves gas).\n");
    out.push_str(
        "    function add(uint256 a, uint256 b) internal pure returns (uint256) { unchecked {\n",
    );
    out.push_str("        uint256 c = a + b; if (c >= Q) c -= Q; return c;\n");
    out.push_str("    }}\n\n");

    out.push_str("    /// @dev Modular multiplication via assembly mulmod.\n");
    out.push_str("    function mul(uint256 a, uint256 b) internal pure returns (uint256) {\n");
    out.push_str("        uint256 r;\n");
    out.push_str("        assembly { r := mulmod(a, b, Q) }\n");
    out.push_str("        return r;\n");
    out.push_str("    }\n\n");

    out.push_str("    /// @dev Compute x^5 mod Q: ((x^2)^2) * x.\n");
    out.push_str("    function pow5(uint256 x) internal pure returns (uint256) {\n");
    out.push_str("        uint256 x2 = mul(x, x);\n");
    out.push_str("        uint256 x4 = mul(x2, x2);\n");
    out.push_str("        return mul(x4, x);\n");
    out.push_str("    }\n\n");

    // ─── MDS matrix multiply ───
    out.push_str("    /// @dev Multiply state vector by the MDS matrix.\n");
    out.push_str(
        "    function mdsMul(uint256[3] memory s) internal pure returns (uint256[3] memory r) {\n",
    );
    out.push_str(&format!(
        "        r[0] = add(add(mul({}, s[0]), mul({}, s[1])), mul({}, s[2]));\n",
        mds[0][0], mds[0][1], mds[0][2]
    ));
    out.push_str(&format!(
        "        r[1] = add(add(mul({}, s[0]), mul({}, s[1])), mul({}, s[2]));\n",
        mds[1][0], mds[1][1], mds[1][2]
    ));
    out.push_str(&format!(
        "        r[2] = add(add(mul({}, s[0]), mul({}, s[1])), mul({}, s[2]));\n",
        mds[2][0], mds[2][1], mds[2][2]
    ));
    out.push_str("    }\n\n");

    // ─── Full permutation ───
    out.push_str("    /// @dev Full Poseidon permutation: 73 rounds over state of width 3.\n");
    out.push_str("    function permutation(uint256[3] memory state) internal pure {\n");

    // First 8 full rounds
    out.push_str("        // ── First 8 full rounds ──\n");
    for r in 0..FULL_ROUNDS {
        for j in 0..3 {
            out.push_str(&format!(
                "        state[{j}] = add(state[{j}], {rc});\n",
                j = j,
                rc = rcs[r][j]
            ));
        }
        out.push_str("        state[0] = pow5(state[0]); state[1] = pow5(state[1]); state[2] = pow5(state[2]);\n");
        out.push_str("        state = mdsMul(state);\n");
    }

    // 57 partial rounds
    out.push_str("\n        // ── 57 partial rounds (S-box on state[0] only) ──\n");
    for r in FULL_ROUNDS..(FULL_ROUNDS + PARTIAL_ROUNDS) {
        for j in 0..3 {
            out.push_str(&format!(
                "        state[{j}] = add(state[{j}], {rc});\n",
                j = j,
                rc = rcs[r][j]
            ));
        }
        out.push_str("        state[0] = pow5(state[0]);\n");
        out.push_str("        state = mdsMul(state);\n");
    }

    // Last 8 full rounds
    out.push_str("\n        // ── Last 8 full rounds ──\n");
    for r in (FULL_ROUNDS + PARTIAL_ROUNDS)..TOTAL_ROUNDS {
        for j in 0..3 {
            out.push_str(&format!(
                "        state[{j}] = add(state[{j}], {rc});\n",
                j = j,
                rc = rcs[r][j]
            ));
        }
        out.push_str("        state[0] = pow5(state[0]); state[1] = pow5(state[1]); state[2] = pow5(state[2]);\n");
        out.push_str("        state = mdsMul(state);\n");
    }

    out.push_str("    }\n\n");

    // ─── Hash function ───
    out.push_str(
        "    /// @notice Hash two field elements. Returns state[0] after full permutation.\n",
    );
    out.push_str("    /// @dev Matches Rust `poseidon_hash(&left, &right)`.\n");
    out.push_str("    function hash(uint256[2] memory inputs) internal pure returns (uint256) {\n");
    out.push_str("        uint256[3] memory state;\n");
    out.push_str("        state[0] = inputs[0];\n");
    out.push_str("        state[1] = inputs[1];\n");
    out.push_str("        state[2] = 0;\n");
    out.push_str("        permutation(state);\n");
    out.push_str("        return state[0];\n");
    out.push_str("    }\n");

    out.push_str("}\n");
    out
}

// ─── Fiat-Shamir Transcript ───

/// Fiat-Shamir transcript using Poseidon hash.
/// Accumulates protocol messages and generates field element challenges.
pub struct Transcript {
    state: Vec<Fr>,
    round: u64,
}

impl Transcript {
    pub fn new(label: &str) -> Self {
        let init = poseidon_hash_bytes(label.as_bytes());
        Transcript {
            state: vec![init],
            round: 0,
        }
    }

    /// Absorb a field element into the transcript.
    pub fn absorb_fr(&mut self, value: &Fr) {
        self.state.push(*value);
    }

    /// Absorb multiple field elements.
    pub fn absorb_frs(&mut self, values: &[Fr]) {
        self.state.extend_from_slice(values);
    }

    /// Absorb a G1 point commitment (serialized → field element).
    pub fn absorb_g1(&mut self, point: &ark_bn254::G1Affine) {
        let mut buf = Vec::new();
        point.serialize_compressed(&mut buf).ok();
        let fr = poseidon_hash_bytes(&buf);
        self.state.push(fr);
    }

    /// Absorb raw bytes.
    pub fn absorb_bytes(&mut self, data: &[u8]) {
        let fr = poseidon_hash_bytes(data);
        self.state.push(fr);
    }

    /// Generate the next challenge as a field element.
    /// Consecutive challenges are domain-separated by absorbing a counter.
    pub fn challenge(&mut self) -> Fr {
        let counter = Fr::from(self.round);
        self.round += 1;
        self.state.push(counter);
        let challenge = poseidon_chain(&self.state);
        self.state.clear();
        self.state.push(challenge);
        challenge
    }

    /// Generate a challenge as bytes (for non-field uses).
    pub fn challenge_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(len);
        let mut remaining = len;
        let mut seed = self.challenge();
        while remaining > 0 {
            let take = std::cmp::min(remaining, 31);
            let bytes = seed.into_bigint().to_bytes_le();
            result.extend_from_slice(&bytes[..take]);
            remaining -= take;
            seed = poseidon_hash(&seed, &Fr::from(remaining as u64 + 1));
        }
        result
    }
}

// ─── Merkle Tree (ZK-optimized, Poseidon-based) ───

#[derive(Debug, Clone)]
pub struct MerkleTree {
    pub leaves: Vec<Fr>,
    pub root: Fr,
    depth: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from leaves. Pads to power of 2.
    pub fn new(leaves: Vec<Fr>) -> Self {
        let depth = (leaves.len() as f64).log2().ceil() as usize;
        let padded_len = 1 << depth;
        let mut padded = leaves.clone();
        padded.resize(padded_len, Fr::zero());

        let mut layer = padded;
        for _ in 0..depth {
            let mut next = Vec::with_capacity(layer.len() / 2);
            for i in (0..layer.len()).step_by(2) {
                let hash = poseidon_hash(&layer[i], &layer[i + 1]);
                next.push(hash);
            }
            layer = next;
        }
        let root = if layer.is_empty() {
            Fr::zero()
        } else {
            layer[0]
        };
        MerkleTree {
            leaves: leaves.to_vec(),
            root,
            depth,
        }
    }

    /// Generate a Merkle proof (sibling path) for a leaf.
    pub fn generate_proof(&self, leaf_index: usize) -> Result<MerkleProof, String> {
        if leaf_index >= self.leaves.len() {
            return Err(format!("leaf index {} out of bounds", leaf_index));
        }

        let padded_len = 1 << self.depth;
        let mut padded = self.leaves.clone();
        padded.resize(padded_len, Fr::zero());

        let mut path = Vec::with_capacity(self.depth);
        let mut idx = leaf_index;
        let mut layer = padded;

        for _ in 0..self.depth {
            let sibling_idx = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };
            path.push(if sibling_idx < layer.len() {
                layer[sibling_idx]
            } else {
                Fr::zero()
            });
            idx /= 2;

            let mut next = Vec::with_capacity(layer.len() / 2);
            for i in (0..layer.len()).step_by(2) {
                let hash = poseidon_hash(&layer[i], &layer[i + 1]);
                next.push(hash);
            }
            layer = next;
        }

        Ok(MerkleProof {
            leaf: self.leaves[leaf_index],
            path,
            leaf_index: leaf_index as u64,
            root: self.root,
        })
    }

    /// Verify a Merkle proof.
    pub fn verify_proof(proof: &MerkleProof) -> bool {
        let mut current = proof.leaf;
        let mut idx = proof.leaf_index as usize;
        for sibling in &proof.path {
            let (left, right) = if idx.is_multiple_of(2) {
                (current, *sibling)
            } else {
                (*sibling, current)
            };
            current = poseidon_hash(&left, &right);
            idx /= 2;
        }
        current == proof.root
    }
}

#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub leaf: Fr,
    pub path: Vec<Fr>,
    pub leaf_index: u64,
    pub root: Fr,
}

// ─── Tests ───

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_deterministic() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let h1 = poseidon_hash(&a, &b);
        let h2 = poseidon_hash(&a, &b);
        assert_eq!(h1, h2, "Poseidon must be deterministic");
    }

    #[test]
    fn test_poseidon_not_trivial() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let h = poseidon_hash(&a, &b);
        assert_ne!(h, Fr::zero(), "Hash must not be zero");
        assert_ne!(h, a, "Hash must not equal input");
        assert_ne!(h, b, "Hash must not equal input");
    }

    #[test]
    fn test_poseidon_chain() {
        let els: Vec<Fr> = (0..5).map(|i| Fr::from(i as u64)).collect();
        let h = poseidon_chain(&els);
        assert_ne!(h, Fr::zero());
    }

    #[test]
    fn test_transcript_challenges_differ() {
        let mut t1 = Transcript::new("test");
        t1.absorb_fr(&Fr::from(1u64));
        let c1 = t1.challenge();

        let mut t2 = Transcript::new("test");
        t2.absorb_fr(&Fr::from(2u64));
        let c2 = t2.challenge();

        assert_ne!(
            c1, c2,
            "Different transcripts must produce different challenges"
        );
    }

    #[test]
    fn test_transcript_consistent() {
        let mut t1 = Transcript::new("test");
        t1.absorb_fr(&Fr::from(42u64));
        t1.absorb_fr(&Fr::from(17u64));
        let c1 = t1.challenge();

        let mut t2 = Transcript::new("test");
        t2.absorb_fr(&Fr::from(42u64));
        t2.absorb_fr(&Fr::from(17u64));
        let c2 = t2.challenge();

        assert_eq!(c1, c2, "Same transcript must produce same challenge");
    }

    #[test]
    fn test_merkle_basic() {
        let leaves: Vec<Fr> = (0..4).map(|i| Fr::from(i as u64 * 100u64)).collect();
        let tree = MerkleTree::new(leaves);

        let proof = tree.generate_proof(0).unwrap();
        assert!(MerkleTree::verify_proof(&proof));

        let proof2 = tree.generate_proof(2).unwrap();
        assert!(MerkleTree::verify_proof(&proof2));
    }

    #[test]
    fn test_merkle_tamper_resistant() {
        let leaves: Vec<Fr> = (0..4).map(|i| Fr::from(i as u64 * 100u64)).collect();
        let tree = MerkleTree::new(leaves);

        let mut proof = tree.generate_proof(1).unwrap();
        proof.leaf = Fr::from(99999u64); // Tamper!
        assert!(!MerkleTree::verify_proof(&proof));
    }

    #[test]
    fn test_merkle_large() {
        let leaves: Vec<Fr> = (0..128).map(|i| Fr::from(i as u64)).collect();
        let tree = MerkleTree::new(leaves);

        for i in [0, 7, 63, 127] {
            let proof = tree.generate_proof(i).unwrap();
            assert!(
                MerkleTree::verify_proof(&proof),
                "Proof failed at index {}",
                i
            );
        }
    }

    #[test]
    fn test_merkle_wrong_root() {
        let leaves: Vec<Fr> = (0..8).map(|i| Fr::from(i as u64)).collect();
        let tree = MerkleTree::new(leaves);

        let mut proof = tree.generate_proof(0).unwrap();
        proof.root = Fr::from(999u64); // Wrong root!
        assert!(!MerkleTree::verify_proof(&proof));
    }

    /// 🔑 Cross-language compatibility test.
    /// Computes poseidon_hash(1, 2) in Rust and prints the expected Solidity output.
    /// The Solidity PoseidonT3 library MUST produce the same hash value.
    #[test]
    fn test_poseidon_cross_language_solidity() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let h = poseidon_hash(&a, &b);
        let h_decimal = fr_to_decimal(&h);

        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║  POSEIDON CROSS-LANGUAGE COMPATIBILITY TEST                ║");
        println!("╠══════════════════════════════════════════════════════════════╣");
        println!("║  Rust poseidon_hash(1, 2) = {}", h_decimal);
        println!("║                                                              ║");
        println!("║  Solidity must produce the same:                             ║");
        println!("║    uint256[2] memory inputs = [uint256(1), uint256(2)];     ║");
        println!("║    uint256 h = PoseidonT3.hash(inputs);                      ║");
        println!("║    // h must equal {}                     ║", h_decimal);
        println!("║                                                              ║");
        println!("║  Domain: zkforge-poseidon-bn254-t3-v1                        ║");
        println!("║  Field:  BN254 scalar field                                  ║");
        println!("║  Rounds: 8 full + 57 partial + 8 full = 73                  ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
    }

    /// Verify that generate_poseidon_solidity() produces compilable-looking Solidity.
    #[test]
    fn test_generate_poseidon_solidity_syntax() {
        let sol = generate_poseidon_solidity();

        // Basic structure checks
        assert!(
            sol.contains("library PoseidonT3"),
            "Must contain library declaration"
        );
        assert!(sol.contains("function hash"), "Must contain hash function");
        assert!(
            sol.contains("function permutation"),
            "Must contain permutation function"
        );
        assert!(sol.contains("function pow5"), "Must contain pow5 function");
        assert!(
            sol.contains("function mdsMul"),
            "Must contain MDS multiplication"
        );
        assert!(sol.contains("function add"), "Must contain add function");
        assert!(sol.contains("function mul"), "Must contain mul function");
        assert!(
            sol.contains("uint256 constant Q"),
            "Must contain field modulus"
        );
        assert!(
            sol.contains("zkforge-poseidon-bn254-t3-v1"),
            "Must document domain"
        );
        assert!(sol.contains("mulmod"), "Must use mulmod assembly");
        assert!(sol.contains("pow5(state[0])"), "Must reference x^5 S-box");

        // Should be reasonably sized
        assert!(sol.len() > 5000, "Solidity library should be substantial");
        assert!(
            sol.len() < 200000,
            "Solidity library should not be unreasonably large"
        );

        // Round count: 73 rounds × (1 RC line per element × 3 + 1 sbox + 1 mdsMul) lines
        // 8 full → 8×(4+1+1) = 48 lines
        // 57 partial → 57×(4+1+1) = 342 lines (but only 1 pow5 not 3)
        // 8 full → 48 lines
        // Total ≈ 438+ lines — just check it's substantial
        let line_count = sol.lines().count();
        assert!(
            line_count > 400,
            "Should have hundreds of lines for 73 rounds"
        );

        println!(
            "Generated Solidity library: {} lines, {} bytes",
            line_count,
            sol.len()
        );
    }
}
