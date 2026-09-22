use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::TransparencyError;
use crate::Result;

pub const SMT_LEAF_DOMAIN: &[u8] = b"SatsPathSmtLeafV1";
pub const SMT_NODE_DOMAIN: &[u8] = b"SatsPathSmtNodeV1";

static EMPTY_HASHES: OnceLock<[[u8; 32]; 257]> = OnceLock::new();

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IdentifierStatus {
    Registered,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateMapValue {
    pub latest_event_hash: String,
    pub sequence: u64,
    pub status: IdentifierStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateMapProof {
    pub key_hash: String,             // The 256-bit identifier hash
    pub value: Option<StateMapValue>, // None if proving non-inclusion
    pub audit_path: Vec<String>,      // Sibling nodes from bottom to top
}

fn decode_hash_bytes(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).map_err(|_| TransparencyError::InvalidInclusionProof)?;
    bytes
        .try_into()
        .map_err(|_| TransparencyError::InvalidInclusionProof.into())
}

#[inline]
pub fn get_bit(key: &[u8; 32], depth: usize) -> u8 {
    (key[depth / 8] >> (7 - (depth % 8))) & 1
}

pub fn smt_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SMT_NODE_DOMAIN);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

pub fn smt_leaf_hash(key: &[u8; 32], value: &StateMapValue) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SMT_LEAF_DOMAIN);
    hasher.update(key);
    if let Ok(event_bytes) = hex::decode(&value.latest_event_hash) {
        hasher.update(&event_bytes);
    } else {
        hasher.update(value.latest_event_hash.as_bytes());
    }
    hasher.update(value.sequence.to_be_bytes());
    let status_byte = match value.status {
        IdentifierStatus::Registered => 1u8,
        IdentifierStatus::Revoked => 2u8,
    };
    hasher.update([status_byte]);
    hasher.finalize().into()
}

pub fn empty_hash(depth: usize) -> [u8; 32] {
    let hashes = EMPTY_HASHES.get_or_init(|| {
        let mut h = [[0u8; 32]; 257];
        // h[256] is the empty leaf [0u8; 32]
        for d in (0..256).rev() {
            h[d] = smt_node_hash(&h[d + 1], &h[d + 1]);
        }
        h
    });
    hashes[depth]
}

impl StateMapProof {
    /// Pure verifier for the state map proof.
    /// Supports both inclusion (value is Some) and non-inclusion (value is None).
    pub fn verify(&self, expected_root: &str) -> Result<bool> {
        if self.audit_path.len() != 256 {
            return Ok(false);
        }

        let key_bytes = match decode_hash_bytes(&self.key_hash) {
            Ok(b) => b,
            Err(_) => return Ok(false),
        };

        let mut current_hash = match &self.value {
            Some(val) => smt_leaf_hash(&key_bytes, val),
            None => empty_hash(256),
        };

        // Sibling nodes are ordered from bottom to top:
        // index 0 is depth 255 (leaf sibling), index 255 is depth 0 (root child sibling).
        for (step, sibling_hex) in self.audit_path.iter().enumerate() {
            let depth = 255 - step;
            let sibling = match decode_hash_bytes(sibling_hex) {
                Ok(s) => s,
                Err(_) => return Ok(false),
            };
            let bit = get_bit(&key_bytes, depth);
            if bit == 0 {
                current_hash = smt_node_hash(&current_hash, &sibling);
            } else {
                current_hash = smt_node_hash(&sibling, &current_hash);
            }
        }

        Ok(hex::encode(current_hash) == expected_root)
    }
}

/// In-memory 256-bit Sparse Merkle Tree for authenticated current state.
#[derive(Debug, Clone, Default)]
pub struct SparseMerkleTree {
    entries: BTreeMap<[u8; 32], StateMapValue>,
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, key: [u8; 32], value: StateMapValue) {
        self.entries.insert(key, value);
    }

    pub fn insert_hex(&mut self, key_hex: &str, value: StateMapValue) -> Result<()> {
        let key = decode_hash_bytes(key_hex)?;
        self.insert(key, value);
        Ok(())
    }

    pub fn get(&self, key: &[u8; 32]) -> Option<&StateMapValue> {
        self.entries.get(key)
    }

    pub fn get_hex(&self, key_hex: &str) -> Result<Option<&StateMapValue>> {
        let key = decode_hash_bytes(key_hex)?;
        Ok(self.get(&key))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Compute the 32-byte Merkle root of the tree.
    pub fn root(&self) -> [u8; 32] {
        let keys_and_values: Vec<([u8; 32], &StateMapValue)> =
            self.entries.iter().map(|(k, v)| (*k, v)).collect();
        compute_subtree_root(0, &keys_and_values)
    }

    /// Compute the 64-character lowercase hex string of the Merkle root.
    pub fn root_hex(&self) -> String {
        hex::encode(self.root())
    }

    /// Generate an inclusion or non-inclusion proof for a given 32-byte key.
    pub fn prove(&self, key: &[u8; 32]) -> StateMapProof {
        let keys_and_values: Vec<([u8; 32], &StateMapValue)> =
            self.entries.iter().map(|(k, v)| (*k, v)).collect();

        let mut siblings_top_to_bottom = Vec::with_capacity(256);
        generate_audit_path(0, key, &keys_and_values, &mut siblings_top_to_bottom);

        // Reverse to satisfy the bottom-to-top convention
        siblings_top_to_bottom.reverse();

        StateMapProof {
            key_hash: hex::encode(key),
            value: self.get(key).cloned(),
            audit_path: siblings_top_to_bottom,
        }
    }

    /// Generate an inclusion or non-inclusion proof for a hex-encoded key.
    pub fn prove_hex(&self, key_hex: &str) -> Result<StateMapProof> {
        let key = decode_hash_bytes(key_hex)?;
        Ok(self.prove(&key))
    }
}

fn compute_subtree_root(depth: usize, keys: &[([u8; 32], &StateMapValue)]) -> [u8; 32] {
    if keys.is_empty() {
        return empty_hash(depth);
    }
    if depth == 256 {
        return smt_leaf_hash(&keys[0].0, keys[0].1);
    }

    let split_idx = keys.partition_point(|(k, _)| get_bit(k, depth) == 0);
    let left_keys = &keys[..split_idx];
    let right_keys = &keys[split_idx..];

    let left_hash = if left_keys.is_empty() {
        empty_hash(depth + 1)
    } else {
        compute_subtree_root(depth + 1, left_keys)
    };

    let right_hash = if right_keys.is_empty() {
        empty_hash(depth + 1)
    } else {
        compute_subtree_root(depth + 1, right_keys)
    };

    smt_node_hash(&left_hash, &right_hash)
}

fn generate_audit_path(
    depth: usize,
    target_key: &[u8; 32],
    keys: &[([u8; 32], &StateMapValue)],
    out_siblings: &mut Vec<String>,
) {
    if depth == 256 {
        return;
    }

    let split_idx = keys.partition_point(|(k, _)| get_bit(k, depth) == 0);
    let left_keys = &keys[..split_idx];
    let right_keys = &keys[split_idx..];

    let bit = get_bit(target_key, depth);
    if bit == 0 {
        // Target is on the left branch, sibling is the right branch
        let sibling_hash = if right_keys.is_empty() {
            empty_hash(depth + 1)
        } else {
            compute_subtree_root(depth + 1, right_keys)
        };
        out_siblings.push(hex::encode(sibling_hash));
        generate_audit_path(depth + 1, target_key, left_keys, out_siblings);
    } else {
        // Target is on the right branch, sibling is the left branch
        let sibling_hash = if left_keys.is_empty() {
            empty_hash(depth + 1)
        } else {
            compute_subtree_root(depth + 1, left_keys)
        };
        out_siblings.push(hex::encode(sibling_hash));
        generate_audit_path(depth + 1, target_key, right_keys, out_siblings);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree_root_is_deterministic() {
        let tree1 = SparseMerkleTree::new();
        let tree2 = SparseMerkleTree::new();
        assert_eq!(tree1.root(), tree2.root());
        assert_eq!(tree1.root_hex(), tree2.root_hex());
        assert_eq!(tree1.root(), empty_hash(0));
    }

    #[test]
    fn test_single_leaf_inclusion_and_verification() {
        let mut tree = SparseMerkleTree::new();
        let key = [0xabu8; 32];
        let val = StateMapValue {
            latest_event_hash: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                .into(),
            sequence: 0,
            status: IdentifierStatus::Registered,
        };

        tree.insert(key, val.clone());
        let root = tree.root_hex();
        assert_ne!(root, hex::encode(empty_hash(0)));

        let proof = tree.prove(&key);
        assert!(proof.value.is_some());
        assert_eq!(proof.value.as_ref().unwrap(), &val);
        assert_eq!(proof.audit_path.len(), 256);

        assert!(proof.verify(&root).expect("proof verification"));
    }

    #[test]
    fn test_non_inclusion_proof_in_empty_tree() {
        let tree = SparseMerkleTree::new();
        let key = [0x55u8; 32];
        let root = tree.root_hex();

        let proof = tree.prove(&key);
        assert!(proof.value.is_none());
        assert_eq!(proof.audit_path.len(), 256);

        // Verification of non-inclusion against empty root succeeds
        assert!(proof.verify(&root).expect("verify non-inclusion"));
    }

    #[test]
    fn test_non_inclusion_proof_with_other_keys_present() {
        let mut tree = SparseMerkleTree::new();
        let key1 = [0x11u8; 32];
        let key2 = [0x22u8; 32];
        let key3_absent = [0x33u8; 32];

        tree.insert(
            key1,
            StateMapValue {
                latest_event_hash:
                    "1111111111111111111111111111111111111111111111111111111111111111".into(),
                sequence: 1,
                status: IdentifierStatus::Registered,
            },
        );
        tree.insert(
            key2,
            StateMapValue {
                latest_event_hash:
                    "2222222222222222222222222222222222222222222222222222222222222222".into(),
                sequence: 0,
                status: IdentifierStatus::Revoked,
            },
        );

        let root = tree.root_hex();

        // Key 1 inclusion proof passes
        let proof1 = tree.prove(&key1);
        assert!(proof1.value.is_some());
        assert!(proof1.verify(&root).expect("verify key1"));

        // Key 2 inclusion proof passes
        let proof2 = tree.prove(&key2);
        assert!(proof2.value.is_some());
        assert!(proof2.verify(&root).expect("verify key2"));

        // Key 3 non-inclusion proof passes
        let proof3 = tree.prove(&key3_absent);
        assert!(proof3.value.is_none());
        assert!(proof3.verify(&root).expect("verify key3 non-inclusion"));
    }

    #[test]
    fn test_tampered_proof_fails_verification() {
        let mut tree = SparseMerkleTree::new();
        let key = [0x77u8; 32];
        tree.insert(
            key,
            StateMapValue {
                latest_event_hash:
                    "7777777777777777777777777777777777777777777777777777777777777777".into(),
                sequence: 0,
                status: IdentifierStatus::Registered,
            },
        );
        let root = tree.root_hex();
        let mut proof = tree.prove(&key);

        // 1. Wrong root fails
        let wrong_root = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(!proof.verify(wrong_root).expect("verify"));

        // 2. Tampered value fails
        let mut tampered_val_proof = proof.clone();
        if let Some(val) = tampered_val_proof.value.as_mut() {
            val.sequence = 999;
        }
        assert!(!tampered_val_proof.verify(&root).expect("verify"));

        // 3. Tampered audit path sibling fails
        proof.audit_path[0] =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();
        assert!(!proof.verify(&root).expect("verify"));

        // 4. Claiming non-inclusion for present key fails
        let mut fake_non_inc = tree.prove(&key);
        fake_non_inc.value = None;
        assert!(!fake_non_inc.verify(&root).expect("verify"));
    }
}
