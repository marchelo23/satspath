//! # satspath-witness - Server-to-Server Checkpoint Witness & Split-View Detector
//!
//! Provides independent cryptographic verification of Transparency Log checkpoints
//! to detect and permanently record operator equivocation and rollback attacks.
//!
//! Features:
//! - Real secp256k1 BIP-340 Schnorr cosignatures over checkpoint commitments
//! - RFC 6962 consistency proof verification on tree advancement
//! - Durable `PinStore` implementation (`FilePinStore`) and fast `MemoryPinStore`
//! - $K$-of-$N$ quorum policy evaluation with deduplication and authorization checks

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use satspath_core::crypto::{
    generate_identity_keypair, sign_message, verify_message_signature, IdentityKeypair,
};
use satspath_core::transparency::{
    verify_checkpoint, verify_consistency_proof, witness_cosignature_message,
    MerkleConsistencyProof, TransparencyCheckpoint, WitnessCosignature,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum WitnessError {
    #[error("Checkpoint signature invalid")]
    InvalidSignature,
    #[error("Tree size rolled back from {pinned} to {proposed}")]
    Rollback { pinned: u64, proposed: u64 },
    #[error("Equivocation detected for log {log_id} at tree size {tree_size}")]
    EquivocationDetected { log_id: String, tree_size: u64 },
    #[error("Consistency proof verification failed")]
    InvalidConsistencyProof,
    #[error("Timestamp outside acceptable freshness window")]
    StaleTimestamp,
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Quorum not met: required {required}, got {actual} valid unique cosignatures")]
    QuorumNotMet { required: usize, actual: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinnedState {
    pub log_id: String,
    pub tree_size: u64,
    pub root_hash: String,
    pub signature: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EquivocationRecord {
    pub log_id: String,
    pub tree_size: u64,
    pub first_seen: PinnedState,
    pub conflicting: PinnedState,
    pub detected_at: i64,
}

#[async_trait]
pub trait PinStore: Send + Sync {
    async fn get_pin(&self, log_id: &str) -> Result<Option<PinnedState>, WitnessError>;
    async fn save_pin(&self, pin: PinnedState) -> Result<(), WitnessError>;
    async fn record_equivocation(
        &self,
        log_id: &str,
        tree_size: u64,
        first_seen: PinnedState,
        conflicting: PinnedState,
    ) -> Result<(), WitnessError>;
    async fn get_equivocations(
        &self,
        log_id: &str,
    ) -> Result<Vec<EquivocationRecord>, WitnessError>;
}

// -- In-Memory Pin Store ----------------------------------------------------------

#[derive(Default, Clone)]
pub struct MemoryPinStore {
    pins: Arc<RwLock<HashMap<String, PinnedState>>>,
    equivocations: Arc<RwLock<HashMap<String, Vec<EquivocationRecord>>>>,
}

impl MemoryPinStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PinStore for MemoryPinStore {
    async fn get_pin(&self, log_id: &str) -> Result<Option<PinnedState>, WitnessError> {
        let read = self.pins.read().await;
        Ok(read.get(log_id).cloned())
    }

    async fn save_pin(&self, pin: PinnedState) -> Result<(), WitnessError> {
        let mut write = self.pins.write().await;
        write.insert(pin.log_id.clone(), pin);
        Ok(())
    }

    async fn record_equivocation(
        &self,
        log_id: &str,
        tree_size: u64,
        first_seen: PinnedState,
        conflicting: PinnedState,
    ) -> Result<(), WitnessError> {
        let mut write = self.equivocations.write().await;
        let record = EquivocationRecord {
            log_id: log_id.to_string(),
            tree_size,
            first_seen,
            conflicting,
            detected_at: chrono::Utc::now().timestamp(),
        };
        write.entry(log_id.to_string()).or_default().push(record);
        Ok(())
    }

    async fn get_equivocations(
        &self,
        log_id: &str,
    ) -> Result<Vec<EquivocationRecord>, WitnessError> {
        let read = self.equivocations.read().await;
        Ok(read.get(log_id).cloned().unwrap_or_default())
    }
}

// -- Persistent File Pin Store ---------------------------------------------------

#[derive(Clone)]
pub struct FilePinStore {
    pins_dir: PathBuf,
    equivocations_dir: PathBuf,
}

impl FilePinStore {
    pub fn open<P: AsRef<Path>>(base_dir: P) -> Result<Self, WitnessError> {
        let base = base_dir.as_ref();
        let pins_dir = base.join("pins");
        let equivocations_dir = base.join("equivocations");

        std::fs::create_dir_all(&pins_dir)
            .map_err(|e| WitnessError::Storage(format!("create pins dir: {e}")))?;
        std::fs::create_dir_all(&equivocations_dir)
            .map_err(|e| WitnessError::Storage(format!("create equivocations dir: {e}")))?;

        Ok(Self {
            pins_dir,
            equivocations_dir,
        })
    }

    fn safe_filename(key: &str) -> String {
        hex::encode(sha2::Sha256::digest(key.as_bytes()))
    }
}

#[async_trait]
impl PinStore for FilePinStore {
    async fn get_pin(&self, log_id: &str) -> Result<Option<PinnedState>, WitnessError> {
        let file_path = self
            .pins_dir
            .join(format!("{}.json", Self::safe_filename(log_id)));
        if !file_path.exists() {
            return Ok(None);
        }
        let data = std::fs::read(&file_path)
            .map_err(|e| WitnessError::Storage(format!("read pin file: {e}")))?;
        let pin: PinnedState = serde_json::from_slice(&data)
            .map_err(|e| WitnessError::Storage(format!("deserialize pin: {e}")))?;
        Ok(Some(pin))
    }

    async fn save_pin(&self, pin: PinnedState) -> Result<(), WitnessError> {
        let file_path = self
            .pins_dir
            .join(format!("{}.json", Self::safe_filename(&pin.log_id)));
        let tmp_path = file_path.with_extension("tmp");
        let encoded = serde_json::to_vec_pretty(&pin)
            .map_err(|e| WitnessError::Storage(format!("serialize pin: {e}")))?;

        std::fs::write(&tmp_path, encoded)
            .map_err(|e| WitnessError::Storage(format!("write pin tmp: {e}")))?;
        std::fs::rename(tmp_path, file_path)
            .map_err(|e| WitnessError::Storage(format!("atomic commit pin: {e}")))?;
        Ok(())
    }

    async fn record_equivocation(
        &self,
        log_id: &str,
        tree_size: u64,
        first_seen: PinnedState,
        conflicting: PinnedState,
    ) -> Result<(), WitnessError> {
        let record = EquivocationRecord {
            log_id: log_id.to_string(),
            tree_size,
            first_seen,
            conflicting,
            detected_at: chrono::Utc::now().timestamp(),
        };

        let file_name = format!(
            "{}_{}_{}.json",
            Self::safe_filename(log_id),
            tree_size,
            record.detected_at
        );
        let file_path = self.equivocations_dir.join(file_name);
        let tmp_path = file_path.with_extension("tmp");
        let encoded = serde_json::to_vec_pretty(&record)
            .map_err(|e| WitnessError::Storage(format!("serialize equivocation: {e}")))?;

        std::fs::write(&tmp_path, encoded)
            .map_err(|e| WitnessError::Storage(format!("write equivocation tmp: {e}")))?;
        std::fs::rename(tmp_path, file_path)
            .map_err(|e| WitnessError::Storage(format!("atomic commit equivocation: {e}")))?;
        Ok(())
    }

    async fn get_equivocations(
        &self,
        log_id: &str,
    ) -> Result<Vec<EquivocationRecord>, WitnessError> {
        let prefix = Self::safe_filename(log_id);
        let mut results = Vec::new();

        let entries = std::fs::read_dir(&self.equivocations_dir)
            .map_err(|e| WitnessError::Storage(format!("read equivocations dir: {e}")))?;

        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with(&prefix) && name_str.ends_with(".json") {
                if let Ok(data) = std::fs::read(entry.path()) {
                    if let Ok(rec) = serde_json::from_slice::<EquivocationRecord>(&data) {
                        results.push(rec);
                    }
                }
            }
        }

        results.sort_by_key(|r| r.detected_at);
        Ok(results)
    }
}

use sha2::Digest;

// -- Witness Service -------------------------------------------------------------

pub struct WitnessService<S: PinStore> {
    pub witness_id: String,
    pub keypair: IdentityKeypair,
    pub store: S,
}

impl<S: PinStore> WitnessService<S> {
    pub fn new(witness_id: String, keypair: IdentityKeypair, store: S) -> Self {
        Self {
            witness_id,
            keypair,
            store,
        }
    }

    pub fn with_generated_key(witness_id: String, store: S) -> Self {
        let keypair = generate_identity_keypair();
        Self::new(witness_id, keypair, store)
    }

    pub fn witness_pubkey(&self) -> String {
        hex::encode(self.keypair.public_key.serialize())
    }

    pub async fn process_checkpoint(
        &self,
        checkpoint: &TransparencyCheckpoint,
        consistency_proof: Option<&MerkleConsistencyProof>,
    ) -> Result<WitnessCosignature, WitnessError> {
        // 1. Verify checkpoint structure and operator signature
        let signature_valid =
            verify_checkpoint(checkpoint).map_err(|_| WitnessError::InvalidSignature)?;
        if !signature_valid {
            return Err(WitnessError::InvalidSignature);
        }

        // 2. State-machine checks against pinned state
        let pinned = self.store.get_pin(&checkpoint.log_id).await?;

        if let Some(pin) = pinned {
            // Rollback check: proposed tree size is less than what was previously pinned
            if checkpoint.log_size < pin.tree_size {
                return Err(WitnessError::Rollback {
                    pinned: pin.tree_size,
                    proposed: checkpoint.log_size,
                });
            }

            // Equivocation check: same tree size but different Merkle root
            if checkpoint.log_size == pin.tree_size && checkpoint.log_root != pin.root_hash {
                let equiv_first = pin.clone();
                let equiv_second = PinnedState {
                    log_id: checkpoint.log_id.clone(),
                    tree_size: checkpoint.log_size,
                    root_hash: checkpoint.log_root.clone(),
                    signature: checkpoint.operator_signature.clone(),
                    timestamp: checkpoint.created_at,
                };
                self.store
                    .record_equivocation(
                        &checkpoint.log_id,
                        checkpoint.log_size,
                        equiv_first,
                        equiv_second,
                    )
                    .await?;
                return Err(WitnessError::EquivocationDetected {
                    log_id: checkpoint.log_id.clone(),
                    tree_size: checkpoint.log_size,
                });
            }

            // Advancement check: tree size grew, verify consistency proof
            if checkpoint.log_size > pin.tree_size {
                let proof = consistency_proof.ok_or(WitnessError::InvalidConsistencyProof)?;

                // Assert proof boundaries align with pinned state and proposed checkpoint
                if proof.old_tree_size != pin.tree_size
                    || proof.new_tree_size != checkpoint.log_size
                    || proof.old_root != pin.root_hash
                    || proof.new_root != checkpoint.log_root
                {
                    return Err(WitnessError::InvalidConsistencyProof);
                }

                let proof_valid = verify_consistency_proof(proof)
                    .map_err(|_| WitnessError::InvalidConsistencyProof)?;
                if !proof_valid {
                    return Err(WitnessError::InvalidConsistencyProof);
                }
            }
        }

        // 3. Save new pinned state
        let new_pin = PinnedState {
            log_id: checkpoint.log_id.clone(),
            tree_size: checkpoint.log_size,
            root_hash: checkpoint.log_root.clone(),
            signature: checkpoint.operator_signature.clone(),
            timestamp: checkpoint.created_at,
        };
        self.store.save_pin(new_pin).await?;

        // 4. Generate real secp256k1 BIP-340 Schnorr cosignature
        let checkpoint_hash = checkpoint
            .checkpoint_hash()
            .map_err(|_| WitnessError::InvalidSignature)?;
        let timestamp = chrono::Utc::now().timestamp();
        let signing_message = witness_cosignature_message(
            &self.witness_id,
            &checkpoint_hash,
            checkpoint.log_size,
            timestamp,
        );

        let signature = sign_message(&signing_message, &self.keypair.secret_key);
        let witness_pubkey = self.witness_pubkey();

        Ok(WitnessCosignature {
            version: 1,
            witness_id: self.witness_id.clone(),
            witness_pubkey,
            checkpoint_hash,
            tree_size: checkpoint.log_size,
            timestamp,
            signature,
        })
    }
}

// -- K-of-N Quorum Policy --------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WitnessQuorumPolicy {
    pub required_quorum: u8,
    pub authorized_pubkeys: HashSet<String>,
}

impl WitnessQuorumPolicy {
    pub fn new(required_quorum: u8, authorized_pubkeys: impl IntoIterator<Item = String>) -> Self {
        Self {
            required_quorum,
            authorized_pubkeys: authorized_pubkeys.into_iter().collect(),
        }
    }

    /// Evaluates witness cosignatures against this policy for a given checkpoint.
    /// Deduplicates signatures by witness public key and returns the number of valid signatures.
    pub fn verify_quorum(
        &self,
        checkpoint: &TransparencyCheckpoint,
        cosignatures: &[WitnessCosignature],
    ) -> Result<usize, WitnessError> {
        let cp_hash = checkpoint
            .checkpoint_hash()
            .map_err(|_| WitnessError::InvalidSignature)?;

        let mut verified_pubkeys = HashSet::new();

        for cs in cosignatures {
            // Must be in authorized set
            if !self.authorized_pubkeys.contains(&cs.witness_pubkey) {
                continue;
            }

            // Must match checkpoint hash and tree size
            if cs.checkpoint_hash != cp_hash || cs.tree_size != checkpoint.log_size {
                continue;
            }

            // Must verify BIP-340 Schnorr signature
            let msg = cs.signing_message();
            if verify_message_signature(&msg, &cs.signature, &cs.witness_pubkey).unwrap_or(false) {
                verified_pubkeys.insert(cs.witness_pubkey.clone());
            }
        }

        if verified_pubkeys.len() >= self.required_quorum as usize {
            Ok(verified_pubkeys.len())
        } else {
            Err(WitnessError::QuorumNotMet {
                required: self.required_quorum as usize,
                actual: verified_pubkeys.len(),
            })
        }
    }
}

pub fn generate_witness_keypair() -> IdentityKeypair {
    generate_identity_keypair()
}

#[cfg(test)]
mod tests {
    use super::*;
    use satspath_core::transparency::{
        consistency_proof, leaf_hash, merkle_root, MerkleConsistencyProof,
    };
    use tempfile::tempdir;

    fn make_test_checkpoint(
        operator_key: &IdentityKeypair,
        log_id: &str,
        size: u64,
        root_hash: &str,
    ) -> TransparencyCheckpoint {
        let mut cp = TransparencyCheckpoint {
            version: 1,
            log_id: log_id.to_string(),
            log_size: size,
            log_root: root_hash.to_string(),
            map_root: None,
            previous_checkpoint_hash: None,
            created_at: 1700000000,
            operator_pubkey: hex::encode(operator_key.public_key.serialize()),
            operator_sequence: size,
            operator_rotation: None,
            operator_signature: String::new(),
            bitcoin_anchor: None,
        };
        cp.sign(&operator_key.secret_key)
            .expect("sign test checkpoint");
        cp
    }

    #[tokio::test]
    async fn test_memory_pin_store_lifecycle() {
        let store = MemoryPinStore::new();
        assert!(store.get_pin("log1").await.unwrap().is_none());

        let pin = PinnedState {
            log_id: "log1".to_string(),
            tree_size: 10,
            root_hash: "abcd".to_string(),
            signature: "sig1".to_string(),
            timestamp: 12345,
        };
        store.save_pin(pin.clone()).await.unwrap();

        let loaded = store.get_pin("log1").await.unwrap().expect("pin exists");
        assert_eq!(loaded, pin);

        let conflicting = PinnedState {
            log_id: "log1".to_string(),
            tree_size: 10,
            root_hash: "ef01".to_string(),
            signature: "sig2".to_string(),
            timestamp: 12346,
        };
        store
            .record_equivocation("log1", 10, pin.clone(), conflicting.clone())
            .await
            .unwrap();

        let equivs = store.get_equivocations("log1").await.unwrap();
        assert_eq!(equivs.len(), 1);
        assert_eq!(equivs[0].first_seen, pin);
        assert_eq!(equivs[0].conflicting, conflicting);
    }

    #[tokio::test]
    async fn test_file_pin_store_persistence_and_atomic_commits() {
        let tmp = tempdir().unwrap();
        let store = FilePinStore::open(tmp.path()).unwrap();

        let pin = PinnedState {
            log_id: "satspath-mainnet".to_string(),
            tree_size: 42,
            root_hash: "0123456789abcdef".to_string(),
            signature: "sig_abc".to_string(),
            timestamp: 1700000000,
        };
        store.save_pin(pin.clone()).await.unwrap();

        // Verify retrieval from existing instance
        let loaded = store
            .get_pin("satspath-mainnet")
            .await
            .unwrap()
            .expect("found pin");
        assert_eq!(loaded, pin);

        // Verify persistence by opening a new FilePinStore on the same directory
        let store2 = FilePinStore::open(tmp.path()).unwrap();
        let reloaded = store2
            .get_pin("satspath-mainnet")
            .await
            .unwrap()
            .expect("reloaded pin across restart");
        assert_eq!(reloaded, pin);

        // Record equivocation and verify persistence across instances
        let conflicting = PinnedState {
            log_id: "satspath-mainnet".to_string(),
            tree_size: 42,
            root_hash: "fedcba9876543210".to_string(),
            signature: "sig_bad".to_string(),
            timestamp: 1700000005,
        };
        store
            .record_equivocation("satspath-mainnet", 42, pin.clone(), conflicting.clone())
            .await
            .unwrap();

        let store3 = FilePinStore::open(tmp.path()).unwrap();
        let equivs = store3.get_equivocations("satspath-mainnet").await.unwrap();
        assert_eq!(equivs.len(), 1);
        assert_eq!(equivs[0].log_id, "satspath-mainnet");
        assert_eq!(equivs[0].tree_size, 42);
        assert_eq!(equivs[0].first_seen, pin);
        assert_eq!(equivs[0].conflicting, conflicting);
    }

    #[tokio::test]
    async fn test_witness_service_first_checkpoint_and_real_schnorr_cosignature() {
        let op_key = generate_identity_keypair();
        let leaf = leaf_hash(b"entry1");
        let root = hex::encode(merkle_root(&[leaf]));

        let cp = make_test_checkpoint(&op_key, "log1", 1, &root);
        let store = MemoryPinStore::new();
        let witness =
            WitnessService::with_generated_key("witness_alpha".to_string(), store.clone());

        let cosig = witness
            .process_checkpoint(&cp, None)
            .await
            .expect("process initial checkpoint");

        assert_eq!(cosig.witness_id, "witness_alpha");
        assert_eq!(cosig.witness_pubkey, witness.witness_pubkey());
        assert_eq!(cosig.tree_size, 1);
        assert_eq!(cosig.checkpoint_hash, cp.checkpoint_hash().unwrap());

        // Verify Schnorr signature via satspath-core protocol verification
        assert!(cosig.verify(&cp).unwrap());

        // Pinned state must match
        let pinned = store.get_pin("log1").await.unwrap().expect("pinned");
        assert_eq!(pinned.tree_size, 1);
        assert_eq!(pinned.root_hash, root);
    }

    #[tokio::test]
    async fn test_witness_service_rollback_detection() {
        let op_key = generate_identity_keypair();
        let store = MemoryPinStore::new();
        let witness = WitnessService::with_generated_key("w1".to_string(), store);

        let root2 = hex::encode(leaf_hash(b"root2"));
        let cp2 = make_test_checkpoint(&op_key, "log1", 2, &root2);
        witness.process_checkpoint(&cp2, None).await.unwrap();

        // Attempt rollback to tree size 1
        let root1 = hex::encode(leaf_hash(b"root1"));
        let cp1 = make_test_checkpoint(&op_key, "log1", 1, &root1);
        let err = witness.process_checkpoint(&cp1, None).await.unwrap_err();
        match err {
            WitnessError::Rollback { pinned, proposed } => {
                assert_eq!(pinned, 2);
                assert_eq!(proposed, 1);
            }
            other => panic!("expected rollback error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_witness_service_equivocation_detection_and_recording() {
        let op_key = generate_identity_keypair();
        let store = MemoryPinStore::new();
        let witness = WitnessService::with_generated_key("w1".to_string(), store.clone());

        let root_a = hex::encode(leaf_hash(b"root_valid_a"));
        let cp_a = make_test_checkpoint(&op_key, "log1", 5, &root_a);
        witness.process_checkpoint(&cp_a, None).await.unwrap();

        // Operator produces conflicting checkpoint at size 5 with different root
        let root_b = hex::encode(leaf_hash(b"root_conflicting_b"));
        let cp_b = make_test_checkpoint(&op_key, "log1", 5, &root_b);
        let err = witness.process_checkpoint(&cp_b, None).await.unwrap_err();
        match err {
            WitnessError::EquivocationDetected { log_id, tree_size } => {
                assert_eq!(log_id, "log1");
                assert_eq!(tree_size, 5);
            }
            other => panic!("expected equivocation error, got: {other:?}"),
        }

        // Equivocation record must be logged in store
        let records = store.get_equivocations("log1").await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].first_seen.root_hash, root_a);
        assert_eq!(records[0].conflicting.root_hash, root_b);
    }

    #[tokio::test]
    async fn test_witness_service_advancement_with_consistency_proof() {
        let op_key = generate_identity_keypair();
        let store = MemoryPinStore::new();
        let witness = WitnessService::with_generated_key("w1".to_string(), store.clone());

        let l1 = leaf_hash(b"item 1");
        let l2 = leaf_hash(b"item 2");
        let l3 = leaf_hash(b"item 3");

        let leaves_size2 = [l1, l2];
        let root2 = hex::encode(merkle_root(&leaves_size2));
        let cp2 = make_test_checkpoint(&op_key, "log1", 2, &root2);
        witness.process_checkpoint(&cp2, None).await.unwrap();

        // Advance tree to size 3
        let leaves_size3 = [l1, l2, l3];
        let root3 = hex::encode(merkle_root(&leaves_size3));
        let cp3 = make_test_checkpoint(&op_key, "log1", 3, &root3);

        // Case A: Missing consistency proof on advancement
        let err_no_proof = witness.process_checkpoint(&cp3, None).await.unwrap_err();
        assert!(matches!(
            err_no_proof,
            WitnessError::InvalidConsistencyProof
        ));

        // Case B: Bogus consistency proof path
        let bogus_proof = MerkleConsistencyProof {
            version: 2,
            old_tree_size: 2,
            new_tree_size: 3,
            old_root: root2.clone(),
            new_root: root3.clone(),
            audit_path: vec!["badhash".to_string()],
        };
        let err_bad_proof = witness
            .process_checkpoint(&cp3, Some(&bogus_proof))
            .await
            .unwrap_err();
        assert!(matches!(
            err_bad_proof,
            WitnessError::InvalidConsistencyProof
        ));

        // Case C: Valid RFC 6962 consistency proof
        let proof_path = consistency_proof(&leaves_size3, 2).expect("compute consistency proof");
        let valid_proof = MerkleConsistencyProof {
            version: 2,
            old_tree_size: 2,
            new_tree_size: 3,
            old_root: root2.clone(),
            new_root: root3.clone(),
            audit_path: proof_path.into_iter().map(hex::encode).collect(),
        };

        let cosig3 = witness
            .process_checkpoint(&cp3, Some(&valid_proof))
            .await
            .expect("advance tree with valid consistency proof");

        assert_eq!(cosig3.tree_size, 3);
        assert!(cosig3.verify(&cp3).unwrap());

        let pinned = store.get_pin("log1").await.unwrap().expect("pinned");
        assert_eq!(pinned.tree_size, 3);
        assert_eq!(pinned.root_hash, root3);
    }

    #[tokio::test]
    async fn test_witness_quorum_policy_k_of_n_and_deduplication() {
        let op_key = generate_identity_keypair();
        let root = hex::encode(merkle_root(&[leaf_hash(b"test")]));
        let cp = make_test_checkpoint(&op_key, "log_quorum", 1, &root);

        let w1 = WitnessService::with_generated_key("w1".to_string(), MemoryPinStore::new());
        let w2 = WitnessService::with_generated_key("w2".to_string(), MemoryPinStore::new());
        let w3 = WitnessService::with_generated_key("w3".to_string(), MemoryPinStore::new());

        let sig1 = w1.process_checkpoint(&cp, None).await.unwrap();
        let sig2 = w2.process_checkpoint(&cp, None).await.unwrap();
        let sig3 = w3.process_checkpoint(&cp, None).await.unwrap();

        let authorized = vec![
            w1.witness_pubkey(),
            w2.witness_pubkey(),
            w3.witness_pubkey(),
        ];
        let policy_2_of_3 = WitnessQuorumPolicy::new(2, authorized);

        // 3 valid cosignatures -> satisfies 2-of-3 quorum
        let count = policy_2_of_3
            .verify_quorum(&cp, &[sig1.clone(), sig2.clone(), sig3.clone()])
            .expect("3 of 3 quorum");
        assert_eq!(count, 3);

        // 2 valid cosignatures -> satisfies 2-of-3 quorum
        let count2 = policy_2_of_3
            .verify_quorum(&cp, &[sig1.clone(), sig2.clone()])
            .expect("2 of 3 quorum");
        assert_eq!(count2, 2);

        // 1 valid cosignature -> fails 2-of-3 quorum
        let err_single = policy_2_of_3
            .verify_quorum(&cp, std::slice::from_ref(&sig1))
            .unwrap_err();
        match err_single {
            WitnessError::QuorumNotMet { required, actual } => {
                assert_eq!(required, 2);
                assert_eq!(actual, 1);
            }
            other => panic!("expected QuorumNotMet, got {other:?}"),
        }

        // Sybil / duplicate replay attack: same witness cosignature passed twice
        let err_duplicate = policy_2_of_3
            .verify_quorum(&cp, &[sig1.clone(), sig1.clone()])
            .unwrap_err();
        match err_duplicate {
            WitnessError::QuorumNotMet { required, actual } => {
                assert_eq!(required, 2);
                assert_eq!(actual, 1); // Deduplication prevents counting twice!
            }
            other => panic!("expected QuorumNotMet on duplicate replay, got {other:?}"),
        }

        // Unknown witness cosignature
        let w_unauthorized =
            WitnessService::with_generated_key("rogue".to_string(), MemoryPinStore::new());
        let rogue_sig = w_unauthorized.process_checkpoint(&cp, None).await.unwrap();
        let err_rogue = policy_2_of_3
            .verify_quorum(&cp, &[rogue_sig, sig1.clone()])
            .unwrap_err();
        match err_rogue {
            WitnessError::QuorumNotMet { required, actual } => {
                assert_eq!(required, 2);
                assert_eq!(actual, 1);
            }
            other => panic!("expected QuorumNotMet with rogue witness, got {other:?}"),
        }

        // Tampered Schnorr signature
        let mut tampered_sig = sig2.clone();
        tampered_sig.signature = hex::encode([0u8; 64]);
        let err_tampered = policy_2_of_3
            .verify_quorum(&cp, &[sig1.clone(), tampered_sig])
            .unwrap_err();
        match err_tampered {
            WitnessError::QuorumNotMet { required, actual } => {
                assert_eq!(required, 2);
                assert_eq!(actual, 1);
            }
            other => panic!("expected QuorumNotMet with tampered signature, got {other:?}"),
        }
    }
}
