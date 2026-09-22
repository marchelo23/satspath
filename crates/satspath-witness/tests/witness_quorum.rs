use satspath_core::crypto::{generate_identity_keypair, IdentityKeypair};
use satspath_core::transparency::{
    consistency_proof, leaf_hash, merkle_root, verify_witness_quorum_against_checkpoint,
    DimensionStatus, MerkleConsistencyProof, TransparencyCheckpoint,
};
use satspath_witness::{
    FilePinStore, MemoryPinStore, PinStore, WitnessError, WitnessQuorumPolicy, WitnessService,
};
use tempfile::tempdir;

fn create_signed_checkpoint(
    operator: &IdentityKeypair,
    log_id: &str,
    size: u64,
    root: &str,
    created_at: i64,
) -> TransparencyCheckpoint {
    let mut cp = TransparencyCheckpoint {
        version: 1,
        log_id: log_id.to_string(),
        log_size: size,
        log_root: root.to_string(),
        map_root: None,
        previous_checkpoint_hash: None,
        created_at,
        operator_pubkey: hex::encode(operator.public_key.serialize()),
        operator_sequence: size,
        operator_rotation: None,
        operator_signature: String::new(),
        bitcoin_anchor: None,
    };
    cp.sign(&operator.secret_key)
        .expect("operator signs checkpoint");
    cp
}

#[tokio::test]
async fn test_end_to_end_multi_witness_quorum_and_resolver_integration() {
    let operator = generate_identity_keypair();
    let log_id = "satspath-transparency-v1";

    // Setup 3 independent witnesses with FilePinStore
    let dir1 = tempdir().unwrap();
    let dir2 = tempdir().unwrap();
    let dir3 = tempdir().unwrap();

    let w1 = WitnessService::with_generated_key(
        "witness-us-east".into(),
        FilePinStore::open(dir1.path()).unwrap(),
    );
    let w2 = WitnessService::with_generated_key(
        "witness-eu-west".into(),
        FilePinStore::open(dir2.path()).unwrap(),
    );
    let w3 = WitnessService::with_generated_key(
        "witness-ap-south".into(),
        FilePinStore::open(dir3.path()).unwrap(),
    );

    let allowed_pubkeys = vec![
        w1.witness_pubkey(),
        w2.witness_pubkey(),
        w3.witness_pubkey(),
    ];

    // Checkpoint 1 (tree size 1)
    let leaf1 = leaf_hash(b"satspath_genesis_event");
    let root1 = hex::encode(merkle_root(&[leaf1]));
    let cp1 = create_signed_checkpoint(&operator, log_id, 1, &root1, 1710000000);

    // All 3 witnesses cosign Checkpoint 1
    let cosig1_w1 = w1.process_checkpoint(&cp1, None).await.unwrap();
    let cosig1_w2 = w2.process_checkpoint(&cp1, None).await.unwrap();
    let cosig1_w3 = w3.process_checkpoint(&cp1, None).await.unwrap();

    // Verify individual BIP-340 Schnorr cosignatures
    assert!(cosig1_w1.verify(&cp1).unwrap());
    assert!(cosig1_w2.verify(&cp1).unwrap());
    assert!(cosig1_w3.verify(&cp1).unwrap());

    // Resolver verifies 2-of-3 quorum with all 3 cosignatures
    let status_3 = verify_witness_quorum_against_checkpoint(
        Some(&cp1),
        &[cosig1_w1.clone(), cosig1_w2.clone(), cosig1_w3.clone()],
        2,
        &allowed_pubkeys,
    );
    assert_eq!(status_3, DimensionStatus::Verified);

    // Resolver verifies 2-of-3 quorum with exactly 2 cosignatures (W1 + W3)
    let status_2 = verify_witness_quorum_against_checkpoint(
        Some(&cp1),
        &[cosig1_w1.clone(), cosig1_w3.clone()],
        2,
        &allowed_pubkeys,
    );
    assert_eq!(status_2, DimensionStatus::Verified);

    // Resolver rejects 2-of-3 quorum when only 1 cosignature is provided
    let status_1 = verify_witness_quorum_against_checkpoint(
        Some(&cp1),
        std::slice::from_ref(&cosig1_w1),
        2,
        &allowed_pubkeys,
    );
    assert!(matches!(status_1, DimensionStatus::Failed(_)));

    // Replay attack: Duplicating the same cosignature must NOT satisfy quorum
    let status_dup = verify_witness_quorum_against_checkpoint(
        Some(&cp1),
        &[cosig1_w1.clone(), cosig1_w1.clone()],
        2,
        &allowed_pubkeys,
    );
    assert!(matches!(status_dup, DimensionStatus::Failed(_)));

    // -- Tree advancement to Checkpoint 2 (tree size 2) -------------------------
    let leaf2 = leaf_hash(b"satspath_second_event");
    let leaves_size2 = [leaf1, leaf2];
    let root2 = hex::encode(merkle_root(&leaves_size2));
    let cp2 = create_signed_checkpoint(&operator, log_id, 2, &root2, 1710001000);

    let proof_path = consistency_proof(&leaves_size2, 1).expect("consistency proof 1->2");
    let consistency = MerkleConsistencyProof {
        version: 2,
        old_tree_size: 1,
        new_tree_size: 2,
        old_root: root1.clone(),
        new_root: root2.clone(),
        audit_path: proof_path.into_iter().map(hex::encode).collect(),
    };

    // W1 and W2 process Checkpoint 2 with consistency proof
    let cosig2_w1 = w1
        .process_checkpoint(&cp2, Some(&consistency))
        .await
        .unwrap();
    let cosig2_w2 = w2
        .process_checkpoint(&cp2, Some(&consistency))
        .await
        .unwrap();

    let status_cp2 = verify_witness_quorum_against_checkpoint(
        Some(&cp2),
        &[cosig2_w1.clone(), cosig2_w2.clone()],
        2,
        &allowed_pubkeys,
    );
    assert_eq!(status_cp2, DimensionStatus::Verified);

    // Attacker tries to mix Checkpoint 1 cosignature with Checkpoint 2
    let status_cross = verify_witness_quorum_against_checkpoint(
        Some(&cp2),
        &[cosig2_w1.clone(), cosig1_w2.clone()],
        2,
        &allowed_pubkeys,
    );
    assert!(matches!(status_cross, DimensionStatus::Failed(_)));
}

#[tokio::test]
async fn test_split_view_equivocation_detection_and_pin_persistence() {
    let operator = generate_identity_keypair();
    let log_id = "equivocation-target-log";
    let dir = tempdir().unwrap();

    let witness_key = generate_identity_keypair();
    let store = FilePinStore::open(dir.path()).unwrap();
    let witness = WitnessService::new("witness-auditor".into(), witness_key.clone(), store);

    // Legitimate Checkpoint at size 10
    let root_legit = hex::encode(leaf_hash(b"canonical_view"));
    let cp_legit = create_signed_checkpoint(&operator, log_id, 10, &root_legit, 1720000000);

    witness
        .process_checkpoint(&cp_legit, None)
        .await
        .expect("legit checkpoint pinned");

    // Operator equivocates and presents a conflicting root at size 10 to the same witness
    let root_fork = hex::encode(leaf_hash(b"forked_split_view"));
    let cp_fork = create_signed_checkpoint(&operator, log_id, 10, &root_fork, 1720000001);

    let err = witness
        .process_checkpoint(&cp_fork, None)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        WitnessError::EquivocationDetected {
            log_id: ref id,
            tree_size: 10
        } if id == log_id
    ));

    // Simulate witness restart by opening a brand new WitnessService with FilePinStore
    let restarted_store = FilePinStore::open(dir.path()).unwrap();
    let restarted_witness = WitnessService::new(
        "witness-auditor".into(),
        witness_key,
        restarted_store.clone(),
    );

    // Pinned state survived restart
    let pin = restarted_store
        .get_pin(log_id)
        .await
        .unwrap()
        .expect("pin exists");
    assert_eq!(pin.tree_size, 10);
    assert_eq!(pin.root_hash, root_legit);

    // Equivocation audit trail survived restart
    let equivocations = restarted_store.get_equivocations(log_id).await.unwrap();
    assert_eq!(equivocations.len(), 1);
    assert_eq!(equivocations[0].log_id, log_id);
    assert_eq!(equivocations[0].first_seen.root_hash, root_legit);
    assert_eq!(equivocations[0].conflicting.root_hash, root_fork);

    // Operator attempts to rollback to size 9 after restart -> detected and rejected
    let root_old = hex::encode(leaf_hash(b"old_view"));
    let cp_old = create_signed_checkpoint(&operator, log_id, 9, &root_old, 1719999999);
    let rollback_err = restarted_witness
        .process_checkpoint(&cp_old, None)
        .await
        .unwrap_err();

    assert!(matches!(
        rollback_err,
        WitnessError::Rollback {
            pinned: 10,
            proposed: 9
        }
    ));
}

#[tokio::test]
async fn test_witness_quorum_policy_evaluation() {
    let operator = generate_identity_keypair();
    let root = hex::encode(leaf_hash(b"quorum_eval_leaf"));
    let cp = create_signed_checkpoint(&operator, "quorum_test", 1, &root, 1730000000);

    let store1 = MemoryPinStore::new();
    let store2 = MemoryPinStore::new();
    let w1 = WitnessService::with_generated_key("node-1".into(), store1);
    let w2 = WitnessService::with_generated_key("node-2".into(), store2);

    let sig1 = w1.process_checkpoint(&cp, None).await.unwrap();
    let sig2 = w2.process_checkpoint(&cp, None).await.unwrap();

    let policy = WitnessQuorumPolicy::new(2, vec![w1.witness_pubkey(), w2.witness_pubkey()]);

    let verified_count = policy.verify_quorum(&cp, &[sig1.clone(), sig2]).unwrap();
    assert_eq!(verified_count, 2);

    // Single cosignature fails threshold
    let err = policy
        .verify_quorum(&cp, std::slice::from_ref(&sig1))
        .unwrap_err();
    assert!(matches!(
        err,
        WitnessError::QuorumNotMet {
            required: 2,
            actual: 1
        }
    ));
}
