//! Official BIP-352 Silent Payments test vector suite and edge-case conformance tests.
//!
//! Validates SatsPath's BIP-352 implementation against all 28 official test groups from
//! `bitcoin/bips` (`bip-0352/send_and_receive_test_vectors.json`), covering:
//! - Public key extraction from P2PKH (including malleated scriptSig), P2WPKH, P2SH-P2WPKH, and P2TR.
//! - Skipping uncompressed keys, invalid P2SH inputs, and Taproot script-path spends with the NUMS point `H`.
//! - Taproot even/odd Y-coordinate parity negation on sender private keys.
//! - Lexicographically smallest outpoint (`outpoint_L`) ordering across all transaction inputs.
//! - Intermediate and final point-at-infinity / zero scalar sum edge cases.
//! - Recipient grouping, multiple outputs, labeled addresses (`BIP0352/Label`), change label `m = 0`,
//!   and `K_max = 2323` recipient group bounds.
//! - Receiver output scanning, tweak computation, and BIP-340 Schnorr spending signature verification.

use std::collections::HashSet;

use bitcoin::secp256k1::{
    Keypair, Message, Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use satspath_router::silent_payments::{
    create_bip352_outputs, parse_silent_payment_address, scan_bip352_transaction,
    Bip352PrevoutInput,
};

const VECTORS_JSON: &str = include_str!("data/bip352_send_and_receive_test_vectors.json");

#[derive(Debug, Deserialize)]
struct TestGroup {
    comment: String,
    sending: Vec<SendingCase>,
    receiving: Vec<ReceivingCase>,
}

#[derive(Debug, Deserialize)]
struct SendingCase {
    given: SendingGiven,
    expected: SendingExpected,
}

#[derive(Debug, Deserialize)]
struct SendingGiven {
    vin: Vec<VectorVin>,
    recipients: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct SendingExpected {
    outputs: Vec<Vec<String>>,
    #[serde(default)]
    shared_secrets: Vec<Option<String>>,
    #[serde(default)]
    input_private_key_sum: Option<String>,
    #[serde(default)]
    input_pub_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ReceivingCase {
    given: ReceivingGiven,
    expected: ReceivingExpected,
}

#[derive(Debug, Deserialize)]
struct ReceivingGiven {
    vin: Vec<VectorVin>,
    outputs: Vec<String>,
    key_material: KeyMaterial,
    labels: Vec<u32>,
}

#[derive(Debug, Deserialize)]
struct KeyMaterial {
    spend_priv_key: String,
    scan_priv_key: String,
}

#[derive(Debug, Deserialize)]
struct ReceivingExpected {
    addresses: Vec<String>,
    #[serde(default)]
    outputs: Vec<ExpectedRecvOutput>,
    #[serde(default)]
    n_outputs: Option<usize>,
    #[serde(default)]
    tweak: Option<String>,
    #[serde(default)]
    shared_secret: Option<String>,
    #[serde(default)]
    input_pub_key_sum: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExpectedRecvOutput {
    pub_key: String,
    priv_key_tweak: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct VectorVin {
    txid: String,
    vout: u32,
    #[serde(rename = "scriptSig")]
    script_sig: String,
    txinwitness: String,
    prevout: VectorPrevout,
    #[serde(default)]
    private_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VectorPrevout {
    #[serde(rename = "scriptPubKey")]
    script_pubkey: VectorScriptPubKey,
}

#[derive(Debug, Deserialize)]
struct VectorScriptPubKey {
    hex: String,
}

/// Convert a JSON test-vector `vin` entry into a [`Bip352PrevoutInput`].
fn to_prevout_input(v: &VectorVin) -> Bip352PrevoutInput {
    Bip352PrevoutInput {
        txid: v.txid.clone(),
        vout: v.vout,
        script_sig: v.script_sig.clone(),
        txinwitness: v.txinwitness.clone(),
        prevout_script_pubkey: v.prevout.script_pubkey.hex.clone(),
        private_key: v.private_key.clone().map(Zeroizing::new),
    }
}

/// Parse a recipient entry from the BIP-352 test vector JSON (either a string or an object with `address` and optional `count`).
fn parse_recipient_entry(val: &serde_json::Value) -> (String, usize) {
    if let Some(addr_str) = val.as_str() {
        (addr_str.to_string(), 1)
    } else if let Some(obj) = val.as_object() {
        let address = obj["address"]
            .as_str()
            .expect("recipient object must have address string")
            .to_string();
        let count = obj
            .get("count")
            .and_then(|c| c.as_u64())
            .map(|c| c as usize)
            .unwrap_or(1);

        // Verify scan_pub_key and spend_pub_key in vector match our Bech32m parser
        if let (Some(expected_scan), Some(expected_spend)) = (
            obj.get("scan_pub_key").and_then(|v| v.as_str()),
            obj.get("spend_pub_key").and_then(|v| v.as_str()),
        ) {
            let (scan_pk, spend_pk, _) =
                parse_silent_payment_address(&address).expect("valid recipient address in vector");
            assert_eq!(hex::encode(scan_pk.serialize()), expected_scan);
            assert_eq!(hex::encode(spend_pk.serialize()), expected_spend);
        }

        (address, count)
    } else {
        panic!("unexpected recipient JSON entry: {val:?}");
    }
}

/// Validate all 28 official BIP-352 sending test cases.
#[test]
fn test_official_bip352_sending_vectors() {
    let groups: Vec<TestGroup> =
        serde_json::from_str(VECTORS_JSON).expect("valid BIP-352 test vectors JSON");
    assert_eq!(groups.len(), 28, "expected all 28 BIP-352 test groups");

    for (g_idx, group) in groups.iter().enumerate() {
        for (s_idx, case) in group.sending.iter().enumerate() {
            let inputs: Vec<Bip352PrevoutInput> =
                case.given.vin.iter().map(to_prevout_input).collect();
            let recipients: Vec<(String, usize)> = case
                .given
                .recipients
                .iter()
                .map(parse_recipient_entry)
                .collect();

            let result = create_bip352_outputs(&inputs, &recipients)
                .unwrap_or_else(|e| panic!("group {g_idx} ({}) failed: {e}", group.comment));

            assert_eq!(
                result.input_pub_keys, case.expected.input_pub_keys,
                "group {g_idx} ({}) s_idx {s_idx}: input_pub_keys mismatch",
                group.comment
            );

            // Check input_private_key_sum when expected is present
            if let Some(ref expected_sum) = case.expected.input_private_key_sum {
                assert_eq!(
                    result.input_private_key_sum.as_ref().map(|s| s.as_str()),
                    Some(expected_sum.as_str()),
                    "group {g_idx} ({}) s_idx {s_idx}: input_private_key_sum mismatch",
                    group.comment
                );
            }

            // Compare multisets, retaining duplicate secrets and checking empty results too.
            let mut expected_secrets: Vec<&String> = case
                .expected
                .shared_secrets
                .iter()
                .filter_map(|s| s.as_ref())
                .collect();
            let mut actual_secrets: Vec<&String> = result.shared_secrets.iter().collect();
            expected_secrets.sort();
            actual_secrets.sort();
            assert_eq!(
                actual_secrets, expected_secrets,
                "group {g_idx} ({}) s_idx {s_idx}: shared_secrets mismatch",
                group.comment
            );

            // Check outputs against expected output permutations
            if case.expected.outputs.is_empty()
                || (case.expected.outputs.len() == 1 && case.expected.outputs[0].is_empty())
            {
                assert!(
                    result.outputs.is_empty(),
                    "group {g_idx} ({}) s_idx {s_idx}: expected empty outputs, got {:?}",
                    group.comment,
                    result.outputs
                );
            } else {
                let actual_set: HashSet<&String> = result.outputs.iter().collect();
                let matches_any = case.expected.outputs.iter().any(|perm| {
                    perm.len() == result.outputs.len()
                        && perm.iter().collect::<HashSet<_>>() == actual_set
                });
                assert!(
                    matches_any,
                    "group {g_idx} ({}) s_idx {s_idx}: outputs {:?} did not match any expected permutation {:?}",
                    group.comment, result.outputs, case.expected.outputs
                );
            }
        }
    }
}

/// Validate all 28 official BIP-352 receiving test cases (including labels, tweaks, and BIP-340 signatures).
#[test]
fn test_official_bip352_receiving_vectors() {
    let groups: Vec<TestGroup> =
        serde_json::from_str(VECTORS_JSON).expect("valid BIP-352 test vectors JSON");
    assert_eq!(groups.len(), 28, "expected all 28 BIP-352 test groups");

    let secp = Secp256k1::new();
    let msg = Message::from_digest(Sha256::digest(b"message").into());
    let aux_rand: [u8; 32] = Sha256::digest(b"random auxiliary data").into();

    for (g_idx, group) in groups.iter().enumerate() {
        for (r_idx, case) in group.receiving.iter().enumerate() {
            let scan_sk = SecretKey::from_slice(
                &hex::decode(&case.given.key_material.scan_priv_key).unwrap(),
            )
            .unwrap();
            let spend_sk = SecretKey::from_slice(
                &hex::decode(&case.given.key_material.spend_priv_key).unwrap(),
            )
            .unwrap();
            let inputs: Vec<Bip352PrevoutInput> =
                case.given.vin.iter().map(to_prevout_input).collect();

            let result = scan_bip352_transaction(
                &scan_sk,
                &PublicKey::from_secret_key(&secp, &spend_sk),
                &case.given.labels,
                &inputs,
                &case.given.outputs,
            )
            .unwrap_or_else(|e| panic!("group {g_idx} ({}) recv failed: {e}", group.comment));

            assert_eq!(
                result.addresses, case.expected.addresses,
                "group {g_idx} ({}) r_idx {r_idx}: derived addresses mismatch",
                group.comment
            );

            if let Some(ref exp_sum) = case.expected.input_pub_key_sum {
                assert_eq!(
                    result.input_pub_key_sum.as_deref(),
                    Some(exp_sum.as_str()),
                    "group {g_idx} ({}) r_idx {r_idx}: input_pub_key_sum mismatch",
                    group.comment
                );
            }

            assert_eq!(
                result.tweak, case.expected.tweak,
                "group {g_idx} ({}) r_idx {r_idx}: tweak mismatch",
                group.comment
            );

            assert_eq!(
                result.shared_secret, case.expected.shared_secret,
                "group {g_idx} ({}) r_idx {r_idx}: shared_secret mismatch",
                group.comment
            );

            if let Some(expected_n) = case.expected.n_outputs {
                assert_eq!(
                    result.outputs.len(),
                    expected_n,
                    "group {g_idx} ({}) r_idx {r_idx}: n_outputs mismatch",
                    group.comment
                );
            } else {
                assert_eq!(
                    result.outputs.len(),
                    case.expected.outputs.len(),
                    "group {g_idx} ({}) r_idx {r_idx}: detected output count mismatch",
                    group.comment
                );

                for exp_out in &case.expected.outputs {
                    let found = result
                        .outputs
                        .iter()
                        .find(|o| o.pub_key == exp_out.pub_key)
                        .unwrap_or_else(|| {
                            panic!(
                                "group {g_idx} ({}) r_idx {r_idx}: missing expected output {}",
                                group.comment, exp_out.pub_key
                            )
                        });
                    assert_eq!(
                        found.priv_key_tweak, exp_out.priv_key_tweak,
                        "group {g_idx} ({}) r_idx {r_idx}: priv_key_tweak mismatch for {}",
                        group.comment, exp_out.pub_key
                    );
                    // Only the wallet/test harness reconstructs full spending keys and signs.
                    let tweak = Scalar::from_be_bytes(
                        hex::decode(&found.priv_key_tweak)
                            .unwrap()
                            .try_into()
                            .unwrap(),
                    )
                    .unwrap();
                    let mut full_sk = spend_sk.add_tweak(&tweak).unwrap();
                    let derived_pk = PublicKey::from_secret_key(&secp, &full_sk);
                    let output_pk =
                        XOnlyPublicKey::from_slice(&hex::decode(&found.pub_key).unwrap()).unwrap();
                    assert_eq!(derived_pk.x_only_public_key().0, output_pk);
                    if derived_pk.x_only_public_key().1 == Parity::Odd {
                        full_sk = full_sk.negate();
                    }
                    let keypair = Keypair::from_secret_key(&secp, &full_sk);
                    let sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, &aux_rand);
                    assert_eq!(
                        hex::encode(sig.as_ref()),
                        exp_out.signature,
                        "group {g_idx} ({}) r_idx {r_idx}: signature mismatch for {}",
                        group.comment,
                        exp_out.pub_key
                    );
                    secp.verify_schnorr(&sig, &msg, &output_pk).unwrap();
                }
            }
        }
    }
}

/// Validate explicit edge-case handling: invalid pubkeys, uncompressed points, mixed-case addresses,
/// and duplicate public keys across distinct inputs.
#[test]
fn test_bip352_edge_cases_invalid_uncompressed_and_duplicate_keys() {
    use satspath_router::silent_payments::extract_bip352_input_pubkey;

    // 1. Mixed-case Bech32m address must be rejected
    let mixed_case = "sp1qqGste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";
    assert!(parse_silent_payment_address(mixed_case).is_err());

    // 2. Uncompressed P2WPKH witness key (65 bytes, 0x04 prefix) must be skipped (Ok(None))
    let uncompressed_p2wpkh = Bip352PrevoutInput {
        txid: "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d".to_string(),
        vout: 1,
        script_sig: String::new(),
        txinwitness: "02473045022100e7d26e77290b37128f5215ade25b9b908ce87cc9a4d498908b5bb8fd6daa1b8d022002568c3a8226f4f0436510283052bfb780b76f3fe4aa60c4c5eb118e43b187374104e0ec4f64b3fa2e463ccfcf4e856e37d5e1e20275bc89ec1def9eb098eff1f85d6fe8190e189be57d0d5bcd17dbcbcd04c9b4a1c5f605b10d5c90abfcc0d12884".to_string(),
        prevout_script_pubkey: "00140423f731a07491364e8dce98b7c00bda63336950".to_string(),
        private_key: None,
    };
    assert_eq!(
        extract_bip352_input_pubkey(&uncompressed_p2wpkh).unwrap(),
        None
    );

    // 3. Invalid curve point in P2TR scriptPubKey (x-coordinate >= field prime p) must be skipped
    let invalid_p2tr = Bip352PrevoutInput {
        txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16".to_string(),
        vout: 0,
        script_sig: String::new(),
        txinwitness: "0140c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b".to_string(),
        prevout_script_pubkey: format!("5120{}", "ff".repeat(32)),
        private_key: None,
    };
    assert_eq!(extract_bip352_input_pubkey(&invalid_p2tr).unwrap(), None);

    // 4. Duplicate public keys across two distinct UTXOs must both be included in the sum (2 * A_1)
    let dup_in_1 = Bip352PrevoutInput {
        txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16".to_string(),
        vout: 0,
        script_sig: String::new(),
        txinwitness: "0140c459b671370d12cfb5acee76da7e3ba7cc29b0b4653e3af8388591082660137d087fdc8e89a612cd5d15be0febe61fc7cdcf3161a26e599a4514aa5c3e86f47b".to_string(),
        prevout_script_pubkey: "51205a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5".to_string(),
        private_key: Some(Zeroizing::new("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1".to_string())),
    };
    let mut dup_in_2 = dup_in_1.clone();
    dup_in_2.vout = 1;

    let recipient = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv".to_string();
    let res = create_bip352_outputs(&[dup_in_1, dup_in_2], &[(recipient, 1)]).unwrap();
    assert_eq!(res.input_pub_keys.len(), 2);
    assert_eq!(res.input_pub_keys[0], res.input_pub_keys[1]);
    assert_eq!(res.outputs.len(), 1);
    assert_eq!(
        res.input_private_key_sum.as_ref().map(|s| s.as_str()),
        Some("d5b8f02cbfe3f1d5295af9fb8a9320e859e9cb07115856486ab1a4e4fb89a621")
    );
    assert_eq!(
        res.outputs,
        ["548ae55c8eec1e736e8d3e520f011f1f42a56d166116ad210b3937599f87f566"]
    );
}

#[test]
fn test_bip352_secret_serialization_and_debug_redaction() {
    let groups: Vec<TestGroup> = serde_json::from_str(VECTORS_JSON).unwrap();
    let case = &groups[0].sending[0];
    let input = to_prevout_input(&case.given.vin[0]);
    let private_key = input.private_key.as_ref().unwrap().as_str();
    let mut serialized = serde_json::to_value(&input).unwrap();
    assert!(serialized.get("private_key").is_none());
    assert!(!serialized.to_string().contains(private_key));
    for debug in [format!("{input:?}"), format!("{input:#?}")] {
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(private_key));
    }

    // Deserialization must still accept sender keys, while serialization always omits them.
    serialized["private_key"] = private_key.into();
    let restored: Bip352PrevoutInput = serde_json::from_value(serialized).unwrap();
    assert_eq!(restored, input);
    let without_key = Bip352PrevoutInput {
        private_key: None,
        ..input.clone()
    };
    assert!(serde_json::to_value(&without_key)
        .unwrap()
        .get("private_key")
        .is_none());

    let inputs: Vec<_> = case.given.vin.iter().map(to_prevout_input).collect();
    let recipients: Vec<_> = case
        .given
        .recipients
        .iter()
        .map(parse_recipient_entry)
        .collect();
    let result = create_bip352_outputs(&inputs, &recipients).unwrap();
    let sum = result.input_private_key_sum.as_ref().unwrap().as_str();
    for debug in [format!("{result:?}"), format!("{result:#?}")] {
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(sum));
    }
}

#[test]
fn test_bip352_sender_rejects_mismatched_keys_and_missing_spend_data() {
    use satspath_router::silent_payments::extract_bip352_sender_privkey;

    let groups: Vec<TestGroup> = serde_json::from_str(VECTORS_JSON).unwrap();
    // P2PKH, P2TR, P2WPKH, and P2SH-P2WPKH respectively.
    for group in [0, 6, 25, 22] {
        let input = to_prevout_input(&groups[group].sending[0].given.vin[0]);
        assert!(extract_bip352_sender_privkey(&input).unwrap().is_some());
        let mut wrong = input.clone();
        wrong.private_key = Some(Zeroizing::new(format!("{:064x}", 1)));
        assert!(extract_bip352_sender_privkey(&wrong)
            .unwrap_err()
            .to_string()
            .contains("does not match"));

        let mut missing_key = input.clone();
        missing_key.private_key = None;
        assert!(extract_bip352_sender_privkey(&missing_key).is_err());

        let mut incomplete = input.clone();
        incomplete.script_sig.clear();
        incomplete.txinwitness.clear();
        assert!(extract_bip352_sender_privkey(&incomplete)
            .unwrap_err()
            .to_string()
            .contains("Missing"));
        incomplete.private_key = None;
        assert!(extract_bip352_sender_privkey(&incomplete)
            .unwrap()
            .is_none());

        if group != 6 {
            // Signature-only placeholders cannot silently omit the real public key.
            incomplete = input.clone();
            if group == 0 {
                incomplete.script_sig = "0100".into();
            } else {
                incomplete.txinwitness = "010100".into();
            }
            assert!(extract_bip352_sender_privkey(&incomplete).is_err());
        }

        if group != 0 {
            // An encoded empty witness is also missing spend-time data.
            incomplete = input.clone();
            incomplete.txinwitness = "00".into();
            assert!(extract_bip352_sender_privkey(&incomplete).is_err());
        }
    }
}

#[test]
fn test_bip352_sender_compares_full_keys_except_for_taproot() {
    use satspath_router::silent_payments::extract_bip352_sender_privkey;

    let groups: Vec<TestGroup> = serde_json::from_str(VECTORS_JSON).unwrap();
    for group in [0, 6] {
        let mut input = to_prevout_input(&groups[group].sending[0].given.vin[0]);
        let key = SecretKey::from_slice(
            &hex::decode(input.private_key.as_ref().unwrap().as_str()).unwrap(),
        )
        .unwrap();
        input.private_key = Some(Zeroizing::new(hex::encode(key.negate().secret_bytes())));
        let result = extract_bip352_sender_privkey(&input);
        if group == 6 {
            // Both private-key parities must resolve to the same even-Y Taproot key.
            let (key, pk) = result.unwrap().unwrap();
            assert_eq!(pk.x_only_public_key().1, Parity::Even);
            assert_eq!(PublicKey::from_secret_key(&Secp256k1::new(), &key), pk);
        } else {
            assert!(result.is_err());
        }
    }
}

#[test]
fn test_bip352_recipient_count_limits_and_grouped_counts() {
    use satspath_router::silent_payments::{
        create_silent_payment_address, derive_labeled_spend_pubkey, BIP0352_MAX_K,
    };

    let groups: Vec<TestGroup> = serde_json::from_str(VECTORS_JSON).unwrap();
    let case = &groups[0].sending[0];
    let inputs: Vec<_> = case.given.vin.iter().map(to_prevout_input).collect();
    let (address, _) = parse_recipient_entry(&case.given.recipients[0]);
    let max = BIP0352_MAX_K as usize;
    for counts in [
        vec![usize::MAX],
        vec![max + 1],
        vec![max, 1],
        vec![1, usize::MAX],
    ] {
        let recipients: Vec<_> = counts.into_iter().map(|n| (address.clone(), n)).collect();
        let result = create_bip352_outputs(&inputs, &recipients).unwrap();
        assert!(result.outputs.is_empty());
        assert!(result.shared_secrets.is_empty());
        assert!(result.input_private_key_sum.is_some());
        assert_eq!(result.input_pub_keys, case.expected.input_pub_keys);
    }
    let at_limit = create_bip352_outputs(&inputs, &[(address.clone(), max)]).unwrap();
    assert_eq!(at_limit.outputs.len(), max);
    let split = create_bip352_outputs(&inputs, &[(address.clone(), 1), (address.clone(), max - 1)])
        .unwrap();
    assert_eq!(split.outputs, at_limit.outputs);
    assert_eq!(
        split.shared_secrets,
        vec![at_limit.shared_secrets[0].clone(); 2]
    );

    // Counts for distinct spend keys sharing a scan key must advance one common index.
    let (scan, spend, _) = parse_silent_payment_address(&address).unwrap();
    let label_key = SecretKey::from_slice(&[1; 32]).unwrap();
    let labeled_spend = derive_labeled_spend_pubkey(&spend, &label_key, 1).unwrap();
    let labeled = create_silent_payment_address(&scan, &labeled_spend).unwrap();
    let counted =
        create_bip352_outputs(&inputs, &[(address.clone(), 2), (labeled.clone(), 2)]).unwrap();
    let expanded = create_bip352_outputs(
        &inputs,
        &[
            (address.clone(), 1),
            (address, 1),
            (labeled.clone(), 1),
            (labeled, 1),
        ],
    )
    .unwrap();
    assert_eq!(counted.outputs, expanded.outputs);
    assert_eq!(counted.outputs.len(), 4);
    assert_eq!(counted.shared_secrets.len(), 2);
}
