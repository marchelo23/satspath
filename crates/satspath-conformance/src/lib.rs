//! Offline reference vectors and comparison of external SDK observations.
//! These checks never sign payments or handle wallet credentials.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

use satspath_core::crypto::{
    canonical_profile_bytes, is_profile_expired_at, verify_signed_profile,
};
use satspath_core::{
    Bip321Instruction, BitcoinNetwork, PaymentMethod, PaymentProfile, SignedPaymentProfile,
};

/// A versioned collection of independently comparable reference cases.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorSuite {
    pub version: u32,
    pub vectors: Vec<Vector>,
}

/// A named input and its expected observable JSON result.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vector {
    pub id: String,
    pub kind: String,
    pub input: Value,
    pub expected: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpiryCheck {
    as_of: i64,
    profile: PaymentProfile,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffCheck {
    uri: String,
    amount_sats: u64,
    network: BitcoinNetwork,
    as_of: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bolt12Check {
    offer: String,
    amount_sats: u64,
    network: BitcoinNetwork,
    as_of: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityCheck {
    method: PaymentMethod,
    amount_sats: u64,
    network: BitcoinNetwork,
    as_of: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolverComparison {
    /// Fixed Unix time keeps the signed-profile vectors reproducible after expiry.
    as_of: i64,
    profiles: Vec<SignedPaymentProfile>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Pass,
    Fail,
    Skip,
}

/// The result and diagnostic for one vector.
#[derive(Debug, Serialize)]
pub struct CaseReport {
    pub id: String,
    pub kind: String,
    pub status: CaseStatus,
    pub detail: String,
}

/// Totals and per-case results for a suite.
#[derive(Debug, Serialize)]
pub struct Report {
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub cases: Vec<CaseReport>,
}

impl Report {
    /// Only a report with every vector passing is complete.
    pub fn is_complete(&self) -> bool {
        self.failed == 0 && self.skipped == 0
    }
}

/// Execute the embedded reference policy against the supplied vectors.
pub fn run_suite(suite: &VectorSuite) -> Report {
    run(suite, None)
}

/// Compare supported reference results with third-party outputs. Missing IDs
/// and incorrect reference expectations fail; unknown features remain skipped.
/// This runner does not attest that the third party actually executed.
pub fn run_observed_suite(suite: &VectorSuite, observed: &HashMap<String, Value>) -> Report {
    run(suite, Some(observed))
}

fn run(suite: &VectorSuite, observed: Option<&HashMap<String, Value>>) -> Report {
    let mut seen = HashSet::new();
    let mut cases = Vec::with_capacity(suite.vectors.len());
    for vector in &suite.vectors {
        let (status, detail) =
            if suite.version != 1 || vector.id.is_empty() || !seen.insert(&vector.id) {
                (
                    CaseStatus::Fail,
                    "invalid suite version or duplicate/empty vector ID".into(),
                )
            } else {
                match observed {
                    Some(outputs) => match evaluate(vector) {
                        Ok(None) => (
                            CaseStatus::Skip,
                            "reference runner does not implement this feature".into(),
                        ),
                        Err(error) => (CaseStatus::Fail, error),
                        Ok(Some(reference)) if reference != vector.expected => (
                            CaseStatus::Fail,
                            format!("vector expectation disagrees with reference: {reference}"),
                        ),
                        Ok(Some(_)) => match outputs.get(&vector.id) {
                            Some(actual) if *actual == vector.expected => {
                                (CaseStatus::Pass, String::new())
                            }
                            Some(actual) => (
                                CaseStatus::Fail,
                                format!("expected {}, got {actual}", vector.expected),
                            ),
                            None => (
                                CaseStatus::Fail,
                                "implementation did not provide a result".into(),
                            ),
                        },
                    },
                    None => match evaluate(vector) {
                        Ok(Some(actual)) if actual == vector.expected => {
                            (CaseStatus::Pass, String::new())
                        }
                        Ok(Some(actual)) => (
                            CaseStatus::Fail,
                            format!("expected {}, got {actual}", vector.expected),
                        ),
                        Ok(None) => (
                            CaseStatus::Skip,
                            "reference runner does not implement this feature".into(),
                        ),
                        Err(error) => (CaseStatus::Fail, error),
                    },
                }
            };
        cases.push(CaseReport {
            id: vector.id.clone(),
            kind: vector.kind.clone(),
            status,
            detail,
        });
    }
    if cases.is_empty() {
        cases.push(CaseReport {
            id: "suite-metadata".into(),
            kind: "suite".into(),
            status: CaseStatus::Fail,
            detail: "empty suite".into(),
        });
    }
    summarize(cases)
}

/// Count passing, failing, and skipped cases without treating skips as success.
pub fn summarize(cases: Vec<CaseReport>) -> Report {
    Report {
        passed: cases
            .iter()
            .filter(|c| c.status == CaseStatus::Pass)
            .count(),
        failed: cases
            .iter()
            .filter(|c| c.status == CaseStatus::Fail)
            .count(),
        skipped: cases
            .iter()
            .filter(|c| c.status == CaseStatus::Skip)
            .count(),
        cases,
    }
}

fn evaluate(vector: &Vector) -> Result<Option<Value>, String> {
    let result = match vector.kind.as_str() {
        "profile_signature" => {
            let signed: SignedPaymentProfile =
                serde_json::from_value(vector.input.clone()).map_err(|e| e.to_string())?;
            json!({"valid": verify_signed_profile(&signed).unwrap_or(false)})
        }
        "expiry" => {
            let check: ExpiryCheck =
                serde_json::from_value(vector.input.clone()).map_err(|e| e.to_string())?;
            json!({"expired": is_profile_expired_at(&check.profile, check.as_of)})
        }
        "bip353_name" => match satspath_core::parse_bip353_name(
            vector.input.as_str().ok_or("expected name string")?,
        ) {
            Ok(name) => json!({"dns_name": name.dns_name}),
            Err(_) => json!({"error": "invalid"}),
        },
        "bip21" => {
            let check: HandoffCheck =
                serde_json::from_value(vector.input.clone()).map_err(|e| e.to_string())?;
            match satspath_core::parse_bip321(&check.uri).and_then(|parsed| {
                parsed.validate_handoff(
                    check.amount_sats,
                    bitcoin_network(check.network),
                    check.as_of,
                )?;
                for instruction in &parsed.instructions {
                    if let Bip321Instruction::Bolt12Offer { offer } = instruction {
                        if !validate_bolt12_conformance(
                            offer,
                            check.amount_sats,
                            check.network,
                            check.as_of,
                        ) {
                            return Err(satspath_core::SatsPathError::InvalidPaymentUri(
                                "BOLT12 offer network or amount mismatch".into(),
                            ));
                        }
                    }
                }
                // Metadata alone (or a bare URI) is not a payment receiver.
                if !parsed.instructions.iter().any(|instruction| {
                    matches!(
                        instruction,
                        Bip321Instruction::Onchain { .. }
                            | Bip321Instruction::LightningBolt11 { .. }
                            | Bip321Instruction::Bolt12Offer { .. }
                            | Bip321Instruction::SilentPayment { .. }
                    )
                }) {
                    return Err(satspath_core::SatsPathError::InvalidPaymentUri(
                        "wallet URI has no payment instructions".into(),
                    ));
                }
                Ok(parsed)
            }) {
                Ok(parsed) => json!({
                    "address": parsed.address,
                    "amount_btc": parsed.amount_btc,
                    "instructions": parsed.instructions,
                }),
                Err(_) => json!({"error": "invalid"}),
            }
        }
        "capability" => {
            let check: CapabilityCheck =
                serde_json::from_value(vector.input.clone()).map_err(|e| e.to_string())?;
            let validated = satspath_core::handoff::validate_method_for_network_at(
                &check.method,
                check.amount_sats,
                check.network,
                check.as_of,
            )
            .is_ok();
            let bolt12_safe = match &check.method {
                PaymentMethod::Bolt12(offer) => {
                    offer
                        .minimum_amount_sats
                        .is_none_or(|minimum| check.amount_sats >= minimum)
                        && check.as_of >= 0
                        && validate_bolt12_conformance(
                            &offer.offer,
                            check.amount_sats,
                            check.network,
                            check.as_of as u64,
                        )
                }
                PaymentMethod::Lightning {
                    bolt12: Some(offer),
                    ..
                } if ["lno1", "lnot1", "lnob1", "lnos1"]
                    .iter()
                    .any(|prefix| offer.to_ascii_lowercase().starts_with(prefix)) =>
                {
                    check.as_of >= 0
                        && validate_bolt12_conformance(
                            offer,
                            check.amount_sats,
                            check.network,
                            check.as_of as u64,
                        )
                }
                _ => true,
            };
            if validated && bolt12_safe {
                json!({"descriptor": check.method.ownership_descriptor()})
            } else {
                json!({"error": "invalid"})
            }
        }
        "bolt12" => {
            let check: Bolt12Check =
                serde_json::from_value(vector.input.clone()).map_err(|e| e.to_string())?;
            // Offers are Bech32 strings, not URI query fragments or parameters.
            let valid = check.offer.bytes().all(|b| b.is_ascii_alphanumeric())
                && satspath_core::parse_bip321(&format!("bitcoin:?lno={}", check.offer))
                    .and_then(|parsed| {
                        if !matches!(
                            parsed.instructions.as_slice(),
                            [Bip321Instruction::Bolt12Offer { .. }]
                        ) {
                            return Err(satspath_core::SatsPathError::InvalidPaymentUri(
                                "expected a single BOLT12 offer".into(),
                            ));
                        }
                        parsed.validate_handoff(
                            check.amount_sats,
                            bitcoin_network(check.network),
                            check.as_of,
                        )?;
                        validate_bolt12_conformance(
                            &check.offer,
                            check.amount_sats,
                            check.network,
                            check.as_of,
                        )
                        .then_some(())
                        .ok_or_else(|| {
                            satspath_core::SatsPathError::InvalidPaymentUri(
                                "BOLT12 offer network or amount mismatch".into(),
                            )
                        })
                    })
                    .is_ok();
            json!({"valid": valid})
        }
        "rotation" => {
            let rotation: satspath_core::KeyRotation =
                serde_json::from_value(vector.input.clone()).map_err(|e| e.to_string())?;
            json!({"valid": rotation.verify().unwrap_or(false)})
        }
        "resolver_disagreement" => {
            let comparison: ResolverComparison =
                serde_json::from_value(vector.input.clone()).map_err(|e| e.to_string())?;
            let bytes: Vec<_> = comparison
                .profiles
                .iter()
                .map(|profile| {
                    if !verify_signed_profile(profile).unwrap_or(false)
                        || profile.profile.revoked
                        || is_profile_expired_at(&profile.profile, comparison.as_of)
                    {
                        None
                    } else {
                        canonical_profile_bytes(&profile.profile).ok()
                    }
                })
                .collect();
            let agree =
                !bytes.is_empty() && bytes.iter().all(|item| item.is_some() && item == &bytes[0]);
            json!({"decision": if agree { "accept" } else { "reject" }})
        }
        "payment_intent" | "wallet_handoff" => return Ok(None),
        _ => return Ok(None),
    };
    Ok(Some(result))
}

fn bitcoin_network(network: BitcoinNetwork) -> bitcoin::Network {
    match network {
        BitcoinNetwork::Mainnet => bitcoin::Network::Bitcoin,
        BitcoinNetwork::Testnet => bitcoin::Network::Testnet,
        BitcoinNetwork::Signet => bitcoin::Network::Signet,
        BitcoinNetwork::Regtest => bitcoin::Network::Regtest,
    }
}

fn validate_bolt12_conformance(
    offer: &str,
    amount_sats: u64,
    network: BitcoinNetwork,
    as_of: u64,
) -> bool {
    let expected_hrp = satspath_core::bolt12::offer_hrp(network);
    if !offer
        .to_ascii_lowercase()
        .starts_with(&format!("{expected_hrp}1"))
    {
        return false;
    }
    let Some(amount_msats) = amount_sats.checked_mul(1000) else {
        return false;
    };
    let Ok(parsed) = satspath_core::bolt12::parse_bolt12_offer(offer) else {
        return false;
    };
    !parsed.is_expired(as_of) && parsed.is_amount_valid(amount_msats)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tracked_vectors_are_complete() {
        let suite: VectorSuite = serde_json::from_str(include_str!("../vectors/v1.json")).unwrap();
        let report = run_suite(&suite);
        assert!(report.is_complete(), "{report:?}");
        assert_eq!(report.passed, suite.vectors.len());
    }
    #[test]
    fn unknown_and_missing_external_results_never_pass() {
        let suite: VectorSuite = serde_json::from_str(r#"{"version":1,"vectors":[{"id":"wallet","kind":"wallet_handoff","input":{},"expected":{"confirmed":true}}]}"#).unwrap();
        assert_eq!(run_suite(&suite).skipped, 1);
        assert_eq!(run_observed_suite(&suite, &HashMap::new()).skipped, 1);
        let mut actual = HashMap::new();
        actual.insert("wallet".into(), json!({"confirmed":true}));
        assert_eq!(run_observed_suite(&suite, &actual).skipped, 1);
        assert!(!run_observed_suite(&suite, &actual).is_complete());

        let mut known: VectorSuite =
            serde_json::from_str(include_str!("../vectors/v1.json")).unwrap();
        known.vectors.retain(|vector| vector.id == "bip353-name");
        assert_eq!(run_observed_suite(&known, &HashMap::new()).failed, 1);
        let correct =
            HashMap::from([("bip353-name".to_owned(), known.vectors[0].expected.clone())]);
        assert!(run_observed_suite(&known, &correct).is_complete());
        known.vectors[0].expected = json!({"dns_name": "wrong.example"});
        let observed = HashMap::from([(
            "bip353-name".to_owned(),
            json!({"dns_name": "wrong.example"}),
        )]);
        assert_eq!(run_observed_suite(&known, &observed).failed, 1);
    }
    #[test]
    fn resolver_vectors_reject_expired_profiles_at_fixed_time() {
        let mut suite: VectorSuite =
            serde_json::from_str(include_str!("../vectors/v1.json")).unwrap();
        suite.vectors.retain(|v| v.id == "resolver-agreement");
        suite.vectors[0].input["as_of"] = json!(1_800_000_060);
        suite.vectors[0].expected = json!({"decision": "reject"});
        assert!(run_suite(&suite).is_complete());
    }

    #[test]
    fn fixed_time_expiry_uses_core_grace_boundary() {
        let suite: VectorSuite = serde_json::from_str(include_str!("../vectors/v1.json")).unwrap();
        let signed: SignedPaymentProfile =
            serde_json::from_value(suite.vectors[0].input.clone()).unwrap();
        let expiry = signed.profile.expires_at.unwrap();
        assert!(!is_profile_expired_at(&signed.profile, expiry + 59));
        assert!(is_profile_expired_at(&signed.profile, expiry + 60));
        // Signature validity is independent of wall-clock expiry.
        assert!(verify_signed_profile(&signed).unwrap());
    }

    #[test]
    fn expiry_vectors_test_both_sides_of_grace_boundary() {
        let mut suite: VectorSuite =
            serde_json::from_str(include_str!("../vectors/v1.json")).unwrap();
        suite.vectors.retain(|v| v.id.starts_with("expiry-grace-"));
        assert_eq!(suite.vectors.len(), 2);
        assert!(run_suite(&suite).is_complete());

        // An implementation returning the same value on both sides fails comparison.
        let observed = HashMap::from([
            ("expiry-grace-59".to_string(), json!({"expired": false})),
            ("expiry-grace-60".to_string(), json!({"expired": false})),
        ]);
        assert_eq!(run_observed_suite(&suite, &observed).failed, 1);
    }

    #[test]
    fn handoff_and_capability_vectors_fail_if_policy_is_bypassed() {
        let mut suite: VectorSuite =
            serde_json::from_str(include_str!("../vectors/v1.json")).unwrap();
        suite
            .vectors
            .retain(|v| v.id == "bip21-onchain" || v.id == "capability-descriptor");
        assert!(run_suite(&suite).is_complete());

        suite.vectors[0].input["network"] = json!("Testnet");
        suite.vectors[1].input["method"]["address"] = json!("tb1qexample");
        assert_eq!(run_suite(&suite).failed, 2);
    }

    #[test]
    fn observed_handoff_must_bind_exact_receiver_for_every_rail() {
        for (id, field) in [
            ("bip21-onchain", "address"),
            ("bolt11-valid-testnet", "invoice"),
            ("bolt12-valid-mainnet", "offer"),
            ("silent-valid-mainnet", "address"),
        ] {
            let mut case: VectorSuite =
                serde_json::from_str(include_str!("../vectors/v1.json")).unwrap();
            case.vectors.retain(|v| v.id == id);
            assert_eq!(case.vectors.len(), 1);
            assert!(run_suite(&case).is_complete());
            let mut wrong_receiver = case.vectors[0].expected.clone();
            wrong_receiver["instructions"][0][field] = json!("different-receiver");
            let observed = HashMap::from([(id.to_owned(), wrong_receiver)]);
            assert_eq!(run_observed_suite(&case, &observed).failed, 1, "{id}");
        }
    }

    #[test]
    fn duplicate_ids_and_wrong_observations_fail_closed() {
        let suite: VectorSuite = serde_json::from_str(r#"{"version":1,"vectors":[{"id":"a","kind":"bip353_name","input":"alice@example.com","expected":{"dns_name":"alice.user._bitcoin-payment.example.com"}},{"id":"a","kind":"bip353_name","input":"alice@example.com","expected":{"dns_name":"alice.user._bitcoin-payment.example.com"}}]}"#).unwrap();
        assert_eq!(run_suite(&suite).failed, 1);
        let observed = HashMap::from([("a".to_owned(), json!({"dns_name":"wrong"}))]);
        assert_eq!(run_observed_suite(&suite, &observed).failed, 2);
    }
}
