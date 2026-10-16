//! Opt-in interop harness. Only an external sovereign wallet and an independent
//! receiver can produce a PASS; no synthetic wallet receipts are generated.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use satspath_core::execution::{
    ExecutionGatePolicy, OnchainReceipt, PaymentReceipt, WalletExecutor,
};
use satspath_core::resolver::ResolverSource;
use satspath_core::transparency::{CheckpointStore, TransactionalTransparencyStore};
use satspath_core::{BitcoinNetwork, SatsPathError};
use satspath_router::quote_response::{quote_with_resolver, QuoteResponse};
use satspath_router::wallet_executor::{
    execute_quote_handoff, prepare_payment_intent, HandoffExecutionReceipt,
    HandoffTransparencyEvidence, HandoffTrust,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

const DRIVER_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: u64 = 8192;

#[derive(Deserialize)]
struct InteropConfig {
    alias: String,
    amount_sats: u64,
    max_fee_sats: u64,
    network: BitcoinNetwork,
    store_dir: PathBuf,
    pins_dir: PathBuf,
    wallet_driver: PathBuf,
    receiving_wallet_checker: PathBuf,
    witness_quorum: u8,
    witness_pubkeys: Vec<String>,
    observer_pubkeys: Vec<String>,
    transparency: HandoffTransparencyEvidence,
}

struct ExternalWallet {
    network: BitcoinNetwork,
    driver: PathBuf,
}

/// No shell is involved. Wallet credentials remain with the external host
/// process; only public destination, amount, fee cap and receipt cross the
/// SatsPath boundary.
async fn invoke(executable: &Path, payload: &Value) -> satspath_core::Result<Value> {
    invoke_with_timeout(executable, payload, DRIVER_TIMEOUT).await
}

async fn invoke_with_timeout(
    executable: &Path,
    payload: &Value,
    timeout: Duration,
) -> satspath_core::Result<Value> {
    let bytes = serde_json::to_vec(payload)
        .map_err(|e| SatsPathError::SerializationError(e.to_string()))?;
    let mut child = Command::new(executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| SatsPathError::NetworkError(e.to_string()))?;
    let result = tokio::time::timeout(timeout, async {
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin.write_all(&bytes).await?;
        drop(stdin);
        let mut output = Vec::new();
        child
            .stdout
            .take()
            .expect("piped stdout")
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut output)
            .await?;
        if output.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(SatsPathError::NetworkError(
                "external response exceeds 8192 bytes".into(),
            ));
        }
        if !child.wait().await?.success() {
            return Err(SatsPathError::NetworkError(
                "external wallet or receiver rejected the request".into(),
            ));
        }
        serde_json::from_slice(&output).map_err(SatsPathError::from)
    })
    .await;
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(error)
        }
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(SatsPathError::NetworkError(
                "external wallet or receiver timed out".into(),
            ))
        }
    }
}

fn validate_wallet_receipt(
    receipt: OnchainReceipt,
    destination: &str,
    amount_sats: u64,
    max_fee_sats: u64,
) -> satspath_core::Result<OnchainReceipt> {
    if receipt.destination != destination
        || receipt.amount_sats != amount_sats
        || receipt.fee_sats > max_fee_sats
        || receipt.txid.len() != 64
        || hex::decode(&receipt.txid).is_err()
    {
        return Err(SatsPathError::ValidationError(
            "host receipt differs from approved payment".into(),
        ));
    }
    Ok(receipt)
}

#[async_trait]
impl WalletExecutor for ExternalWallet {
    fn network(&self) -> BitcoinNetwork {
        self.network
    }

    async fn pay_bolt11(&self, _: &str, _: Option<u64>) -> satspath_core::Result<PaymentReceipt> {
        Err(SatsPathError::ValidationError(
            "Lightning driver is not configured".into(),
        ))
    }

    async fn send_onchain(
        &self,
        _: &str,
        _: u64,
        _: Option<u64>,
    ) -> satspath_core::Result<OnchainReceipt> {
        Err(SatsPathError::ValidationError(
            "unbounded wallet handoff disabled".into(),
        ))
    }

    async fn sign_and_broadcast_psbt(&self, _: &str) -> satspath_core::Result<String> {
        Err(SatsPathError::ValidationError(
            "direct PSBT signing disabled".into(),
        ))
    }

    async fn send_onchain_with_max_fee(
        &self,
        destination: &str,
        amount_sats: u64,
        max_fee_sats: u64,
    ) -> satspath_core::Result<OnchainReceipt> {
        let value = invoke(
            &self.driver,
            &json!({
                "action": "send_onchain", "network": self.network,
                "destination": destination, "amount_sats": amount_sats,
                "max_fee_sats": max_fee_sats,
            }),
        )
        .await?;
        let receipt: OnchainReceipt = serde_json::from_value(value)?;
        validate_wallet_receipt(receipt, destination, amount_sats, max_fee_sats)
    }
}

#[derive(Deserialize)]
struct ReceiverConfirmation {
    txid: String,
    destination: String,
    amount_sats: u64,
    confirmations: u32,
}

fn validate_receiver_confirmation(
    confirmed: &ReceiverConfirmation,
    receipt: &OnchainReceipt,
) -> satspath_core::Result<()> {
    if confirmed.txid != receipt.txid
        || confirmed.destination != receipt.destination
        || confirmed.amount_sats != receipt.amount_sats
        || confirmed.confirmations == 0
    {
        return Err(SatsPathError::ValidationError(
            "independent receiver did not confirm payment".into(),
        ));
    }
    Ok(())
}

/// Run only with a real HTTPS profile, persisted transparency state and two
/// independently configured wallet executables. Missing evidence is an error.
#[tokio::test]
#[ignore = "requires real regtest/testnet wallet and independent receiver"]
async fn https_onchain_wallet_receiver_confirms_payment() {
    let path = std::env::var("SATSPATH_INTEROP_CONFIG")
        .expect("set SATSPATH_INTEROP_CONFIG to an external JSON configuration file");
    let config: InteropConfig = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert!(
        matches!(
            config.network,
            BitcoinNetwork::Testnet | BitcoinNetwork::Regtest
        ),
        "mainnet is not an automated test network"
    );
    assert!(config.witness_quorum > 0 && !config.observer_pubkeys.is_empty());
    let store = TransactionalTransparencyStore::open(&config.store_dir).unwrap();
    let trust = HandoffTrust {
        checkpoints: Mutex::new(CheckpointStore::new(&config.pins_dir)),
        witness_quorum: config.witness_quorum,
        witness_pubkeys: config.witness_pubkeys,
        observer_pubkeys: config.observer_pubkeys,
    };
    let resolver = satspath_core::HttpResolver::new();
    let quote = quote_with_resolver(&resolver, &config.alias, config.amount_sats).await;
    assert!(
        matches!(
            &quote,
            QuoteResponse::Ok {
                selected_method: satspath_core::PaymentMethod::Onchain { .. },
                ..
            }
        ),
        "HTTPS must resolve to a verified, payable on-chain route"
    );
    let wallet = ExternalWallet {
        network: config.network,
        driver: config.wallet_driver,
    };
    let intent = prepare_payment_intent(
        &store,
        &trust,
        &config.transparency,
        &quote,
        config.network,
        config.amount_sats,
        config.max_fee_sats,
        vec![ResolverSource::Http],
    )
    .expect("identity, capability and transparency must verify before approval");
    assert!(intent.verification_status.profile_signature_verified);
    let approved = intent
        .approve(true)
        .expect("host explicitly approves public intent");
    let receipt = execute_quote_handoff(
        &wallet,
        &store,
        &trust,
        &config.transparency,
        &quote,
        approved,
        &ExecutionGatePolicy::testnet_default(),
    )
    .await
    .expect("real host wallet must return a bounded receipt");
    let HandoffExecutionReceipt::Onchain(receipt) = receipt else {
        panic!("expected an on-chain receipt")
    };
    let checked = invoke(
        &config.receiving_wallet_checker,
        &json!({
            "action": "confirm_receive", "network": config.network,
            "txid": receipt.txid, "destination": receipt.destination,
            "amount_sats": receipt.amount_sats,
        }),
    )
    .await
    .expect("independent receiving wallet must be reachable");
    let confirmed: ReceiverConfirmation = serde_json::from_value(checked).unwrap();
    validate_receiver_confirmation(&confirmed, &receipt)
        .expect("broadcast is not receiver confirmation");
}

#[test]
fn invalid_host_receipts_fail_closed() {
    let valid = OnchainReceipt {
        txid: "ab".repeat(32),
        destination: "bcrt1qreceiver".into(),
        amount_sats: 10_000,
        fee_sats: 100,
        timestamp: 1,
    };
    assert!(validate_wallet_receipt(valid.clone(), &valid.destination, 10_000, 100).is_ok());
    let mut wrong_destination = valid.clone();
    wrong_destination.destination = "bcrt1qattacker".into();
    let mut wrong_amount = valid.clone();
    wrong_amount.amount_sats += 1;
    let mut excessive_fee = valid.clone();
    excessive_fee.fee_sats += 1;
    let mut invalid_txid = valid.clone();
    invalid_txid.txid = "not-a-txid".into();
    for receipt in [wrong_destination, wrong_amount, excessive_fee, invalid_txid] {
        assert!(validate_wallet_receipt(receipt, &valid.destination, 10_000, 100).is_err());
    }
}

#[test]
fn receiver_must_confirm_exact_payment() {
    let receipt = OnchainReceipt {
        txid: "ab".repeat(32),
        destination: "bcrt1qreceiver".into(),
        amount_sats: 10_000,
        fee_sats: 100,
        timestamp: 1,
    };
    let mut confirmed = ReceiverConfirmation {
        txid: receipt.txid.clone(),
        destination: receipt.destination.clone(),
        amount_sats: receipt.amount_sats,
        confirmations: 1,
    };
    assert!(validate_receiver_confirmation(&confirmed, &receipt).is_ok());
    confirmed.confirmations = 0;
    assert!(validate_receiver_confirmation(&confirmed, &receipt).is_err());
    confirmed.confirmations = 1;
    confirmed.txid = "cd".repeat(32);
    assert!(validate_receiver_confirmation(&confirmed, &receipt).is_err());
    confirmed.txid = receipt.txid.clone();
    confirmed.destination = "bcrt1qattacker".into();
    assert!(validate_receiver_confirmation(&confirmed, &receipt).is_err());
    confirmed.destination = receipt.destination.clone();
    confirmed.amount_sats += 1;
    assert!(validate_receiver_confirmation(&confirmed, &receipt).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn external_driver_timeout_and_output_limit() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("driver");
    std::fs::write(&script, "#!/bin/sh\nwhile :; do :; done\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let error = invoke_with_timeout(&script, &json!({}), Duration::from_millis(50))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("timed out"), "{error}");
    std::fs::write(&script, "#!/bin/sh\nyes x | head -c 9000\n").unwrap();
    let error = invoke_with_timeout(&script, &json!({}), Duration::from_secs(2))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("exceeds 8192 bytes"), "{error}");
}
