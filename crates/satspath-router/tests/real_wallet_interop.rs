//! Opt-in interop harness. Only an external sovereign wallet and an independent
//! receiver can produce a PASS; no synthetic wallet receipts are generated.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

use async_trait::async_trait;
use satspath_core::execution::{ExecutionGatePolicy, OnchainReceipt, PaymentReceipt, WalletExecutor};
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
fn invoke(executable: &Path, payload: &Value) -> satspath_core::Result<Value> {
    let bytes = serde_json::to_vec(payload)
        .map_err(|e| SatsPathError::SerializationError(e.to_string()))?;
    let mut child = Command::new(executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| SatsPathError::NetworkError(e.to_string()))?;
    child.stdin.take().expect("piped stdin").write_all(&bytes)?;
    let output = child.wait_with_output()?;
    if !output.status.success() || output.stdout.len() > 8192 {
        return Err(SatsPathError::NetworkError("external wallet or receiver rejected the request".into()));
    }
    serde_json::from_slice(&output.stdout).map_err(SatsPathError::from)
}

#[async_trait]
impl WalletExecutor for ExternalWallet {
    fn network(&self) -> BitcoinNetwork { self.network }

    async fn pay_bolt11(&self, _: &str, _: Option<u64>) -> satspath_core::Result<PaymentReceipt> {
        Err(SatsPathError::ValidationError("Lightning driver is not configured".into()))
    }

    async fn send_onchain(&self, _: &str, _: u64, _: Option<u64>) -> satspath_core::Result<OnchainReceipt> {
        Err(SatsPathError::ValidationError("unbounded wallet handoff disabled".into()))
    }

    async fn sign_and_broadcast_psbt(&self, _: &str) -> satspath_core::Result<String> {
        Err(SatsPathError::ValidationError("direct PSBT signing disabled".into()))
    }

    async fn send_onchain_with_max_fee(
        &self, destination: &str, amount_sats: u64, max_fee_sats: u64,
    ) -> satspath_core::Result<OnchainReceipt> {
        let value = invoke(&self.driver, &json!({
            "action": "send_onchain", "network": self.network,
            "destination": destination, "amount_sats": amount_sats,
            "max_fee_sats": max_fee_sats,
        }))?;
        let receipt: OnchainReceipt = serde_json::from_value(value)?;
        if receipt.destination != destination || receipt.amount_sats != amount_sats
            || receipt.fee_sats > max_fee_sats || receipt.txid.len() != 64
            || hex::decode(&receipt.txid).is_err()
        {
            return Err(SatsPathError::ValidationError("host receipt differs from approved payment".into()));
        }
        Ok(receipt)
    }
}

#[derive(Deserialize)]
struct ReceiverConfirmation {
    txid: String,
    destination: String,
    amount_sats: u64,
    confirmations: u32,
}

/// Run only with a real HTTPS profile, persisted transparency state and two
/// independently configured wallet executables. Missing evidence is an error.
#[tokio::test]
#[ignore = "requires real regtest/testnet wallet and independent receiver"]
async fn https_onchain_wallet_receiver_confirms_payment() {
    let path = std::env::var("SATSPATH_INTEROP_CONFIG")
        .expect("set SATSPATH_INTEROP_CONFIG to an external JSON configuration file");
    let config: InteropConfig = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert!(matches!(config.network, BitcoinNetwork::Testnet | BitcoinNetwork::Regtest), "mainnet is not an automated test network");
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
    assert!(matches!(&quote, QuoteResponse::Ok { selected_method: satspath_core::PaymentMethod::Onchain { .. }, .. }), "HTTPS must resolve to a verified, payable on-chain route");
    let wallet = ExternalWallet { network: config.network, driver: config.wallet_driver };
    let intent = prepare_payment_intent(
        &store, &trust, &config.transparency, &quote, config.network,
        config.amount_sats, config.max_fee_sats, vec![ResolverSource::Http],
    ).expect("identity, capability and transparency must verify before approval");
    assert!(intent.verification_status.profile_signature_verified);
    let approved = intent.approve(true).expect("host explicitly approves public intent");
    let receipt = execute_quote_handoff(
        &wallet, &store, &trust, &config.transparency, &quote, approved,
        &ExecutionGatePolicy::testnet_default(),
    ).await.expect("real host wallet must return a bounded receipt");
    let HandoffExecutionReceipt::Onchain(receipt) = receipt else { panic!("expected an on-chain receipt") };
    let checked = invoke(&config.receiving_wallet_checker, &json!({
        "action": "confirm_receive", "network": config.network,
        "txid": receipt.txid, "destination": receipt.destination,
        "amount_sats": receipt.amount_sats,
    })).expect("independent receiving wallet must be reachable");
    let confirmed: ReceiverConfirmation = serde_json::from_value(checked).unwrap();
    assert_eq!(confirmed.txid, receipt.txid);
    assert_eq!(confirmed.destination, receipt.destination);
    assert_eq!(confirmed.amount_sats, receipt.amount_sats);
    assert!(confirmed.confirmations > 0, "broadcast is not receiver confirmation");
}
