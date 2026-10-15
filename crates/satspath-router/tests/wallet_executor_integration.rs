//! End-to-end integration tests for the standardized `WalletExecutor` SDK interface and
//! non-custodial host wallet bridges (BDK on-chain, LDK Lightning, and Boltz Testnet Swaps)
//! per Issue #156.

use std::str::FromStr;

use anyhow::Result;
use async_trait::async_trait;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::Address;
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use satspath_core::crypto::{generate_identity_keypair, sign_profile};
use satspath_core::execution::{
    ExecutionGatePolicy, OnchainReceipt, PaymentReceipt, WalletExecutor,
};
use satspath_core::pointer::BitcoinNetwork;
use satspath_core::profile::{PaymentMethod, PaymentProfile};
use satspath_core::resolver::ProfileResolver;
use satspath_core::transparency::{
    profile_hash, NameAction, NameEvent, TransactionalTransparencyStore,
};
use satspath_core::{IdentityKeypair, SignedPaymentProfile};
use satspath_router::quote_response::{
    build_qr_payload, quote_with_resolver, QuoteRecipient, QuoteResponse,
};
use satspath_router::wallet_executor::{
    execute_quote_handoff, BdkHostWallet, BdkOnchainBridge, BdkUtxoDescriptor,
    BoltzHostSignerBroadcaster, BoltzTestnetSwapBridge, HandoffExecutionReceipt,
    HostWalletSdkBridge, LdkHostNode, LdkLightningBridge,
};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

// ─── Simulated Sovereign BDK Host Wallet ────────────────────────────────────────

struct SimulatedBdkWallet {
    change_address: String,
    utxo: BdkUtxoDescriptor,
}

impl SimulatedBdkWallet {
    /// Supply one public Testnet UTXO and a change address.
    fn new_testnet() -> Self {
        let addr_str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        let addr = Address::from_str(addr_str).unwrap().assume_checked();
        Self {
            change_address: addr_str.to_string(),
            utxo: BdkUtxoDescriptor {
                txid: "11".repeat(32),
                vout: 0,
                amount_sats: 500_000,
                script_pubkey_hex: hex::encode(addr.script_pubkey().as_bytes()),
            },
        }
    }
}

#[async_trait]
impl BdkHostWallet for SimulatedBdkWallet {
    /// Return the fixed public funding UTXO.
    async fn select_utxos_and_change(
        &self,
        _target_sats: u64,
        _fee_rate_sat_vb: u64,
    ) -> Result<(Vec<BdkUtxoDescriptor>, String)> {
        Ok((vec![self.utxo.clone()], self.change_address.clone()))
    }

    /// Inspect the unsigned PSBT and return a synthetic transaction ID for this test.
    async fn sign_and_broadcast_psbt(&self, unsigned_psbt_hex: &str) -> Result<String> {
        // Verify valid PSBT deserialization and witness_utxo presence
        let psbt_bytes = hex::decode(unsigned_psbt_hex)?;
        let psbt = Psbt::deserialize(&psbt_bytes)?;
        assert_eq!(psbt.inputs.len(), 1);
        assert!(psbt.inputs[0].witness_utxo.is_some());
        assert!(!psbt.unsigned_tx.output.is_empty());

        let txid = psbt.unsigned_tx.compute_txid().to_string();
        Ok(txid)
    }
}

// ─── Simulated Sovereign LDK Host Node ──────────────────────────────────────────

struct SimulatedLdkNode;

#[async_trait]
impl LdkHostNode for SimulatedLdkNode {
    /// Return a synthetic payment receipt after host dispatch.
    async fn send_bolt11_payment(
        &self,
        bolt11_invoice: &str,
        expected_amount_msats: u64,
        max_fee_msats: u64,
    ) -> Result<PaymentReceipt> {
        assert!(max_fee_msats >= 1_000);
        let payment_hash = hex::encode(Sha256::digest(bolt11_invoice.as_bytes()));
        let preimage = hex::encode(Sha256::digest(payment_hash.as_bytes()));
        Ok(PaymentReceipt {
            payment_hash,
            preimage: Some(preimage),
            amount_msats: expected_amount_msats,
            fee_msats: 250,
            timestamp: 1_700_000_000,
        })
    }
}

// ─── Simulated Sovereign Boltz Swap Signer & Broadcaster ────────────────────────

struct RejectBoltzHostCalls;

#[async_trait]
impl BoltzHostSignerBroadcaster for RejectBoltzHostCalls {
    /// Fail the test if disabled swap execution ever requests a signature.
    async fn sign_swap_digest(&self, _swap_id: &str, _sighash: [u8; 32]) -> Result<Vec<u8>> {
        panic!("disabled swap execution must never sign");
    }

    /// Fail the test if disabled swap execution ever requests a broadcast.
    async fn broadcast_swap_tx(&self, _raw_tx_hex: &str) -> Result<String> {
        panic!("disabled swap execution must never broadcast");
    }
}

// ─── Mock Profile Resolver ──────────────────────────────────────────────────────

struct StaticProfileResolver {
    signed: SignedPaymentProfile,
}

#[async_trait]
impl ProfileResolver for StaticProfileResolver {
    /// Resolve only the fixture alias.
    async fn resolve_alias(&self, alias: &str) -> satspath_core::Result<SignedPaymentProfile> {
        if alias == self.signed.profile.alias {
            Ok(self.signed.clone())
        } else {
            Err(satspath_core::SatsPathError::AliasNotFound(alias.into()))
        }
    }
}

/// Build a valid signed Testnet BOLT11 invoice for `amount_sats`.
fn make_testnet_bolt11(amount_sats: u64) -> String {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x33; 32]).unwrap();
    let payment_hash = sha256::Hash::from_slice(&[0x55; 32]).unwrap();
    let payment_secret = PaymentSecret([0x77; 32]);

    let invoice = InvoiceBuilder::new(Currency::BitcoinTestnet)
        .description("Testnet Coffee".into())
        .payment_hash(payment_hash)
        .payment_secret(payment_secret)
        .amount_milli_satoshis(amount_sats * 1_000)
        .current_timestamp()
        .min_final_cltv_expiry_delta(144)
        .build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &sk))
        .unwrap();
    invoice.to_string()
}

/// Resolve a quote and execute its current, transparency-bound on-chain method.
#[tokio::test]
async fn test_end_to_end_alias_resolution_to_bdk_onchain_execution() {
    let kp = generate_identity_keypair();
    let recipient_addr = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn";
    let profile = PaymentProfile {
        alias: "merchant@satspath.dev".to_string(),
        identity_pubkey: hex::encode(kp.public_key.serialize()),
        methods: vec![PaymentMethod::Onchain {
            label: "Testnet Vault".into(),
            network: BitcoinNetwork::Testnet,
            address: Some(recipient_addr.to_string()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: Vec::new(),
        }],
        updated_at: 1_700_000_000,
        expires_at: None,
        sequence: Some(0),
        preferences: Vec::new(),
        nonce: None,
        rotation: None,
        method_verifications: Vec::new(),
        hybrid_pubkey: None,
        pqc_required: false,
        revoked: false,
        recovery_policy: None,
        recovery: None,
    };
    let signed = sign_profile(profile, &kp.secret_key).unwrap();
    let home = tempfile::tempdir().unwrap();
    let store = TransactionalTransparencyStore::open(home.path()).unwrap();
    commit_profile(&store, &signed, &kp, NameAction::Register);
    let resolver = StaticProfileResolver { signed };

    // 1. Resolve alias and generate QuoteResponse handoff
    let quote_resp = quote_with_resolver(&resolver, "merchant@satspath.dev", 120_000).await;

    // 2. Execute handoff via HostWalletSdkBridge (BDK + LDK)
    let bdk = BdkOnchainBridge::new(
        BitcoinNetwork::Testnet,
        5,
        100,
        SimulatedBdkWallet::new_testnet(),
    );
    let ldk = LdkLightningBridge::new(BitcoinNetwork::Testnet, 100, SimulatedLdkNode);
    let sdk_bridge = HostWalletSdkBridge::new(BitcoinNetwork::Testnet, bdk, ldk);

    let receipt = execute_quote_handoff(
        &sdk_bridge,
        &store,
        &quote_resp,
        120_000,
        &ExecutionGatePolicy::testnet_default(),
        true,
    )
    .await
    .expect("BDK on-chain execution must succeed");

    match receipt {
        HandoffExecutionReceipt::Onchain(onchain) => {
            assert_eq!(onchain.amount_sats, 120_000);
            assert_eq!(onchain.destination, recipient_addr);
            assert_eq!(onchain.txid.len(), 64);
            assert_eq!(onchain.fee_sats, 5 * 141);
        }
        other => panic!("expected Onchain receipt, got {other:?}"),
    }
}

/// Validate the exact invoice amount before LDK host dispatch.
#[tokio::test]
async fn test_ldk_lightning_bridge_validates_and_executes_bolt11() {
    let invoice_str = make_testnet_bolt11(25_000);
    let bdk = BdkOnchainBridge::new(
        BitcoinNetwork::Testnet,
        5,
        100,
        SimulatedBdkWallet::new_testnet(),
    );
    let ldk = LdkLightningBridge::new(BitcoinNetwork::Testnet, 100, SimulatedLdkNode);
    let sdk_bridge = HostWalletSdkBridge::new(BitcoinNetwork::Testnet, bdk, ldk);

    // 1. Exact amount match succeeds
    let receipt = sdk_bridge
        .ldk()
        .validate_and_pay_bolt11(&invoice_str, 25_000)
        .await
        .expect("valid testnet BOLT11 must execute");
    assert_eq!(receipt.amount_msats, 25_000_000);
    assert!(receipt.preimage.is_some());

    // 2. Amount mismatch is rejected before calling host LDK node
    let err_amt = sdk_bridge
        .ldk()
        .validate_and_pay_bolt11(&invoice_str, 30_000)
        .await
        .unwrap_err();
    assert!(err_amt.to_string().contains("BOLT11 validation failed"));
}

/// Reject claims and refunds on every network without signing or broadcasting.
#[tokio::test]
async fn boltz_claims_and_refunds_fail_closed_on_every_network() {
    let preimage = [0x99; 32];
    let mut formerly_accepted_script = vec![0x82, 0x01, 0x20, 0x87, 0x63, 0xa8, 0x20];
    formerly_accepted_script.extend_from_slice(&Sha256::digest(preimage));
    formerly_accepted_script.push(0x88);
    for network in [
        BitcoinNetwork::Mainnet,
        BitcoinNetwork::Testnet,
        BitcoinNetwork::Regtest,
    ] {
        let bridge = BoltzTestnetSwapBridge::new(network, RejectBoltzHostCalls);
        for script in [
            hex::encode(&formerly_accepted_script),
            "51".into(),
            "5120".to_owned() + &"11".repeat(32),
            String::new(),
        ] {
            let claim = bridge
                .execute_reverse_claim(
                    "reverse",
                    &"22".repeat(32),
                    0,
                    50_000,
                    &hex::encode(preimage),
                    &script,
                    "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
                    500,
                )
                .await
                .unwrap_err();
            assert!(claim.to_string().contains("execution is disabled"));
            for height in [799_999, 800_000, 800_001] {
                let refund = bridge
                    .execute_submarine_refund(
                        "refund",
                        &"22".repeat(32),
                        0,
                        50_000,
                        800_000,
                        height,
                        &script,
                        "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
                        500,
                    )
                    .await
                    .unwrap_err();
                assert!(refund.to_string().contains("execution is disabled"));
            }
        }
    }
}

/// Build signed invoices, including expired or amountless adversarial fixtures.
fn make_invoice(currency: Currency, amount_msats: Option<u64>, expired: bool) -> String {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x33; 32]).unwrap();
    let builder = InvoiceBuilder::new(currency)
        .description("wallet handoff regression".into())
        .payment_hash(sha256::Hash::hash(&[0x55; 32]))
        .payment_secret(PaymentSecret([0x77; 32]))
        .min_final_cltv_expiry_delta(144);
    let builder = match amount_msats {
        Some(amount) => builder.amount_milli_satoshis(amount),
        None => builder,
    };
    let builder = if expired {
        builder
            .timestamp(SystemTime::now() - Duration::from_secs(3600))
            .expiry_time(Duration::from_secs(1))
    } else {
        builder.current_timestamp()
    };
    builder
        .build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &sk))
        .unwrap()
        .to_string()
}

/// Commit a real signed event and checkpoint for the supplied test profile.
fn commit_profile(
    store: &TransactionalTransparencyStore,
    signed: &SignedPaymentProfile,
    identity: &IdentityKeypair,
    action: NameAction,
) {
    let log = store.load_log().unwrap();
    let identifier = satspath_core::identifier_hash(&signed.profile.alias);
    let previous = log
        .history(&identifier)
        .last()
        .map(|event| event.event_hash().unwrap());
    let mut event = NameEvent {
        version: 1,
        identifier_hash: identifier,
        action,
        identity_pubkey: signed.profile.identity_pubkey.clone(),
        profile_hash: profile_hash(signed).unwrap(),
        sequence: signed.profile.sequence.unwrap(),
        previous_event_hash: previous,
        created_at: chrono::Utc::now().timestamp(),
        identifier_attestation_hash: None,
        removed_method_hashes: vec![],
        rotation: signed.profile.rotation.clone(),
        recovery_policy: signed.profile.recovery_policy.clone(),
        recovery: signed.profile.recovery.clone(),
        owner_signature: String::new(),
    };
    event.sign(&identity.secret_key).unwrap();
    let operator = SecretKey::from_slice(&[0x66; 32]).unwrap();
    let checkpoint = log
        .prepare_append(event.clone(), signed)
        .unwrap()
        .prepare_checkpoint(&operator)
        .unwrap();
    store
        .commit_profile_event_checkpoint(&signed.profile.alias, signed, &event, &checkpoint)
        .unwrap();
}

/// Create a signed profile binding an invoice and the Lightning node's public key.
fn signed_lightning_profile(identity: &IdentityKeypair, invoice: &str) -> SignedPaymentProfile {
    let payee = lightning_invoice::Bolt11Invoice::from_str(invoice)
        .unwrap()
        .recover_payee_pub_key()
        .to_string();
    sign_profile(
        PaymentProfile {
            alias: "merchant@satspath.dev".into(),
            identity_pubkey: hex::encode(identity.public_key.serialize()),
            methods: vec![PaymentMethod::Lightning {
                label: "Test node".into(),
                lightning_address: Some(invoice.into()),
                lnurl: None,
                bolt12: None,
                receiver_pubkey: Some(payee),
            }],
            updated_at: chrono::Utc::now().timestamp(),
            expires_at: None,
            sequence: Some(0),
            preferences: vec![],
            nonce: None,
            rotation: None,
            method_verifications: vec![],
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
            recovery_policy: None,
            recovery: None,
        },
        &identity.secret_key,
    )
    .unwrap()
}

/// Build the public handoff representation for an authenticated fixture profile.
fn quote_for(signed: &SignedPaymentProfile, amount_sats: u64) -> QuoteResponse {
    let method = signed.profile.methods[0].clone();
    QuoteResponse::Ok {
        recipient: QuoteRecipient {
            alias: signed.profile.alias.clone(),
            verified: true,
            profile_signature_verified: true,
            identifier_verified: false,
            identifier_verification: "test".into(),
            fingerprint: Some(
                satspath_core::crypto::fingerprint_pubkey(&signed.profile.identity_pubkey).unwrap(),
            ),
        },
        qr: build_qr_payload(&method, amount_sats).unwrap(),
        selected_method: method,
        fee_sats: None,
        eta: None,
        reason: "fixture".into(),
        execution: None,
        wallet_hint: None,
    }
}

/// Deliberately permissive executor used to prove the dispatcher validates first.
struct CountingExecutor {
    network: BitcoinNetwork,
    calls: AtomicUsize,
}

#[async_trait]
impl WalletExecutor for CountingExecutor {
    /// Return the network under test.
    fn network(&self) -> BitcoinNetwork {
        self.network
    }

    /// Accept any invoice to detect dispatcher validation bypasses.
    async fn pay_bolt11(
        &self,
        _invoice: &str,
        amount_msats: Option<u64>,
    ) -> satspath_core::Result<PaymentReceipt> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(PaymentReceipt {
            payment_hash: "11".repeat(32),
            preimage: None,
            amount_msats: amount_msats.unwrap_or(0),
            fee_msats: 0,
            timestamp: 0,
        })
    }

    /// Count an on-chain dispatch without touching a network.
    async fn send_onchain(
        &self,
        destination: &str,
        amount_sats: u64,
        _fee_rate: Option<u64>,
    ) -> satspath_core::Result<OnchainReceipt> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(OnchainReceipt {
            txid: "11".repeat(32),
            amount_sats,
            fee_sats: 0,
            destination: destination.into(),
            timestamp: 0,
        })
    }

    /// Reject unexpected PSBT calls from dispatcher tests.
    async fn sign_and_broadcast_psbt(&self, _psbt: &str) -> satspath_core::Result<String> {
        panic!("unexpected PSBT dispatch")
    }
}

/// Accept exactly the matching BOLT11 network and reject all other currencies at both boundaries.
#[tokio::test]
async fn bolt11_networks_are_exact_in_bridge_and_dispatcher() {
    for (network, currency) in [
        (BitcoinNetwork::Mainnet, Currency::Bitcoin),
        (BitcoinNetwork::Testnet, Currency::BitcoinTestnet),
        (BitcoinNetwork::Regtest, Currency::Regtest),
    ] {
        for invoice_currency in [
            Currency::Bitcoin,
            Currency::BitcoinTestnet,
            Currency::Regtest,
            Currency::Signet,
            Currency::Simnet,
        ] {
            let invoice = make_invoice(invoice_currency.clone(), Some(1_000), false);
            let bridge = LdkLightningBridge::new(network, 100, SimulatedLdkNode);
            let should_pass = currency == invoice_currency;
            assert_eq!(
                bridge.validate_and_pay_bolt11(&invoice, 1).await.is_ok(),
                should_pass
            );
            let identity = generate_identity_keypair();
            let signed = signed_lightning_profile(&identity, &invoice);
            let home = tempfile::tempdir().unwrap();
            let store = TransactionalTransparencyStore::open(home.path()).unwrap();
            commit_profile(&store, &signed, &identity, NameAction::Register);
            let executor = CountingExecutor {
                network,
                calls: AtomicUsize::new(0),
            };
            let result = execute_quote_handoff(
                &executor,
                &store,
                &quote_for(&signed, 1),
                1,
                &ExecutionGatePolicy::mainnet_guarded(1, true),
                true,
            )
            .await;
            assert_eq!(
                result.is_ok(),
                should_pass,
                "{network:?} / {invoice_currency:?}: {result:?}"
            );
            assert_eq!(
                executor.calls.load(Ordering::SeqCst),
                usize::from(should_pass)
            );
        }
    }
}

/// Reject malformed, expired, amountless, fractional, zero and overflowing invoices before execution.
#[tokio::test]
async fn dispatcher_and_bridge_reject_invalid_bolt11_amounts_and_payloads() {
    let good = make_testnet_bolt11(1);
    let identity = generate_identity_keypair();
    let signed = signed_lightning_profile(&identity, &good);
    let home = tempfile::tempdir().unwrap();
    let store = TransactionalTransparencyStore::open(home.path()).unwrap();
    commit_profile(&store, &signed, &identity, NameAction::Register);
    let executor = CountingExecutor {
        network: BitcoinNetwork::Testnet,
        calls: AtomicUsize::new(0),
    };
    let bridge = LdkLightningBridge::new(BitcoinNetwork::Testnet, 100, SimulatedLdkNode);
    let cases = [
        (invoice_with_invalid_signature(), 1),
        ("lntb1garbage".into(), 1),
        (make_invoice(Currency::BitcoinTestnet, Some(1_000), true), 1),
        (make_invoice(Currency::BitcoinTestnet, None, false), 1),
        (
            make_invoice(Currency::BitcoinTestnet, Some(1_001), false),
            1,
        ),
        (good.clone(), 2),
        (good.clone(), 0),
        (good, u64::MAX),
    ];
    for (invoice, amount) in cases {
        assert!(bridge
            .validate_and_pay_bolt11(&invoice, amount)
            .await
            .is_err());
        let mut quote = quote_for(&signed, amount);
        if let QuoteResponse::Ok { qr, .. } = &mut quote {
            *qr = invoice;
        }
        assert!(execute_quote_handoff(
            &executor,
            &store,
            &quote,
            amount,
            &ExecutionGatePolicy::testnet_default(),
            true
        )
        .await
        .is_err());
    }
    for scheme in [
        "lno1unsupported",
        "ark:unsupported",
        "sp1unsupported",
        "bitcoin:sp1unsupported",
    ] {
        let mut quote = quote_for(&signed, 1);
        if let QuoteResponse::Ok { qr, .. } = &mut quote {
            *qr = scheme.into();
        }
        assert!(execute_quote_handoff(
            &executor,
            &store,
            &quote,
            1,
            &ExecutionGatePolicy::testnet_default(),
            true
        )
        .await
        .is_err());
    }
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
}

/// Reject exact-msat inputs that would otherwise be truncated by the SDK adapter.
#[tokio::test]
async fn sdk_bridge_rejects_fractional_satoshis() {
    let sdk = HostWalletSdkBridge::new(
        BitcoinNetwork::Testnet,
        BdkOnchainBridge::new(
            BitcoinNetwork::Testnet,
            5,
            100,
            SimulatedBdkWallet::new_testnet(),
        ),
        LdkLightningBridge::new(BitcoinNetwork::Testnet, 100, SimulatedLdkNode),
    );
    let invoice = make_testnet_bolt11(1);
    for amount in [Some(1_001), Some(999), Some(0), None] {
        assert!(sdk.pay_bolt11(&invoice, amount).await.is_err());
    }
    assert_eq!(
        sdk.pay_bolt11(&invoice, Some(1_000))
            .await
            .unwrap()
            .amount_msats,
        1_000
    );
}

/// Reload state after quote creation and reject both revocations and replaced payment methods.
#[tokio::test]
async fn handoff_rejects_quotes_after_revocation_or_profile_update() {
    for action in [NameAction::Revoke, NameAction::UpdateProfile] {
        let invoice = make_testnet_bolt11(1_000);
        let identity = generate_identity_keypair();
        let signed = signed_lightning_profile(&identity, &invoice);
        let home = tempfile::tempdir().unwrap();
        let store = TransactionalTransparencyStore::open(home.path()).unwrap();
        commit_profile(&store, &signed, &identity, NameAction::Register);
        let resolver = StaticProfileResolver {
            signed: signed.clone(),
        };
        let quote = quote_with_resolver(&resolver, &signed.profile.alias, 1_000).await;
        assert!(matches!(quote, QuoteResponse::Ok { .. }));
        let executor = CountingExecutor {
            network: BitcoinNetwork::Testnet,
            calls: AtomicUsize::new(0),
        };
        assert!(execute_quote_handoff(
            &executor,
            &store,
            &quote,
            1_000,
            &ExecutionGatePolicy::testnet_default(),
            true
        )
        .await
        .is_ok());
        executor.calls.store(0, Ordering::SeqCst);
        let mut updated = signed.profile.clone();
        updated.sequence = Some(1);
        if action == NameAction::Revoke {
            updated.revoked = true;
        } else {
            updated.methods.clear();
        }
        let updated = sign_profile(updated, &identity.secret_key).unwrap();
        commit_profile(&store, &updated, &identity, action);
        assert!(execute_quote_handoff(
            &executor,
            &store,
            &quote,
            1_000,
            &ExecutionGatePolicy::testnet_default(),
            true
        )
        .await
        .is_err());
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    }
}

/// A serialized signature flag and fingerprint cannot authorize a missing profile or changed payload.
#[tokio::test]
async fn handoff_rejects_missing_current_state_and_unbound_destinations() {
    let invoice = make_testnet_bolt11(1);
    let identity = generate_identity_keypair();
    let signed = signed_lightning_profile(&identity, &invoice);
    let home = tempfile::tempdir().unwrap();
    let store = TransactionalTransparencyStore::open(home.path()).unwrap();
    let executor = CountingExecutor {
        network: BitcoinNetwork::Testnet,
        calls: AtomicUsize::new(0),
    };
    let quote = quote_for(&signed, 1);
    assert!(execute_quote_handoff(
        &executor,
        &store,
        &quote,
        1,
        &ExecutionGatePolicy::testnet_default(),
        true
    )
    .await
    .is_err());
    commit_profile(&store, &signed, &identity, NameAction::Register);
    let mut changed = quote.clone();
    if let QuoteResponse::Ok { qr, .. } = &mut changed {
        *qr = "bitcoin:mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn?amount=0.00000001".into();
    }
    assert!(execute_quote_handoff(
        &executor,
        &store,
        &changed,
        1,
        &ExecutionGatePolicy::testnet_default(),
        true
    )
    .await
    .is_err());
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
}

/// Build a checksum-valid invoice signed by a different key than its explicit payee.
fn invoice_with_invalid_signature() -> String {
    let secp = Secp256k1::new();
    let signer = SecretKey::from_slice(&[0x33; 32]).unwrap();
    let wrong_payee = bitcoin::secp256k1::PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_slice(&[0x22; 32]).unwrap(),
    );
    InvoiceBuilder::new(Currency::BitcoinTestnet)
        .description("invalid signature".into())
        .payment_hash(sha256::Hash::hash(&[0x55; 32]))
        .payment_secret(PaymentSecret([0x77; 32]))
        .amount_milli_satoshis(1_000)
        .current_timestamp()
        .min_final_cltv_expiry_delta(144)
        .payee_pub_key(wrong_payee)
        .build_raw()
        .unwrap()
        .sign(|hash| Ok::<_, ()>(secp.sign_ecdsa_recoverable(hash, &signer)))
        .unwrap()
        .to_string()
}

/// Reject a stale identity after an authorized rotation, even when its payment method is unchanged.
#[tokio::test]
async fn handoff_rejects_quote_after_identity_rotation() {
    let invoice = make_testnet_bolt11(1);
    let old = generate_identity_keypair();
    let new = generate_identity_keypair();
    let signed = signed_lightning_profile(&old, &invoice);
    let home = tempfile::tempdir().unwrap();
    let store = TransactionalTransparencyStore::open(home.path()).unwrap();
    commit_profile(&store, &signed, &old, NameAction::Register);
    let quote = quote_for(&signed, 1);
    let mut rotated = signed.profile.clone();
    rotated.sequence = Some(1);
    rotated.identity_pubkey = hex::encode(new.public_key.serialize());
    let log = store.load_log().unwrap();
    let previous = log.events().last().unwrap().event_hash().unwrap();
    rotated.rotation = Some(
        satspath_core::KeyRotation::create(
            satspath_core::identifier_hash(&rotated.alias),
            signed.profile.identity_pubkey.clone(),
            &old.secret_key,
            rotated.identity_pubkey.clone(),
            &new.secret_key,
            previous,
            1,
        )
        .unwrap(),
    );
    let rotated = sign_profile(rotated, &new.secret_key).unwrap();
    commit_profile(&store, &rotated, &old, NameAction::RotateKey);
    let executor = CountingExecutor {
        network: BitcoinNetwork::Testnet,
        calls: AtomicUsize::new(0),
    };
    assert!(execute_quote_handoff(
        &executor,
        &store,
        &quote,
        1,
        &ExecutionGatePolicy::testnet_default(),
        true
    )
    .await
    .is_err());
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    assert!(execute_quote_handoff(
        &executor,
        &store,
        &quote_for(&rotated, 1),
        1,
        &ExecutionGatePolicy::testnet_default(),
        true
    )
    .await
    .is_ok());
}

/// Bind fetched invoices to the signed payee key and reject an unrelated invoice signer.
#[tokio::test]
async fn fetched_invoice_requires_current_signed_payee_key() {
    let invoice = make_testnet_bolt11(1);
    let identity = generate_identity_keypair();
    for bind_payee in [false, true] {
        let mut profile = signed_lightning_profile(&identity, &invoice).profile;
        if let PaymentMethod::Lightning {
            lightning_address,
            receiver_pubkey,
            ..
        } = &mut profile.methods[0]
        {
            *lightning_address = Some("merchant@example.com".into());
            if !bind_payee {
                *receiver_pubkey = None;
            }
        }
        let signed = sign_profile(profile, &identity.secret_key).unwrap();
        let home = tempfile::tempdir().unwrap();
        let store = TransactionalTransparencyStore::open(home.path()).unwrap();
        commit_profile(&store, &signed, &identity, NameAction::Register);
        let mut quote = quote_for(&signed, 1);
        if let QuoteResponse::Ok { qr, .. } = &mut quote {
            *qr = invoice.clone();
        }
        let executor = CountingExecutor {
            network: BitcoinNetwork::Testnet,
            calls: AtomicUsize::new(0),
        };
        assert_eq!(
            execute_quote_handoff(
                &executor,
                &store,
                &quote,
                1,
                &ExecutionGatePolicy::testnet_default(),
                true
            )
            .await
            .is_ok(),
            bind_payee
        );
        assert_eq!(
            executor.calls.load(Ordering::SeqCst),
            usize::from(bind_payee)
        );
        if let QuoteResponse::Ok { qr, .. } = &mut quote {
            let raw = lightning_invoice::Bolt11Invoice::from_str(&invoice)
                .unwrap()
                .into_signed_raw()
                .raw_invoice()
                .clone();
            let other_key = SecretKey::from_slice(&[0x22; 32]).unwrap();
            *qr = raw
                .sign(|hash| Ok::<_, ()>(Secp256k1::new().sign_ecdsa_recoverable(hash, &other_key)))
                .unwrap()
                .to_string();
        }
        assert!(execute_quote_handoff(
            &executor,
            &store,
            &quote,
            1,
            &ExecutionGatePolicy::testnet_default(),
            true
        )
        .await
        .is_err());
        assert_eq!(
            executor.calls.load(Ordering::SeqCst),
            usize::from(bind_payee)
        );
    }
}
