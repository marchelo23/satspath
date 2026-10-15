//! End-to-end integration tests for the standardized `WalletExecutor` SDK interface and
//! non-custodial host wallet bridges (BDK on-chain, LDK Lightning, and Boltz Testnet Swaps)
//! per Issue #156.

use std::str::FromStr;

use anyhow::Result;
use async_trait::async_trait;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::Address;
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use satspath_core::crypto::{generate_identity_keypair, sign_profile};
use satspath_core::execution::{ExecutionGatePolicy, PaymentReceipt};
use satspath_core::pointer::BitcoinNetwork;
use satspath_core::profile::{PaymentMethod, PaymentProfile};
use satspath_core::resolver::ProfileResolver;
use satspath_core::SignedPaymentProfile;
use satspath_router::quote_response::quote_with_resolver;
use satspath_router::wallet_executor::{
    execute_quote_handoff, BdkHostWallet, BdkOnchainBridge, BdkUtxoDescriptor,
    BoltzHostSignerBroadcaster, BoltzTestnetSwapBridge, HandoffExecutionReceipt,
    HostWalletSdkBridge, LdkHostNode, LdkLightningBridge,
};
use sha2::{Digest, Sha256};

// ─── Simulated Sovereign BDK Host Wallet ────────────────────────────────────────

struct SimulatedBdkWallet {
    change_address: String,
    utxo: BdkUtxoDescriptor,
}

impl SimulatedBdkWallet {
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
    async fn select_utxos_and_change(
        &self,
        _target_sats: u64,
        _fee_rate_sat_vb: u64,
    ) -> Result<(Vec<BdkUtxoDescriptor>, String)> {
        Ok((vec![self.utxo.clone()], self.change_address.clone()))
    }

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

struct SimulatedBoltzHostSigner {
    ephemeral_key: SecretKey,
}

#[async_trait]
impl BoltzHostSignerBroadcaster for SimulatedBoltzHostSigner {
    async fn sign_swap_digest(&self, _swap_id: &str, sighash: [u8; 32]) -> Result<Vec<u8>> {
        let secp = Secp256k1::new();
        let msg = Message::from_digest(sighash);
        let sig = secp.sign_ecdsa(&msg, &self.ephemeral_key);
        let mut der = sig.serialize_der().to_vec();
        der.push(0x01); // SIGHASH_ALL
        Ok(der)
    }

    async fn broadcast_swap_tx(&self, raw_tx_hex: &str) -> Result<String> {
        let tx_bytes = hex::decode(raw_tx_hex)?;
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes)?;
        Ok(tx.compute_txid().to_string())
    }
}

// ─── Mock Profile Resolver ──────────────────────────────────────────────────────

struct StaticProfileResolver {
    signed: SignedPaymentProfile,
}

#[async_trait]
impl ProfileResolver for StaticProfileResolver {
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
        sequence: Some(1),
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

#[tokio::test]
async fn test_boltz_testnet_swap_claim_and_refund_with_host_signing() {
    let signer = SimulatedBoltzHostSigner {
        ephemeral_key: SecretKey::from_slice(&[0x44; 32]).unwrap(),
    };
    let swap_bridge = BoltzTestnetSwapBridge::new(BitcoinNetwork::Testnet, signer);

    let preimage = [0x99u8; 32];
    let preimage_hex = hex::encode(preimage);
    let preimage_hash: [u8; 32] = Sha256::digest(preimage).into();

    // Build an HTLC witness script that embeds SHA256(preimage)
    let mut redeem_script = vec![0x82, 0x01, 0x20, 0x87, 0x63, 0xa8, 0x20];
    redeem_script.extend_from_slice(&preimage_hash);
    redeem_script.push(0x88);
    let redeem_script_hex = hex::encode(&redeem_script);

    let dest_addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    let lockup_txid = "22".repeat(32);

    // 1. Reverse swap claim succeeds when witness script commits to SHA256(preimage)
    let claim_receipt = swap_bridge
        .execute_reverse_claim(
            "swap_rev_01",
            &lockup_txid,
            0,
            50_000,
            &preimage_hex,
            &redeem_script_hex,
            dest_addr,
            500,
        )
        .await
        .expect("reverse swap claim must succeed on testnet");

    match claim_receipt {
        HandoffExecutionReceipt::SwapSettlement {
            swap_id,
            settlement_kind,
            txid,
            output_amount_sats,
            fee_sats,
        } => {
            assert_eq!(swap_id, "swap_rev_01");
            assert_eq!(settlement_kind, "reverse_claim");
            assert_eq!(txid.len(), 64);
            assert_eq!(output_amount_sats, 49_500);
            assert_eq!(fee_sats, 500);
        }
        other => panic!("expected SwapSettlement receipt, got {other:?}"),
    }

    // 2. Unverified redeem script (does not commit to SHA256(preimage)) fails closed
    assert!(swap_bridge
        .execute_reverse_claim(
            "swap_rev_bad",
            &lockup_txid,
            0,
            50_000,
            &preimage_hex,
            "51", // OP_TRUE without hashlock commitment
            dest_addr,
            500,
        )
        .await
        .is_err());

    // 3. Submarine swap refund before CLTV timeout block fails closed
    assert!(swap_bridge
        .execute_submarine_refund(
            "swap_sub_early",
            &lockup_txid,
            0,
            50_000,
            800_000,
            799_999, // current < timeout
            &redeem_script_hex,
            dest_addr,
            500,
        )
        .await
        .is_err());

    // 4. Submarine swap refund at/after CLTV timeout block succeeds
    let refund_receipt = swap_bridge
        .execute_submarine_refund(
            "swap_sub_ok",
            &lockup_txid,
            0,
            50_000,
            800_000,
            800_001,
            &redeem_script_hex,
            dest_addr,
            500,
        )
        .await
        .expect("submarine refund after timeout must succeed");
    assert!(matches!(
        refund_receipt,
        HandoffExecutionReceipt::SwapSettlement { ref settlement_kind, .. } if settlement_kind == "submarine_refund"
    ));

    // 5. Mainnet swap bridge fails closed
    let mainnet_bridge = BoltzTestnetSwapBridge::new(
        BitcoinNetwork::Mainnet,
        SimulatedBoltzHostSigner {
            ephemeral_key: SecretKey::from_slice(&[0x44; 32]).unwrap(),
        },
    );
    assert!(mainnet_bridge
        .execute_reverse_claim(
            "swap_mainnet_blocked",
            &lockup_txid,
            0,
            50_000,
            &preimage_hex,
            &redeem_script_hex,
            "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            500,
        )
        .await
        .is_err());
}
