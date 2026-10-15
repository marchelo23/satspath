//! Standardized non-custodial [`WalletExecutor`] SDK bridges for BDK, LDK, and Boltz Swaps.
//!
//! # Non-Custodial Invariant
//! SatsPath discovers capabilities, verifies cryptographic profile identities, scores routes,
//! and outputs validated payment handoff payloads (`QuoteResponse`). SatsPath **never** holds,
//! requests, or generates user seed phrases, `xprv`/`tprv` keys, or Lightning node credentials.
//! All transaction signing and settlement broadcast are sovereignly executed by the host wallet
//! via the trait bridges defined in this module.

use std::str::FromStr;

use anyhow::Result;
use async_trait::async_trait;
use bitcoin::absolute::LockTime;
use bitcoin::psbt::Psbt;
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut};
use lightning_invoice::{Bolt11Invoice, Currency};
use satspath_core::bip321::parse_bip321;
use satspath_core::crypto::{check_profile_expiry, fingerprint_pubkey, verify_signed_profile};
use satspath_core::execution::{
    ExecutionGatePolicy, OnchainReceipt, PaymentReceipt, WalletExecutor,
};
use satspath_core::pointer::BitcoinNetwork;
use satspath_core::privacy::{canonical_identifier, identifier_hash};
use satspath_core::transparency::{
    next_identifier_sequence, verify_checkpoint_inclusion, NameAction,
    TransactionalTransparencyStore,
};
use satspath_core::validation::{
    assert_no_private_material, validate_amount_sats, validate_bitcoin_address,
};
use satspath_core::PaymentMethod;
use satspath_core::{Result as CoreResult, SatsPathError};
use serde::{Deserialize, Serialize};

use crate::lightning::validate_bolt11_invoice;
use crate::quote_response::{build_qr_payload, QuoteResponse};

/// Unified receipt returned after a host wallet executes a validated SatsPath handoff payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "rail", rename_all = "snake_case")]
pub enum HandoffExecutionReceipt {
    /// On-chain Bitcoin transaction executed by the host wallet (e.g. BDK).
    Onchain(OnchainReceipt),
    /// Lightning BOLT11 payment executed by the host wallet (e.g. LDK).
    Lightning(PaymentReceipt),
    /// Reserved for verified swap settlement; current swap execution APIs always fail closed.
    SwapSettlement {
        /// Swap identifier.
        swap_id: String,
        /// Settlement kind (`"reverse_claim"` or `"submarine_refund"`).
        settlement_kind: String,
        /// Broadcast on-chain transaction ID (64-char hex).
        txid: String,
        /// Net output amount in satoshis delivered to the host wallet address.
        output_amount_sats: u64,
        /// Miner fee in satoshis.
        fee_sats: u64,
    },
}

// ============================================================================
// 1. Reference BDK (Bitcoin Development Kit) On-Chain Bridge
// ============================================================================

/// Non-custodial UTXO input descriptor supplied by a host BDK wallet for PSBT construction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BdkUtxoDescriptor {
    /// Previous output transaction ID (64-char hex).
    pub txid: String,
    /// Previous output index.
    pub vout: u32,
    /// Value of the UTXO in satoshis.
    pub amount_sats: u64,
    /// Hex-encoded `scriptPubKey` of the UTXO.
    pub script_pubkey_hex: String,
}

/// Callback interface implemented by the host BDK wallet.
///
/// The host wallet retains exclusive control over private spending keys: it supplies public
/// UTXO descriptors and a change address, inspects the unsigned PSBT constructed by the bridge,
/// signs it internally, and broadcasts the finalized transaction.
#[async_trait]
pub trait BdkHostWallet: Send + Sync {
    /// Select spendable public UTXOs and a host-controlled change address to fund `target_sats`.
    async fn select_utxos_and_change(
        &self,
        target_sats: u64,
        fee_rate_sat_vb: u64,
    ) -> Result<(Vec<BdkUtxoDescriptor>, String)>;

    /// Inspect, sign, and broadcast an unsigned base64 PSBT, returning the 64-char hex `txid`.
    async fn sign_and_broadcast_psbt(&self, unsigned_psbt_base64: &str) -> Result<String>;
}

/// Reference BDK on-chain executor that validates BIP-21 handoffs, constructs unsigned PSBTs
/// with strict fee guardrails, and delegates signing + broadcast to a [`BdkHostWallet`].
pub struct BdkOnchainBridge<W: BdkHostWallet> {
    network: BitcoinNetwork,
    max_fee_rate_sat_vb: u64,
    default_fee_rate_sat_vb: u64,
    host_wallet: W,
}

impl<W: BdkHostWallet> BdkOnchainBridge<W> {
    /// Construct a new BDK on-chain bridge for `network` with a maximum fee-rate cap.
    pub fn new(
        network: BitcoinNetwork,
        default_fee_rate_sat_vb: u64,
        max_fee_rate_sat_vb: u64,
        host_wallet: W,
    ) -> Self {
        Self {
            network,
            max_fee_rate_sat_vb,
            default_fee_rate_sat_vb,
            host_wallet,
        }
    }

    /// Construct an unsigned [`Psbt`] for an on-chain payment, enforcing address network validation,
    /// fee guardrails, and dust thresholds.
    pub async fn build_unsigned_psbt(
        &self,
        destination_address: &str,
        amount_sats: u64,
        fee_rate_sat_vb: Option<u64>,
    ) -> CoreResult<(Psbt, u64)> {
        validate_amount_sats(amount_sats)?;
        assert_no_private_material(destination_address)?;
        validate_bitcoin_address(destination_address, self.network)?;

        let rate = fee_rate_sat_vb.unwrap_or(self.default_fee_rate_sat_vb);
        if rate == 0 || rate > self.max_fee_rate_sat_vb {
            return Err(SatsPathError::ValidationError(format!(
                "Fee rate {rate} sat/vB is outside allowed bounds (1..={} sat/vB)",
                self.max_fee_rate_sat_vb
            )));
        }

        // Estimate 1-in-2-out SegWit vBytes (~141 vB)
        let estimated_fee_sats = rate.saturating_mul(141);
        let required_total = amount_sats.saturating_add(estimated_fee_sats);

        let (utxos, change_address) = self
            .host_wallet
            .select_utxos_and_change(required_total, rate)
            .await
            .map_err(|e| {
                SatsPathError::ValidationError(format!("BDK coin selection failed: {e}"))
            })?;

        if utxos.is_empty() {
            return Err(SatsPathError::ValidationError(
                "BDK host wallet returned no UTXOs".into(),
            ));
        }
        validate_bitcoin_address(&change_address, self.network)?;

        let mut total_in: u64 = 0;
        let mut tx_ins = Vec::with_capacity(utxos.len());
        let mut witness_utxos = Vec::with_capacity(utxos.len());

        for u in &utxos {
            let outpoint = OutPoint::from_str(&format!("{}:{}", u.txid, u.vout)).map_err(|e| {
                SatsPathError::ValidationError(format!("invalid UTXO outpoint: {e}"))
            })?;
            let spk_bytes = hex::decode(u.script_pubkey_hex.trim()).map_err(|e| {
                SatsPathError::ValidationError(format!("invalid UTXO scriptPubKey hex: {e}"))
            })?;
            total_in = total_in.saturating_add(u.amount_sats);
            tx_ins.push(TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            });
            witness_utxos.push(TxOut {
                value: Amount::from_sat(u.amount_sats),
                script_pubkey: ScriptBuf::from_bytes(spk_bytes),
            });
        }

        if total_in < required_total {
            return Err(SatsPathError::ValidationError(format!(
                "insufficient UTXO funds: input {total_in} sats < required {required_total} sats"
            )));
        }

        let dest_addr = Address::from_str(destination_address.trim())
            .map_err(|e| SatsPathError::InvalidPaymentPointer(e.to_string()))?
            .assume_checked();
        let change_addr = Address::from_str(change_address.trim())
            .map_err(|e| SatsPathError::InvalidPaymentPointer(e.to_string()))?
            .assume_checked();

        let change_sats = total_in - required_total;
        let mut outputs = vec![TxOut {
            value: Amount::from_sat(amount_sats),
            script_pubkey: dest_addr.script_pubkey(),
        }];
        if change_sats >= 546 {
            outputs.push(TxOut {
                value: Amount::from_sat(change_sats),
                script_pubkey: change_addr.script_pubkey(),
            });
        }

        let unsigned_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: tx_ins,
            output: outputs,
        };

        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)
            .map_err(|e| SatsPathError::ValidationError(format!("PSBT creation failed: {e}")))?;
        for (idx, w_utxo) in witness_utxos.into_iter().enumerate() {
            psbt.inputs[idx].witness_utxo = Some(w_utxo);
        }

        Ok((psbt, estimated_fee_sats))
    }

    /// Parse a `bitcoin:` BIP-21 URI handoff, construct an unsigned PSBT, and execute via the host wallet.
    pub async fn execute_bip21_uri(
        &self,
        bip21_uri: &str,
        fallback_amount_sats: u64,
        fee_rate_sat_vb: Option<u64>,
    ) -> CoreResult<OnchainReceipt> {
        assert_no_private_material(bip21_uri)?;
        let parsed = parse_bip321(bip21_uri)?;
        let address = parsed.address.ok_or_else(|| {
            SatsPathError::InvalidPaymentUri("BIP-21 URI is missing an on-chain address".into())
        })?;
        let amount_sats = if let Some(ref btc_str) = parsed.amount_btc {
            let amt =
                Amount::from_str_in(btc_str, bitcoin::Denomination::Bitcoin).map_err(|e| {
                    SatsPathError::InvalidPaymentUri(format!("invalid BTC amount: {e}"))
                })?;
            amt.to_sat()
        } else {
            fallback_amount_sats
        };
        if amount_sats != fallback_amount_sats {
            return Err(SatsPathError::ValidationError(format!(
                "BIP-21 URI amount ({amount_sats} sats) mismatches expected quote amount ({fallback_amount_sats} sats)"
            )));
        }
        let (psbt, fee_sats) = self
            .build_unsigned_psbt(&address, amount_sats, fee_rate_sat_vb)
            .await?;
        let psbt_hex = psbt.serialize_hex();
        let txid = self
            .host_wallet
            .sign_and_broadcast_psbt(&psbt_hex)
            .await
            .map_err(|e| {
                SatsPathError::NetworkError(format!("BDK PSBT signing/broadcast failed: {e}"))
            })?;
        Ok(OnchainReceipt {
            txid,
            amount_sats,
            fee_sats,
            destination: address,
            timestamp: chrono::Utc::now().timestamp(),
        })
    }
}

// ============================================================================
// 2. Reference LDK / LNURL Lightning Bridge
// ============================================================================

/// Callback interface implemented by a host LDK node or LNURL-capable wallet.
#[async_trait]
pub trait LdkHostNode: Send + Sync {
    /// Dispatch a validated BOLT11 invoice payment through the host Lightning node.
    async fn send_bolt11_payment(
        &self,
        bolt11_invoice: &str,
        expected_amount_msats: u64,
        max_fee_msats: u64,
    ) -> Result<PaymentReceipt>;
}

/// Reference LDK / Lightning executor that validates BOLT11 invoices (signature, network,
/// expiry, and exact amount) before delegating payment execution to an [`LdkHostNode`].
pub struct LdkLightningBridge<L: LdkHostNode> {
    network: BitcoinNetwork,
    max_fee_bps: u64,
    host_node: L,
}

impl<L: LdkHostNode> LdkLightningBridge<L> {
    /// Construct a new LDK Lightning bridge for `network` with a maximum routing fee in basis points.
    pub fn new(network: BitcoinNetwork, max_fee_bps: u64, host_node: L) -> Self {
        Self {
            network,
            max_fee_bps,
            host_node,
        }
    }

    /// Validate a BOLT11 invoice and execute payment via the host LDK node.
    pub async fn validate_and_pay_bolt11(
        &self,
        invoice_str: &str,
        expected_amount_sats: u64,
    ) -> CoreResult<PaymentReceipt> {
        let validated =
            validate_handoff_bolt11(invoice_str.trim(), expected_amount_sats, self.network)?;
        let amount_msats = validated
            .amount_milli_satoshis()
            .expect("validated exact amount");
        let max_fee_msats = (amount_msats.saturating_mul(self.max_fee_bps) / 10_000).max(1_000);

        self.host_node
            .send_bolt11_payment(invoice_str.trim(), amount_msats, max_fee_msats)
            .await
            .map_err(|e| SatsPathError::NetworkError(format!("LDK payment failed: {e}")))
    }
}

// ============================================================================
// 3. Combined Non-Custodial Host Wallet Bridge (BDK + LDK -> WalletExecutor)
// ============================================================================

/// Combined non-custodial host wallet adapter implementing [`WalletExecutor`] by bridging
/// on-chain operations to [`BdkOnchainBridge`] and Lightning operations to [`LdkLightningBridge`].
pub struct HostWalletSdkBridge<W: BdkHostWallet, L: LdkHostNode> {
    network: BitcoinNetwork,
    bdk: BdkOnchainBridge<W>,
    ldk: LdkLightningBridge<L>,
}

impl<W: BdkHostWallet, L: LdkHostNode> HostWalletSdkBridge<W, L> {
    /// Construct a unified host wallet bridge from a BDK on-chain bridge and an LDK Lightning bridge.
    pub fn new(
        network: BitcoinNetwork,
        bdk: BdkOnchainBridge<W>,
        ldk: LdkLightningBridge<L>,
    ) -> Self {
        Self { network, bdk, ldk }
    }

    /// Reference to the underlying [`BdkOnchainBridge`].
    pub fn bdk(&self) -> &BdkOnchainBridge<W> {
        &self.bdk
    }

    /// Reference to the underlying [`LdkLightningBridge`].
    pub fn ldk(&self) -> &LdkLightningBridge<L> {
        &self.ldk
    }
}

#[async_trait]
impl<W: BdkHostWallet, L: LdkHostNode> WalletExecutor for HostWalletSdkBridge<W, L> {
    /// Return the configured host wallet network.
    fn network(&self) -> BitcoinNetwork {
        self.network
    }

    /// Reject fractional satoshis and validate the exact invoice before host dispatch.
    async fn pay_bolt11(
        &self,
        invoice: &str,
        amount_msats: Option<u64>,
    ) -> CoreResult<PaymentReceipt> {
        let amount_msats = amount_msats.ok_or_else(|| {
            SatsPathError::ValidationError(
                "amount_msats is required for verified BOLT11 execution".into(),
            )
        })?;
        if amount_msats % 1_000 != 0 {
            return Err(SatsPathError::ValidationError(
                "amount_msats must be an exact number of satoshis".into(),
            ));
        }
        let amount_sats = amount_msats / 1_000;
        self.ldk.validate_and_pay_bolt11(invoice, amount_sats).await
    }

    /// Build an on-chain PSBT and delegate its execution to the host wallet.
    async fn send_onchain(
        &self,
        destination_address: &str,
        amount_sats: u64,
        fee_rate_sat_vb: Option<u64>,
    ) -> CoreResult<OnchainReceipt> {
        let (psbt, fee_sats) = self
            .bdk
            .build_unsigned_psbt(destination_address, amount_sats, fee_rate_sat_vb)
            .await?;
        let psbt_b64 = base64_encode_psbt(&psbt);
        let txid = self.sign_and_broadcast_psbt(&psbt_b64).await?;
        Ok(OnchainReceipt {
            txid,
            amount_sats,
            fee_sats,
            destination: destination_address.to_string(),
            timestamp: chrono::Utc::now().timestamp(),
        })
    }

    /// Delegate PSBT signing and broadcasting and validate the returned transaction ID.
    async fn sign_and_broadcast_psbt(&self, psbt_base64: &str) -> CoreResult<String> {
        if psbt_base64.trim().is_empty() {
            return Err(SatsPathError::ValidationError(
                "PSBT cannot be empty".into(),
            ));
        }
        assert_no_private_material(psbt_base64)?;
        let txid = self
            .bdk
            .host_wallet
            .sign_and_broadcast_psbt(psbt_base64)
            .await
            .map_err(|e| {
                SatsPathError::NetworkError(format!("BDK PSBT signing/broadcast failed: {e}"))
            })?;
        if txid.len() != 64 || hex::decode(&txid).is_err() {
            return Err(SatsPathError::ValidationError(format!(
                "host wallet returned invalid txid: {txid}"
            )));
        }
        Ok(txid)
    }
}

/// Encode a [`Psbt`] to hex using its consensus serialization.
fn base64_encode_psbt(psbt: &Psbt) -> String {
    psbt.serialize_hex()
}

// ============================================================================
// 4. Boltz Testnet Swap Claim/Refund Host-Wallet Execution Bridge
// ============================================================================

/// Reserved host-wallet swap callbacks. The current bridge never invokes them.
///
/// Enabling execution requires a separate verified lockup, witness and chain-evidence
/// interface; the signature bytes and transaction ID returned here cannot prove settlement.
#[async_trait]
pub trait BoltzHostSignerBroadcaster: Send + Sync {
    /// Sign a 32-byte sighash digest with the host wallet's ephemeral swap key (`claim` or `refund`)
    /// and return a DER-encoded ECDSA signature (with sighash byte) or 64-byte Schnorr signature.
    async fn sign_swap_digest(&self, swap_id: &str, sighash: [u8; 32]) -> Result<Vec<u8>>;

    /// Broadcast a fully constructed raw transaction hex to the Testnet/Regtest network and
    /// return the confirmed/verified 64-char hex `txid`.
    async fn broadcast_swap_tx(&self, raw_tx_hex: &str) -> Result<String>;
}

/// Reserved Boltz swap bridge. Claims and refunds are disabled on every network.
///
/// The current API cannot authenticate the lockup UTXO, supported witness script,
/// spending sighash, signature, or independent chain settlement evidence. It must
/// never invoke the signer/broadcaster or issue a settlement receipt, including
/// for Taproot and cross-chain swaps, until that verification flow exists.
pub struct BoltzTestnetSwapBridge<S: BoltzHostSignerBroadcaster> {
    _network: BitcoinNetwork,
    _signer: S,
}

impl<S: BoltzHostSignerBroadcaster> BoltzTestnetSwapBridge<S> {
    /// Retain the host integration configuration without enabling swap execution.
    pub fn new(network: BitcoinNetwork, signer: S) -> Self {
        Self {
            _network: network,
            _signer: signer,
        }
    }

    /// Reject every reverse claim before signing or broadcasting.
    ///
    /// Caller-supplied outpoints, amounts, preimages and scripts are insufficient
    /// to authenticate a spend or demonstrate settlement.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_reverse_claim(
        &self,
        _swap_id: &str,
        _lockup_txid: &str,
        _lockup_vout: u32,
        _lockup_amount_sats: u64,
        _preimage_hex: &str,
        _redeem_script_hex: &str,
        _destination_address: &str,
        _miner_fee_sats: u64,
    ) -> CoreResult<HandoffExecutionReceipt> {
        Err(SatsPathError::ValidationError(
            "Boltz swap execution is disabled: verified lockup, witness and chain evidence are required".into(),
        ))
    }

    /// Reject every submarine refund before signing or broadcasting.
    ///
    /// Caller-supplied block heights do not prove the timelock or spend rules.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_submarine_refund(
        &self,
        _swap_id: &str,
        _lockup_txid: &str,
        _lockup_vout: u32,
        _lockup_amount_sats: u64,
        _timeout_block_height: u32,
        _current_block_height: u32,
        _redeem_script_hex: &str,
        _destination_address: &str,
        _miner_fee_sats: u64,
    ) -> CoreResult<HandoffExecutionReceipt> {
        Err(SatsPathError::ValidationError(
            "Boltz swap execution is disabled: verified lockup, witness and chain evidence are required".into(),
        ))
    }
}

// ============================================================================
// 5. End-to-End QuoteResponse -> WalletExecutor Dispatcher
// ============================================================================

/// Verify current local identity state and a payment payload before host dispatch.
///
/// `profile_store` must be the caller's authoritative, continuously updated local
/// transparency store. The profile and history are loaded afresh for each call;
/// missing state, revocations, unauthorized key changes and stale payment methods
/// fail closed. The serialized quote verification flags are never sufficient.
///
/// BOLT11 invoices must match the configured network and exact amount. A fetched
/// invoice also requires a payee key bound to the current signed Lightning method;
/// an LNURL/address alone cannot authenticate an arbitrary invoice. Unsupported
/// BOLT12, Ark, Silent Payment and swap handoffs remain disabled.
pub async fn execute_quote_handoff(
    executor: &dyn WalletExecutor,
    profile_store: &TransactionalTransparencyStore,
    quote_response: &QuoteResponse,
    expected_amount_sats: u64,
    policy: &ExecutionGatePolicy,
    user_confirmed: bool,
) -> CoreResult<HandoffExecutionReceipt> {
    validate_amount_sats(expected_amount_sats)?;
    policy.check_execution_safety(executor.network(), expected_amount_sats, user_confirmed)?;

    let QuoteResponse::Ok {
        recipient,
        selected_method,
        qr,
        ..
    } = quote_response
    else {
        return Err(SatsPathError::ValidationError(
            "cannot execute non-Ok QuoteResponse".into(),
        ));
    };

    if !recipient.profile_signature_verified {
        return Err(SatsPathError::InvalidSignature);
    }

    verify_current_handoff_profile(profile_store, recipient, selected_method)?;

    assert_no_private_material(qr)?;
    let trimmed = qr.trim();
    let lower = trimmed.to_ascii_lowercase();

    if lower.starts_with("bitcoin:") {
        if !matches!(selected_method, PaymentMethod::Onchain { network, silent_payment_pubkey: None, .. } if *network == executor.network())
            || build_qr_payload(selected_method, expected_amount_sats)? != trimmed
        {
            return Err(SatsPathError::ValidationError(
                "handoff does not match the current signed on-chain method".into(),
            ));
        }
        let parsed = parse_bip321(trimmed)?;
        let addr = parsed.address.ok_or_else(|| {
            SatsPathError::InvalidPaymentUri("BIP-21 handoff URI is missing address".into())
        })?;
        validate_bitcoin_address(&addr, executor.network())?;
        if let Some(ref btc_str) = parsed.amount_btc {
            let amt =
                Amount::from_str_in(btc_str, bitcoin::Denomination::Bitcoin).map_err(|e| {
                    SatsPathError::InvalidPaymentUri(format!("invalid BTC amount: {e}"))
                })?;
            if amt.to_sat() != expected_amount_sats {
                return Err(SatsPathError::ValidationError(format!(
                    "BIP-21 handoff amount {} sats does not match expected {} sats",
                    amt.to_sat(),
                    expected_amount_sats
                )));
            }
        }
        let receipt = executor
            .send_onchain(&addr, expected_amount_sats, None)
            .await?;
        return Ok(HandoffExecutionReceipt::Onchain(receipt));
    }

    if lower.starts_with("lnbc") || lower.starts_with("lntb") {
        let invoice = validate_handoff_bolt11(trimmed, expected_amount_sats, executor.network())?;
        let PaymentMethod::Lightning {
            receiver_pubkey, ..
        } = selected_method
        else {
            return Err(SatsPathError::ValidationError(
                "BOLT11 handoff requires a signed Lightning method".into(),
            ));
        };
        let signed_payload = build_qr_payload(selected_method, expected_amount_sats)?;
        let payee = invoice.recover_payee_pub_key().to_string();
        if signed_payload != trimmed && receiver_pubkey.as_deref() != Some(payee.as_str()) {
            return Err(SatsPathError::ValidationError(
                "BOLT11 payee is not bound to the current signed profile".into(),
            ));
        }
        let receipt = executor
            .pay_bolt11(trimmed, invoice.amount_milli_satoshis())
            .await?;
        return Ok(HandoffExecutionReceipt::Lightning(receipt));
    }

    Err(SatsPathError::ValidationError(format!(
        "unsupported handoff payload scheme for direct WalletExecutor settlement: {trimmed}"
    )))
}

/// Decode and verify a BOLT11 invoice against an exact satoshi amount and network.
fn validate_handoff_bolt11(
    invoice_str: &str,
    expected_amount_sats: u64,
    network: BitcoinNetwork,
) -> CoreResult<Bolt11Invoice> {
    assert_no_private_material(invoice_str)?;
    validate_amount_sats(expected_amount_sats)?;
    let expected_msats = expected_amount_sats.checked_mul(1_000).ok_or_else(|| {
        SatsPathError::ValidationError("BOLT11 millisatoshi amount overflow".into())
    })?;
    validate_bolt11_invoice(invoice_str, expected_msats)
        .map_err(|e| SatsPathError::ValidationError(format!("BOLT11 validation failed: {e}")))?;
    // Bolt11Invoice's constructor verifies the signature and all semantic fields.
    let invoice = Bolt11Invoice::from_str(invoice_str)
        .map_err(|e| SatsPathError::ValidationError(format!("BOLT11 validation failed: {e}")))?;
    let currency = match network {
        BitcoinNetwork::Mainnet => Currency::Bitcoin,
        BitcoinNetwork::Testnet => Currency::BitcoinTestnet,
        BitcoinNetwork::Regtest => Currency::Regtest,
    };
    if invoice.currency() != currency {
        return Err(SatsPathError::ValidationError(format!(
            "BOLT11 invoice network does not match wallet network {network:?}"
        )));
    }
    Ok(invoice)
}

/// Reload and verify the alias history and bind the selected method to its current profile.
fn verify_current_handoff_profile(
    store: &TransactionalTransparencyStore,
    recipient: &crate::quote_response::QuoteRecipient,
    selected_method: &PaymentMethod,
) -> CoreResult<()> {
    let signed = store
        .profile(&recipient.alias)?
        .ok_or_else(|| SatsPathError::AliasNotFound(recipient.alias.clone()))?;
    let profile = &signed.profile;
    if canonical_identifier(&profile.alias) != canonical_identifier(&recipient.alias)
        || !verify_signed_profile(&signed)?
    {
        return Err(SatsPathError::InvalidSignature);
    }
    check_profile_expiry(profile)?;
    let log = store.load_log()?;
    let history: Vec<_> = log
        .history(&identifier_hash(&recipient.alias))
        .into_iter()
        .cloned()
        .collect();
    // Validates all signatures, authorized rotations and strictly increasing sequences,
    // and binds the latest event's full profile hash, identity key and sequence.
    next_identifier_sequence(Some(&signed), &history)?;
    let latest = history.last().ok_or_else(|| {
        SatsPathError::ValidationError("handoff requires transparency history".into())
    })?;
    if profile.revoked || latest.action == NameAction::Revoke {
        return Err(SatsPathError::RegistryError(
            "handoff recipient has been revoked".into(),
        ));
    }
    let checkpoint = log.checkpoints().last().ok_or_else(|| {
        SatsPathError::ValidationError("handoff requires a transparency checkpoint".into())
    })?;
    let event_hash = latest.event_hash()?;
    let inclusion = log.inclusion(&event_hash, None)?;
    verify_checkpoint_inclusion(&event_hash, &inclusion, checkpoint)?;
    if recipient.fingerprint.as_deref()
        != Some(fingerprint_pubkey(&profile.identity_pubkey)?.as_str())
        || !profile.methods.contains(selected_method)
    {
        return Err(SatsPathError::ValidationError(
            "quote no longer matches the current recipient profile".into(),
        ));
    }
    Ok(())
}
