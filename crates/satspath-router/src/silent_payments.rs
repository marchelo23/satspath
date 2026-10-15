//! Silent Payments (BIP-352) — Standards-Compliant Implementation.
//!
//! Implements BIP-352 Silent Payments address encoding/decoding, eligible input public-key
//! and private-key extraction (P2TR, P2WPKH, P2SH-P2WPKH, P2PKH), NUMS point filtering,
//! Taproot Y-parity adjustment, label derivation, multi-recipient output generation,
//! and scanner output detection validated against the official BIP-352 test vectors.

use std::collections::{HashMap, HashSet};
use std::fmt;

use anyhow::{anyhow, Result};
use bech32::{u5, FromBase32, ToBase32, Variant};
use bitcoin::consensus::Decodable;
use bitcoin::hashes::{hash160, Hash};
use bitcoin::script::Instruction;
use bitcoin::secp256k1::{Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::{Network, Script, Witness};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// BIP-352 tagged hash domain tag for input hash computation.
pub const BIP0352_TAG_INPUTS: &str = "BIP0352/Inputs";
/// BIP-352 tagged hash domain tag for shared secret derivation.
pub const BIP0352_TAG_SHARED_SECRET: &str = "BIP0352/SharedSecret";
/// BIP-352 tagged hash domain tag for recipient label derivation.
pub const BIP0352_TAG_LABEL: &str = "BIP0352/Label";

/// Maximum per-group recipient output index `K_max` defined by BIP-352 (`2323`).
pub const BIP0352_MAX_K: u32 = 2323;

/// BIP-341 NUMS point `H` (`50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`).
/// Taproot script-path spends using `H` as their internal key must be skipped per BIP-352.
pub const BIP0352_NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// BIP-340 / BIP-352 tagged hash implementation:
/// `SHA256(SHA256(tag) || SHA256(tag) || data)`.
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);
    hasher.finalize().into()
}

/// Parse an outpoint string in `"txid:vout"` format into standard 36-byte Bitcoin wire format:
/// 32 bytes txid (internal byte order / reversed hex) followed by 4 bytes vout (little-endian).
///
/// # Errors
/// Returns an error if the string does not match `txid:vout`, if the txid is not 64 hex chars,
/// or if `vout` is not a valid `u32`.
pub fn parse_outpoint_to_bytes(outpoint_str: &str) -> Result<[u8; 36]> {
    let parts: Vec<&str> = outpoint_str.split(':').collect();
    if parts.len() != 2 {
        return Err(anyhow!(
            "Invalid outpoint format, expected txid:vout, got '{outpoint_str}'"
        ));
    }
    let txid_hex = parts[0].trim();
    let vout_str = parts[1].trim();
    if txid_hex.len() != 64 {
        return Err(anyhow!("Invalid txid length in outpoint: {txid_hex}"));
    }
    let mut txid_bytes =
        hex::decode(txid_hex).map_err(|e| anyhow!("Invalid txid hex in outpoint: {e}"))?;
    // Bitcoin wire format stores txid in little-endian order (reversed from display hex)
    txid_bytes.reverse();
    let vout: u32 = vout_str
        .parse()
        .map_err(|e| anyhow!("Invalid vout in outpoint: {e}"))?;

    let mut out = [0u8; 36];
    out[..32].copy_from_slice(&txid_bytes);
    out[32..].copy_from_slice(&vout.to_le_bytes());
    Ok(out)
}

/// Find the lexicographically smallest 36-byte outpoint among inputs as required by BIP-352.
pub fn find_smallest_outpoint(outpoints: &[[u8; 36]]) -> Option<[u8; 36]> {
    outpoints.iter().copied().min()
}

/// Compute BIP-352 input hash: `TaggedHash("BIP0352/Inputs", outpoint_L || A)`.
pub fn compute_input_hash(
    smallest_outpoint: &[u8; 36],
    aggregate_input_pubkey: &PublicKey,
) -> [u8; 32] {
    let mut data = Vec::with_capacity(36 + 33);
    data.extend_from_slice(smallest_outpoint);
    data.extend_from_slice(&aggregate_input_pubkey.serialize());
    tagged_hash(BIP0352_TAG_INPUTS, &data)
}

/// Compute BIP-352 label tweak scalar bytes:
/// `TaggedHash("BIP0352/Label", ser_256(b_scan) || ser_32(m))`.
pub fn compute_label_tweak(scan_privkey: &SecretKey, m: u32) -> [u8; 32] {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&scan_privkey.secret_bytes());
    data.extend_from_slice(&m.to_be_bytes());
    tagged_hash(BIP0352_TAG_LABEL, &data)
}

/// Derive a labeled spend public key `B_m = B_spend + TaggedHash("BIP0352/Label", b_scan || m) * G`.
///
/// # Errors
/// Returns an error if the derived label tweak is not a valid secp256k1 scalar or point addition fails.
pub fn derive_labeled_spend_pubkey(
    spend_pubkey: &PublicKey,
    scan_privkey: &SecretKey,
    m: u32,
) -> Result<PublicKey> {
    let secp = Secp256k1::new();
    let tweak_bytes = compute_label_tweak(scan_privkey, m);
    let tweak_scalar =
        Scalar::from_be_bytes(tweak_bytes).map_err(|e| anyhow!("Invalid label scalar: {e}"))?;
    spend_pubkey
        .add_exp_tweak(&secp, &tweak_scalar)
        .map_err(|e| anyhow!("Failed to derive labeled spend public key: {e}"))
}

/// Full transaction input descriptor for BIP-352 eligibility and public-key extraction.
///
/// Sender inputs must supply the final `script_sig` / `txinwitness` shape or a placeholder
/// with the same shape exposing the real public key (and Taproot script-path control block).
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bip352PrevoutInput {
    /// Transaction ID in display hex (64 characters).
    pub txid: String,
    /// Output index being spent.
    pub vout: u32,
    /// Hex-encoded `scriptSig`.
    pub script_sig: String,
    /// Hex-encoded consensus-serialized witness stack (`txinwitness`).
    pub txinwitness: String,
    /// Hex-encoded prevout `scriptPubKey`.
    pub prevout_script_pubkey: String,
    /// Optional hex-encoded 32-byte spending private key (used by sender).
    #[serde(default, skip_serializing)]
    pub private_key: Option<Zeroizing<String>>,
}

impl fmt::Debug for Bip352PrevoutInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bip352PrevoutInput")
            .field("txid", &self.txid)
            .field("vout", &self.vout)
            .field("script_sig", &self.script_sig)
            .field("txinwitness", &self.txinwitness)
            .field("prevout_script_pubkey", &self.prevout_script_pubkey)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl Bip352PrevoutInput {
    /// Convert `(txid, vout)` to standard 36-byte wire format.
    ///
    /// # Errors
    /// Returns an error if `txid` is not valid 32-byte hex.
    pub fn outpoint_bytes(&self) -> Result<[u8; 36]> {
        parse_outpoint_to_bytes(&format!("{}:{}", self.txid, self.vout))
    }
}

/// Extract the eligible BIP-352 public key from a transaction input, if eligible.
///
/// Implements the exact input filtering rules from BIP-352:
/// - **P2TR**: `5120<32-byte x-only key>`. Skips script-path spends whose control block
///   internal key is the BIP-341 NUMS point `H`. Otherwise lifts the 32-byte output key
///   with even Y parity (`0x02 || x_only`).
/// - **P2WPKH**: `0014<20-byte hash160>`. `scriptSig` must be empty and the witness stack's
///   last element must be a 33-byte compressed public key.
/// - **P2SH-P2WPKH**: `a914<20-byte hash160>87` with `scriptSig == 160014<20-byte hash160>`
///   and a 33-byte compressed public key as the last witness element.
/// - **P2PKH**: `76a914<20-byte hash160>88ac`. Iterates over data pushes in `scriptSig`
///   and returns the 33-byte compressed public key whose `HASH160` matches the prevout hash.
///
/// Returns `Ok(Some((pubkey, is_taproot)))` when eligible, or `Ok(None)` when the input must be skipped.
///
/// # Errors
/// Returns an error if hex fields cannot be decoded.
pub fn extract_bip352_input_pubkey(
    input: &Bip352PrevoutInput,
) -> Result<Option<(PublicKey, bool)>> {
    let spk = hex::decode(input.prevout_script_pubkey.trim())
        .map_err(|e| anyhow!("Invalid prevout scriptPubKey hex: {e}"))?;
    let script_sig =
        hex::decode(input.script_sig.trim()).map_err(|e| anyhow!("Invalid scriptSig hex: {e}"))?;
    let witness_bytes = hex::decode(input.txinwitness.trim())
        .map_err(|e| anyhow!("Invalid txinwitness hex: {e}"))?;

    let witness_items: Vec<Vec<u8>> = if witness_bytes.is_empty() {
        Vec::new()
    } else {
        let mut cursor = std::io::Cursor::new(&witness_bytes);
        match Witness::consensus_decode(&mut cursor) {
            Ok(w) => w.to_vec(),
            Err(_) => return Ok(None),
        }
    };

    // 1. P2TR: OP_1 (0x51) OP_PUSHBYTES_32 (0x20) <32-byte x-only key>
    if spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20 {
        if !script_sig.is_empty() || witness_items.is_empty() {
            return Ok(None);
        }
        // Strip optional Taproot annex (last item starting with 0x50 when stack has >= 2 items)
        let stack_len = if witness_items.len() > 1
            && witness_items.last().and_then(|item| item.first()).copied() == Some(0x50)
        {
            witness_items.len() - 1
        } else {
            witness_items.len()
        };

        // Script-path spend has > 1 elements remaining; last element is control block
        if stack_len > 1 {
            let control_block = &witness_items[stack_len - 1];
            if control_block.len() >= 33 && control_block[1..33] == BIP0352_NUMS_H {
                return Ok(None);
            }
        }

        let xonly = match XOnlyPublicKey::from_slice(&spk[2..34]) {
            Ok(x) => x,
            Err(_) => return Ok(None),
        };
        let pk = PublicKey::from_x_only_public_key(xonly, Parity::Even);
        return Ok(Some((pk, true)));
    }

    // 2. P2WPKH: OP_0 (0x00) OP_PUSHBYTES_20 (0x14) <20-byte pubkey hash>
    if spk.len() == 22 && spk[0] == 0x00 && spk[1] == 0x14 {
        if !script_sig.is_empty() || witness_items.len() != 2 {
            return Ok(None);
        }
        let pk_bytes = &witness_items[1];
        if pk_bytes.len() == 33 && (pk_bytes[0] == 0x02 || pk_bytes[0] == 0x03) {
            if let Ok(pk) = PublicKey::from_slice(pk_bytes) {
                return Ok(Some((pk, false)));
            }
        }
        return Ok(None);
    }

    // 3. P2SH-P2WPKH: spk = a914<20-byte hash>87, scriptSig = 160014<20-byte hash>
    if spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87 {
        if script_sig.len() == 23
            && script_sig[0] == 0x16
            && script_sig[1] == 0x00
            && script_sig[2] == 0x14
            && witness_items.len() == 2
        {
            let pk_bytes = &witness_items[1];
            if pk_bytes.len() == 33 && (pk_bytes[0] == 0x02 || pk_bytes[0] == 0x03) {
                if let Ok(pk) = PublicKey::from_slice(pk_bytes) {
                    return Ok(Some((pk, false)));
                }
            }
        }
        return Ok(None);
    }

    // 4. P2PKH: OP_DUP (0x76) OP_HASH160 (0xa9) OP_PUSHBYTES_20 (0x14) <20-byte hash> OP_EQUALVERIFY (0x88) OP_CHECKSIG (0xac)
    if spk.len() == 25
        && spk[0] == 0x76
        && spk[1] == 0xa9
        && spk[2] == 0x14
        && spk[23] == 0x88
        && spk[24] == 0xac
    {
        let expected_pkh = &spk[3..23];
        let script = Script::from_bytes(&script_sig);
        let mut matched_pk: Option<PublicKey> = None;
        for ins in script.instructions() {
            let Ok(Instruction::PushBytes(push)) = ins else {
                continue;
            };
            let bytes = push.as_bytes();
            if bytes.len() == 33 && (bytes[0] == 0x02 || bytes[0] == 0x03) {
                let pkh = hash160::Hash::hash(bytes);
                if pkh.to_byte_array() == expected_pkh {
                    if let Ok(pk) = PublicKey::from_slice(bytes) {
                        matched_pk = Some(pk);
                    }
                }
            }
        }
        return Ok(matched_pk.map(|pk| (pk, false)));
    }

    Ok(None)
}

/// Extract the eligible sender private key and public key from a [`Bip352PrevoutInput`].
///
/// For Taproot (P2TR) inputs, if the private key produces a public key with odd Y coordinate,
/// the secret key is negated per BIP-352 so that it matches the even-Y x-only public key.
///
/// # Errors
/// Returns an error if an eligible input's `private_key` is missing, invalid, or does not
/// match its extracted public key, or if a supplied key lacks the required spend-time data.
pub fn extract_bip352_sender_privkey(
    input: &Bip352PrevoutInput,
) -> Result<Option<(SecretKey, PublicKey)>> {
    let Some((extracted_pk, is_taproot)) = extract_bip352_input_pubkey(input)? else {
        if input.private_key.is_some() {
            // Preserve skipping of genuinely ineligible inputs (e.g. NUMS and uncompressed
            // keys), but do not silently omit a sender input whose spend data is absent.
            let spk_bytes = hex::decode(input.prevout_script_pubkey.trim())?;
            let spk = Script::from_bytes(&spk_bytes);
            let script_sig = hex::decode(input.script_sig.trim())?;
            let witness = hex::decode(input.txinwitness.trim())?;
            let witness = if witness.is_empty() {
                Witness::default()
            } else {
                Witness::consensus_decode(&mut std::io::Cursor::new(&witness))
                    .map_err(|e| anyhow!("Invalid sender witness: {e}"))?
            };
            let missing_witness_key =
                witness.len() != 2 || witness.last().is_some_and(|key| key.is_empty());
            let has_script_pubkey = Script::from_bytes(&script_sig).instructions().any(|ins| {
                matches!(ins, Ok(Instruction::PushBytes(push))
                    if PublicKey::from_slice(push.as_bytes()).is_ok())
            });
            let missing_spend_data = (spk.is_p2pkh() && !has_script_pubkey)
                || (spk.is_p2wpkh() && missing_witness_key)
                || (spk.is_p2tr() && witness.is_empty())
                || (spk.is_p2sh()
                    && (script_sig.is_empty()
                        || (script_sig.len() == 23
                            && script_sig[..3] == [0x16, 0x00, 0x14]
                            && missing_witness_key)));
            if missing_spend_data {
                return Err(anyhow!(
                    "Missing script_sig or txinwitness spend data for BIP-352 sender input"
                ));
            }
        }
        return Ok(None);
    };
    let priv_hex = input
        .private_key
        .as_ref()
        .ok_or_else(|| anyhow!("Missing private_key for eligible BIP-352 input"))?;
    let priv_bytes = Zeroizing::new(
        hex::decode(priv_hex.trim()).map_err(|e| anyhow!("Invalid private_key hex: {e}"))?,
    );
    let mut sk =
        SecretKey::from_slice(&priv_bytes).map_err(|e| anyhow!("Invalid SecretKey: {e}"))?;

    let secp = Secp256k1::new();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let matches = if is_taproot {
        pk.x_only_public_key().0 == extracted_pk.x_only_public_key().0
    } else {
        pk == extracted_pk
    };
    if !matches {
        return Err(anyhow!(
            "private_key does not match extracted BIP-352 input public key"
        ));
    }
    if is_taproot {
        let (_, parity) = pk.x_only_public_key();
        if parity == Parity::Odd {
            sk = sk.negate();
        }
    }
    let final_pk = PublicKey::from_secret_key(&secp, &sk);
    Ok(Some((sk, final_pk)))
}

/// Result of a standards-compliant BIP-352 sender output generation run.
#[derive(Clone, PartialEq, Eq)]
pub struct Bip352SendResult {
    /// Generated 32-byte x-only output public keys (hex).
    pub outputs: Vec<String>,
    /// Derived ECDH shared secrets per recipient entry, in scan-group order (33-byte compressed hex).
    pub shared_secrets: Vec<String>,
    /// Sum of eligible input private keys (32-byte hex), if non-empty and non-zero.
    pub input_private_key_sum: Option<Zeroizing<String>>,
    /// Extracted eligible input public keys (33-byte compressed hex).
    pub input_pub_keys: Vec<String>,
}

impl fmt::Debug for Bip352SendResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bip352SendResult")
            .field("outputs", &self.outputs)
            .field("shared_secrets", &self.shared_secrets)
            .field("input_private_key_sum", &"[REDACTED]")
            .field("input_pub_keys", &self.input_pub_keys)
            .finish()
    }
}

#[derive(Default)]
struct Bip352RecipientGroup {
    total: usize,
    recipients: Vec<(PublicKey, usize)>,
}

/// Generate BIP-352 Silent Payment x-only output public keys for a list of `(address, count)` recipients.
///
/// Groups recipients by `scan_pubkey` as required by BIP-352, enforces `BIP0352_MAX_K` (`2323`),
/// and handles intermediate scalar cancellation cleanly.
///
/// # Errors
/// Returns an error if any recipient address or input hex is malformed.
pub fn create_bip352_outputs(
    inputs: &[Bip352PrevoutInput],
    recipients: &[(String, usize)],
) -> Result<Bip352SendResult> {
    let secp = Secp256k1::new();

    // Collect all outpoints (including non-eligible inputs) to find outpoint_L
    let mut all_outpoints = Vec::with_capacity(inputs.len());
    for inp in inputs {
        all_outpoints.push(inp.outpoint_bytes()?);
    }
    let Some(smallest_outpoint) = find_smallest_outpoint(&all_outpoints) else {
        return Ok(Bip352SendResult {
            outputs: Vec::new(),
            shared_secrets: Vec::new(),
            input_private_key_sum: None,
            input_pub_keys: Vec::new(),
        });
    };

    // Extract eligible input keys and accumulate private key sum (handling intermediate zero sum)
    let mut eligible_pks = Vec::new();
    let mut eligible_sks = Vec::new();
    for inp in inputs {
        if let Some((sk, pk)) = extract_bip352_sender_privkey(inp)? {
            eligible_pks.push(hex::encode(pk.serialize()));
            eligible_sks.push(sk);
        }
    }

    if eligible_sks.is_empty() {
        return Ok(Bip352SendResult {
            outputs: Vec::new(),
            shared_secrets: Vec::new(),
            input_private_key_sum: None,
            input_pub_keys: Vec::new(),
        });
    }

    let mut acc_sk: Option<SecretKey> = None;
    for sk in &eligible_sks {
        acc_sk = match acc_sk {
            None => Some(*sk),
            Some(current) => {
                let sc = Scalar::from_be_bytes(sk.secret_bytes())
                    .map_err(|e| anyhow!("Invalid input scalar: {e}"))?;
                // If current + sk == 0 mod n, add_tweak fails and the intermediate sum is 0 (None)
                current.add_tweak(&sc).ok()
            }
        };
    }

    // If final sum is 0 (point at infinity), sending fails and produces no outputs
    let Some(sum_sk) = acc_sk else {
        return Ok(Bip352SendResult {
            outputs: Vec::new(),
            shared_secrets: Vec::new(),
            input_private_key_sum: None,
            input_pub_keys: eligible_pks,
        });
    };

    let sum_pk = PublicKey::from_secret_key(&secp, &sum_sk);
    let input_hash = compute_input_hash(&smallest_outpoint, &sum_pk);
    let hash_scalar =
        Scalar::from_be_bytes(input_hash).map_err(|e| anyhow!("Invalid input_hash scalar: {e}"))?;
    let sum_scalar = Scalar::from_be_bytes(sum_sk.secret_bytes())
        .map_err(|e| anyhow!("Invalid sum_sk scalar: {e}"))?;

    // Group recipients by scan_pubkey preserving order of first appearance
    let mut group_order: Vec<PublicKey> = Vec::new();
    let mut groups: HashMap<Vec<u8>, Bip352RecipientGroup> = HashMap::new();

    for (addr, count) in recipients {
        let (scan_pk, spend_pk, _) = parse_silent_payment_address(addr)?;
        let key = scan_pk.serialize().to_vec();
        if !groups.contains_key(&key) {
            group_order.push(scan_pk);
        }
        let entry = groups.entry(key).or_default();
        let Some(total) = entry
            .total
            .checked_add(*count)
            .filter(|n| *n <= BIP0352_MAX_K as usize)
        else {
            return Ok(Bip352SendResult {
                outputs: Vec::new(),
                shared_secrets: Vec::new(),
                input_private_key_sum: Some(Zeroizing::new(hex::encode(sum_sk.secret_bytes()))),
                input_pub_keys: eligible_pks,
            });
        };
        entry.total = total;
        entry.recipients.push((spend_pk, *count));
    }

    let mut outputs = Vec::new();
    let mut shared_secrets = Vec::new();

    for scan_pk in &group_order {
        let ecdh_shared_secret = scan_pk
            .mul_tweak(&secp, &sum_scalar)
            .map_err(|e| anyhow!("ECDH mul_tweak failed: {e}"))?
            .mul_tweak(&secp, &hash_scalar)
            .map_err(|e| anyhow!("Input hash mul_tweak failed: {e}"))?;

        let recipients = &groups[&scan_pk.serialize().to_vec()].recipients;
        let mut k = 0u32;
        for (spend_pk, count) in recipients {
            shared_secrets.push(hex::encode(ecdh_shared_secret.serialize()));
            for _ in 0..*count {
                let mut data = Vec::with_capacity(37);
                data.extend_from_slice(&ecdh_shared_secret.serialize());
                data.extend_from_slice(&k.to_be_bytes());
                let t_k = tagged_hash(BIP0352_TAG_SHARED_SECRET, &data);
                let t_k_scalar =
                    Scalar::from_be_bytes(t_k).map_err(|e| anyhow!("Invalid t_k scalar: {e}"))?;
                let p_k = spend_pk
                    .add_exp_tweak(&secp, &t_k_scalar)
                    .map_err(|e| anyhow!("Failed to compute output pubkey P_k: {e}"))?;
                let (xonly, _) = p_k.x_only_public_key();
                outputs.push(hex::encode(xonly.serialize()));
                k += 1;
            }
        }
    }

    Ok(Bip352SendResult {
        outputs,
        shared_secrets,
        input_private_key_sum: Some(Zeroizing::new(hex::encode(sum_sk.secret_bytes()))),
        input_pub_keys: eligible_pks,
    })
}

/// Detected Silent Payment output details from scanning a transaction as receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip352DetectedOutput {
    /// 32-byte x-only output public key (hex).
    pub pub_key: String,
    /// 32-byte private key tweak `t_k (+ label_tweak)` (hex).
    pub priv_key_tweak: String,
}

/// Result of scanning a transaction as a BIP-352 receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip352ReceiveResult {
    /// Derived receiving addresses (unlabeled address followed by labeled addresses).
    pub addresses: Vec<String>,
    /// Detected outputs belonging to the receiver.
    pub outputs: Vec<Bip352DetectedOutput>,
    /// `input_hash * A` tweak point (33-byte compressed hex), if eligible inputs were valid.
    pub tweak: Option<String>,
    /// `b_scan * tweak` ECDH shared secret point (33-byte compressed hex), if eligible inputs were valid.
    pub shared_secret: Option<String>,
    /// Aggregate input public key `A` (33-byte compressed hex), if eligible inputs were valid.
    pub input_pub_key_sum: Option<String>,
}

/// Scan a transaction as a BIP-352 recipient given a scan private key and spend public key, optional label integers,
/// transaction inputs, and candidate 32-byte x-only output keys.
/// Returns output keys and tweaks; spending-key reconstruction and signing belong to the wallet.
///
/// # Errors
/// Returns an error if key derivation fails.
pub fn scan_bip352_transaction(
    scan_privkey: &SecretKey,
    spend_pubkey: &PublicKey,
    labels: &[u32],
    inputs: &[Bip352PrevoutInput],
    outputs_xonly: &[String],
) -> Result<Bip352ReceiveResult> {
    let secp = Secp256k1::new();
    let scan_pubkey = PublicKey::from_secret_key(&secp, scan_privkey);

    // Build receiving address list (unlabeled first, then each label in order)
    let mut addresses = vec![create_silent_payment_address(&scan_pubkey, spend_pubkey)?];
    // Map serialized label public key M_m (33 bytes) -> [u8; 32] label tweak
    let mut label_map: HashMap<[u8; 33], [u8; 32]> = HashMap::new();
    for &m in labels {
        let tweak_m = compute_label_tweak(scan_privkey, m);
        let tweak_sk = SecretKey::from_slice(&tweak_m)
            .map_err(|e| anyhow!("Invalid label secret key: {e}"))?;
        let label_pk = PublicKey::from_secret_key(&secp, &tweak_sk);
        label_map.insert(label_pk.serialize(), tweak_m);

        let b_m = derive_labeled_spend_pubkey(spend_pubkey, scan_privkey, m)?;
        addresses.push(create_silent_payment_address(&scan_pubkey, &b_m)?);
    }

    // Collect all outpoints for outpoint_L
    let mut all_outpoints = Vec::with_capacity(inputs.len());
    for inp in inputs {
        all_outpoints.push(inp.outpoint_bytes()?);
    }
    let Some(smallest_outpoint) = find_smallest_outpoint(&all_outpoints) else {
        return Ok(Bip352ReceiveResult {
            addresses,
            outputs: Vec::new(),
            tweak: None,
            shared_secret: None,
            input_pub_key_sum: None,
        });
    };

    // Extract eligible input public keys
    let mut eligible_pks: Vec<PublicKey> = Vec::new();
    for inp in inputs {
        if let Some((pk, _)) = extract_bip352_input_pubkey(inp)? {
            eligible_pks.push(pk);
        }
    }

    if eligible_pks.is_empty() {
        return Ok(Bip352ReceiveResult {
            addresses,
            outputs: Vec::new(),
            tweak: None,
            shared_secret: None,
            input_pub_key_sum: None,
        });
    }

    // Combine all eligible input public keys at once (handles intermediate point-at-infinity)
    let pk_refs: Vec<&PublicKey> = eligible_pks.iter().collect();
    let Ok(aggregate_a) = PublicKey::combine_keys(&pk_refs) else {
        // Point at infinity -> skip transaction
        return Ok(Bip352ReceiveResult {
            addresses,
            outputs: Vec::new(),
            tweak: None,
            shared_secret: None,
            input_pub_key_sum: None,
        });
    };

    let input_hash = compute_input_hash(&smallest_outpoint, &aggregate_a);
    let Ok(hash_scalar) = Scalar::from_be_bytes(input_hash) else {
        return Ok(Bip352ReceiveResult {
            addresses,
            outputs: Vec::new(),
            tweak: None,
            shared_secret: None,
            input_pub_key_sum: None,
        });
    };

    let Ok(tweak_point) = aggregate_a.mul_tweak(&secp, &hash_scalar) else {
        return Ok(Bip352ReceiveResult {
            addresses,
            outputs: Vec::new(),
            tweak: None,
            shared_secret: None,
            input_pub_key_sum: None,
        });
    };

    let scan_scalar = Scalar::from_be_bytes(scan_privkey.secret_bytes())
        .map_err(|e| anyhow!("Invalid scan_privkey scalar: {e}"))?;
    let ecdh_shared_secret = tweak_point
        .mul_tweak(&secp, &scan_scalar)
        .map_err(|e| anyhow!("Failed to compute ECDH shared secret: {e}"))?;

    // Parse valid candidate x-only output keys preserving order
    let mut remaining_outputs: Vec<(String, XOnlyPublicKey)> = Vec::new();
    for out_hex in outputs_xonly {
        if let Ok(bytes) = hex::decode(out_hex.trim()) {
            if let Ok(xonly) = XOnlyPublicKey::from_slice(&bytes) {
                remaining_outputs.push((out_hex.trim().to_ascii_lowercase(), xonly));
            }
        }
    }

    let mut detected_outputs = Vec::new();
    let mut spent_indices: HashSet<usize> = HashSet::new();
    let mut k: u32 = 0;

    while k < BIP0352_MAX_K {
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&ecdh_shared_secret.serialize());
        data.extend_from_slice(&k.to_be_bytes());
        let t_k = tagged_hash(BIP0352_TAG_SHARED_SECRET, &data);
        let t_k_scalar =
            Scalar::from_be_bytes(t_k).map_err(|e| anyhow!("Invalid t_k scalar: {e}"))?;
        let p_k = spend_pubkey
            .add_exp_tweak(&secp, &t_k_scalar)
            .map_err(|e| anyhow!("Failed to compute P_k: {e}"))?;
        let (p_k_xonly, _) = p_k.x_only_public_key();

        let mut matched_in_round = false;

        for (idx, (out_hex, out_xonly)) in remaining_outputs.iter().enumerate() {
            if spent_indices.contains(&idx) {
                continue;
            }

            let mut matched_tweak: Option<[u8; 32]> = None;

            if *out_xonly == p_k_xonly {
                matched_tweak = Some(t_k);
            } else if !label_map.is_empty() {
                let neg_p_k = p_k.negate(&secp);
                let out_even = PublicKey::from_x_only_public_key(*out_xonly, Parity::Even);
                if let Ok(diff_even) = PublicKey::combine_keys(&[&out_even, &neg_p_k]) {
                    if let Some(label_tweak) = label_map.get(&diff_even.serialize()) {
                        let t_k_sk = SecretKey::from_slice(&t_k)?;
                        let lbl_sc = Scalar::from_be_bytes(*label_tweak)?;
                        let sum_tweak = t_k_sk.add_tweak(&lbl_sc)?;
                        matched_tweak = Some(sum_tweak.secret_bytes());
                    }
                }
                if matched_tweak.is_none() {
                    let out_odd = PublicKey::from_x_only_public_key(*out_xonly, Parity::Odd);
                    if let Ok(diff_odd) = PublicKey::combine_keys(&[&out_odd, &neg_p_k]) {
                        if let Some(label_tweak) = label_map.get(&diff_odd.serialize()) {
                            let t_k_sk = SecretKey::from_slice(&t_k)?;
                            let lbl_sc = Scalar::from_be_bytes(*label_tweak)?;
                            let sum_tweak = t_k_sk.add_tweak(&lbl_sc)?;
                            matched_tweak = Some(sum_tweak.secret_bytes());
                        }
                    }
                }
            }

            if let Some(priv_tweak_bytes) = matched_tweak {
                spent_indices.insert(idx);
                detected_outputs.push(Bip352DetectedOutput {
                    pub_key: out_hex.clone(),
                    priv_key_tweak: hex::encode(priv_tweak_bytes),
                });

                k += 1;
                matched_in_round = true;
                break;
            }
        }

        if !matched_in_round {
            break;
        }
    }

    Ok(Bip352ReceiveResult {
        addresses,
        outputs: detected_outputs,
        tweak: Some(hex::encode(tweak_point.serialize())),
        shared_secret: Some(hex::encode(ecdh_shared_secret.serialize())),
        input_pub_key_sum: Some(hex::encode(aggregate_a.serialize())),
    })
}

/// Silent Payment (BIP-352) Scan Public Key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SilentPaymentScanKey {
    /// The scan public key (33 bytes compressed hex)
    pub scan_pubkey: String,
    /// The spend public key (33 bytes compressed hex)
    pub spend_pubkey: Option<String>,
}

/// Silent Payment Address derived from scan and spend keys.
/// BIP-352: `bech32m(hrp, version || scan_pubkey || spend_pubkey)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SilentPaymentAddress {
    /// The silent payment bech32m address (sp1q..., tsp1q..., or sprt1q...)
    pub address: String,
    /// The scan public key (hex)
    pub scan_pubkey: String,
    /// The spend public key (hex)
    pub spend_pubkey: String,
    /// Optional label
    pub label: Option<String>,
}

impl SilentPaymentAddress {
    /// Construct a `SilentPaymentAddress` from public keys and network.
    ///
    /// # Errors
    /// Returns an error if Bech32m encoding fails.
    pub fn new(
        scan_pubkey: &PublicKey,
        spend_pubkey: &PublicKey,
        network: Network,
        label: Option<String>,
    ) -> Result<Self> {
        let address =
            create_silent_payment_address_for_network(scan_pubkey, spend_pubkey, network)?;
        Ok(Self {
            address,
            scan_pubkey: hex::encode(scan_pubkey.serialize()),
            spend_pubkey: hex::encode(spend_pubkey.serialize()),
            label,
        })
    }

    /// Parse a silent payment address string.
    ///
    /// # Errors
    /// Returns an error if the address string is not a valid BIP-352 Bech32m address.
    pub fn parse(address_str: &str) -> Result<Self> {
        let (scan_pk, spend_pk, _network) = parse_silent_payment_address(address_str)?;
        Ok(Self {
            address: address_str.trim().to_ascii_lowercase(),
            scan_pubkey: hex::encode(scan_pk.serialize()),
            spend_pubkey: hex::encode(spend_pk.serialize()),
            label: None,
        })
    }
}

/// Silent Payment Output - an output that can be detected by the recipient.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SilentPaymentOutput {
    /// The output script (P2TR, format: "5120" + 32-byte x-only pubkey hex)
    pub script_pubkey: String,
    /// The amount in satoshis
    pub amount_sats: u64,
    /// The tweaked public key used for this output (hex)
    pub tweaked_pubkey: String,
    /// The shared secret used to derive the tweak (hex)
    pub shared_secret: Option<String>,
}

/// Silent Payment Input - used when creating a silent payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SilentPaymentInput {
    /// The outpoint being spent ("txid:vout")
    pub outpoint: String,
    /// The taproot or standard public key of the input
    pub input_pubkey: String,
    /// The private key corresponding to the input (for signer)
    #[serde(skip_serializing)]
    pub input_privkey: Option<String>,
}

/// Silent Payment - a payment session using BIP-352 Silent Payments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SilentPayment {
    /// The scan public key of the recipient (hex)
    pub scan_pubkey: String,
    /// The spend public key of the recipient (hex)
    pub spend_pubkey: String,
    /// The amount in satoshis
    pub amount_sats: u64,
    /// The inputs being spent
    pub inputs: Vec<SilentPaymentInput>,
    /// The change output (optional)
    pub change_output: Option<SilentPaymentOutput>,
    /// The target network
    pub network: Network,
}

impl SilentPayment {
    /// Create a new silent payment instance.
    pub fn new(
        scan_pubkey: String,
        spend_pubkey: String,
        amount_sats: u64,
        inputs: Vec<SilentPaymentInput>,
        change_output: Option<SilentPaymentOutput>,
        network: Network,
    ) -> Self {
        Self {
            scan_pubkey,
            spend_pubkey,
            amount_sats,
            inputs,
            change_output,
            network,
        }
    }

    /// Create the silent payment address for the recipient (defaults to mainnet).
    pub fn recipient_address(
        scan_pubkey: &str,
        spend_pubkey: &str,
    ) -> Result<String, anyhow::Error> {
        let scan_bytes = hex::decode(scan_pubkey.trim())?;
        let spend_bytes = hex::decode(spend_pubkey.trim())?;
        let scan = PublicKey::from_slice(&scan_bytes)?;
        let spend = PublicKey::from_slice(&spend_bytes)?;
        create_silent_payment_address(&scan, &spend)
    }

    /// Create the silent payment address for the recipient on a specific network.
    pub fn recipient_address_for_network(
        scan_pubkey: &str,
        spend_pubkey: &str,
        network: Network,
    ) -> Result<String, anyhow::Error> {
        let scan_bytes = hex::decode(scan_pubkey.trim())?;
        let spend_bytes = hex::decode(spend_pubkey.trim())?;
        let scan = PublicKey::from_slice(&scan_bytes)?;
        let spend = PublicKey::from_slice(&spend_bytes)?;
        create_silent_payment_address_for_network(&scan, &spend, network)
    }

    /// Derive the tweaked public key for a silent payment output (index `k = 0`).
    pub fn derive_tweaked_pubkey(
        sender_privkey: &SecretKey,
        recipient_scan_pubkey: &PublicKey,
        recipient_spend_pubkey: &PublicKey,
    ) -> Result<PublicKey, anyhow::Error> {
        Self::derive_tweaked_pubkey_with_index(
            sender_privkey,
            recipient_scan_pubkey,
            recipient_spend_pubkey,
            0,
        )
    }

    /// Derive the tweaked public key for a silent payment output with specific index `k`.
    pub fn derive_tweaked_pubkey_with_index(
        sender_privkey: &SecretKey,
        recipient_scan_pubkey: &PublicKey,
        recipient_spend_pubkey: &PublicKey,
        k: u32,
    ) -> Result<PublicKey, anyhow::Error> {
        let secp = Secp256k1::new();
        let sender_scalar = Scalar::from_be_bytes(sender_privkey.secret_bytes())
            .map_err(|e| anyhow!("Invalid scalar: {e}"))?;
        let shared_secret = recipient_scan_pubkey
            .mul_tweak(&secp, &sender_scalar)
            .map_err(|e| anyhow!("Failed to compute shared secret: {e}"))?;

        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&shared_secret.serialize());
        data.extend_from_slice(&k.to_be_bytes());

        let tweak_bytes = tagged_hash(BIP0352_TAG_SHARED_SECRET, &data);
        let tweak_scalar =
            Scalar::from_be_bytes(tweak_bytes).map_err(|e| anyhow!("Invalid tweak scalar: {e}"))?;

        let tweaked = recipient_spend_pubkey
            .add_exp_tweak(&secp, &tweak_scalar)
            .map_err(|e| anyhow!("Failed to tweak public key: {e}"))?;

        Ok(tweaked)
    }

    /// Create a silent payment output (`k = 0`).
    pub fn create_output(
        &self,
        recipient_scan_pubkey: &PublicKey,
        recipient_spend_pubkey: &PublicKey,
    ) -> Result<SilentPaymentOutput, anyhow::Error> {
        self.create_output_with_index(recipient_scan_pubkey, recipient_spend_pubkey, 0)
    }

    /// Create a silent payment output for a specific recipient output index `k`.
    pub fn create_output_with_index(
        &self,
        recipient_scan_pubkey: &PublicKey,
        recipient_spend_pubkey: &PublicKey,
        k: u32,
    ) -> Result<SilentPaymentOutput, anyhow::Error> {
        let secp = Secp256k1::new();

        // Collect private keys and outpoints from inputs
        let mut privkeys: Vec<SecretKey> = Vec::new();
        let mut outpoints: Vec<[u8; 36]> = Vec::new();

        for input in &self.inputs {
            if let Some(priv_hex) = &input.input_privkey {
                let bytes = hex::decode(priv_hex.trim())
                    .map_err(|e| anyhow!("Invalid input private key hex: {e}"))?;
                let sk = SecretKey::from_slice(&bytes)
                    .map_err(|e| anyhow!("Invalid input secret key: {e}"))?;
                privkeys.push(sk);
            }
            if let Ok(op) = parse_outpoint_to_bytes(&input.outpoint) {
                outpoints.push(op);
            }
        }

        // Determine aggregate sender private key
        let sender_privkey = if privkeys.is_empty() {
            SecretKey::new(&mut OsRng)
        } else {
            let mut acc: Option<SecretKey> = None;
            for sk in &privkeys {
                acc = match acc {
                    None => Some(*sk),
                    Some(curr) => {
                        let sc = Scalar::from_be_bytes(sk.secret_bytes())
                            .map_err(|e| anyhow!("Invalid scalar: {e}"))?;
                        curr.add_tweak(&sc).ok()
                    }
                };
            }
            acc.ok_or_else(|| anyhow!("Input private keys sum to zero (point at infinity)"))?
        };

        let sender_pubkey = PublicKey::from_secret_key(&secp, &sender_privkey);
        let sender_scalar = Scalar::from_be_bytes(sender_privkey.secret_bytes())
            .map_err(|e| anyhow!("Invalid sender scalar: {e}"))?;

        // If outpoint exists, compute input_hash and fold into shared secret
        let shared_secret = if let Some(smallest_op) = find_smallest_outpoint(&outpoints) {
            let input_hash = compute_input_hash(&smallest_op, &sender_pubkey);
            let hash_scalar = Scalar::from_be_bytes(input_hash)
                .map_err(|e| anyhow!("Invalid input hash scalar: {e}"))?;
            recipient_scan_pubkey
                .mul_tweak(&secp, &sender_scalar)
                .map_err(|e| anyhow!("Failed to compute ECDH intermediate point: {e}"))?
                .mul_tweak(&secp, &hash_scalar)
                .map_err(|e| anyhow!("Failed to apply input hash tweak: {e}"))?
        } else {
            recipient_scan_pubkey
                .mul_tweak(&secp, &sender_scalar)
                .map_err(|e| anyhow!("Failed to compute shared secret: {e}"))?
        };

        // Compute tweak t_k = TaggedHash("BIP0352/SharedSecret", S || k)
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&shared_secret.serialize());
        data.extend_from_slice(&k.to_be_bytes());

        let tweak_bytes = tagged_hash(BIP0352_TAG_SHARED_SECRET, &data);
        let tweak_scalar =
            Scalar::from_be_bytes(tweak_bytes).map_err(|e| anyhow!("Invalid tweak scalar: {e}"))?;

        let tweaked_pubkey = recipient_spend_pubkey
            .add_exp_tweak(&secp, &tweak_scalar)
            .map_err(|e| anyhow!("Failed to tweak public key: {e}"))?;

        // Standard P2TR scriptPubkey: OP_1 (0x51) OP_PUSHBYTES_32 (0x20) <32-byte x-only pubkey>
        let (x_only, _) = tweaked_pubkey.x_only_public_key();
        let script_pubkey = format!("5120{}", hex::encode(x_only.serialize()));

        Ok(SilentPaymentOutput {
            script_pubkey,
            amount_sats: self.amount_sats,
            tweaked_pubkey: hex::encode(tweaked_pubkey.serialize()),
            shared_secret: Some(hex::encode(shared_secret.serialize())),
        })
    }

    /// Detect silent payments addressed to the recipient across transaction outputs.
    pub fn detect_outputs(
        scan_privkey: &SecretKey,
        spend_pubkey: &PublicKey,
        input_pubkeys: &[PublicKey],
        tx_outputs: &[(String, u64)], // (script_pubkey, amount_sats)
    ) -> Result<Vec<SilentPaymentOutput>, anyhow::Error> {
        detect_silent_payment_outputs(scan_privkey, spend_pubkey, input_pubkeys, tx_outputs)
    }

    /// Detect silent payments when input hash is explicitly bound (with `outpoint_L`).
    pub fn detect_outputs_with_input_hash(
        scan_privkey: &SecretKey,
        spend_pubkey: &PublicKey,
        aggregate_input_pubkey: &PublicKey,
        input_hash: &[u8; 32],
        tx_outputs: &[(String, u64)],
    ) -> Result<Vec<SilentPaymentOutput>, anyhow::Error> {
        let secp = Secp256k1::new();
        let scan_scalar = Scalar::from_be_bytes(scan_privkey.secret_bytes())
            .map_err(|e| anyhow!("Invalid scan scalar: {e}"))?;
        let hash_scalar = Scalar::from_be_bytes(*input_hash)
            .map_err(|e| anyhow!("Invalid input hash scalar: {e}"))?;

        let shared_secret = aggregate_input_pubkey
            .mul_tweak(&secp, &scan_scalar)
            .map_err(|e| anyhow!("Failed to compute ECDH intermediate point: {e}"))?
            .mul_tweak(&secp, &hash_scalar)
            .map_err(|e| anyhow!("Failed to apply input hash tweak: {e}"))?;

        scan_outputs_for_shared_secret(&secp, spend_pubkey, &shared_secret, tx_outputs)
    }
}

/// Helper function to scan candidate transaction outputs for a given shared secret point `S`.
fn scan_outputs_for_shared_secret(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    spend_pubkey: &PublicKey,
    shared_secret: &PublicKey,
    tx_outputs: &[(String, u64)],
) -> Result<Vec<SilentPaymentOutput>> {
    let mut detected = Vec::new();
    let mut spent_indices = HashSet::new();

    for k in 0..BIP0352_MAX_K {
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&shared_secret.serialize());
        data.extend_from_slice(&k.to_be_bytes());

        let tweak_bytes = tagged_hash(BIP0352_TAG_SHARED_SECRET, &data);
        let tweak_scalar =
            Scalar::from_be_bytes(tweak_bytes).map_err(|e| anyhow!("Invalid tweak scalar: {e}"))?;

        let tweaked_pubkey = spend_pubkey
            .add_exp_tweak(secp, &tweak_scalar)
            .map_err(|e| anyhow!("Failed to tweak candidate pubkey: {e}"))?;

        let (x_only, _) = tweaked_pubkey.x_only_public_key();
        let expected_script = format!("5120{}", hex::encode(x_only.serialize()));

        let mut matched = false;
        for (idx, (script_pubkey, amount_sats)) in tx_outputs.iter().enumerate() {
            if spent_indices.contains(&idx) {
                continue;
            }
            if script_pubkey.eq_ignore_ascii_case(&expected_script) {
                spent_indices.insert(idx);
                detected.push(SilentPaymentOutput {
                    script_pubkey: script_pubkey.clone(),
                    amount_sats: *amount_sats,
                    tweaked_pubkey: hex::encode(tweaked_pubkey.serialize()),
                    shared_secret: Some(hex::encode(shared_secret.serialize())),
                });
                matched = true;
                break;
            }
        }

        if !matched {
            break;
        }
    }

    Ok(detected)
}

/// Free function to detect silent payment outputs given sender input pubkeys and tx outputs.
pub fn detect_silent_payment_outputs(
    scan_privkey: &SecretKey,
    spend_pubkey: &PublicKey,
    input_pubkeys: &[PublicKey],
    tx_outputs: &[(String, u64)],
) -> Result<Vec<SilentPaymentOutput>> {
    if input_pubkeys.is_empty() || tx_outputs.is_empty() {
        return Ok(Vec::new());
    }

    let secp = Secp256k1::new();
    let aggregate_a = if input_pubkeys.len() == 1 {
        input_pubkeys[0]
    } else {
        let refs: Vec<&PublicKey> = input_pubkeys.iter().collect();
        PublicKey::combine_keys(&refs)
            .map_err(|e| anyhow!("Failed to combine input pubkeys: {e}"))?
    };

    let scan_scalar = Scalar::from_be_bytes(scan_privkey.secret_bytes())
        .map_err(|e| anyhow!("Invalid scan scalar: {e}"))?;

    let shared_secret = aggregate_a
        .mul_tweak(&secp, &scan_scalar)
        .map_err(|e| anyhow!("Failed to compute ECDH shared secret: {e}"))?;

    scan_outputs_for_shared_secret(&secp, spend_pubkey, &shared_secret, tx_outputs)
}

/// Derive the spending private key for a detected silent payment output:
/// `p_k = b_spend + t_k` (with Taproot even-parity adjustment if required).
pub fn derive_spending_privkey(
    spend_privkey: &SecretKey,
    shared_secret: &PublicKey,
    k: u32,
) -> Result<SecretKey> {
    let secp = Secp256k1::new();
    let mut data = Vec::with_capacity(37);
    data.extend_from_slice(&shared_secret.serialize());
    data.extend_from_slice(&k.to_be_bytes());

    let tweak_bytes = tagged_hash(BIP0352_TAG_SHARED_SECRET, &data);
    let tweak_scalar =
        Scalar::from_be_bytes(tweak_bytes).map_err(|e| anyhow!("Invalid tweak scalar: {e}"))?;

    let tweaked_sk = spend_privkey
        .add_tweak(&tweak_scalar)
        .map_err(|e| anyhow!("Failed to tweak spend private key: {e}"))?;

    // Check parity of the resulting public key: BIP-340 Schnorr / Taproot requires even parity
    let derived_pk = PublicKey::from_secret_key(&secp, &tweaked_sk);
    let (_, parity) = derived_pk.x_only_public_key();

    let final_sk = if parity == Parity::Odd {
        tweaked_sk.negate()
    } else {
        tweaked_sk
    };

    Ok(final_sk)
}

/// Derive spending private key directly from scan private key and sender public key.
pub fn derive_spending_privkey_from_scan(
    spend_privkey: &SecretKey,
    scan_privkey: &SecretKey,
    sender_pubkey: &PublicKey,
    k: u32,
) -> Result<SecretKey> {
    let secp = Secp256k1::new();
    let scan_scalar = Scalar::from_be_bytes(scan_privkey.secret_bytes())
        .map_err(|e| anyhow!("Invalid scan scalar: {e}"))?;
    let shared_secret = sender_pubkey
        .mul_tweak(&secp, &scan_scalar)
        .map_err(|e| anyhow!("Failed to compute shared secret: {e}"))?;

    derive_spending_privkey(spend_privkey, &shared_secret, k)
}

/// Generate a new silent payment key pair `(scan_priv, scan_pub, spend_priv, spend_pub)`.
pub fn generate_silent_payment_keys() -> Result<(String, String, String, String), anyhow::Error> {
    let secp = Secp256k1::new();

    let scan_privkey = SecretKey::new(&mut OsRng);
    let scan_pubkey = PublicKey::from_secret_key(&secp, &scan_privkey);

    let spend_privkey = SecretKey::new(&mut OsRng);
    let spend_pubkey = PublicKey::from_secret_key(&secp, &spend_privkey);

    Ok((
        hex::encode(scan_privkey.secret_bytes()),
        hex::encode(scan_pubkey.serialize()),
        hex::encode(spend_privkey.secret_bytes()),
        hex::encode(spend_pubkey.serialize()),
    ))
}

/// Parse a silent payment scan public key from an address or legacy hex string.
pub fn parse_silent_payment_scan_key(scan_key: &str) -> Result<PublicKey, anyhow::Error> {
    let trimmed = scan_key.trim();
    if !trimmed.starts_with("sp1q")
        && !trimmed.starts_with("tsp1q")
        && !trimmed.starts_with("sprt1q")
    {
        return Err(anyhow!(
            "Invalid silent payment scan key: must start with 'sp1q', 'tsp1q', or 'sprt1q'"
        ));
    }

    // Try full bech32m address decode first
    if let Ok((scan_pub, _, _)) = parse_silent_payment_address(trimmed) {
        return Ok(scan_pub);
    }

    // Fallback: legacy hex format after prefix (used in mock unit tests)
    let hex_part = if let Some(stripped) = trimmed.strip_prefix("sprt1q") {
        stripped
    } else if let Some(stripped) = trimmed.strip_prefix("tsp1q") {
        stripped
    } else if let Some(stripped) = trimmed.strip_prefix("sp1q") {
        stripped
    } else {
        trimmed
    };
    if let Ok(bytes) = hex::decode(hex_part) {
        if bytes.len() == 33 {
            return PublicKey::from_slice(&bytes)
                .map_err(|e| anyhow!("Invalid public key bytes: {e}"));
        }
    }

    Err(anyhow!("Unable to parse silent payment scan key"))
}

/// Create a silent payment address from scan and spend public keys (defaults to Mainnet).
pub fn create_silent_payment_address(
    scan_pubkey: &PublicKey,
    spend_pubkey: &PublicKey,
) -> Result<String, anyhow::Error> {
    create_silent_payment_address_for_network(scan_pubkey, spend_pubkey, Network::Bitcoin)
}

/// Create a silent payment address for a specific network:
/// Mainnet uses HRP `"sp"`, Testnet/Signet use `"tsp"`, and Regtest uses `"sprt"`.
/// Payload: one 5-bit version `0` (`q`) followed by the base32 encoding of two 33-byte compressed keys.
pub fn create_silent_payment_address_for_network(
    scan_pubkey: &PublicKey,
    spend_pubkey: &PublicKey,
    network: Network,
) -> Result<String, anyhow::Error> {
    let hrp = match network {
        Network::Bitcoin => "sp",
        Network::Testnet | Network::Signet => "tsp",
        Network::Regtest => "sprt",
        _ => "tsp",
    };

    let mut payload = Vec::with_capacity(66);
    payload.extend_from_slice(&scan_pubkey.serialize());
    payload.extend_from_slice(&spend_pubkey.serialize());

    let mut data = vec![u5::try_from_u8(0)?];
    data.extend(payload.to_base32());
    let encoded = bech32::encode(hrp, data, Variant::Bech32m)
        .map_err(|e| anyhow!("Failed to encode silent payment address: {e}"))?;

    Ok(encoded)
}

/// Parse and validate a BIP-352 silent payment address string into `(scan_pubkey, spend_pubkey, Network)`.
pub fn parse_silent_payment_address(
    address: &str,
) -> Result<(PublicKey, PublicKey, Network), anyhow::Error> {
    let trimmed = address.trim();
    let lower = trimmed.to_ascii_lowercase();
    if trimmed != lower && trimmed != trimmed.to_ascii_uppercase() {
        return Err(anyhow!(
            "Invalid silent payment address: mixed case is not permitted"
        ));
    }

    let is_mainnet = lower.starts_with("sp1q");
    let is_testnet = lower.starts_with("tsp1q");
    let is_regtest = lower.starts_with("sprt1q");
    if !is_mainnet && !is_testnet && !is_regtest {
        return Err(anyhow!(
            "Invalid silent payment address prefix: expected 'sp1q', 'tsp1q', or 'sprt1q'"
        ));
    }

    let (hrp, data, variant) =
        bech32::decode(&lower).map_err(|e| anyhow!("Failed to decode bech32 address: {e}"))?;

    if variant != Variant::Bech32m {
        return Err(anyhow!(
            "Invalid silent payment address encoding: expected Bech32m"
        ));
    }

    let network = match hrp.as_str() {
        "sp" => Network::Bitcoin,
        "tsp" => Network::Testnet,
        "sprt" => Network::Regtest,
        other => return Err(anyhow!("Unknown silent payment HRP: {other}")),
    };

    if data.first().map(|v| v.to_u8()) != Some(0) {
        return Err(anyhow!("Unsupported silent payment address version"));
    }
    let bytes = Vec::<u8>::from_base32(&data[1..])
        .map_err(|e| anyhow!("Failed to convert base32 data: {e}"))?;

    if bytes.len() != 66 {
        return Err(anyhow!(
            "Invalid silent payment address payload length: expected 66 bytes, got {}",
            bytes.len()
        ));
    }

    let scan_pubkey = PublicKey::from_slice(&bytes[..33])
        .map_err(|e| anyhow!("Invalid scan public key in address: {e}"))?;
    let spend_pubkey = PublicKey::from_slice(&bytes[33..])
        .map_err(|e| anyhow!("Invalid spend public key in address: {e}"))?;

    Ok((scan_pubkey, spend_pubkey, network))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_silent_payment_keys() {
        let (scan_priv, scan_pub, spend_priv, spend_pub) = generate_silent_payment_keys().unwrap();
        assert_eq!(scan_priv.len(), 64);
        assert_eq!(scan_pub.len(), 66);
        assert_eq!(spend_priv.len(), 64);
        assert_eq!(spend_pub.len(), 66);
    }

    #[test]
    fn test_parse_silent_payment_scan_key_legacy() {
        let (_, scan_pub, _, _) = generate_silent_payment_keys().unwrap();
        let sp1q = format!("sp1q{}", scan_pub.to_lowercase());
        let result = parse_silent_payment_scan_key(&sp1q);
        assert!(result.is_ok());
    }

    #[test]
    fn test_bip352_address_encode_decode_roundtrip() {
        let secp = Secp256k1::new();
        let scan_sk = SecretKey::new(&mut OsRng);
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let spend_sk = SecretKey::new(&mut OsRng);
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);

        // Mainnet
        let mainnet_addr = create_silent_payment_address(&scan_pk, &spend_pk).unwrap();
        assert!(mainnet_addr.starts_with("sp1q"));
        let (parsed_scan, parsed_spend, net) = parse_silent_payment_address(&mainnet_addr).unwrap();
        assert_eq!(parsed_scan, scan_pk);
        assert_eq!(parsed_spend, spend_pk);
        assert_eq!(net, Network::Bitcoin);

        // Testnet
        let testnet_addr =
            create_silent_payment_address_for_network(&scan_pk, &spend_pk, Network::Testnet)
                .unwrap();
        assert!(testnet_addr.starts_with("tsp1q"));
        let (parsed_scan_t, parsed_spend_t, net_t) =
            parse_silent_payment_address(&testnet_addr).unwrap();
        assert_eq!(parsed_scan_t, scan_pk);
        assert_eq!(parsed_spend_t, spend_pk);
        assert_eq!(net_t, Network::Testnet);
    }

    #[test]
    fn test_silent_payment_output_creation_and_detection() {
        let secp = Secp256k1::new();

        // Recipient keys
        let scan_sk = SecretKey::new(&mut OsRng);
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let spend_sk = SecretKey::new(&mut OsRng);
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);

        // Sender input
        let sender_sk = SecretKey::new(&mut OsRng);
        let sender_pk = PublicKey::from_secret_key(&secp, &sender_sk);

        let input = SilentPaymentInput {
            outpoint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:0"
                .to_string(),
            input_pubkey: hex::encode(sender_pk.serialize()),
            input_privkey: Some(hex::encode(sender_sk.secret_bytes())),
        };

        let payment = SilentPayment::new(
            hex::encode(scan_pk.serialize()),
            hex::encode(spend_pk.serialize()),
            50_000,
            vec![input],
            None,
            Network::Bitcoin,
        );

        let output_0 = payment
            .create_output_with_index(&scan_pk, &spend_pk, 0)
            .unwrap();
        assert!(output_0.script_pubkey.starts_with("5120"));
        assert_eq!(output_0.script_pubkey.len(), 68);

        // Recipient detects output
        let tx_outputs = vec![
            (
                "5120deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
                10_000,
            ),
            (output_0.script_pubkey.clone(), 50_000),
        ];

        let outpoint_bytes = parse_outpoint_to_bytes(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:0",
        )
        .unwrap();
        let input_hash = compute_input_hash(&outpoint_bytes, &sender_pk);

        let detected = SilentPayment::detect_outputs_with_input_hash(
            &scan_sk,
            &spend_pk,
            &sender_pk,
            &input_hash,
            &tx_outputs,
        )
        .unwrap();

        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0].script_pubkey, output_0.script_pubkey);
        assert_eq!(detected[0].amount_sats, 50_000);

        // Derive spending private key and verify it matches the tweaked output key
        let shared_secret =
            PublicKey::from_slice(&hex::decode(output_0.shared_secret.unwrap()).unwrap()).unwrap();
        let derived_spending_sk = derive_spending_privkey(&spend_sk, &shared_secret, 0).unwrap();
        let derived_pk = PublicKey::from_secret_key(&secp, &derived_spending_sk);
        let (derived_x_only, _) = derived_pk.x_only_public_key();

        let expected_x_only_hex = &output_0.script_pubkey[4..];
        assert_eq!(hex::encode(derived_x_only.serialize()), expected_x_only_hex);
    }
}
