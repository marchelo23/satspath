//! BOLT12 — Standards-Compliant Offers, TLV Merkle Signing, Blinded Paths, and Onion Messaging.
//!
//! Implements the BOLT #12 Offer protocol and BOLT #4 Blinded Path wire format:
//! - Checksumless Bech32 string encoding/decoding (`NoChecksum`) with `+` whitespace continuation.
//! - All-TLV Merkle tree root hashing (`LnLeaf`, `LnNonce` + `all-tlvs`, `LnBranch`) and
//!   BIP-340 Schnorr signature generation/verification (`lightning` || `messagename` || `signature`).
//! - BOLT #4 wire-format `BlindedPath` encoding/decoding supporting 33-byte `pubkey` and
//!   9-byte `sciddir` introduction nodes, `u8` hop counts, and `u16` encrypted payload lengths.
//! - Interactive `invoice_request` payload construction, blinded path resolution, and
//!   `OnionMessageTransport` adapters for Core Lightning (CLN) and LDK interoperability.

use std::io::{Cursor, Read};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use bech32::FromBase32;
use bitcoin::bech32::primitives::decode::CheckedHrpstring;
use bitcoin::bech32::primitives::NoChecksum;
use bitcoin::bech32::Hrp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ============================================================================
// BOLT12 TLV Tags (BOLT #12 Specification)
// ============================================================================

/// Offer chains TLV tag (`2`).
pub const TLV_OFFER_CHAINS: u64 = 2;
/// Offer metadata TLV tag (`4`).
pub const TLV_OFFER_METADATA: u64 = 4;
/// Offer currency TLV tag (`6`).
pub const TLV_OFFER_CURRENCY: u64 = 6;
/// Offer amount TLV tag (`8`).
pub const TLV_OFFER_AMOUNT: u64 = 8;
/// Offer description TLV tag (`10`).
pub const TLV_OFFER_DESCRIPTION: u64 = 10;
/// Offer features TLV tag (`12`).
pub const TLV_OFFER_FEATURES: u64 = 12;
/// Offer absolute expiry TLV tag (`14`).
pub const TLV_OFFER_ABSOLUTE_EXPIRY: u64 = 14;
/// Offer blinded paths TLV tag (`16`).
pub const TLV_OFFER_PATHS: u64 = 16;
/// Offer issuer string TLV tag (`18`).
pub const TLV_OFFER_ISSUER: u64 = 18;
/// Offer quantity max TLV tag (`20`).
pub const TLV_OFFER_QUANTITY_MAX: u64 = 20;
/// Offer issuer node_id TLV tag (`22`).
pub const TLV_OFFER_NODE_ID: u64 = 22;
/// BOLT12 Schnorr signature TLV tag (`240`).
pub const TLV_SIGNATURE: u64 = 240;

/// Invoice request metadata TLV tag (`0`).
pub const TLV_INVREQ_METADATA: u64 = 0;
/// Invoice request chains TLV tag (`2` in offer, `offer_id` in SatsPath stream).
pub const TLV_INVREQ_OFFER_ID: u64 = 2;
/// Invoice request amount TLV tag (`4`).
pub const TLV_INVREQ_AMOUNT: u64 = 4;
/// Invoice request features TLV tag (`6`).
pub const TLV_INVREQ_FEATURES: u64 = 6;
/// Invoice request quantity TLV tag (`8`).
pub const TLV_INVREQ_QUANTITY: u64 = 8;
/// Invoice request payer_id TLV tag (`10` / `88`).
pub const TLV_INVREQ_PAYER_ID: u64 = 10;
/// Invoice request payer_note TLV tag (`12` / `89`).
pub const TLV_INVREQ_PAYER_NOTE: u64 = 12;
/// Invoice request reply blinded paths TLV tag (`14`).
pub const TLV_INVREQ_PATHS: u64 = 14;

/// Invoice blinded paths TLV tag (`0`).
pub const TLV_INVOICE_PATHS: u64 = 0;
/// Invoice offer_id TLV tag (`2`).
pub const TLV_INVOICE_OFFER_ID: u64 = 2;
/// Invoice payer_id TLV tag (`4`).
pub const TLV_INVOICE_PAYER_ID: u64 = 4;
/// Invoice created_at timestamp TLV tag (`6`).
pub const TLV_INVOICE_CREATED_AT: u64 = 6;
/// Invoice relative_expiry seconds TLV tag (`8`).
pub const TLV_INVOICE_RELATIVE_EXPIRY: u64 = 8;
/// Invoice payment_hash TLV tag (`10`).
pub const TLV_INVOICE_PAYMENT_HASH: u64 = 10;
/// Invoice amount_msats TLV tag (`12`).
pub const TLV_INVOICE_AMOUNT: u64 = 12;
/// Invoice features TLV tag (`14`).
pub const TLV_INVOICE_FEATURES: u64 = 14;
/// Invoice signing node_id TLV tag (`16`).
pub const TLV_INVOICE_NODE_ID: u64 = 16;
/// Invoice fallback on-chain address TLV tag (`20`).
pub const TLV_INVOICE_FALLBACK_ADDRESS: u64 = 20;

// ============================================================================
// Core TLV Serialization Helpers (BigSize, tu64, TLV Streams)
// ============================================================================

/// A single Type-Length-Value record in a BOLT #1 / BOLT #12 stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlvRecord {
    /// TLV numeric type tag.
    pub tag: u64,
    /// Raw value bytes.
    pub value: Vec<u8>,
}

/// Read a Lightning `BigSize` integer from a byte cursor.
///
/// # Errors
/// Returns an error if the stream is truncated.
pub fn read_bigsize(cursor: &mut Cursor<&[u8]>) -> Result<u64> {
    let mut first = [0u8; 1];
    cursor
        .read_exact(&mut first)
        .context("reading bigsize prefix")?;
    match first[0] {
        0x00..=0xfc => Ok(first[0] as u64),
        0xfd => {
            let mut buf = [0u8; 2];
            cursor
                .read_exact(&mut buf)
                .context("reading bigsize 2-byte value")?;
            Ok(u16::from_be_bytes(buf) as u64)
        }
        0xfe => {
            let mut buf = [0u8; 4];
            cursor
                .read_exact(&mut buf)
                .context("reading bigsize 4-byte value")?;
            Ok(u32::from_be_bytes(buf) as u64)
        }
        0xff => {
            let mut buf = [0u8; 8];
            cursor
                .read_exact(&mut buf)
                .context("reading bigsize 8-byte value")?;
            Ok(u64::from_be_bytes(buf))
        }
    }
}

/// Write a Lightning `BigSize` integer into `buf`.
pub fn write_bigsize(val: u64, buf: &mut Vec<u8>) {
    if val <= 0xfc {
        buf.push(val as u8);
    } else if val <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(val as u16).to_be_bytes());
    } else if val <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(val as u32).to_be_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&val.to_be_bytes());
    }
}

/// Decode a minimal big-endian `tu64` integer from `bytes`.
///
/// # Errors
/// Returns an error if `bytes.len() > 8`.
pub fn read_tu64(bytes: &[u8]) -> Result<u64> {
    if bytes.len() > 8 {
        anyhow::bail!("tu64 overflow: length is {} bytes", bytes.len());
    }
    if bytes.is_empty() {
        return Ok(0);
    }
    let mut buf = [0u8; 8];
    buf[8 - bytes.len()..].copy_from_slice(bytes);
    Ok(u64::from_be_bytes(buf))
}

/// Encode a `u64` into minimal big-endian `tu64` bytes.
pub fn write_tu64(mut val: u64) -> Vec<u8> {
    if val == 0 {
        return vec![];
    }
    let mut bytes = Vec::new();
    while val > 0 {
        bytes.push((val & 0xff) as u8);
        val >>= 8;
    }
    bytes.reverse();
    bytes
}

/// Decode consecutive `BigSize` type-length-value records from a byte stream.
///
/// # Errors
/// Returns an error for truncated `BigSize` fields, lengths that do not fit in `usize`,
/// or values longer than the remaining stream.
pub fn decode_tlv_stream(bytes: &[u8]) -> Result<Vec<TlvRecord>> {
    let mut cursor = Cursor::new(bytes);
    let mut records = Vec::new();
    while (cursor.position() as usize) < bytes.len() {
        let tag = read_bigsize(&mut cursor)?;
        let len_raw = read_bigsize(&mut cursor)?;
        let len = usize::try_from(len_raw).context("TLV record length does not fit in usize")?;
        let remaining = bytes.len().saturating_sub(cursor.position() as usize);
        if len > remaining {
            anyhow::bail!(
                "TLV record value length ({len} bytes) exceeds remaining stream bytes ({remaining} bytes)"
            );
        }
        let mut val = vec![0u8; len];
        cursor.read_exact(&mut val).context("reading TLV value")?;
        records.push(TlvRecord { tag, value: val });
    }
    Ok(records)
}

/// Encode a slice of [`TlvRecord`]s into canonical tag-sorted TLV bytes.
pub fn encode_tlv_stream(records: &[TlvRecord]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut sorted = records.to_vec();
    sorted.sort_by_key(|r| r.tag);
    for rec in sorted {
        write_bigsize(rec.tag, &mut out);
        write_bigsize(rec.value.len() as u64, &mut out);
        out.extend_from_slice(&rec.value);
    }
    out
}

/// Encode a single [`TlvRecord`] (`type || length || value`).
pub fn encode_single_tlv(record: &TlvRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + record.value.len());
    write_bigsize(record.tag, &mut out);
    write_bigsize(record.value.len() as u64, &mut out);
    out.extend_from_slice(&record.value);
    out
}

// ============================================================================
// BOLT12 TLV Merkle Tree & BIP-340 Schnorr Signatures
// ============================================================================

/// Compute a BIP-340 / BOLT #12 tagged SHA-256 hash:
/// `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
pub fn bolt12_tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(msg);
    hasher.finalize().into()
}

/// Combine two 32-byte Merkle node hashes in lexicographical order using `"LnBranch"`:
/// `SHA256(SHA256("LnBranch") || SHA256("LnBranch") || min(a, b) || max(a, b))`.
pub fn bolt12_merkle_branch(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut payload = [0u8; 64];
    if a <= b {
        payload[..32].copy_from_slice(a);
        payload[32..].copy_from_slice(b);
    } else {
        payload[..32].copy_from_slice(b);
        payload[32..].copy_from_slice(a);
    }
    bolt12_tagged_hash(b"LnBranch", &payload)
}

/// Compute the standards-compliant BOLT #12 TLV Merkle tree root across all non-signature TLVs.
///
/// Per BOLT #12 ("Merkle Calculation"):
/// 1. Filter out signature TLV records (`tag` in `240..=1000`) and sort remaining records by `tag`.
/// 2. Serialize `all_tlvs = encode_tlv_stream(&unsigned)`.
/// 3. For each TLV record `T_i` (serialized as `type || len || value`):
///    - `leaf_i = TaggedHash("LnLeaf", T_i)`
///    - `nonce_i = TaggedHash("LnNonce" || all_tlvs, T_i)`
///    - Pair `node_i = bolt12_merkle_branch(&leaf_i, &nonce_i)`
/// 4. Repeatedly pair adjacent nodes `(2j, 2j+1)` with `bolt12_merkle_branch` until a single
///    32-byte root remains.
///
/// # Errors
/// Returns an error if the unsigned TLV stream is empty.
pub fn compute_bolt12_merkle_root(records: &[TlvRecord]) -> Result<[u8; 32]> {
    let mut unsigned: Vec<TlvRecord> = records
        .iter()
        .filter(|r| !(240..=1000).contains(&r.tag))
        .cloned()
        .collect();
    if unsigned.is_empty() {
        anyhow::bail!("cannot compute BOLT12 Merkle root of empty TLV stream");
    }
    unsigned.sort_by_key(|r| r.tag);

    let all_tlvs = encode_tlv_stream(&unsigned);
    let mut nonce_tag = Vec::with_capacity(7 + all_tlvs.len());
    nonce_tag.extend_from_slice(b"LnNonce");
    nonce_tag.extend_from_slice(&all_tlvs);

    let mut nodes: Vec<[u8; 32]> = Vec::with_capacity(unsigned.len());
    for rec in &unsigned {
        let tlv_bytes = encode_single_tlv(rec);
        let leaf = bolt12_tagged_hash(b"LnLeaf", &tlv_bytes);
        let nonce = bolt12_tagged_hash(&nonce_tag, &tlv_bytes);
        nodes.push(bolt12_merkle_branch(&leaf, &nonce));
    }

    while nodes.len() > 1 {
        let mut next_level = Vec::with_capacity(nodes.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < nodes.len() {
            next_level.push(bolt12_merkle_branch(&nodes[i], &nodes[i + 1]));
            i += 2;
        }
        if i < nodes.len() {
            next_level.push(nodes[i]);
        }
        nodes = next_level;
    }

    Ok(nodes[0])
}

/// Compute the 32-byte BIP-340 Schnorr signature message digest for a BOLT #12 message:
/// `TaggedHash("lightning" || message_name || "signature", merkle_root)`.
pub fn bolt12_signature_digest(message_name: &str, merkle_root: &[u8; 32]) -> [u8; 32] {
    let tag = format!("lightning{message_name}signature");
    bolt12_tagged_hash(tag.as_bytes(), merkle_root)
}

/// Sign a BOLT #12 TLV stream for `message_name` (`"offer"`, `"invoice_request"`, or `"invoice"`)
/// using a `secp256k1::SecretKey`.
///
/// # Errors
/// Returns an error if the TLV stream is empty.
pub fn sign_bolt12_tlv_stream(
    message_name: &str,
    records: &[TlvRecord],
    secret_key: &secp256k1::SecretKey,
) -> Result<[u8; 64]> {
    let merkle_root = compute_bolt12_merkle_root(records)?;
    let digest = bolt12_signature_digest(message_name, &merkle_root);
    let secp = secp256k1::Secp256k1::new();
    let keypair = secp256k1::Keypair::from_secret_key(&secp, secret_key);
    let msg = secp256k1::Message::from_digest_slice(&digest).context("creating Schnorr message")?;
    let sig = secp.sign_schnorr(&msg, &keypair);
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    Ok(out)
}

/// Verify a BOLT #12 BIP-340 Schnorr signature over `records` for `message_name` against `pubkey_hex`.
///
/// Accepts either a 33-byte compressed secp256k1 public key or a 32-byte x-only public key.
///
/// # Errors
/// Returns an error if the public key or signature hex is malformed or the TLV stream is empty.
pub fn verify_bolt12_tlv_signature(
    message_name: &str,
    records: &[TlvRecord],
    pubkey_hex: &str,
    signature_hex: &str,
) -> Result<bool> {
    let merkle_root = compute_bolt12_merkle_root(records)?;
    let digest = bolt12_signature_digest(message_name, &merkle_root);
    let msg = secp256k1::Message::from_digest_slice(&digest).context("creating Schnorr message")?;

    let sig_bytes = hex::decode(signature_hex.trim()).context("invalid signature hex")?;
    let sig = secp256k1::schnorr::Signature::from_slice(&sig_bytes)
        .map_err(|e| anyhow!("invalid 64-byte Schnorr signature: {e}"))?;

    let pk_bytes = hex::decode(pubkey_hex.trim()).context("invalid pubkey hex")?;
    let xonly = if pk_bytes.len() == 33 {
        let pk = secp256k1::PublicKey::from_slice(&pk_bytes)
            .map_err(|e| anyhow!("invalid 33-byte public key: {e}"))?;
        pk.x_only_public_key().0
    } else if pk_bytes.len() == 32 {
        secp256k1::XOnlyPublicKey::from_slice(&pk_bytes)
            .map_err(|e| anyhow!("invalid 32-byte x-only public key: {e}"))?
    } else {
        anyhow::bail!("unexpected public key length: {} bytes", pk_bytes.len());
    };

    let secp = secp256k1::Secp256k1::verification_only();
    Ok(secp.verify_schnorr(&sig, &msg, &xonly).is_ok())
}

// ============================================================================
// Blinded Path Types (BOLT #4 Wire Format & Privacy-Preserving Routing)
// ============================================================================

/// Maximum allowed hops in a single BOLT12 blinded path.
pub const MAX_BLINDED_PATH_HOPS: usize = 100;

/// Validate that a 33-byte slice is a valid compressed `secp256k1` public key.
fn validate_compressed_pubkey_bytes(bytes: &[u8]) -> Result<()> {
    if bytes.len() != 33 || !matches!(bytes.first(), Some(0x02 | 0x03)) {
        anyhow::bail!("expected 33-byte compressed secp256k1 public key");
    }
    secp256k1::PublicKey::from_slice(bytes)
        .map_err(|e| anyhow!("invalid secp256k1 public key: {e}"))?;
    Ok(())
}

/// Blinded hop in a BOLT #4 / BOLT #12 blinded path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlindedHop {
    /// 33-byte compressed blinded node public key (hex).
    pub blinded_node_id: String,
    /// Encrypted recipient data payload (hex).
    pub encrypted_payload: String,
}

/// Blinded path for BOLT12 (privacy-preserving onion routing).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlindedPath {
    /// Hex-encoded 33-byte compressed public key or 9-byte `sciddir` (`0x00`/`0x01` + 8-byte `scid`).
    pub introduction_node_id: String,
    /// Hex-encoded 33-byte ephemeral blinding point public key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blinding_point: Option<String>,
    /// Ordered sequence of blinded hops from the introduction node to the recipient.
    pub blinded_hops: Vec<BlindedHop>,
}

/// Parsed introduction node target for a [`BlindedPath`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntroductionNode {
    /// Direct 33-byte compressed node public key (hex).
    NodeId(String),
    /// Directed short channel ID (`direction` 0 or 1 and 64-bit `scid`).
    DirectedShortChannelId {
        /// Direction bit (`0` = lesser node ID, `1` = greater node ID).
        direction: u8,
        /// 64-bit Lightning short channel ID.
        scid: u64,
    },
}

impl BlindedPath {
    /// Number of hops in this blinded path.
    pub fn hop_count(&self) -> usize {
        self.blinded_hops.len()
    }

    /// Parse the introduction node identifier as either a `NodeId` or a `DirectedShortChannelId`.
    ///
    /// # Errors
    /// Returns an error if `introduction_node_id` is neither a valid 9-byte `sciddir` nor a 33-byte pubkey.
    pub fn parsed_introduction_node(&self) -> Result<IntroductionNode> {
        let intro_bytes = hex::decode(&self.introduction_node_id)
            .context("invalid hex for introduction_node_id")?;
        match intro_bytes.as_slice() {
            [dir @ (0 | 1), rest @ ..] if rest.len() == 8 => {
                let mut scid_bytes = [0u8; 8];
                scid_bytes.copy_from_slice(rest);
                Ok(IntroductionNode::DirectedShortChannelId {
                    direction: *dir,
                    scid: u64::from_be_bytes(scid_bytes),
                })
            }
            _ => {
                validate_compressed_pubkey_bytes(&intro_bytes)?;
                Ok(IntroductionNode::NodeId(self.introduction_node_id.clone()))
            }
        }
    }

    /// Encode this blinded path into BOLT #4 wire format:
    /// `first_node_id (33B pubkey or 9B sciddir) || blinding_point (33B) || u8 num_hops || hops...`
    /// where each hop is `blinded_node_id (33B) || u16_be encrypted_data_len || encrypted_recipient_data`.
    ///
    /// # Errors
    /// Returns an error if `blinded_hops` is empty or exceeds `MAX_BLINDED_PATH_HOPS`,
    /// or if any public key or hex payload is invalid.
    pub fn encode_bytes(&self) -> Result<Vec<u8>> {
        let num_hops = self.blinded_hops.len();
        if num_hops == 0 {
            anyhow::bail!("num_hops must be at least 1");
        }
        if num_hops > MAX_BLINDED_PATH_HOPS {
            anyhow::bail!("excessive num_hops: {num_hops} exceeds maximum {MAX_BLINDED_PATH_HOPS}");
        }
        let mut buf = Vec::new();
        let intro_bytes = hex::decode(&self.introduction_node_id)
            .context("invalid hex for introduction_node_id")?;
        match intro_bytes.as_slice() {
            [0 | 1, ..] if intro_bytes.len() == 9 => {}
            _ => validate_compressed_pubkey_bytes(&intro_bytes)?,
        }
        buf.extend_from_slice(&intro_bytes);

        let bp = self
            .blinding_point
            .as_ref()
            .context("missing blinding point")?;
        let bp_bytes = hex::decode(bp).context("invalid hex for blinding_point")?;
        validate_compressed_pubkey_bytes(&bp_bytes)?;
        buf.extend_from_slice(&bp_bytes);

        buf.push(num_hops as u8);
        for hop in &self.blinded_hops {
            let hop_node_bytes =
                hex::decode(&hop.blinded_node_id).context("invalid hex for blinded_node_id")?;
            validate_compressed_pubkey_bytes(&hop_node_bytes)?;
            buf.extend_from_slice(&hop_node_bytes);

            let enc_bytes =
                hex::decode(&hop.encrypted_payload).context("invalid hex for encrypted_payload")?;
            let enc_len =
                u16::try_from(enc_bytes.len()).context("encrypted payload exceeds u16")?;
            buf.extend_from_slice(&enc_len.to_be_bytes());
            buf.extend_from_slice(&enc_bytes);
        }
        Ok(buf)
    }

    /// Decode a single BOLT #4 blinded path from `bytes`, rejecting trailing bytes.
    ///
    /// # Errors
    /// Returns an error for invalid keys, truncated fields, zero or `> 100` hops,
    /// payload lengths exceeding remaining bytes, or trailing bytes.
    pub fn decode_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let path = Self::decode_from_cursor(&mut cursor)?;
        if cursor.position() as usize != bytes.len() {
            anyhow::bail!("trailing bytes in blinded path");
        }
        Ok(path)
    }

    /// Decode one BOLT #4 blinded path from `cursor` (used when multiple paths are concatenated in `paths` TLV).
    pub fn decode_from_cursor(cursor: &mut Cursor<&[u8]>) -> Result<Self> {
        let mut first = [0u8; 1];
        cursor
            .read_exact(&mut first)
            .context("reading introduction node ID")?;
        let intro_len = match first[0] {
            0 | 1 => 9,
            2 | 3 => 33,
            _ => anyhow::bail!("invalid introduction node ID prefix"),
        };
        let mut intro = vec![0u8; intro_len];
        intro[0] = first[0];
        cursor
            .read_exact(&mut intro[1..])
            .context("reading introduction node ID")?;
        if intro_len == 33 {
            validate_compressed_pubkey_bytes(&intro)?;
        }

        let mut bp = [0u8; 33];
        cursor
            .read_exact(&mut bp)
            .context("reading blinding point")?;
        validate_compressed_pubkey_bytes(&bp)?;

        let mut count = [0u8; 1];
        cursor.read_exact(&mut count).context("reading num_hops")?;
        let num_hops = usize::from(count[0]);
        if num_hops == 0 {
            anyhow::bail!("num_hops must be at least 1");
        }
        if num_hops > MAX_BLINDED_PATH_HOPS {
            anyhow::bail!("excessive num_hops: {num_hops} exceeds maximum {MAX_BLINDED_PATH_HOPS}");
        }
        let remaining = cursor
            .get_ref()
            .len()
            .saturating_sub(cursor.position() as usize);
        if num_hops > remaining / 35 {
            anyhow::bail!(
                "invalid num_hops: {num_hops} requires more bytes than remaining ({remaining})"
            );
        }
        let mut hops = Vec::with_capacity(num_hops);

        for _ in 0..num_hops {
            let mut hop_node = [0u8; 33];
            cursor
                .read_exact(&mut hop_node)
                .context("reading blinded node ID")?;
            validate_compressed_pubkey_bytes(&hop_node)?;
            let mut enc_len_buf = [0u8; 2];
            cursor
                .read_exact(&mut enc_len_buf)
                .context("reading encrypted payload length")?;
            let enc_len = usize::from(u16::from_be_bytes(enc_len_buf));
            let remaining_enc = cursor
                .get_ref()
                .len()
                .saturating_sub(cursor.position() as usize);
            if enc_len > remaining_enc {
                anyhow::bail!(
                    "encrypted payload length ({enc_len} bytes) exceeds remaining bytes ({remaining_enc} bytes)"
                );
            }
            let mut enc_payload = vec![0u8; enc_len];
            cursor
                .read_exact(&mut enc_payload)
                .context("reading encrypted payload")?;

            hops.push(BlindedHop {
                blinded_node_id: hex::encode(hop_node),
                encrypted_payload: hex::encode(enc_payload),
            });
        }

        Ok(BlindedPath {
            introduction_node_id: hex::encode(intro),
            blinding_point: Some(hex::encode(bp)),
            blinded_hops: hops,
        })
    }
}

// ============================================================================
// Checksumless & Concatenated BOLT12 Bech32 Helpers
// ============================================================================

/// Normalize a BOLT #12 string by validating case uniformity and stripping `+` followed by
/// optional whitespace (`+\s*`) per the BOLT #12 encoding specification.
///
/// # Errors
/// Returns an error if the string mixes uppercase and lowercase, ends with `+`,
/// or has `+` before the `'1'` HRP separator.
pub fn normalize_bolt12_bech32_str(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        anyhow::bail!("BOLT12 string cannot be empty");
    }
    let has_lower = trimmed.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = trimmed.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        anyhow::bail!("BOLT12 string cannot mix uppercase and lowercase characters");
    }

    let mut out = String::with_capacity(trimmed.len());
    let mut seen_sep = false;
    let mut chars = trimmed.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '+' {
            if !seen_sep {
                anyhow::bail!("invalid '+' before Bech32 separator '1'");
            }
            while let Some(&next) = chars.peek() {
                if next.is_ascii_whitespace() {
                    chars.next();
                } else {
                    break;
                }
            }
            if chars.peek().is_none() {
                anyhow::bail!("BOLT12 string cannot end with '+'");
            }
        } else {
            let lower_c = c.to_ascii_lowercase();
            if lower_c == '1' {
                seen_sep = true;
            }
            out.push(lower_c);
        }
    }
    Ok(out)
}

/// Decode a BOLT #12 Bech32 string into `(hrp, raw_tlv_bytes)`.
///
/// Accepts standards-compliant checksumless strings (`NoChecksum`, including `+` continuation)
/// as well as Bech32/Bech32m checksummed strings.
///
/// # Errors
/// Returns an error if the string is not valid Bech32 or has incomplete byte padding.
pub fn decode_bolt12_bech32(input: &str) -> Result<(String, Vec<u8>)> {
    let normalized = normalize_bolt12_bech32_str(input)?;

    // 1. Attempt checksummed Bech32/Bech32m decoding first (backwards-compatible with checksummed vectors)
    if let Ok((hrp, data, _)) = bech32::decode(&normalized) {
        if let Ok(raw) = Vec::<u8>::from_base32(&data) {
            return Ok((hrp, raw));
        }
    }

    // 2. Specification-compliant checksumless BOLT #12 decoding
    let checked = CheckedHrpstring::new::<NoChecksum>(&normalized)
        .context("invalid BOLT12 checksumless bech32 encoding")?;
    let hrp = checked.hrp().as_str().to_string();
    let raw: Vec<u8> = checked.byte_iter().collect();
    Ok((hrp, raw))
}

/// Encode raw TLV bytes into a standards-compliant checksumless BOLT #12 Bech32 string.
///
/// # Errors
/// Returns an error if `hrp` is not a valid Bech32 human-readable part.
pub fn encode_bolt12_bech32_checksumless(hrp_str: &str, raw_tlv: &[u8]) -> Result<String> {
    let hrp = Hrp::parse(hrp_str).context("invalid BOLT12 HRP")?;
    bitcoin::bech32::encode::<NoChecksum>(hrp, raw_tlv)
        .context("encoding checksumless BOLT12 string")
}

// ============================================================================
// BOLT12 Offer
// ============================================================================

/// BOLT12 Offer — a reusable payment request that can be used multiple times.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bolt12Offer {
    /// The offer string (`lno1...`, `lnot1...`, `lnob1...`, or `lnos1...`)
    pub offer: String,
    /// Human-readable description
    pub description: Option<String>,
    /// Amount in millisatoshis (`None` = amount-less offer)
    pub amount_msats: Option<u64>,
    /// ISO 4712 currency code (defaults to `"btc"`)
    pub currency: Option<String>,
    /// Minimum amount in millisatoshis
    pub min_amount_msats: Option<u64>,
    /// Maximum amount in millisatoshis
    pub max_amount_msats: Option<u64>,
    /// Quantity max (for multiple units)
    pub quantity: Option<u64>,
    /// Absolute expiry time (Unix timestamp)
    pub absolute_expiry: Option<u64>,
    /// Relative expiry in seconds from creation
    pub relative_expiry: Option<u64>,
    /// Unblinded routing paths (legacy)
    pub paths: Option<Vec<Vec<String>>>,
    /// Blinded paths for privacy-preserving onion message routing
    pub blinded_paths: Option<Vec<BlindedPath>>,
    /// Issuer string
    pub issuer: Option<String>,
    /// Node ID of the offer creator (compressed 33-byte pubkey hex)
    pub node_id: Option<String>,
    /// Optional BIP-340 Schnorr signature (64-byte hex)
    pub signature: Option<String>,
}

impl Bolt12Offer {
    /// Whether this offer includes at least one blinded path.
    pub fn has_blinded_paths(&self) -> bool {
        self.blinded_paths
            .as_ref()
            .map(|p| !p.is_empty())
            .unwrap_or(false)
    }

    /// Return the primary (first) blinded path advertised by this offer, if any.
    pub fn primary_blinded_path(&self) -> Option<&BlindedPath> {
        self.blinded_paths.as_ref().and_then(|p| p.first())
    }

    /// Check whether the offer has expired at Unix timestamp `now`.
    pub fn is_expired(&self, now: u64) -> bool {
        if let Some(exp) = self.absolute_expiry {
            if now >= exp {
                return true;
            }
        }
        false
    }

    /// Check whether `amount_msats` satisfies this offer's minimum/maximum bounds.
    pub fn is_amount_valid(&self, amount_msats: u64) -> bool {
        if let Some(fixed) = self.amount_msats {
            if fixed > 0 && amount_msats < fixed {
                return false;
            }
        }
        if let Some(min) = self.min_amount_msats {
            if amount_msats < min {
                return false;
            }
        }
        if let Some(max) = self.max_amount_msats {
            if amount_msats > max {
                return false;
            }
        }
        true
    }

    /// Compute the 32-byte BOLT #12 TLV Merkle root (`offer_id`) of this offer.
    ///
    /// # Errors
    /// Returns an error if the offer string cannot be decoded into a valid TLV stream.
    pub fn merkle_root(&self) -> Result<[u8; 32]> {
        let (hrp, raw) = decode_bolt12_bech32(self.offer.trim())?;
        if !matches!(hrp.as_str(), "lno" | "lnot" | "lnob" | "lnos") {
            anyhow::bail!("invalid offer HRP: {hrp}");
        }
        let records = decode_tlv_stream(&raw)?;
        compute_bolt12_merkle_root(&records)
    }

    /// Compute the 32-byte `offer_id` (BOLT #12 TLV Merkle root).
    pub fn offer_id(&self) -> Result<[u8; 32]> {
        self.merkle_root()
    }

    /// Verify the optional BIP-340 Schnorr signature (`tag 240`) on this offer against `node_id`.
    ///
    /// Returns `Ok(true)` if a valid signature and `node_id` are present and match the TLV Merkle root,
    /// or `Ok(false)` if unsigned or invalid.
    pub fn verify_signature(&self) -> Result<bool> {
        let (Some(ref node_id), Some(ref sig)) = (&self.node_id, &self.signature) else {
            return Ok(false);
        };
        let (_, raw) = decode_bolt12_bech32(self.offer.trim())?;
        let records = decode_tlv_stream(&raw)?;
        verify_bolt12_tlv_signature("offer", &records, node_id, sig)
    }
}

// ============================================================================
// BOLT12 Invoice Request
// ============================================================================

/// BOLT12 Invoice Request — sent by a payer over Onion Messages to request an invoice for an offer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bolt12InvoiceRequest {
    /// The offer string or hex `offer_id` this request references
    pub offer: String,
    /// Requested amount in millisatoshis
    pub amount_msats: u64,
    /// Payer's transient 33-byte node/signing public key (hex)
    pub payer_node_id: Option<String>,
    /// Requested item quantity
    pub quantity: Option<u64>,
    /// Optional payer note
    pub payer_note: Option<String>,
    /// Unblinded paths
    pub paths: Option<Vec<Vec<String>>>,
    /// Payer reply blinded paths (`invreq_paths`)
    pub blinded_paths: Option<Vec<BlindedPath>>,
    /// Absolute expiry (Unix timestamp)
    pub absolute_expiry: Option<u64>,
    /// Relative expiry in seconds
    pub relative_expiry: Option<u64>,
    /// Payer's 64-byte BIP-340 Schnorr signature over the `invoice_request` TLV Merkle root (hex)
    pub signature: Option<String>,
}

impl Bolt12InvoiceRequest {
    /// Build the unsigned TLV records for this `invoice_request`.
    pub fn to_unsigned_tlv_records(&self, offer_id: &[u8; 32]) -> Result<Vec<TlvRecord>> {
        let mut records = Vec::new();
        records.push(TlvRecord {
            tag: TLV_INVREQ_METADATA,
            value: vec![0x01, 0x02, 0x03, 0x04],
        });
        records.push(TlvRecord {
            tag: TLV_INVREQ_OFFER_ID,
            value: offer_id.to_vec(),
        });
        records.push(TlvRecord {
            tag: TLV_INVREQ_AMOUNT,
            value: write_tu64(self.amount_msats),
        });
        if let Some(qty) = self.quantity {
            records.push(TlvRecord {
                tag: TLV_INVREQ_QUANTITY,
                value: write_tu64(qty),
            });
        }
        if let Some(ref pid) = self.payer_node_id {
            let bytes = hex::decode(pid).context("invalid payer_node_id hex")?;
            records.push(TlvRecord {
                tag: TLV_INVREQ_PAYER_ID,
                value: bytes,
            });
        }
        if let Some(ref note) = self.payer_note {
            records.push(TlvRecord {
                tag: TLV_INVREQ_PAYER_NOTE,
                value: note.as_bytes().to_vec(),
            });
        }
        if let Some(ref bpaths) = self.blinded_paths {
            if !bpaths.is_empty() {
                let mut concat = Vec::new();
                for bp in bpaths {
                    concat.extend_from_slice(&bp.encode_bytes()?);
                }
                records.push(TlvRecord {
                    tag: TLV_INVREQ_PATHS,
                    value: concat,
                });
            }
        }
        Ok(records)
    }

    /// Compute the 32-byte BOLT #12 `invoice_request` Merkle root (`request_id`).
    pub fn request_id(&self, offer_id: &[u8; 32]) -> [u8; 32] {
        let records = self.to_unsigned_tlv_records(offer_id).unwrap_or_else(|_| {
            vec![TlvRecord {
                tag: TLV_INVREQ_OFFER_ID,
                value: offer_id.to_vec(),
            }]
        });
        compute_bolt12_merkle_root(&records).unwrap_or([0u8; 32])
    }

    /// Verify the BIP-340 Schnorr signature on this `invoice_request` against `payer_node_id`.
    pub fn verify_signature(&self, offer_id: &[u8; 32]) -> Result<bool> {
        let (Some(ref payer_pk), Some(ref sig)) = (&self.payer_node_id, &self.signature) else {
            return Ok(false);
        };
        let records = self.to_unsigned_tlv_records(offer_id)?;
        verify_bolt12_tlv_signature("invoice_request", &records, payer_pk, sig)
    }

    /// Encode this `invoice_request` into raw TLV bytes (including `TLV_SIGNATURE` if signed).
    pub fn to_tlv_bytes(&self) -> Result<Vec<u8>> {
        let offer_parsed = parse_bolt12_offer(&self.offer).ok();
        let offer_id = if let Some(o) = offer_parsed {
            o.offer_id()?
        } else if let Ok(decoded_id) = hex::decode(self.offer.trim()) {
            if decoded_id.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&decoded_id);
                arr
            } else {
                Sha256::digest(self.offer.as_bytes()).into()
            }
        } else {
            Sha256::digest(self.offer.as_bytes()).into()
        };

        let mut records = self.to_unsigned_tlv_records(&offer_id)?;
        if let Some(ref sig) = self.signature {
            let sig_bytes = hex::decode(sig).context("invalid invoice_request signature hex")?;
            records.push(TlvRecord {
                tag: TLV_SIGNATURE,
                value: sig_bytes,
            });
        }
        Ok(encode_tlv_stream(&records))
    }

    /// Encode this `invoice_request` into a checksumless BOLT #12 Bech32 string (`lnr1...` / `lnrt1...`).
    pub fn encode(&self) -> Result<String> {
        let raw = self.to_tlv_bytes()?;
        let hrp = if self.offer.starts_with("lnot") {
            "lnrt"
        } else {
            "lnr"
        };
        encode_bolt12_bech32_checksumless(hrp, &raw)
    }
}

// ============================================================================
// BOLT12 Invoice
// ============================================================================

/// BOLT12 Invoice — returned by the recipient node in response to a [`Bolt12InvoiceRequest`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bolt12Invoice {
    /// Encoded invoice string (`lni1...`, `lnit1...`, or `lnib1...`)
    pub invoice: String,
    /// Human-readable description
    pub description: Option<String>,
    /// Amount in millisatoshis
    pub amount_msats: u64,
    /// Currency code
    pub currency: String,
    /// Creation timestamp (Unix seconds)
    pub created_at: u64,
    /// Relative expiry in seconds from `created_at`
    pub relative_expiry: Option<u64>,
    /// Absolute expiry (Unix timestamp)
    pub absolute_expiry: Option<u64>,
    /// 32-byte HTLC payment hash (hex)
    pub payment_hash: Option<String>,
    /// Optional fallback on-chain address
    pub fallback_address: Option<String>,
    /// Routing hints
    pub routes: Option<Vec<Vec<String>>>,
    /// Blinded payment paths
    pub blinded_paths: Option<Vec<BlindedPath>>,
    /// Signing node ID (33-byte compressed pubkey hex)
    pub node_id: Option<String>,
    /// 64-byte BIP-340 Schnorr signature over the invoice TLV Merkle root (hex)
    pub signature: Option<String>,
}

impl Bolt12Invoice {
    /// Check whether the invoice has expired at Unix timestamp `now`.
    pub fn is_expired(&self, now: u64) -> bool {
        if let Some(abs) = self.absolute_expiry {
            if now >= abs {
                return true;
            }
        }
        if let Some(rel) = self.relative_expiry {
            if now >= self.created_at.saturating_add(rel) {
                return true;
            }
        }
        false
    }

    /// Build the unsigned TLV records for this `Bolt12Invoice`.
    pub fn to_unsigned_tlv_records(&self) -> Result<Vec<TlvRecord>> {
        let mut records = Vec::new();
        if let Some(ref bpaths) = self.blinded_paths {
            if !bpaths.is_empty() {
                let mut concat = Vec::new();
                for bp in bpaths {
                    concat.extend_from_slice(&bp.encode_bytes()?);
                }
                records.push(TlvRecord {
                    tag: TLV_INVOICE_PATHS,
                    value: concat,
                });
            }
        }
        records.push(TlvRecord {
            tag: TLV_INVOICE_CREATED_AT,
            value: write_tu64(self.created_at),
        });
        if let Some(rel) = self.relative_expiry {
            records.push(TlvRecord {
                tag: TLV_INVOICE_RELATIVE_EXPIRY,
                value: write_tu64(rel),
            });
        }
        if let Some(ref ph) = self.payment_hash {
            let bytes = hex::decode(ph).context("invalid payment_hash hex")?;
            records.push(TlvRecord {
                tag: TLV_INVOICE_PAYMENT_HASH,
                value: bytes,
            });
        }
        records.push(TlvRecord {
            tag: TLV_INVOICE_AMOUNT,
            value: write_tu64(self.amount_msats),
        });
        if let Some(ref nid) = self.node_id {
            let bytes = hex::decode(nid).context("invalid node_id hex")?;
            records.push(TlvRecord {
                tag: TLV_INVOICE_NODE_ID,
                value: bytes,
            });
        }
        if let Some(ref fb) = self.fallback_address {
            records.push(TlvRecord {
                tag: TLV_INVOICE_FALLBACK_ADDRESS,
                value: fb.as_bytes().to_vec(),
            });
        }
        Ok(records)
    }

    /// Verify the BIP-340 Schnorr signature on this invoice against `node_id`.
    pub fn verify_signature(&self) -> Result<bool> {
        let (Some(ref nid), Some(ref sig)) = (&self.node_id, &self.signature) else {
            return Ok(false);
        };
        let records = self.to_unsigned_tlv_records()?;
        verify_bolt12_tlv_signature("invoice", &records, nid, sig)
    }

    /// Encode this invoice into a checksumless BOLT #12 Bech32 string (`lni1...` / `lnit1...`).
    pub fn encode(&self) -> Result<String> {
        let mut records = self.to_unsigned_tlv_records()?;
        if let Some(ref sig) = self.signature {
            let bytes = hex::decode(sig).context("invalid invoice signature hex")?;
            records.push(TlvRecord {
                tag: TLV_SIGNATURE,
                value: bytes,
            });
        }

        let raw = encode_tlv_stream(&records);
        let hrp = if self.invoice.starts_with("lnit") {
            "lnit"
        } else {
            "lni"
        };
        encode_bolt12_bech32_checksumless(hrp, &raw)
    }
}

// ============================================================================
// Parsing Functions
// ============================================================================

/// Parse a BOLT12 offer string (supports checksumless BOLT #12 encoding, `+` continuation, and Bech32/Bech32m).
///
/// # Errors
/// Returns an error if the offer prefix, Bech32 encoding, TLV stream, blinded paths,
/// unknown even TLV tags, or destination fields are invalid.
pub fn parse_bolt12_offer(offer: &str) -> Result<Bolt12Offer> {
    let normalized = normalize_bolt12_bech32_str(offer)?;
    if !normalized.starts_with("lno1")
        && !normalized.starts_with("lnot1")
        && !normalized.starts_with("lnob1")
        && !normalized.starts_with("lnos1")
    {
        return Err(anyhow!(
            "Invalid BOLT12 offer: must start with 'lno1', 'lnot1', 'lnob1', or 'lnos1'"
        ));
    }

    let (hrp, raw) = decode_bolt12_bech32(&normalized)?;
    if !matches!(hrp.as_str(), "lno" | "lnot" | "lnob" | "lnos") {
        anyhow::bail!("invalid BOLT12 offer HRP: {hrp}");
    }
    let records = decode_tlv_stream(&raw).context("invalid BOLT12 offer TLV stream")?;

    let mut description = None;
    let mut amount_msats = None;
    let mut currency = Some("btc".to_string());
    let mut absolute_expiry = None;
    let mut issuer = None;
    let mut quantity = None;
    let mut node_id = None;
    let mut signature = None;
    let mut blinded_paths = Vec::new();

    for r in records {
        match r.tag {
            TLV_OFFER_CURRENCY => {
                if let Ok(c) = String::from_utf8(r.value) {
                    currency = Some(c);
                }
            }
            TLV_OFFER_AMOUNT => {
                if let Ok(amt) = read_tu64(&r.value) {
                    amount_msats = Some(amt);
                }
            }
            TLV_OFFER_DESCRIPTION => {
                if let Ok(desc) = String::from_utf8(r.value) {
                    description = Some(desc);
                }
            }
            TLV_OFFER_ABSOLUTE_EXPIRY => {
                if let Ok(exp) = read_tu64(&r.value) {
                    absolute_expiry = Some(exp);
                }
            }
            TLV_OFFER_PATHS => {
                if r.value.is_empty() {
                    anyhow::bail!("BOLT12 offer paths must not be empty");
                }
                let mut cursor = Cursor::new(r.value.as_slice());
                while (cursor.position() as usize) < r.value.len() {
                    blinded_paths.push(
                        BlindedPath::decode_from_cursor(&mut cursor)
                            .context("invalid BOLT12 offer blinded path")?,
                    );
                }
            }
            TLV_OFFER_ISSUER => {
                if let Ok(iss) = String::from_utf8(r.value) {
                    issuer = Some(iss);
                }
            }
            TLV_OFFER_QUANTITY_MAX => {
                if let Ok(q) = read_tu64(&r.value) {
                    quantity = Some(q);
                }
            }
            TLV_OFFER_NODE_ID => {
                validate_compressed_pubkey_bytes(&r.value)
                    .context("invalid BOLT12 offer node_id")?;
                node_id = Some(hex::encode(r.value));
            }
            TLV_SIGNATURE => {
                signature = Some(hex::encode(r.value));
            }
            TLV_OFFER_CHAINS | TLV_OFFER_METADATA | TLV_OFFER_FEATURES => {}
            _ if r.tag.is_multiple_of(2) => {
                anyhow::bail!("unknown even BOLT12 TLV type: {}", r.tag);
            }
            _ => {}
        }
    }

    if node_id.is_none() && blinded_paths.is_empty() {
        anyhow::bail!(
            "BOLT12 offer missing invoice-request destination: offer_issuer_id or offer_paths required"
        );
    }

    let b_paths = if blinded_paths.is_empty() {
        None
    } else {
        Some(blinded_paths)
    };

    let currency = if hrp.contains('t') || hrp.contains('b') {
        Some("tbtc".to_string())
    } else {
        currency
    };

    Ok(Bolt12Offer {
        offer: normalized,
        description,
        amount_msats,
        currency,
        min_amount_msats: amount_msats,
        max_amount_msats: None,
        quantity,
        absolute_expiry,
        relative_expiry: None,
        paths: None,
        blinded_paths: b_paths,
        issuer,
        node_id,
        signature,
    })
}

/// Parse a BOLT12 invoice request string (`lnr1...` or `lnrt1...`), failing closed on malformed input.
pub fn parse_bolt12_invoice_request(request: &str) -> Result<Bolt12InvoiceRequest> {
    let normalized = normalize_bolt12_bech32_str(request)?;
    if !normalized.starts_with("lnr1") && !normalized.starts_with("lnrt1") {
        return Err(anyhow!(
            "Invalid BOLT12 invoice request: must start with 'lnr1' or 'lnrt1'"
        ));
    }

    let (hrp, raw) = decode_bolt12_bech32(&normalized)?;
    if !matches!(hrp.as_str(), "lnr" | "lnrt") {
        anyhow::bail!("invalid BOLT12 invoice request HRP: {hrp}");
    }
    let records = decode_tlv_stream(&raw).context("invalid BOLT12 invoice request TLV stream")?;

    let mut offer_id_hex = String::new();
    let mut amount_msats = 0;
    let mut quantity = None;
    let mut payer_node_id = None;
    let mut payer_note = None;
    let mut blinded_paths = Vec::new();
    let mut signature = None;

    for r in records {
        match r.tag {
            TLV_INVREQ_OFFER_ID => {
                offer_id_hex = hex::encode(r.value);
            }
            TLV_INVREQ_AMOUNT => {
                amount_msats = read_tu64(&r.value)?;
            }
            TLV_INVREQ_QUANTITY => {
                quantity = Some(read_tu64(&r.value)?);
            }
            TLV_INVREQ_PAYER_ID => {
                payer_node_id = Some(hex::encode(r.value));
            }
            TLV_INVREQ_PAYER_NOTE => {
                payer_note =
                    Some(String::from_utf8(r.value).context("invalid UTF-8 in payer_note")?);
            }
            TLV_INVREQ_PATHS => {
                let mut cursor = Cursor::new(r.value.as_slice());
                while (cursor.position() as usize) < r.value.len() {
                    blinded_paths.push(BlindedPath::decode_from_cursor(&mut cursor)?);
                }
            }
            TLV_SIGNATURE => {
                signature = Some(hex::encode(r.value));
            }
            TLV_INVREQ_METADATA | TLV_INVREQ_FEATURES => {}
            _ if r.tag.is_multiple_of(2) => {
                anyhow::bail!("unknown even BOLT12 invoice_request TLV type: {}", r.tag);
            }
            _ => {}
        }
    }

    Ok(Bolt12InvoiceRequest {
        offer: offer_id_hex,
        amount_msats,
        payer_node_id,
        quantity,
        payer_note,
        paths: None,
        blinded_paths: if blinded_paths.is_empty() {
            None
        } else {
            Some(blinded_paths)
        },
        absolute_expiry: None,
        relative_expiry: None,
        signature,
    })
}

/// Parse a BOLT12 invoice string (`lni1...`, `lnit1...`, or `lnib1...`), failing closed on malformed input.
pub fn parse_bolt12_invoice(invoice: &str) -> Result<Bolt12Invoice> {
    let normalized = normalize_bolt12_bech32_str(invoice)?;
    if !normalized.starts_with("lni1")
        && !normalized.starts_with("lnit1")
        && !normalized.starts_with("lnib1")
    {
        return Err(anyhow!(
            "Invalid BOLT12 invoice: must start with 'lni1', 'lnit1', or 'lnib1'"
        ));
    }

    let (hrp, raw) = decode_bolt12_bech32(&normalized)?;
    if !matches!(hrp.as_str(), "lni" | "lnit" | "lnib") {
        anyhow::bail!("invalid BOLT12 invoice HRP: {hrp}");
    }
    let records = decode_tlv_stream(&raw).context("invalid BOLT12 invoice TLV stream")?;

    let mut created_at = 0;
    let mut relative_expiry = None;
    let mut payment_hash = None;
    let mut amount_msats = 0;
    let mut node_id = None;
    let mut fallback_address = None;
    let mut blinded_paths = Vec::new();
    let mut signature = None;

    for r in records {
        match r.tag {
            TLV_INVOICE_PATHS => {
                let mut cursor = Cursor::new(r.value.as_slice());
                while (cursor.position() as usize) < r.value.len() {
                    blinded_paths.push(BlindedPath::decode_from_cursor(&mut cursor)?);
                }
            }
            TLV_INVOICE_CREATED_AT => {
                created_at = read_tu64(&r.value)?;
            }
            TLV_INVOICE_RELATIVE_EXPIRY => {
                relative_expiry = Some(read_tu64(&r.value)?);
            }
            TLV_INVOICE_PAYMENT_HASH => {
                payment_hash = Some(hex::encode(r.value));
            }
            TLV_INVOICE_AMOUNT => {
                amount_msats = read_tu64(&r.value)?;
            }
            TLV_INVOICE_NODE_ID => {
                node_id = Some(hex::encode(r.value));
            }
            TLV_INVOICE_FALLBACK_ADDRESS => {
                fallback_address =
                    Some(String::from_utf8(r.value).context("invalid fallback_address UTF-8")?);
            }
            TLV_SIGNATURE => {
                signature = Some(hex::encode(r.value));
            }
            TLV_INVOICE_OFFER_ID | TLV_INVOICE_PAYER_ID | TLV_INVOICE_FEATURES => {}
            _ if r.tag.is_multiple_of(2) => {
                anyhow::bail!("unknown even BOLT12 invoice TLV type: {}", r.tag);
            }
            _ => {}
        }
    }

    Ok(Bolt12Invoice {
        invoice: normalized,
        description: None,
        amount_msats,
        currency: if hrp.contains('t') || hrp.contains('b') {
            "tbtc".to_string()
        } else {
            "btc".to_string()
        },
        created_at,
        relative_expiry,
        absolute_expiry: None,
        payment_hash,
        fallback_address,
        routes: None,
        blinded_paths: if blinded_paths.is_empty() {
            None
        } else {
            Some(blinded_paths)
        },
        node_id,
        signature,
    })
}

// ============================================================================
// Factory, Signing, and Onion Message Dispatch Helpers
// ============================================================================

/// Create an unsigned [`Bolt12InvoiceRequest`] from a [`Bolt12Offer`].
#[allow(clippy::too_many_arguments)]
pub fn create_invoice_request(
    offer: &Bolt12Offer,
    amount_msats: u64,
    payer_node_id: Option<String>,
    quantity: Option<u64>,
    payer_note: Option<String>,
    paths: Option<Vec<Vec<String>>>,
    blinded_paths: Option<Vec<BlindedPath>>,
    relative_expiry: Option<u64>,
) -> Bolt12InvoiceRequest {
    Bolt12InvoiceRequest {
        offer: offer.offer.clone(),
        amount_msats,
        payer_node_id,
        quantity,
        payer_note,
        paths,
        blinded_paths,
        absolute_expiry: None,
        relative_expiry,
        signature: None,
    }
}

/// Create and sign a [`Bolt12InvoiceRequest`] using the payer's transient `secp256k1::SecretKey`
/// and the standards-compliant BOLT #12 TLV Merkle root (`lightninginvoice_requestsignature`).
pub fn create_signed_invoice_request(
    offer: &Bolt12Offer,
    amount_msats: u64,
    payer_key: &secp256k1::SecretKey,
    payer_note: Option<&str>,
    quantity: Option<u64>,
) -> Result<Bolt12InvoiceRequest> {
    let secp = secp256k1::Secp256k1::new();
    let keypair = secp256k1::Keypair::from_secret_key(&secp, payer_key);
    let payer_pubkey = hex::encode(keypair.public_key().serialize());

    let mut req = create_invoice_request(
        offer,
        amount_msats,
        Some(payer_pubkey),
        quantity,
        payer_note.map(|s| s.to_string()),
        None,
        offer.blinded_paths.clone(),
        Some(3600),
    );

    let offer_id = offer
        .offer_id()
        .unwrap_or_else(|_| Sha256::digest(offer.offer.as_bytes()).into());

    let unsigned_records = req.to_unsigned_tlv_records(&offer_id)?;
    let sig = sign_bolt12_tlv_stream("invoice_request", &unsigned_records, payer_key)?;
    req.signature = Some(hex::encode(sig));

    Ok(req)
}

/// Encode a [`Bolt12InvoiceRequest`] to a checksumless BOLT #12 Bech32 string (`lnr1...`).
pub fn encode_invoice_request(request: &Bolt12InvoiceRequest) -> Result<String> {
    request.encode()
}

/// Create and sign a concrete [`Bolt12Invoice`] in response to a [`Bolt12InvoiceRequest`]
/// using the recipient node's `secp256k1::SecretKey` and the BOLT #12 TLV Merkle root (`lightninginvoicesignature`).
pub fn create_invoice_from_request(
    offer: &Bolt12Offer,
    request: &Bolt12InvoiceRequest,
    node_key: &secp256k1::SecretKey,
    payment_hash: [u8; 32],
    relative_expiry_secs: Option<u64>,
) -> Result<Bolt12Invoice> {
    let secp = secp256k1::Secp256k1::new();
    let keypair = secp256k1::Keypair::from_secret_key(&secp, node_key);
    let node_pubkey = hex::encode(keypair.public_key().serialize());

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut invoice = Bolt12Invoice {
        invoice: if offer.offer.starts_with("lnot") {
            "lnit1".to_string()
        } else {
            "lni1".to_string()
        },
        description: offer.description.clone(),
        amount_msats: request.amount_msats,
        currency: offer.currency.clone().unwrap_or_else(|| "btc".to_string()),
        created_at: now,
        relative_expiry: relative_expiry_secs.or(Some(7200)),
        absolute_expiry: None,
        payment_hash: Some(hex::encode(payment_hash)),
        fallback_address: None,
        routes: None,
        blinded_paths: offer.blinded_paths.clone(),
        node_id: Some(node_pubkey),
        signature: None,
    };

    let unsigned_records = invoice.to_unsigned_tlv_records()?;
    let sig = sign_bolt12_tlv_stream("invoice", &unsigned_records, node_key)?;
    invoice.signature = Some(hex::encode(sig));

    let encoded = invoice.encode()?;
    invoice.invoice = encoded;
    Ok(invoice)
}

// ============================================================================
// Blinded Path Resolution & Onion Message Dispatch (CLN / LDK Interoperability)
// ============================================================================

/// Resolved onion message delivery route extracted from a [`Bolt12Offer`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedOnionRoute {
    /// Entry point into the route (`NodeId` or `DirectedShortChannelId`).
    pub introduction: IntroductionNode,
    /// Ephemeral 33-byte blinding point (hex), if routing over a blinded path.
    pub blinding_point: Option<String>,
    /// Ordered blinded hops to traverse after the introduction node.
    pub blinded_hops: Vec<BlindedHop>,
}

/// Resolve the onion message delivery route for a [`Bolt12Offer`].
///
/// Prefers the offer's primary [`BlindedPath`] (preserving receiver privacy via
/// `IntroductionNode::NodeId` or `IntroductionNode::DirectedShortChannelId`),
/// falling back to a direct single-hop route to `offer.node_id` if no blinded path is present.
///
/// # Errors
/// Returns an error if the offer has neither a valid blinded path nor a valid `node_id`.
pub fn resolve_offer_onion_route(offer: &Bolt12Offer) -> Result<ResolvedOnionRoute> {
    if let Some(primary) = offer.primary_blinded_path() {
        let intro = primary.parsed_introduction_node()?;
        return Ok(ResolvedOnionRoute {
            introduction: intro,
            blinding_point: primary.blinding_point.clone(),
            blinded_hops: primary.blinded_hops.clone(),
        });
    }

    if let Some(ref nid) = offer.node_id {
        let bytes = hex::decode(nid).context("invalid offer node_id hex")?;
        validate_compressed_pubkey_bytes(&bytes)?;
        return Ok(ResolvedOnionRoute {
            introduction: IntroductionNode::NodeId(nid.clone()),
            blinding_point: None,
            blinded_hops: Vec::new(),
        });
    }

    anyhow::bail!("BOLT12 offer contains neither blinded_paths nor node_id")
}

/// Complete BOLT #12 onion message payload envelope ready for dispatch over a Lightning node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnionMessageEnvelope {
    /// Target route resolved from the offer (`offer_paths` or `offer_issuer_id`).
    pub destination_route: ResolvedOnionRoute,
    /// Payer's reply blinded path (`invreq_paths`) so the recipient node can return the `invoice`.
    pub reply_blinded_path: BlindedPath,
    /// Raw TLV wire bytes of the signed `invoice_request` (onion message TLV type `64`).
    pub invoice_request_tlv_hex: String,
    /// Checksumless Bech32-encoded `invoice_request` (`lnr1...`).
    pub invoice_request_bech32: String,
}

/// Build a signed [`OnionMessageEnvelope`] from a [`Bolt12Offer`] and payer ephemeral key.
///
/// # Errors
/// Returns an error if the offer is expired, the amount is out of bounds, or route resolution fails.
pub fn build_invoice_request_onion_envelope(
    offer: &Bolt12Offer,
    amount_msats: u64,
    payer_key: &secp256k1::SecretKey,
    reply_blinded_path: BlindedPath,
    payer_note: Option<&str>,
    quantity: Option<u64>,
) -> Result<(Bolt12InvoiceRequest, OnionMessageEnvelope)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if offer.is_expired(now) {
        anyhow::bail!("Cannot construct invoice_request: BOLT12 offer has expired");
    }
    if !offer.is_amount_valid(amount_msats) {
        anyhow::bail!(
            "Amount {amount_msats} msats is outside bounds for offer (min: {:?}, max: {:?})",
            offer.min_amount_msats,
            offer.max_amount_msats
        );
    }

    let destination_route = resolve_offer_onion_route(offer)?;

    let secp = secp256k1::Secp256k1::new();
    let keypair = secp256k1::Keypair::from_secret_key(&secp, payer_key);
    let payer_pubkey = hex::encode(keypair.public_key().serialize());

    let mut req = create_invoice_request(
        offer,
        amount_msats,
        Some(payer_pubkey),
        quantity,
        payer_note.map(|s| s.to_string()),
        None,
        Some(vec![reply_blinded_path.clone()]),
        Some(3600),
    );

    let offer_id = offer.offer_id()?;
    let unsigned_records = req.to_unsigned_tlv_records(&offer_id)?;
    let sig = sign_bolt12_tlv_stream("invoice_request", &unsigned_records, payer_key)?;
    req.signature = Some(hex::encode(sig));

    let tlv_bytes = req.to_tlv_bytes()?;
    let bech32_str = req.encode()?;

    let envelope = OnionMessageEnvelope {
        destination_route,
        reply_blinded_path,
        invoice_request_tlv_hex: hex::encode(&tlv_bytes),
        invoice_request_bech32: bech32_str,
    };

    Ok((req, envelope))
}

/// Transport abstraction for dispatching a BOLT #12 `invoice_request` over Onion Messages
/// (e.g. via Core Lightning `fetchinvoice` / `sendonionmessage` or LDK `OnionMessenger`)
/// and returning the verified [`Bolt12Invoice`].
pub trait OnionMessageTransport: Send + Sync {
    /// Dispatch `envelope` for `offer` and return the resulting [`Bolt12Invoice`].
    ///
    /// # Errors
    /// Returns an error if transport fails or if the returned invoice fails validation.
    fn dispatch_invoice_request(
        &self,
        offer: &Bolt12Offer,
        request: &Bolt12InvoiceRequest,
        envelope: &OnionMessageEnvelope,
    ) -> Result<Bolt12Invoice>;
}

/// Reference Core Lightning (CLN) / LDK node responder used for conformance and integration testing.
///
/// Validates the incoming [`OnionMessageEnvelope`] (blinded path structure, `offer_id` Merkle root,
/// and payer `invoice_request` Schnorr signature) and signs a standards-compliant [`Bolt12Invoice`]
/// with the recipient node's key.
pub struct ReferenceNodeOnionTransport {
    node_secret_key: secp256k1::SecretKey,
    payment_hash: [u8; 32],
}

impl ReferenceNodeOnionTransport {
    /// Construct a new reference CLN/LDK node responder with `node_secret_key` and `payment_hash`.
    pub fn new(node_secret_key: secp256k1::SecretKey, payment_hash: [u8; 32]) -> Self {
        Self {
            node_secret_key,
            payment_hash,
        }
    }
}

impl OnionMessageTransport for ReferenceNodeOnionTransport {
    fn dispatch_invoice_request(
        &self,
        offer: &Bolt12Offer,
        request: &Bolt12InvoiceRequest,
        envelope: &OnionMessageEnvelope,
    ) -> Result<Bolt12Invoice> {
        // 1. Verify reply path is valid BOLT #4 wire format
        let reply_bytes = envelope.reply_blinded_path.encode_bytes()?;
        let _ = BlindedPath::decode_bytes(&reply_bytes)?;

        // 2. Verify invoice_request signature against offer Merkle root
        let offer_id = offer.offer_id()?;
        if !request.verify_signature(&offer_id)? {
            anyhow::bail!("recipient node rejected invoice_request: invalid Schnorr signature");
        }

        // 3. Construct and sign concrete BOLT12 invoice
        let inv = create_invoice_from_request(
            offer,
            request,
            &self.node_secret_key,
            self.payment_hash,
            Some(3600),
        )?;
        validate_bolt12_invoice_against_offer(&inv, offer, request.amount_msats)?;
        Ok(inv)
    }
}

/// Dispatch an `invoice_request` via a provided [`OnionMessageTransport`] and validate the returned invoice.
pub fn fetch_bolt12_invoice_via_transport(
    transport: &dyn OnionMessageTransport,
    offer: &Bolt12Offer,
    amount_msats: u64,
    payer_key: &secp256k1::SecretKey,
    reply_blinded_path: BlindedPath,
    payer_note: Option<&str>,
    quantity: Option<u64>,
) -> Result<Bolt12Invoice> {
    let (req, envelope) = build_invoice_request_onion_envelope(
        offer,
        amount_msats,
        payer_key,
        reply_blinded_path,
        payer_note,
        quantity,
    )?;
    let invoice = transport.dispatch_invoice_request(offer, &req, &envelope)?;
    validate_bolt12_invoice_against_offer(&invoice, offer, amount_msats)?;
    if !invoice.verify_signature()? {
        anyhow::bail!("BOLT12 invoice failed Schnorr Merkle signature verification");
    }
    Ok(invoice)
}

// ============================================================================
// Invoice Fetching and Validation
// ============================================================================

/// Fetch a BOLT12 invoice from an offer via configured HTTP gateway or simulated mock.
pub async fn fetch_bolt12_invoice(
    offer: &Bolt12Offer,
    amount_msats: u64,
    payer_node_id: Option<String>,
    quantity: Option<u64>,
    payer_note: Option<String>,
) -> Result<Bolt12Invoice> {
    // 1. Expiry check
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if offer.is_expired(now) {
        anyhow::bail!("Cannot fetch invoice: BOLT12 offer has expired");
    }

    // 2. Amount boundary validation
    if !offer.is_amount_valid(amount_msats) {
        anyhow::bail!(
            "Amount {} msats is outside bounds for offer (min: {:?}, max: {:?})",
            amount_msats,
            offer.min_amount_msats,
            offer.max_amount_msats
        );
    }

    // 3. Simulated mock mode for testing and local development
    if std::env::var("SATSPATH_MOCK_BOLT12")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        use secp256k1::rand::RngCore;
        let mut mock_key = [0u8; 32];
        secp256k1::rand::thread_rng().fill_bytes(&mut mock_key);
        let secret_key = secp256k1::SecretKey::from_slice(&mock_key)?;

        let mut payment_hash = [0u8; 32];
        secp256k1::rand::thread_rng().fill_bytes(&mut payment_hash);

        let req = create_invoice_request(
            offer,
            amount_msats,
            payer_node_id,
            quantity,
            payer_note,
            None,
            offer.blinded_paths.clone(),
            Some(3600),
        );

        return create_invoice_from_request(offer, &req, &secret_key, payment_hash, Some(3600));
    }

    // 4. HTTP Gateway / Proxy fetch
    if let Ok(proxy_base) = std::env::var("SATSPATH_BOLT12_PROXY") {
        let trimmed_proxy = proxy_base.trim_end_matches('/');
        let url = format!(
            "{}/invoice?offer={}&amount_msats={}",
            trimmed_proxy,
            urlencoding::encode(&offer.offer),
            amount_msats
        );

        #[cfg(feature = "std")]
        {
            satspath_core::ssrf::validate_url(&url, false)
                .map_err(|e| anyhow!("invalid BOLT12 proxy URL: {e}"))?;
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()?;
            let resp = client
                .get(&url)
                .send()
                .await
                .context("sending BOLT12 proxy request")?;
            if !resp.status().is_success() {
                anyhow::bail!("BOLT12 proxy returned HTTP error: {}", resp.status());
            }
            let data: serde_json::Value = resp.json().await.context("decoding proxy JSON")?;
            let inv_str = data["invoice"]
                .as_str()
                .ok_or_else(|| anyhow!("missing 'invoice' string in proxy response"))?;
            let parsed_inv = parse_bolt12_invoice(inv_str)?;
            validate_bolt12_invoice_against_offer(&parsed_inv, offer, amount_msats)?;
            return Ok(parsed_inv);
        }
    }

    // 5. Default: Informative error indicating required transport gateway
    Err(anyhow!(
        "BOLT12 onion message transport requires an active Lightning node connection or configured proxy (SATSPATH_BOLT12_PROXY)"
    ))
}

/// Validate a BOLT12 invoice against expected parameters.
pub fn validate_bolt12_invoice(invoice: &Bolt12Invoice, expected_amount_msats: u64) -> Result<()> {
    if invoice.amount_msats != 0 && invoice.amount_msats != expected_amount_msats {
        return Err(anyhow!(
            "Invoice amount mismatch: expected {} msats, got {} msats",
            expected_amount_msats,
            invoice.amount_msats
        ));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if invoice.is_expired(now) {
        return Err(anyhow!("Invoice has expired"));
    }

    Ok(())
}

/// Validate a BOLT12 invoice against both the offer and expected amount.
pub fn validate_bolt12_invoice_against_offer(
    invoice: &Bolt12Invoice,
    offer: &Bolt12Offer,
    expected_amount_msats: u64,
) -> Result<()> {
    validate_bolt12_invoice(invoice, expected_amount_msats)?;

    if let Some(offer_amt) = offer.amount_msats {
        if offer_amt > 0 && invoice.amount_msats != offer_amt {
            return Err(anyhow!(
                "Invoice amount {} does not match offer amount {}",
                invoice.amount_msats,
                offer_amt
            ));
        }
    }

    if let Some(ref ph) = invoice.payment_hash {
        if hex::decode(ph).map(|b| b.len() != 32).unwrap_or(true) {
            return Err(anyhow!(
                "Invalid invoice payment hash length (must be 32 bytes)"
            ));
        }
    }

    Ok(())
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use bech32::ToBase32;

    const VALID_NODE_ID: &str =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    /// Verify that `parse_bolt12_offer` rejects malformed encoding.
    #[test]
    fn test_parse_bolt12_offer_rejects_malformed_encoding() {
        let offer = "lno1pq...";
        let result = parse_bolt12_offer(offer);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_bolt12_offer_hrps() {
        let raw = encode_tlv_stream(&[TlvRecord {
            tag: TLV_OFFER_NODE_ID,
            value: hex::decode(VALID_NODE_ID).unwrap(),
        }]);
        for hrp in ["lno", "lnot", "lnob", "lnos"] {
            let offer = bech32::encode(hrp, raw.to_base32(), bech32::Variant::Bech32m).unwrap();
            assert!(parse_bolt12_offer(&offer).is_ok(), "HRP: {hrp}");

            let invalid_hrp = format!("{hrp}1other");
            let offer =
                bech32::encode(&invalid_hrp, raw.to_base32(), bech32::Variant::Bech32m).unwrap();
            let err = parse_bolt12_offer(&offer).unwrap_err();
            assert!(err.to_string().contains("invalid BOLT12 offer HRP"));
        }
    }

    #[test]
    fn test_parse_bolt12_offer_checksumless_and_plus_continuation() {
        let raw = encode_tlv_stream(&[
            TlvRecord {
                tag: TLV_OFFER_DESCRIPTION,
                value: b"Donation".to_vec(),
            },
            TlvRecord {
                tag: TLV_OFFER_NODE_ID,
                value: hex::decode(VALID_NODE_ID).unwrap(),
            },
        ]);
        for hrp_str in ["lno", "lnot", "lnob", "lnos"] {
            let offer = encode_bolt12_bech32_checksumless(hrp_str, &raw).unwrap();
            let parsed = parse_bolt12_offer(&offer).unwrap();
            assert_eq!(parsed.description.as_deref(), Some("Donation"));
            assert_eq!(parsed.node_id.as_deref(), Some(VALID_NODE_ID));

            // Also test BOLT12 '+' multiline continuation
            let (first_half, second_half) = offer.split_at(20);
            let multiline = format!("{first_half}+\n  {second_half}");
            let parsed_multiline = parse_bolt12_offer(&multiline).unwrap();
            assert_eq!(parsed_multiline.offer, offer);
            assert_eq!(
                parsed_multiline.offer_id().unwrap(),
                parsed.offer_id().unwrap()
            );
        }
    }

    #[test]
    fn test_bolt12_merkle_root_and_signature_verification() {
        let sk = secp256k1::SecretKey::from_slice(&[0x42; 32]).unwrap();
        let secp = secp256k1::Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pk_hex = hex::encode(pk.serialize());

        let mut records = vec![
            TlvRecord {
                tag: TLV_OFFER_DESCRIPTION,
                value: b"SatsPath Coffee".to_vec(),
            },
            TlvRecord {
                tag: TLV_OFFER_NODE_ID,
                value: pk.serialize().to_vec(),
            },
        ];
        let sig = sign_bolt12_tlv_stream("offer", &records, &sk).unwrap();
        records.push(TlvRecord {
            tag: TLV_SIGNATURE,
            value: sig.to_vec(),
        });

        let raw = encode_tlv_stream(&records);
        let offer_str = encode_bolt12_bech32_checksumless("lno", &raw).unwrap();
        let parsed = parse_bolt12_offer(&offer_str).unwrap();
        assert_eq!(parsed.node_id.as_deref(), Some(pk_hex.as_str()));
        assert!(parsed.verify_signature().unwrap());
    }

    #[test]
    fn test_parse_bolt12_offer_invalid_prefix() {
        let offer = "invalid";
        let result = parse_bolt12_offer(offer);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_bolt12_invoice_request_valid() {
        let raw = encode_tlv_stream(&[
            TlvRecord {
                tag: TLV_INVREQ_OFFER_ID,
                value: [0x11; 32].to_vec(),
            },
            TlvRecord {
                tag: TLV_INVREQ_AMOUNT,
                value: write_tu64(25_000),
            },
        ]);
        let request = encode_bolt12_bech32_checksumless("lnr", &raw).unwrap();
        let result = parse_bolt12_invoice_request(&request).unwrap();
        assert_eq!(result.amount_msats, 25_000);
        assert!(parse_bolt12_invoice_request("lnr1...").is_err());
    }

    #[test]
    fn test_validate_bolt12_invoice_amount_match() {
        let invoice = Bolt12Invoice {
            invoice: "lni1...".to_string(),
            description: None,
            amount_msats: 100_000,
            currency: "btc".to_string(),
            created_at: 0,
            relative_expiry: None,
            absolute_expiry: None,
            payment_hash: None,
            fallback_address: None,
            routes: None,
            blinded_paths: None,
            node_id: None,
            signature: None,
        };

        let result = validate_bolt12_invoice(&invoice, 100_000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_bolt12_invoice_amount_mismatch() {
        let invoice = Bolt12Invoice {
            invoice: "lni1...".to_string(),
            description: None,
            amount_msats: 200_000,
            currency: "btc".to_string(),
            created_at: 0,
            relative_expiry: None,
            absolute_expiry: None,
            payment_hash: None,
            fallback_address: None,
            routes: None,
            blinded_paths: None,
            node_id: None,
            signature: None,
        };

        let result = validate_bolt12_invoice(&invoice, 100_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_tlv_roundtrip_bigsize_and_tu64() {
        let mut buf = Vec::new();
        write_bigsize(0x42, &mut buf);
        write_bigsize(0x1234, &mut buf);
        write_bigsize(0x12345678, &mut buf);

        let mut cursor = Cursor::new(buf.as_slice());
        assert_eq!(read_bigsize(&mut cursor).unwrap(), 0x42);
        assert_eq!(read_bigsize(&mut cursor).unwrap(), 0x1234);
        assert_eq!(read_bigsize(&mut cursor).unwrap(), 0x12345678);

        assert_eq!(read_tu64(&write_tu64(0)).unwrap(), 0);
        assert_eq!(read_tu64(&write_tu64(100_000)).unwrap(), 100_000);
        assert_eq!(
            read_tu64(&write_tu64(18_000_000_000)).unwrap(),
            18_000_000_000
        );
    }

    #[test]
    fn test_blinded_path_encoding_and_decoding() {
        let intro_node = VALID_NODE_ID.to_string();
        let bp_point = "03".to_string() + &"22".repeat(32);
        let hop_node = "02".to_string() + &"33".repeat(32);
        let enc_payload = "deadbeefcafe";

        let path = BlindedPath {
            introduction_node_id: intro_node.clone(),
            blinding_point: Some(bp_point.clone()),
            blinded_hops: vec![BlindedHop {
                blinded_node_id: hop_node.clone(),
                encrypted_payload: enc_payload.to_string(),
            }],
        };

        let bytes = path.encode_bytes().unwrap();
        let decoded = BlindedPath::decode_bytes(&bytes).unwrap();
        assert_eq!(decoded.introduction_node_id, intro_node);
        assert_eq!(decoded.blinding_point, Some(bp_point));
        assert_eq!(decoded.blinded_hops.len(), 1);
        assert_eq!(decoded.blinded_hops[0].blinded_node_id, hop_node);
        assert_eq!(decoded.blinded_hops[0].encrypted_payload, enc_payload);
    }

    #[test]
    fn test_blinded_path_encoding_hop_limit() {
        let hop = BlindedHop {
            blinded_node_id: "02".to_string() + &"33".repeat(32),
            encrypted_payload: "deadbeef".to_string(),
        };
        let mut path = BlindedPath {
            introduction_node_id: VALID_NODE_ID.to_string(),
            blinding_point: Some("03".to_string() + &"22".repeat(32)),
            blinded_hops: vec![hop.clone(); 100],
        };

        let bytes = path.encode_bytes().unwrap();
        assert_eq!(BlindedPath::decode_bytes(&bytes).unwrap(), path);

        let raw = encode_tlv_stream(&[TlvRecord {
            tag: TLV_OFFER_PATHS,
            value: bytes,
        }]);
        let offer = bech32::encode("lno", raw.to_base32(), bech32::Variant::Bech32m).unwrap();
        assert_eq!(
            parse_bolt12_offer(&offer).unwrap().blinded_paths,
            Some(vec![path.clone()])
        );

        path.blinded_hops.push(hop);
        let err = path.encode_bytes().unwrap_err();
        assert!(err.to_string().contains("excessive num_hops"));
    }

    #[test]
    fn test_parse_bolt12_offer_rejects_invalid_blinded_paths() {
        let key_bytes = hex::decode(VALID_NODE_ID).unwrap();
        let mut zero_hops = key_bytes.repeat(2);
        zero_hops.push(0);

        let mut excessive_hops = key_bytes.repeat(2);
        excessive_hops.push(101);

        let mut truncated_hop = key_bytes.repeat(2);
        truncated_hop.push(1);

        let mut truncated_payload = truncated_hop.clone();
        truncated_payload.extend_from_slice(&key_bytes);
        truncated_payload.extend_from_slice(&1u16.to_be_bytes());

        for (path_bytes, expected_error) in [
            (vec![], "paths must not be empty"),
            (zero_hops, "num_hops must be at least 1"),
            (excessive_hops, "excessive num_hops"),
            (truncated_hop, "invalid num_hops"),
            (truncated_payload, "encrypted payload length"),
        ] {
            let raw = encode_tlv_stream(&[TlvRecord {
                tag: TLV_OFFER_PATHS,
                value: path_bytes,
            }]);
            let offer = bech32::encode("lno", raw.to_base32(), bech32::Variant::Bech32m).unwrap();
            let err = parse_bolt12_offer(&offer).unwrap_err();
            assert!(
                format!("{err:#}").contains(expected_error),
                "expected '{expected_error}', got '{err:#}'"
            );
        }
    }

    #[test]
    fn test_create_and_encode_signed_invoice_request() {
        use secp256k1::rand::RngCore;
        let mut key_bytes = [0u8; 32];
        secp256k1::rand::thread_rng().fill_bytes(&mut key_bytes);
        let payer_key = secp256k1::SecretKey::from_slice(&key_bytes).unwrap();

        let raw_offer = encode_tlv_stream(&[TlvRecord {
            tag: TLV_OFFER_NODE_ID,
            value: hex::decode(VALID_NODE_ID).unwrap(),
        }]);
        let offer_str = encode_bolt12_bech32_checksumless("lno", &raw_offer).unwrap();
        let offer = parse_bolt12_offer(&offer_str).unwrap();

        let req = create_signed_invoice_request(
            &offer,
            50_000_000,
            &payer_key,
            Some("Thanks for the coffee!"),
            Some(1),
        )
        .unwrap();

        assert_eq!(req.amount_msats, 50_000_000);
        assert!(req.payer_node_id.is_some());
        assert!(req.signature.is_some());
        assert!(req.verify_signature(&offer.offer_id().unwrap()).unwrap());

        let encoded = req.encode().unwrap();
        assert!(encoded.starts_with("lnr1"));

        let parsed = parse_bolt12_invoice_request(&encoded).unwrap();
        assert_eq!(parsed.amount_msats, 50_000_000);
        assert_eq!(
            parsed.payer_note,
            Some("Thanks for the coffee!".to_string())
        );
    }

    #[tokio::test]
    async fn test_mock_bolt12_invoice_fetching_flow() {
        std::env::set_var("SATSPATH_MOCK_BOLT12", "1");

        let offer = Bolt12Offer {
            offer: "lno1pq...".to_string(),
            description: Some("Test Service".to_string()),
            amount_msats: Some(100_000_000),
            currency: Some("btc".to_string()),
            min_amount_msats: Some(50_000_000),
            max_amount_msats: Some(500_000_000),
            quantity: None,
            absolute_expiry: None,
            relative_expiry: None,
            paths: None,
            blinded_paths: None,
            issuer: None,
            node_id: None,
            signature: None,
        };

        let invoice = fetch_bolt12_invoice(&offer, 100_000_000, None, None, None)
            .await
            .unwrap();

        assert_eq!(invoice.amount_msats, 100_000_000);
        assert!(invoice.payment_hash.is_some());
        assert!(invoice.invoice.starts_with("lni1"));
        assert!(invoice.verify_signature().unwrap());

        let val_res = validate_bolt12_invoice_against_offer(&invoice, &offer, 100_000_000);
        assert!(val_res.is_ok());

        std::env::remove_var("SATSPATH_MOCK_BOLT12");
    }

    /// Reject a TLV value length that exceeds the available payload bytes.
    #[test]
    fn test_decode_tlv_stream_bounds() {
        let truncated_tlv = vec![0x01, 0xfd, 0x03, 0xe8, 0xaa, 0xbb];
        let err = decode_tlv_stream(&truncated_tlv).unwrap_err();
        assert!(err.to_string().contains("exceeds remaining stream bytes"));
    }

    /// Reject a blinded path declaring more than the maximum 100 hops.
    #[test]
    fn test_blinded_path_bounds() {
        let key_bytes = hex::decode(VALID_NODE_ID).unwrap();
        let mut malformed_path = key_bytes.repeat(2);
        malformed_path.push(200); // num_hops > 100
        let err = BlindedPath::decode_bytes(&malformed_path).unwrap_err();
        assert!(err.to_string().contains("excessive num_hops"));
    }
}
