use bech32::FromBase32;
use bitcoin::{Address, Network};
use secp256k1::PublicKey;
use std::str::FromStr;

use crate::ark::{validate_ark_receive_pointer, verify_ark_ownership_proof, ArkReceivePointer};
use crate::errors::{Result, SatsPathError};
use crate::pointer::BitcoinNetwork;
use crate::profile::{ClaimPolicy, PaymentMethod, PaymentProfile};

pub const LARGE_PREVIEW_AMOUNT_SATS: u64 = 100_000_000;
pub const MAX_PREVIEW_AMOUNT_SATS: u64 = 21_000_000 * 100_000_000;

pub fn validate_amount_sats(amount_sats: u64) -> Result<()> {
    if amount_sats == 0 {
        return Err(SatsPathError::InvalidPaymentPointer(
            "amount must be positive".into(),
        ));
    }
    if amount_sats > MAX_PREVIEW_AMOUNT_SATS {
        return Err(SatsPathError::InvalidPaymentPointer(
            "amount exceeds Bitcoin supply".into(),
        ));
    }
    Ok(())
}

pub fn validate_compressed_pubkey(pubkey_hex: &str) -> Result<()> {
    let bytes =
        hex::decode(pubkey_hex).map_err(|e| SatsPathError::InvalidPublicKey(e.to_string()))?;
    if bytes.len() != 33 || !matches!(bytes.first(), Some(0x02 | 0x03)) {
        return Err(SatsPathError::InvalidPublicKey(
            "expected 33-byte compressed secp256k1 pubkey".into(),
        ));
    }
    PublicKey::from_slice(&bytes).map_err(|e| SatsPathError::InvalidPublicKey(e.to_string()))?;
    Ok(())
}

pub fn validate_lightning_address(address: &str) -> Result<()> {
    let trimmed = address.trim();
    let Some((local, domain)) = trimmed.split_once('@') else {
        return Err(SatsPathError::InvalidPaymentPointer(
            "Lightning Address must be user@domain".into(),
        ));
    };
    let valid_local = !local.is_empty()
        && local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'));
    let valid_domain = domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
    if valid_local && valid_domain {
        Ok(())
    } else {
        Err(SatsPathError::InvalidPaymentPointer(
            "invalid Lightning Address format".into(),
        ))
    }
}

/// Validate a BOLT12 offer string.
/// BOLT12 offers are bech32 encoded with prefix "lno" (mainnet) or "lnot" (testnet).
/// They contain an amount, node_id, paths, and other metadata.
pub fn validate_bolt12_offer(offer: &str) -> Result<()> {
    let trimmed = offer.trim();
    if trimmed.is_empty() {
        return Err(SatsPathError::InvalidPaymentPointer(
            "BOLT12 offer cannot be empty".into(),
        ));
    }
    let lower = trimmed.to_ascii_lowercase();
    // BOLT12 offers use bech32 with prefixes lno (mainnet) or lnot (testnet)
    if !lower.starts_with("lno") && !lower.starts_with("lnot") {
        return Err(SatsPathError::InvalidPaymentPointer(
            "BOLT12 offer must start with 'lno' (mainnet) or 'lnot' (testnet)".into(),
        ));
    }
    // Decode and validate the bech32 payload
    let (_, data, _) = bech32::decode(&lower).map_err(|e| {
        SatsPathError::InvalidPaymentPointer(format!("BOLT12 offer bech32 decode failed: {e}"))
    })?;
    // A real BOLT12 offer always has substantial TLV data -- reject suspiciously
    // short payloads that are likely truncated, synthetic, or just a prefix.
    if data.len() < 40 {
        return Err(SatsPathError::InvalidPaymentPointer(
            "BOLT12 offer data too short -- likely truncated or invalid".into(),
        ));
    }
    // Ensure no private material
    assert_no_private_material(trimmed)?;
    Ok(())
}

pub fn validate_bitcoin_address(address: &str, network: BitcoinNetwork) -> Result<()> {
    let parsed = Address::from_str(address.trim())
        .map_err(|e| SatsPathError::InvalidPaymentPointer(e.to_string()))?;
    let expected = match network {
        BitcoinNetwork::Mainnet => Network::Bitcoin,
        BitcoinNetwork::Testnet => Network::Testnet,
        BitcoinNetwork::Regtest => Network::Regtest,
    };
    parsed
        .require_network(expected)
        .map_err(|e| SatsPathError::InvalidPaymentPointer(e.to_string()))?;
    Ok(())
}

/// Validate a BIP-352 Silent Payment Bech32m address for the expected Bitcoin network.
///
/// Enforces:
/// - Non-empty string with no private key material or mixed casing.
/// - Correct Bech32m HRP (`sp` for mainnet, `tsp` for testnet, `tsp` or `sprt` for regtest).
/// - 5-bit witness version `0` (`q`) followed by 66 bytes (two 33-byte compressed `secp256k1` keys).
///
/// # Errors
/// Returns [`SatsPathError::InvalidPaymentPointer`] or [`SatsPathError::PrivateMaterialRejected`]
/// if the address is malformed, uses the wrong network prefix, or embeds private material.
pub fn validate_silent_payment_address(address: &str, network: BitcoinNetwork) -> Result<()> {
    let trimmed = address.trim();
    if trimmed.is_empty() {
        return Err(SatsPathError::InvalidPaymentPointer(
            "silent payment address cannot be empty".into(),
        ));
    }

    assert_no_private_material(trimmed)?;

    let lower = trimmed.to_ascii_lowercase();
    if trimmed != lower && trimmed != trimmed.to_ascii_uppercase() {
        return Err(SatsPathError::InvalidPaymentPointer(
            "silent payment address cannot mix uppercase and lowercase characters".into(),
        ));
    }

    let (hrp, data, variant) = bech32::decode(&lower).map_err(|e| {
        SatsPathError::InvalidPaymentPointer(format!("silent payment bech32 decode failed: {e}"))
    })?;

    // BIP-352: mainnet uses 'sp', testnet uses 'tsp', regtest uses 'sprt' (or 'tsp')
    let valid_hrp = match network {
        BitcoinNetwork::Mainnet => hrp == "sp",
        BitcoinNetwork::Testnet => hrp == "tsp",
        BitcoinNetwork::Regtest => hrp == "sprt" || hrp == "tsp",
    };

    if !valid_hrp {
        return Err(SatsPathError::InvalidPaymentPointer(format!(
            "silent payment address HRP '{hrp}' is invalid for {network:?}"
        )));
    }

    if variant != bech32::Variant::Bech32m {
        return Err(SatsPathError::InvalidPaymentPointer(
            "silent payment address must use Bech32m encoding".into(),
        ));
    }

    let Some(version_u5) = data.first() else {
        return Err(SatsPathError::InvalidPaymentPointer(
            "silent payment address is missing version".into(),
        ));
    };
    if version_u5.to_u8() != 0 {
        return Err(SatsPathError::InvalidPaymentPointer(format!(
            "unsupported silent payment address version: {}",
            version_u5.to_u8()
        )));
    }

    let bytes = Vec::<u8>::from_base32(&data[1..]).map_err(|e| {
        SatsPathError::InvalidPaymentPointer(format!(
            "silent payment base32 conversion failed: {e}"
        ))
    })?;

    // BIP-352 payload after 5-bit version 0: 33 bytes scan pubkey + 33 bytes spend pubkey = 66 bytes
    if bytes.len() != 66 {
        return Err(SatsPathError::InvalidPaymentPointer(format!(
            "silent payment address payload must be 66 bytes, got {}",
            bytes.len()
        )));
    }

    // Validate both compressed public keys (must start with 0x02 or 0x03)
    let scan_header = bytes[0];
    let spend_header = bytes[33];
    if (scan_header != 0x02 && scan_header != 0x03)
        || (spend_header != 0x02 && spend_header != 0x03)
    {
        return Err(SatsPathError::InvalidPaymentPointer(
            "silent payment public keys must be 33-byte compressed secp256k1 keys".into(),
        ));
    }

    secp256k1::PublicKey::from_slice(&bytes[..33]).map_err(|e| {
        SatsPathError::InvalidPaymentPointer(format!("invalid scan public key: {e}"))
    })?;
    secp256k1::PublicKey::from_slice(&bytes[33..66]).map_err(|e| {
        SatsPathError::InvalidPaymentPointer(format!("invalid spend public key: {e}"))
    })?;

    Ok(())
}

pub fn assert_no_private_material(payload: &str) -> Result<()> {
    let lower = payload.to_ascii_lowercase();
    let blocked = [
        "xprv",
        "tprv",
        "seed phrase",
        "mnemonic",
        "private_key",
        "private key",
        "secret_key",
        "macaroon",
        "cert",
        "api_key",
        "apikey",
        "secret_key",
        "secret_hex",
        "password",
    ];
    if let Some(term) = blocked.iter().find(|term| lower.contains(**term)) {
        return Err(SatsPathError::PrivateMaterialRejected((*term).into()));
    }

    let word_count = payload
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|word| word.len() >= 3)
        .count();
    if word_count >= 12 && lower.contains("seed") {
        return Err(SatsPathError::PrivateMaterialRejected(
            "seed phrase-like payload".into(),
        ));
    }
    Ok(())
}

pub fn assert_mainnet_preview_safe(payload: &str) -> Result<()> {
    assert_no_private_material(payload)?;

    let lower = payload.to_ascii_lowercase();
    let blocked = [
        "seed",
        "mnemonic",
        "xprv",
        "tprv",
        "private key",
        "privkey",
        "macaroon",
        "cert",
        "api_key",
        "secret_key",
        "secret_hex",
        "password",
        "refund_key",
        "claim_key",
        "preimage",
    ];
    if let Some(term) = blocked.iter().find(|term| lower.contains(**term)) {
        return Err(SatsPathError::PrivateMaterialRejected((*term).into()));
    }

    let secret_field_names = [
        "seed",
        "mnemonic",
        "xprv",
        "tprv",
        "private_key",
        "privkey",
        "macaroon",
        "cert",
        "api_key",
        "secret_key",
        "secret_hex",
        "password",
        "refund_key",
        "claim_key",
        "preimage",
    ];
    for field in secret_field_names {
        if lower.contains(&format!("\"{field}\"")) || lower.contains(&format!("'{field}'")) {
            return Err(SatsPathError::PrivateMaterialRejected(format!(
                "secret-bearing field `{field}`"
            )));
        }
    }

    Ok(())
}

pub fn validate_claim_policy(policy: &ClaimPolicy) -> Result<()> {
    match policy {
        ClaimPolicy::SingleSig { receiver_pubkey } => validate_compressed_pubkey(receiver_pubkey),
        ClaimPolicy::Multisig {
            threshold,
            pubkeys,
            descriptor,
        } => {
            if *threshold == 0 || usize::from(*threshold) > pubkeys.len() {
                return Err(SatsPathError::InvalidPaymentPointer(
                    "invalid multisig threshold".into(),
                ));
            }
            for pubkey in pubkeys {
                validate_compressed_pubkey(pubkey)?;
            }
            if let Some(descriptor) = descriptor {
                assert_no_private_material(descriptor)?;
            }
            Ok(())
        }
        ClaimPolicy::FutureTaproot {
            internal_key,
            script_policy_hint,
        } => {
            validate_compressed_pubkey(internal_key)?;
            if let Some(hint) = script_policy_hint {
                assert_no_private_material(hint)?;
            }
            Ok(())
        }
    }
}

pub fn validate_public_profile(profile: &PaymentProfile) -> Result<()> {
    assert_no_private_material(&profile.alias)?;
    validate_compressed_pubkey(&profile.identity_pubkey)?;
    if let Some(expires_at) = profile.expires_at {
        if expires_at <= profile.updated_at {
            return Err(SatsPathError::InvalidPaymentPointer(
                "profile expires before it is updated".into(),
            ));
        }
    }

    for method in &profile.methods {
        match method {
            PaymentMethod::Lightning {
                lightning_address,
                lnurl,
                bolt12,
                receiver_pubkey,
                ..
            } => {
                if let Some(address) = lightning_address {
                    validate_lightning_address(address)?;
                }
                if let Some(url) = lnurl {
                    let parsed = url::Url::parse(url)
                        .map_err(|e| SatsPathError::InvalidPaymentPointer(e.to_string()))?;
                    if !matches!(parsed.scheme(), "https" | "http") {
                        return Err(SatsPathError::InvalidPaymentPointer(
                            "LNURL must be http(s)".into(),
                        ));
                    }
                }
                if let Some(invoice) = bolt12 {
                    validate_bolt12_offer(invoice)?;
                }
                if let Some(pubkey) = receiver_pubkey {
                    validate_compressed_pubkey(pubkey)?;
                }
            }
            PaymentMethod::Onchain {
                network,
                address,
                silent_payment_pubkey,
                pubkey_hint,
                descriptor_hint,
                ..
            } => {
                if let Some(addr) = address {
                    validate_bitcoin_address(addr, *network)?;
                }
                if let Some(sp) = silent_payment_pubkey {
                    validate_silent_payment_address(sp, *network)?;
                }
                if let Some(pubkey) = pubkey_hint {
                    validate_compressed_pubkey(pubkey)?;
                }
                if let Some(descriptor) = descriptor_hint {
                    assert_no_private_material(descriptor)?;
                }
            }
            PaymentMethod::Bolt12(offer) => {
                validate_bolt12_offer(&offer.offer)?;
            }
            PaymentMethod::Ark {
                server,
                pubkey,
                vtxo_pointer,
                proof,
                expires_at,
                opaque_uri,
                ..
            } => {
                if let Some(uri) = opaque_uri {
                    // Arkade opaque URI path -- server + pubkey are empty sentinels.
                    // Validate only the public URI; ownership proof is not possible.
                    crate::ark::validate_arkade_opaque_uri(uri)?;
                } else {
                    // Full server + pubkey path -- existing validation.
                    let pointer = ArkReceivePointer {
                        server: server.clone(),
                        receiver_pubkey: pubkey.clone(),
                        vtxo_pointer: vtxo_pointer.clone(),
                        proof: proof.clone(),
                        expires_at: *expires_at,
                    };
                    let now = chrono::Utc::now().timestamp();
                    validate_ark_receive_pointer(&pointer, now)?;
                    if proof.is_some()
                        && !verify_ark_ownership_proof(
                            &profile.alias,
                            &profile.identity_pubkey,
                            &pointer,
                            now,
                        )?
                    {
                        return Err(SatsPathError::InvalidSignature);
                    }
                }
            }
        }
    }

    // Ownership attestations are structurally validated here (no private
    // material, well-formed proofs, sane expiry). Cryptographic re-verification
    // is performed separately at resolve time by
    // `ownership::verify_method_verification`.
    for verification in &profile.method_verifications {
        crate::ownership::validate_method_verification(verification)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    #[test]
    fn mainnet_address_accepted_in_mainnet_preview() {
        assert!(validate_bitcoin_address(
            "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            BitcoinNetwork::Mainnet
        )
        .is_ok());
    }

    #[test]
    fn testnet_address_rejected_in_mainnet_preview() {
        assert!(validate_bitcoin_address(
            "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
            BitcoinNetwork::Mainnet
        )
        .is_err());
    }

    #[test]
    fn compressed_secp256k1_pubkey_accepted() {
        assert!(validate_compressed_pubkey(VALID_PUBKEY).is_ok());
    }

    #[test]
    fn invalid_pubkey_rejected() {
        assert!(validate_compressed_pubkey("04abcdef").is_err());
    }

    #[test]
    fn lightning_address_parsed() {
        assert!(validate_lightning_address("rodrigo@example.com").is_ok());
        assert!(validate_lightning_address("not-an-address").is_err());
    }

    #[test]
    fn profile_rejects_private_material() {
        let profile = PaymentProfile {
            alias: "alice@example.com".into(),
            identity_pubkey: VALID_PUBKEY.into(),
            methods: vec![PaymentMethod::Lightning {
                label: "LN".into(),
                lightning_address: Some("alice@example.com".into()),
                lnurl: None,
                bolt12: Some("secret xprv payload".into()),
                receiver_pubkey: None,
            }],
            updated_at: 1,
            expires_at: Some(2),
            sequence: None,
            preferences: vec![],
            nonce: None,
            rotation: None,
            method_verifications: Vec::new(),
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
            recovery_policy: None,
            recovery: None,
        };
        assert!(validate_public_profile(&profile).is_err());
    }

    #[test]
    fn mainnet_preview_safe_rejects_secret_terms() {
        assert!(assert_mainnet_preview_safe("bitcoin:bc1qexample?amount=0.1").is_ok());
        assert!(assert_mainnet_preview_safe("{\"claim_key\":\"abc\"}").is_err());
        assert!(assert_mainnet_preview_safe("lnbc1_refund_key_payload").is_err());
    }

    #[test]
    fn multisig_claim_policy_validates_pubkeys() {
        let policy = ClaimPolicy::Multisig {
            threshold: 2,
            pubkeys: vec![VALID_PUBKEY.into(), VALID_PUBKEY.into()],
            descriptor: Some("wsh(sortedmulti(2,...))".into()),
        };
        assert!(validate_claim_policy(&policy).is_ok());
    }

    /// Accept valid Silent Payment encodings on their expected networks and
    /// reject network mismatches, empty/private material, truncation, and versions.
    #[test]
    fn silent_payment_address_validation() {
        use bech32::{u5, ToBase32};

        let secp = secp256k1::Secp256k1::new();
        let sk1 = secp256k1::SecretKey::new(&mut rand::thread_rng());
        let pk1 = secp256k1::PublicKey::from_secret_key(&secp, &sk1);
        let sk2 = secp256k1::SecretKey::new(&mut rand::thread_rng());
        let pk2 = secp256k1::PublicKey::from_secret_key(&secp, &sk2);

        let mut payload = Vec::with_capacity(66);
        payload.extend_from_slice(&pk1.serialize());
        payload.extend_from_slice(&pk2.serialize());

        let mut data = vec![u5::try_from_u8(0).unwrap()];
        data.extend(payload.to_base32());

        let mainnet_sp = bech32::encode("sp", data.clone(), bech32::Variant::Bech32m).unwrap();
        let testnet_sp = bech32::encode("tsp", data.clone(), bech32::Variant::Bech32m).unwrap();
        let regtest_sp = bech32::encode("sprt", data.clone(), bech32::Variant::Bech32m).unwrap();

        // Valid addresses
        assert!(validate_silent_payment_address(&mainnet_sp, BitcoinNetwork::Mainnet).is_ok());
        assert!(validate_silent_payment_address(&testnet_sp, BitcoinNetwork::Testnet).is_ok());
        assert!(validate_silent_payment_address(&regtest_sp, BitcoinNetwork::Regtest).is_ok());

        // Official BIP-352 mainnet test vector address
        assert!(validate_silent_payment_address(
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
            BitcoinNetwork::Mainnet
        )
        .is_ok());

        // Network mismatch
        assert!(validate_silent_payment_address(&mainnet_sp, BitcoinNetwork::Testnet).is_err());
        assert!(validate_silent_payment_address(&testnet_sp, BitcoinNetwork::Mainnet).is_err());

        // Empty address
        assert!(validate_silent_payment_address("", BitcoinNetwork::Mainnet).is_err());

        // Private material rejected
        assert!(
            validate_silent_payment_address("sp1q_xprv_secret", BitcoinNetwork::Mainnet).is_err()
        );

        // Truncated payload
        let mut truncated_data = vec![u5::try_from_u8(0).unwrap()];
        truncated_data.extend(payload[..30].to_vec().to_base32());
        let truncated = bech32::encode("sp", truncated_data, bech32::Variant::Bech32m).unwrap();
        assert!(validate_silent_payment_address(&truncated, BitcoinNetwork::Mainnet).is_err());

        // Invalid version byte
        let mut bad_version_data = vec![u5::try_from_u8(1).unwrap()];
        bad_version_data.extend(payload.to_base32());
        let bad_version = bech32::encode("sp", bad_version_data, bech32::Variant::Bech32m).unwrap();
        assert!(validate_silent_payment_address(&bad_version, BitcoinNetwork::Mainnet).is_err());
    }
}
