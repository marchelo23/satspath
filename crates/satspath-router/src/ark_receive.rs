//! Wallet-generated Arkade addresses and canonical BIP-321 receive handoffs.
//!
//! A signing key and server URL are not an address: the wallet must supply its
//! contract's output key. This module never constructs contracts or transactions.

use anyhow::{bail, Result};
use bitcoin::secp256k1::{PublicKey, XOnlyPublicKey};
use satspath_core::PaymentMethod;

use crate::handoff::fmt_btc;

/// Decode the version-zero Arkade wire format: version byte and two x-only keys.
pub fn decode_ark_address(address: &str) -> Result<(bool, XOnlyPublicKey, XOnlyPublicKey)> {
    satspath_handoff::ark_address(address).map_err(anyhow::Error::msg)
}

/// Validate an address-backed method and bind it to its public output key.
/// Legacy opaque URIs and VTXO outpoints are not payment addresses.
pub fn ark_receive_payload(
    method: &PaymentMethod,
    network: &str,
    amount_sats: Option<u64>,
) -> Result<String> {
    let PaymentMethod::Ark {
        server,
        pubkey,
        opaque_uri: Some(address),
        vtxo_pointer,
        expires_at,
        ..
    } = method
    else {
        bail!("Ark handoff requires a wallet-generated Ark address");
    };
    satspath_core::ark::validate_ark_server_url(server)?;
    satspath_core::validation::validate_compressed_pubkey(pubkey)?;
    if vtxo_pointer.is_some()
        || expires_at.is_some_and(|expiry| expiry <= chrono::Utc::now().timestamp())
    {
        bail!("unsupported VTXO pointer or expired Ark method");
    }
    let (mainnet, _, output_key) = decode_ark_address(address)?;
    let expected_mainnet = match network.trim().to_ascii_lowercase().as_str() {
        "bitcoin" | "mainnet" => true,
        "testnet" | "signet" | "regtest" | "devnet" | "mutinynet" => false,
        _ => bail!("unsupported Ark handoff network"),
    };
    if mainnet != expected_mainnet {
        bail!("Ark address network mismatch");
    }
    let receiver = PublicKey::from_slice(&hex::decode(pubkey)?)?
        .x_only_public_key()
        .0;
    if receiver != output_key {
        bail!("Ark address output key does not match the configured receiver");
    }
    let mut payload = format!("bitcoin:?ark={address}");
    if let Some(sats) = amount_sats {
        satspath_core::validation::validate_amount_sats(sats)?;
        payload.push_str(&format!("&amount={}", fmt_btc(sats)));
    }
    satspath_core::validation::assert_no_private_material(&payload)?;
    Ok(payload)
}

/// Bind a wallet address to validated ASP discovery data, not merely a URL.
pub fn validate_ark_asp(address: &str, info: &crate::ark::ArkAspInfo) -> Result<()> {
    info.validate()?;
    let (mainnet, operator, _) = decode_ark_address(address)?;
    let asp_key = PublicKey::from_slice(&hex::decode(&info.pubkey)?)?
        .x_only_public_key()
        .0;
    if asp_key != operator
        || mainnet
            != matches!(
                info.network.trim().to_ascii_lowercase().as_str(),
                "bitcoin" | "mainnet"
            )
    {
        bail!("Ark address does not match the discovered ASP");
    }
    Ok(())
}

/// Build an amount-bound wallet URI using validated ASP discovery state.
/// Unlike an address's test-network prefix, the ASP state binds the exact chain.
/// Callers obtain this state from `LiveArkAspClient::get_asp_info`; this helper
/// performs no network requests and does not authenticate caller-invented state.
pub fn build_qr_payload_with_ark_asp(
    method: &PaymentMethod,
    amount_sats: u64,
    network: &str,
    info: &crate::ark::ArkAspInfo,
) -> Result<String> {
    let PaymentMethod::Ark {
        opaque_uri: Some(address),
        ..
    } = method
    else {
        bail!("ASP-backed handoff requires a wallet-generated Ark address");
    };
    validate_ark_asp(address, info)?;
    let canonical = |name: &str| match name.trim().to_ascii_lowercase().as_str() {
        "bitcoin" | "mainnet" => "mainnet".to_owned(),
        "devnet" => "testnet".to_owned(),
        other => other.to_owned(),
    };
    if canonical(network) != canonical(&info.network) {
        bail!("ASP network does not match the intended handoff network");
    }
    if amount_sats < info.dust_limit_sats {
        bail!("Ark amount is below the ASP dust limit");
    }
    let payload = crate::build_qr_payload(method, amount_sats)?;
    crate::handoff::validate_payload(method, &payload, network, Some(amount_sats))?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bech32::ToBase32;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    /// Deterministic public fixture key; never used in production.
    fn key(n: u8) -> PublicKey {
        PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[n; 32]).unwrap())
    }

    /// Encode a public wire-format fixture, including unsupported-version cases.
    fn address(hrp: &str, version: u8, operator: PublicKey, output: PublicKey) -> String {
        let bytes = [
            vec![version],
            operator.x_only_public_key().0.serialize().to_vec(),
            output.x_only_public_key().0.serialize().to_vec(),
        ]
        .concat();
        bech32::encode(hrp, bytes.to_base32(), bech32::Variant::Bech32m).unwrap()
    }

    /// A wallet-address-backed method with independently chosen operator/output keys.
    fn method(hrp: &str) -> PaymentMethod {
        PaymentMethod::Ark {
            label: "Ark".into(),
            server: "https://ark.example.com".into(),
            pubkey: key(2).to_string(),
            opaque_uri: Some(address(hrp, 0, key(1), key(2))),
            vtxo_pointer: None,
            proof: None,
            expires_at: None,
        }
    }

    #[test]
    /// Cross-check decoding against the published Arkade SDK example.
    fn official_sdk_vector_decodes_without_reencoding() {
        // https://docs.arkadeos.com/wallets/getting-started/addresses
        let (_, operator, output) = decode_ark_address("ark1qzpq904am6clw3pgqwyh4p02708fy4xs0hcpwt7rwfdttuxsjameetl3ujgrw8089sl27rtp79aqcl0xspkahwnm4teg5lmhe47pxulw9m6rn8").unwrap();
        assert_eq!(
            operator.to_string(),
            "8202bebddeb1f7442803897a85eaf3ce9254d07df0172fc3725ab5f0d097779c"
        );
        assert_eq!(
            output.to_string(),
            "aff1e490371de72c3eaf0d61f17a0c7de6806ddbba7baaf28a7f77cd7c1373ee"
        );
    }

    #[test]
    /// The outgoing URI is bound to its exact selected method and amount.
    fn qr_binds_address_amount_network_and_all_parameters() {
        for (hrp, network) in [("ark", "mainnet"), ("tark", "regtest")] {
            let method = method(hrp);
            let payload = crate::build_qr_payload(&method, 5_000).unwrap();
            assert!(payload.ends_with("&amount=0.00005000"));
            crate::handoff::validate_payload(&method, &payload, network, Some(5_000)).unwrap();
            for bad in [
                payload.replace("0.00005000", "5000"),
                format!("{payload}&amount=0.00005000"),
                format!("{payload}&server=https://evil.example"),
                payload.replace("?ark=", "?ark=wrong"),
            ] {
                assert!(
                    crate::handoff::validate_payload(&method, &bad, network, Some(5_000)).is_err(),
                    "{bad}"
                );
            }
            assert!(crate::handoff::validate_payload(&method, &payload, network, None).is_err());
            assert!(ark_receive_payload(
                &method,
                if hrp == "ark" { "regtest" } else { "mainnet" },
                None
            )
            .is_err());
            for amount in [0, u64::MAX] {
                assert!(crate::build_qr_payload(&method, amount).is_err());
            }
        }
    }

    #[test]
    /// Reject malformed addresses and legacy, expired or mismatched method state.
    fn malformed_and_legacy_addresses_fail_closed() {
        let valid = address("ark", 0, key(1), key(2));
        let mut bad_checksum = valid.clone();
        bad_checksum.pop();
        bad_checksum.push(if valid.ends_with('q') { 'p' } else { 'q' });
        let mut invalid_point = vec![0; 65];
        invalid_point[1..33].fill(0xff);
        let valid_bytes = [
            vec![0],
            key(1).x_only_public_key().0.serialize().to_vec(),
            key(2).x_only_public_key().0.serialize().to_vec(),
        ]
        .concat();
        for bad in [
            bad_checksum,
            valid.to_uppercase(),
            address("ark", 1, key(1), key(2)),
            address("other", 0, key(1), key(2)),
            "ark:receiver".into(),
            bech32::encode("ark", valid_bytes.to_base32(), bech32::Variant::Bech32).unwrap(),
            bech32::encode("ark", invalid_point.to_base32(), bech32::Variant::Bech32m).unwrap(),
            bech32::encode("ark", vec![0; 64].to_base32(), bech32::Variant::Bech32m).unwrap(),
            format!("{}q", address("ark", 0, key(1), key(2))),
        ] {
            assert!(decode_ark_address(&bad).is_err(), "{bad}");
        }
        for change in 0..6 {
            let mut m = method("ark");
            if let PaymentMethod::Ark {
                server,
                pubkey,
                opaque_uri,
                vtxo_pointer,
                expires_at,
                ..
            } = &mut m
            {
                match change {
                    0 => *server = "http://ark.example.com".into(),
                    1 => *pubkey = key(3).to_string(),
                    2 => *opaque_uri = None,
                    3 => *vtxo_pointer = Some("outpoint".into()),
                    4 => *expires_at = Some(1),
                    _ => *pubkey = "00".repeat(33),
                }
            }
            assert!(crate::build_qr_payload(&m, 5000).is_err(), "{m:?}");
        }
        for server in [
            "https://user@ark.example.com",
            "https://user:pass@ark.example.com",
            "https://ark.example.com/#fragment",
        ] {
            let mut m = method("ark");
            if let PaymentMethod::Ark { server: value, .. } = &mut m {
                *value = server.into();
            }
            assert!(crate::build_qr_payload(&m, 5000).is_err(), "{server}");
        }
    }

    #[test]
    /// Discovery state must bind both keys, exact chain and operational amount constraints.
    fn discovery_parameters_bind_operator_and_network() {
        let address = address("tark", 0, key(1), key(2));
        let mut info = crate::ark::ArkAspInfo {
            pubkey: key(1).to_string(),
            network: "regtest".into(),
            round_interval_secs: None,
            vtxo_tree_expiry: None,
            unilateral_exit_delay: 144,
            dust_limit_sats: 330,
            boarding_descriptor_template: None,
            fees: None,
        };
        validate_ark_asp(&address, &info).unwrap();
        let method = method("tark");
        assert_eq!(
            build_qr_payload_with_ark_asp(&method, 5000, "regtest", &info).unwrap(),
            crate::build_qr_payload(&method, 5000).unwrap()
        );
        assert!(build_qr_payload_with_ark_asp(&method, 5000, "signet", &info).is_err());
        assert!(build_qr_payload_with_ark_asp(&method, 329, "regtest", &info).is_err());
        info.network = "mutinynet".into();
        let payload = build_qr_payload_with_ark_asp(&method, 5000, "mutinynet", &info).unwrap();
        crate::handoff::validate_payload(&method, &payload, " MUTINYNET ", Some(5000)).unwrap();
        assert!(build_qr_payload_with_ark_asp(&method, 5000, "signet", &info).is_err());
        info.network = "signet".into();
        assert!(build_qr_payload_with_ark_asp(&method, 5000, "mutinynet", &info).is_err());
        info.pubkey = key(3).to_string();
        assert!(validate_ark_asp(&address, &info).is_err());
        info.pubkey = key(1).to_string();
        info.network = "bitcoin".into();
        assert!(validate_ark_asp(&address, &info).is_err());
        info.network = "regtest".into();
        info.unilateral_exit_delay = 0;
        assert!(validate_ark_asp(&address, &info).is_err());
    }

    #[test]
    /// Native/browser shared validation uses the same key and network policy.
    fn shared_handoff_checker_enforces_the_same_address_policy() {
        let address = address("tark", 0, key(1), key(2));
        for (network, valid) in [
            (bitcoin::Network::Bitcoin, false),
            (bitcoin::Network::Regtest, true),
        ] {
            assert_eq!(
                satspath_handoff::validate_method(
                    satspath_handoff::PaymentMethod::Ark {
                        server: "https://ark.example.com",
                        pubkey: &key(2).to_string(),
                        vtxo_pointer: None,
                        opaque_uri: Some(&address),
                        expires_at: None,
                    },
                    5000,
                    100,
                    Some(network)
                )
                .is_ok(),
                valid
            );
        }
    }
}
