//! Offline independent consumer of an on-chain QuoteResponse. This checks the
//! handoff contract, not remote identity authority, and cannot authorize a spend.

use anyhow::{ensure, Result};
use satspath_core::{privacy::canonical_identifier, PaymentMethod};
use satspath_router::QuoteResponse;
use std::{io::Read, path::Path};

pub fn cmd_check_handoff(
    path: &Path,
    recipient: &str,
    destination: &str,
    amount: u64,
    network: &str,
) -> Result<()> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(50 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 50 * 1024, "quote exceeds 50 KiB");
    let quote: QuoteResponse = serde_json::from_slice(&bytes)?;
    let payload = check(&quote, recipient, destination, amount, network)?;
    println!(
        "{}",
        serde_json::json!({
            "status": "valid_handoff", "mode": "preview_only", "payment_payload": payload,
            "amount_sats": amount, "network": network,
            "destination": destination,
            "identity_authority_verified_by_this_command": false,
            "requires_host_wallet_approval": true, "approval_granted": false,
            "signs_transactions": false, "broadcasts_transactions": false,
        })
    );
    Ok(())
}

fn check<'a>(
    quote: &'a QuoteResponse,
    expected: &str,
    destination: &str,
    amount: u64,
    network: &str,
) -> Result<&'a str> {
    satspath_core::validation::validate_amount_sats(amount)?;
    ensure!(
        matches!(
            network,
            "mainnet" | "bitcoin" | "testnet" | "signet" | "regtest"
        ),
        "unsupported network"
    );
    let QuoteResponse::Ok {
        recipient,
        selected_method,
        qr,
        ..
    } = quote
    else {
        anyhow::bail!("only a successful quote can carry a handoff");
    };
    ensure!(
        canonical_identifier(&recipient.alias) == canonical_identifier(expected),
        "recipient mismatch"
    );
    ensure!(
        recipient.profile_signature_verified,
        "quote does not report profile signature verification"
    );
    ensure!(
        matches!(
            selected_method,
            PaymentMethod::Onchain {
                silent_payment_pubkey: None,
                ..
            }
        ),
        "only standard on-chain handoffs are supported"
    );
    satspath_router::handoff::validate_payload(selected_method, qr, network, Some(amount))?;
    ensure!(
        satspath_core::bip321::parse_bip321(qr)?.address.as_deref() == Some(destination),
        "destination mismatch against payer bounds"
    );
    Ok(qr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use satspath_core::{BitcoinNetwork, PaymentMethod};
    use satspath_router::QuoteRecipient;

    #[test]
    fn independent_contract_checker_rejects_wrong_payer_bounds() {
        let quote = QuoteResponse::Ok {
            recipient: QuoteRecipient {
                alias: "alice@example.com".into(),
                verified: true,
                profile_signature_verified: true,
                identifier_verified: false,
                identifier_verification: "not attested".into(),
                fingerprint: None,
            },
            selected_method: PaymentMethod::Onchain {
                label: "Bitcoin".into(),
                network: BitcoinNetwork::Mainnet,
                address: Some("1BoatSLRHtKNngkdXEeobR76b53LETtpyT".into()),
                silent_payment_pubkey: None,
                pubkey_hint: None,
                descriptor_hint: None,
                address_list: vec![],
            },
            fee_sats: None,
            eta: None,
            reason: "test".into(),
            qr: "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.00021001".into(),
            execution: None,
            wallet_hint: None,
        };
        let destination = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT";
        assert!(check(&quote, "alice@example.com", destination, 21_001, "mainnet").is_ok());
        assert!(check(&quote, "alice@example.com", "attacker", 21_001, "mainnet").is_err());
        for (alias, amount, network) in [
            ("bob@example.com", 21_001, "mainnet"),
            ("alice@example.com", 21_000, "mainnet"),
            ("alice@example.com", 21_001, "regtest"),
            ("alice@example.com", 21_001, "unknown"),
        ] {
            assert!(check(&quote, alias, destination, amount, network).is_err());
        }
        assert!(check(
            &QuoteResponse::NoRoute {
                reason: "unverified".into()
            },
            "alice@example.com",
            destination,
            21_001,
            "mainnet"
        )
        .is_err());
    }
}
