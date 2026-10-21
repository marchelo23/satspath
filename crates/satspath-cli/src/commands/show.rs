use anyhow::Result;

use satspath_core::{
    crypto::{fingerprint_pubkey, verify_signed_profile},
    evaluate_method_trust_for_profile,
    privacy::{mask_address, mask_identifier, mask_invoice, mask_pubkey},
    stored_status_for_method, well_known_url_of, MethodTrust, PaymentMethod,
};

use super::get_resolver;
use satspath_core::resolver::ProfileResolver;

/// Fetch the body served at a well-known URL (for online re-verification).
async fn fetch_text(url: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let resp = client.get(url).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("HTTP {}", resp.status());
    }
    Ok(resp.text().await?)
}

/// Resolves `alias`, verifies its profile signature and per-method ownership proofs, and displays the summary.
pub async fn cmd_show(alias: &str, verify_online: bool) -> Result<()> {
    let resolver = get_resolver(alias)?;
    let signed = resolver
        .resolve_alias(alias)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let valid = verify_signed_profile(&signed)?;
    let fp = fingerprint_pubkey(&signed.profile.identity_pubkey)?;
    let now = chrono::Utc::now().timestamp();

    println!("Alias:          {}", mask_identifier(&signed.profile.alias));
    println!(
        "Identity pubkey:{}",
        mask_pubkey(&signed.profile.identity_pubkey)
    );
    println!("Fingerprint:    {}", fp);
    println!(
        "Signature valid: {}",
        if valid {
            "yes"
        } else {
            "NO — profile may be tampered!"
        }
    );
    println!("Updated at:     {}", signed.profile.updated_at);
    if let Some(rot) = &signed.profile.rotation {
        println!("⚠ IDENTITY KEY ROTATED at {}", rot.rotated_at);
        println!("  Previous key: {}", mask_pubkey(&rot.previous_pubkey));
    }

    // Per-method ownership trust, re-verified client-side. Domain-control proofs
    // need their well-known URL fetched to confirm; with --verify-online we fetch
    // it, otherwise they show as "claimed · domain control (re-verify on fetch)".
    let mut trusts: Vec<MethodTrust> = Vec::with_capacity(signed.profile.methods.len());
    for method in &signed.profile.methods {
        let body: Option<String> = if verify_online {
            let status = stored_status_for_method(&signed.profile.method_verifications, method);
            match well_known_url_of(status) {
                Some(url) => fetch_text(url).await.ok(),
                None => None,
            }
        } else {
            None
        };
        trusts.push(evaluate_method_trust_for_profile(
            &signed.profile,
            method,
            now,
            body.as_deref(),
        ));
    }

    let verified = trusts.iter().filter(|t| t.is_verified()).count();
    let self_asserted = trusts.iter().filter(|t| t.is_self_asserted()).count();
    let suspicious = trusts.iter().filter(|t| t.is_suspicious()).count();
    println!(
        "Ownership:      {} of {} method(s) independently verified",
        verified,
        trusts.len()
    );
    if self_asserted > 0 {
        println!(
            "  {} method(s) self-asserted only (no independent proof).",
            self_asserted
        );
    }
    if suspicious > 0 {
        println!(
            "  ⚠  {} method(s) carry an INVALID or EXPIRED proof — do not trust them.",
            suspicious
        );
    }

    println!();
    println!("Methods:");
    for (method, trust) in signed.profile.methods.iter().zip(&trusts) {
        print_method(method, trust);
    }
    Ok(())
}

/// Prints a single [`PaymentMethod`] and its verified [`MethodTrust`] badge.
fn print_method(method: &PaymentMethod, trust: &MethodTrust) {
    match method {
        PaymentMethod::Bolt12(offer_data) => {
            println!("  - {} [BOLT12]      {}", offer_data.label, trust.badge());
            println!("      Offer: {}", mask_invoice(&offer_data.offer));
        }
        PaymentMethod::Lightning {
            label,
            lightning_address,
            lnurl,
            bolt12,
            receiver_pubkey,
        } => {
            println!("  - {} [Lightning]   {}", label, trust.badge());
            if let Some(la) = lightning_address {
                println!("      Lightning Address: {}", mask_identifier(la));
            }
            if let Some(url) = lnurl {
                println!("      LNURL: {}", mask_address(url));
            }
            if let Some(b12) = bolt12 {
                println!("      BOLT12: {}", mask_invoice(b12));
            }
            if let Some(pubkey) = receiver_pubkey {
                println!("      Receiver pubkey: {}", mask_pubkey(pubkey));
            }
        }
        PaymentMethod::Onchain {
            label,
            network,
            address,
            silent_payment_pubkey,
            pubkey_hint,
            descriptor_hint,
            ..
        } => {
            println!("  - {} [On-chain]   {}", label, trust.badge());
            println!("      Network: {:?}", network);
            let target = silent_payment_pubkey
                .clone()
                .unwrap_or_else(|| address.clone().unwrap_or_default());
            println!("      Address: {}", mask_address(&target));
            if let Some(hint) = pubkey_hint {
                println!("      Pubkey hint: {}", mask_pubkey(hint));
            }
            if descriptor_hint.is_some() {
                println!("      Descriptor hint: present");
            }
        }
        PaymentMethod::Ark {
            label,
            server,
            pubkey,
            vtxo_pointer,
            proof,
            expires_at,
            opaque_uri,
        } => {
            println!("  - {} [Ark]   {}", label, trust.badge());
            if let Some(uri) = opaque_uri {
                println!("      Arkade receive URI: {}…", &uri[..uri.len().min(24)]);
                println!("      Execution: manual_wallet (preview only)");
            } else {
                println!("      Server: {}", mask_address(server));
                println!("      Pubkey: {}", mask_pubkey(pubkey));
                if vtxo_pointer.is_some() {
                    println!("      VTXO pointer: present");
                }
                println!(
                    "      Ark ownership proof: {}",
                    if proof.is_some() {
                        "claimed"
                    } else {
                        "not provided"
                    }
                );
                if let Some(expires_at) = expires_at {
                    println!("      Expires at: {}", expires_at);
                }
            }
        }
    }
    // Surface the failure reason so a suspicious method is actionable.
    if let MethodTrust::Invalid(reason) = trust {
        println!("      ⚠  proof rejected: {}", reason);
    }
}
