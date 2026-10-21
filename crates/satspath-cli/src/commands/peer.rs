//! Legacy profile transfer: `export` and `import`.
//!
//! These tools are now primarily intended for one-time manual migration
//! of legacy local or P2P profiles into the new architecture.
//! `export` prints a signed profile as raw JSON; `import` reads one
//! (from a file, stdin, or an HTTPS URL), **verifies its signature and expiry**,
//! and stores it in the local registry. A tampered profile is rejected.
//!
//! No funds move, nothing is signed or broadcast — this only moves public,
//! signed payment profiles.

use std::io::Read;

use anyhow::Result;

use satspath_core::crypto::{check_profile_expiry, fingerprint_pubkey, verify_signed_profile};
use satspath_core::privacy::mask_identifier;
use satspath_core::resolvers::http::HttpResolver;
use satspath_core::SignedPaymentProfile;

use super::open_registry;

/// Print a peer's signed profile as raw JSON (stdout only), so it can be
/// redirected to a file and handed to another machine.
pub fn cmd_export(alias: &str) -> Result<()> {
    let registry = open_registry()?;
    let signed = registry
        .resolve_alias(alias)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    // Only the JSON goes to stdout; the confirmation goes to stderr so that
    // `satspath export alice@x > alice.json` produces a clean file.
    println!("{}", serde_json::to_string_pretty(signed)?);
    eprintln!(
        "Exported signed profile for {} (give this file to the other machine).",
        mask_identifier(&signed.profile.alias)
    );
    Ok(())
}

/// Import a signed profile from a file, stdin, or an HTTPS URL into the local
/// registry, verifying the signature and expiry first. Fails closed on tamper.
pub async fn cmd_import(source: Option<&str>, url: Option<&str>) -> Result<()> {
    let signed: SignedPaymentProfile = if let Some(url) = url {
        // resolve_from_url already verifies signature + expiry (fail closed).
        HttpResolver::new()
            .resolve_from_url(url)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?
    } else {
        let raw = read_source(source)?;
        let signed: SignedPaymentProfile = serde_json::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("not a valid signed profile JSON: {e}"))?;
        if !verify_signed_profile(&signed)? {
            anyhow::bail!("signature INVALID — refusing to import a tampered profile.");
        }
        check_profile_expiry(&signed.profile).map_err(|e| anyhow::anyhow!("{e}"))?;
        signed
    };

    let fp = fingerprint_pubkey(&signed.profile.identity_pubkey)?;
    let alias = signed.profile.alias.clone();

    let mut registry = open_registry()?;
    registry
        .update_profile(signed)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!(
        "Imported {} — signature valid, fingerprint {}.",
        mask_identifier(&alias),
        fp
    );
    println!("Stored in the local registry. Try it:");
    println!("  satspath show {alias}");
    println!("  satspath quote {alias} 1000");
    Ok(())
}

/// Reads a signed profile JSON string from `source` path or standard input when `source` is `None`.
fn read_source(source: Option<&str>) -> Result<String> {
    match source {
        Some(path) => {
            std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("could not read {path}: {e}"))
        }
        None => {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            Ok(buf)
        }
    }
}
