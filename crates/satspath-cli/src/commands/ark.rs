use anyhow::Result;
use satspath_core::{
    crypto::verify_signed_profile,
    privacy::{mask_address, mask_pubkey},
    resolver::ProfileResolver,
    validate_ark_receive_pointer, verify_ark_ownership_proof, ArkIntentStatus, ArkPaymentIntent,
    ArkReceivePointer, ArkRouteKind, ClientValidationReport, PaymentMethod,
};
use satspath_router::{plan_ark_route, SenderCapabilities};
use satspath_swaps::{ensure_claim_refund_builders_available, SwapKind};

use super::get_resolver;

const EXEC_CONFIRMATION: &str = "execute testnet ark intent";

/// Side of an experimental Ark swap route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArkSwapSide {
    Ark,
    Lightning,
    Onchain,
}

/// Resolves `alias` and displays a testnet Ark receive intent preview.
pub async fn cmd_ark_receive(alias: &str, testnet: bool, execute_testnet: bool) -> Result<()> {
    ensure_testnet(testnet)?;
    if execute_testnet {
        anyhow::bail!("Ark receive execution requires --confirm '{EXEC_CONFIRMATION}' in a future implementation. Preview only.");
    }
    let signed = get_resolver(alias)?.resolve_alias(alias).await?;
    let pointer = first_ark_pointer(&signed.profile.methods)?;
    let report = build_validation_report(alias, &signed, &pointer)?;
    print_validation_report(&report);
    print_intent(&ArkPaymentIntent {
        route_kind: ArkRouteKind::ArkToArk,
        amount_sats: 0,
        receiver_pointer: pointer,
        status: ArkIntentStatus::PreviewOnly,
        created_at: chrono::Utc::now().timestamp(),
        expires_at: chrono::Utc::now().timestamp() + 900,
    });
    Ok(())
}

/// Resolves `alias`, plans an Ark route, and displays a testnet Ark send preview.
pub async fn cmd_ark_send(
    alias: &str,
    amount_sats: u64,
    testnet: bool,
    execute_testnet: bool,
    confirm: Option<&str>,
) -> Result<()> {
    ensure_testnet(testnet)?;
    let signed = get_resolver(alias)?.resolve_alias(alias).await?;
    let pointer = first_ark_pointer(&signed.profile.methods)?;
    let report = build_validation_report(alias, &signed, &pointer)?;
    let plan = plan_ark_route(
        &SenderCapabilities {
            ark_server: Some(pointer.server.clone()),
            ..SenderCapabilities::default()
        },
        &signed,
    )
    .ok_or_else(|| anyhow::anyhow!("unsupported Ark route; failed closed"))?;

    println!("Ark route preview");
    println!("Route: {:?}", plan.kind);
    println!("Server: {}", mask_address(&pointer.server));
    println!("Receiver pubkey: {}", mask_pubkey(&pointer.receiver_pubkey));
    println!("Amount: {} sats", amount_sats);
    println!("Status: preview_only");
    println!("No funds moved.");
    print_validation_report(&report);

    if execute_testnet {
        ensure_exact_confirmation(confirm)?;
        ensure_execution_allowed(&report)?;
        println!("Execution: blocked");
        anyhow::bail!("Ark method not implemented by bridge");
    }
    Ok(())
}

/// Resolves `alias` and displays a testnet Ark swap intent preview between `from` and `to`.
pub async fn cmd_ark_swap(
    alias: &str,
    amount_sats: u64,
    from: ArkSwapSide,
    to: ArkSwapSide,
    testnet: bool,
    execute_testnet: bool,
    confirm: Option<&str>,
) -> Result<()> {
    ensure_testnet(testnet)?;
    let signed = get_resolver(alias)?.resolve_alias(alias).await?;
    let pointer = first_ark_pointer(&signed.profile.methods).ok();
    let route_kind = route_kind_from_sides(from, to)?;
    let requires_builder = match route_kind {
        ArkRouteKind::ArkToLightning => Some(SwapKind::Submarine),
        ArkRouteKind::LightningToArk => Some(SwapKind::Reverse),
        ArkRouteKind::ArkToOnchain | ArkRouteKind::OnchainToArk => Some(SwapKind::Chain),
        ArkRouteKind::ArkToArk => None,
    };

    println!("Ark swap intent preview");
    println!("Route: {:?}", route_kind);
    println!("Amount: {} sats", amount_sats);
    println!("Experimental: yes");
    println!("Testnet only: yes");
    if let Some(pointer) = &pointer {
        println!("Receiver Ark server: {}", mask_address(&pointer.server));
        println!("Receiver pubkey: {}", mask_pubkey(&pointer.receiver_pubkey));
    }
    println!("No funds moved.");

    if execute_testnet {
        ensure_exact_confirmation(confirm)?;
        if let Some(kind) = requires_builder {
            ensure_claim_refund_builders_available(kind).map_err(|e| anyhow::anyhow!("{}", e))?;
        }
        anyhow::bail!("Ark swap execution blocked: bridge/onboard/offboard path not implemented");
    }

    Ok(())
}

/// Ensures `--testnet` was explicitly passed for experimental Ark commands.
fn ensure_testnet(testnet: bool) -> Result<()> {
    if !testnet {
        anyhow::bail!(
            "Ark commands are testnet-gated. Re-run with --testnet. Mainnet execution is disabled."
        );
    }
    Ok(())
}

/// Ensures `confirm` matches [`EXEC_CONFIRMATION`] before attempting testnet execution.
fn ensure_exact_confirmation(confirm: Option<&str>) -> Result<()> {
    if confirm != Some(EXEC_CONFIRMATION) {
        anyhow::bail!("testnet execution requires --confirm '{EXEC_CONFIRMATION}'");
    }
    Ok(())
}

/// Verifies that `report` permits testnet execution.
fn ensure_execution_allowed(report: &ClientValidationReport) -> Result<()> {
    if report.safe_for_testnet_execution {
        Ok(())
    } else {
        anyhow::bail!("testnet execution blocked: {}", report.errors.join("; "))
    }
}

/// Extracts the first [`ArkReceivePointer`] from `methods`.
fn first_ark_pointer(methods: &[PaymentMethod]) -> Result<ArkReceivePointer> {
    methods
        .iter()
        .find_map(|method| match method {
            PaymentMethod::Ark {
                server,
                pubkey,
                vtxo_pointer,
                proof,
                expires_at,
                ..
            } => Some(ArkReceivePointer {
                server: server.clone(),
                receiver_pubkey: pubkey.clone(),
                vtxo_pointer: vtxo_pointer.clone(),
                proof: proof.clone(),
                expires_at: *expires_at,
            }),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("profile has no Ark receive pointer"))
}

/// Builds a [`ClientValidationReport`] for `alias`, `signed`, and `pointer`.
fn build_validation_report(
    alias: &str,
    signed: &satspath_core::SignedPaymentProfile,
    pointer: &ArkReceivePointer,
) -> Result<ClientValidationReport> {
    let now = chrono::Utc::now().timestamp();
    let mut report = ClientValidationReport {
        profile_signature_valid: verify_signed_profile(signed)?,
        profile_fresh: signed.profile.expires_at.map(|ts| ts > now).unwrap_or(true),
        ..ClientValidationReport::default()
    };

    match validate_ark_receive_pointer(pointer, now) {
        Ok(()) => report.ark_pointer_valid = true,
        Err(e) => report.errors.push(e.to_string()),
    }

    match verify_ark_ownership_proof(alias, &signed.profile.identity_pubkey, pointer, now) {
        Ok(true) => report.ark_ownership_verified = true,
        Ok(false) => report
            .warnings
            .push("Ark ownership proof not provided; preview only.".into()),
        Err(e) => report.errors.push(e.to_string()),
    }

    report.method_verified = report.ark_ownership_verified;
    if !report.profile_signature_valid {
        report.errors.push("profile signature invalid".into());
    }
    if !report.profile_fresh {
        report.errors.push("profile expired".into());
    }
    report.safe_for_preview =
        report.profile_signature_valid && report.profile_fresh && report.ark_pointer_valid;
    report.safe_for_testnet_execution = report.safe_for_preview && report.ark_ownership_verified;
    Ok(report)
}

/// Prints the human-readable [`ClientValidationReport`] summary.
fn print_validation_report(report: &ClientValidationReport) {
    println!(
        "Profile signature: {}",
        valid_word(report.profile_signature_valid)
    );
    println!("Profile freshness: {}", valid_word(report.profile_fresh));
    println!("Ark pointer: {}", valid_word(report.ark_pointer_valid));
    println!(
        "Ark ownership: {}",
        if report.ark_ownership_verified {
            "verified"
        } else {
            "unverified"
        }
    );
    println!(
        "Execution: {}",
        if report.safe_for_testnet_execution {
            "testnet allowed"
        } else {
            "preview only / blocked"
        }
    );
    for warning in &report.warnings {
        println!("Warning: {warning}");
    }
    for error in &report.errors {
        println!("Error: {error}");
    }
}

/// Prints the human-readable [`ArkPaymentIntent`] preview.
fn print_intent(intent: &ArkPaymentIntent) {
    println!("Ark route preview");
    println!("Route: {:?}", intent.route_kind);
    println!("Server: {}", mask_address(&intent.receiver_pointer.server));
    println!(
        "Receiver pubkey: {}",
        mask_pubkey(&intent.receiver_pointer.receiver_pubkey)
    );
    println!("Status: {:?}", intent.status);
    println!("No funds moved.");
}

/// Formats a boolean check as `"valid"` or `"invalid"`.
fn valid_word(value: bool) -> &'static str {
    if value {
        "valid"
    } else {
        "invalid"
    }
}

/// Maps source and destination [`ArkSwapSide`]s into an [`ArkRouteKind`].
fn route_kind_from_sides(from: ArkSwapSide, to: ArkSwapSide) -> Result<ArkRouteKind> {
    match (from, to) {
        (ArkSwapSide::Ark, ArkSwapSide::Lightning) => Ok(ArkRouteKind::ArkToLightning),
        (ArkSwapSide::Lightning, ArkSwapSide::Ark) => Ok(ArkRouteKind::LightningToArk),
        (ArkSwapSide::Ark, ArkSwapSide::Onchain) => Ok(ArkRouteKind::ArkToOnchain),
        (ArkSwapSide::Onchain, ArkSwapSide::Ark) => Ok(ArkRouteKind::OnchainToArk),
        (ArkSwapSide::Ark, ArkSwapSide::Ark) => Ok(ArkRouteKind::ArkToArk),
        _ => anyhow::bail!("unsupported Ark swap route; failed closed"),
    }
}

impl std::str::FromStr for ArkSwapSide {
    type Err = anyhow::Error;

    /// Parses an [`ArkSwapSide`] from `"ark"`, `"lightning"`, or `"onchain"`.
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "ark" => Ok(Self::Ark),
            "lightning" => Ok(Self::Lightning),
            "onchain" => Ok(Self::Onchain),
            _ => anyhow::bail!("expected one of: ark, lightning, onchain"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that omitting `--testnet` fails closed.
    #[test]
    fn no_testnet_means_fail() {
        assert!(ensure_testnet(false).is_err());
    }

    /// Verifies that exact confirmation string is required for testnet execution.
    #[test]
    fn exact_confirmation_required() {
        assert!(ensure_exact_confirmation(None).is_err());
        assert!(ensure_exact_confirmation(Some("wrong")).is_err());
        assert!(ensure_exact_confirmation(Some(EXEC_CONFIRMATION)).is_ok());
    }

    /// Verifies supported and unsupported [`ArkSwapSide`] route combinations.
    #[test]
    fn swap_side_routes() {
        assert_eq!(
            route_kind_from_sides(ArkSwapSide::Ark, ArkSwapSide::Lightning).unwrap(),
            ArkRouteKind::ArkToLightning
        );
        assert!(route_kind_from_sides(ArkSwapSide::Lightning, ArkSwapSide::Onchain).is_err());
    }
}
