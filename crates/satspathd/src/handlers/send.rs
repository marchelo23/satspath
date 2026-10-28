//! Send, receive, broadcast, and email invite handlers.

use anyhow::Result;
use satspath_core::{
    crypto::check_profile_expiry,
    privacy::{canonical_identifier, mask_identifier, validate_ascii_identifier},
    validation::{assert_no_private_material, validate_amount_sats},
    PaymentMethod, SatsPathError, TransactionalTransparencyStore,
};
use satspath_router::{
    handoff::{fmt_btc, validate_payload},
    quote_verified_profile_for_network, QuoteResponse,
};

#[cfg(test)]
use satspath_core::ProfileResolver;
#[cfg(test)]
use satspath_router::{fees::fetch_fee_estimate, select_priority_route};

use crate::config::AppState;
use crate::handlers::profile::ensure_signed_profile;
use crate::handlers::resolve::resolve_profile;
use crate::handlers::wallet::load_wallet;
use crate::types::{
    build_methods, pct, safety_status, EmailInvite, ReceiveRequest, ReceiveView, SendRequest,
    SendResponse,
};
use crate::ui::qr_svg;

/// Operational bound for the invite file. Expired invites are pruned before a
/// new record is refused, so this is not a lifetime limit on claimed invites.
const MAX_STORED_INVITES: usize = 10_000;

/// Choose a configured receive rail and validate its final public QR payload.
pub(crate) fn receive_view(state: &AppState, req: ReceiveRequest) -> Result<ReceiveView> {
    let wallet = load_wallet(&state.home)?;
    let alias = wallet
        .alias
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no profile yet -- set one via POST /v1/profile"))?;
    let methods = build_methods(&wallet, &state.network);

    let method = if let Some(req_rail) = req.rail {
        let req_rail = req_rail.to_lowercase();
        methods
            .into_iter()
            .find(|m| m.method_name().to_lowercase() == req_rail)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "requested rail '{}' is not configured in your profile",
                    req_rail
                )
            })?
    } else {
        let onchain = methods
            .iter()
            .find(|m| matches!(m, PaymentMethod::Onchain { .. }));
        let lightning = methods
            .iter()
            .find(|m| matches!(m, PaymentMethod::Lightning { .. }));
        (if req.amount_sats.is_some() {
            onchain.or(lightning)
        } else {
            lightning.or(onchain)
        })
        .or_else(|| {
            methods
                .iter()
                .find(|m| matches!(m, PaymentMethod::Ark { .. }))
        })
        .ok_or_else(|| {
            anyhow::anyhow!("no receive methods -- add one via POST /v1/profile/methods")
        })?
        .clone()
    };

    let mut payload = receive_payload_for(&method)?;

    // Append amount if requested
    if let Some(sats) = req.amount_sats {
        if matches!(method, PaymentMethod::Onchain { .. }) {
            let sep = if payload.contains('?') { "&" } else { "?" };
            payload = format!("{}{}amount={}", payload, sep, fmt_btc(sats));
        } else if matches!(method, PaymentMethod::Ark { .. }) {
            payload = format!("{}&amount={}", payload, fmt_btc(sats));
        }
        // Note: Lightning Address/LNURL doesn't support amount in the static string.
    }

    validate_payload(&method, &payload, &state.network, req.amount_sats)?;

    Ok(ReceiveView {
        alias: mask_identifier(&alias),
        rail: method.method_name().to_string(),
        qr_svg: qr_svg(&payload)?,
        payload,
    })
}

/// A public, amount-less receive pointer for a method.
/// Encode an amount-less receive pointer; the caller validates the final payload.
pub(crate) fn receive_payload_for(method: &PaymentMethod) -> Result<String> {
    let payload = match method {
        PaymentMethod::Lightning {
            lightning_address: Some(addr),
            ..
        } => addr.clone(),
        PaymentMethod::Lightning {
            lnurl: Some(url), ..
        } => url.clone(),
        PaymentMethod::Onchain {
            address,
            silent_payment_pubkey,
            ..
        } => match (silent_payment_pubkey, address) {
            (Some(sp), Some(addr)) => format!("bitcoin:{addr}?sp={sp}"),
            (Some(sp), None) => format!("bitcoin:?sp={sp}"),
            (None, Some(addr)) => format!("bitcoin:{addr}"),
            (None, None) => {
                anyhow::bail!("on-chain method has no address or silent payment pubkey")
            }
        },
        PaymentMethod::Ark {
            opaque_uri: Some(address),
            ..
        } => {
            let (mainnet, _, _) = satspath_router::ark_receive::decode_ark_address(address)?;
            satspath_router::ark_receive::ark_receive_payload(
                method,
                if mainnet { "mainnet" } else { "testnet" },
                None,
            )?
        }
        _ => anyhow::bail!("selected method has no receive pointer"),
    };
    assert_no_private_material(&payload)?;
    Ok(payload)
}

/// Only locally transparent SQLite profiles can become payable. The legacy
/// registry and external resolvers return signed profiles but do not supply the
/// verified inclusion, continuity and ownership state required for a send.
pub(crate) async fn send_response(state: &AppState, body: SendRequest) -> SendResponse {
    if let Err(e) = validate_amount_sats(body.amount_sats) {
        return SendResponse::NoRoute {
            reason: e.to_string(),
        };
    }
    // The legacy health simulation cannot constrain a proof-checked quote.
    // Reject an explicit outage rather than silently ignoring the caller's hint.
    if body.routing_ok == Some(false) {
        return SendResponse::NoRoute {
            reason: "routing_ok=false is unsupported by the verified send path".into(),
        };
    }
    if let Err(e) = validate_ascii_identifier(&body.recipient) {
        return SendResponse::NoRoute {
            reason: e.to_string(),
        };
    }
    match resolve_profile(state, &body.recipient) {
        Ok(resolved) => {
            let signed = resolved.signed_profile;
            // The SQLite lookup uses an identifier hash. Never allow a corrupt
            // store (or a substituted profile) to change the recipient.
            if canonical_identifier(&signed.profile.alias) != canonical_identifier(&body.recipient)
                || signed.profile.revoked
            {
                return SendResponse::NoRoute {
                    reason: "recipient profile alias mismatch or revoked".into(),
                };
            }
            if let Err(e) = check_profile_expiry(&signed.profile) {
                return SendResponse::NoRoute {
                    reason: e.to_string(),
                };
            }
            let allowed: Vec<String> = resolved
                .verification
                .payment_method_states
                .iter()
                .filter(|method| method.verified)
                .map(|method| method.descriptor.clone())
                .collect();
            // quote_verified_profile uses select_route, amount-bound QR validation
            // and ONLY independently verified ownership descriptors. No proof is
            // synthesized from an identity signature or a static receive address.
            match quote_verified_profile_for_network(
                signed,
                &body.recipient,
                body.amount_sats,
                &allowed,
                &state.network,
            )
            .await
            {
                QuoteResponse::Ok {
                    selected_method,
                    reason,
                    qr,
                    ..
                } => {
                    if let Err(e) = validate_payload(
                        &selected_method,
                        &qr,
                        &state.network,
                        Some(body.amount_sats),
                    ) {
                        return SendResponse::NoRoute {
                            reason: e.to_string(),
                        };
                    }
                    let qr_svg = match qr_svg(&qr) {
                        Ok(svg) => svg,
                        Err(e) => {
                            return SendResponse::NoRoute {
                                reason: e.to_string(),
                            }
                        }
                    };
                    SendResponse::Ok {
                        mode: "preview_only",
                        rail: selected_method.method_name().to_string(),
                        reason,
                        recipient: mask_identifier(&body.recipient),
                        profile_signature_verified: true,
                        identifier_verified: resolved.verification.identifier_verified,
                        identifier_verification: "identifier attestation checked; see /v1/resolve for verification details",
                        amount_sats: body.amount_sats,
                        payload: qr,
                        qr_svg,
                        safety: safety_status(),
                    }
                }
                QuoteResponse::NoRoute { reason } => SendResponse::NoRoute { reason },
                QuoteResponse::InvalidSignature { .. } => SendResponse::InvalidSignature {
                    recipient: mask_identifier(&body.recipient),
                },
                QuoteResponse::NotRegistered { .. } => SendResponse::NoRoute {
                    reason: "registered recipient has no verified payment route".into(),
                },
            }
        }
        Err(error)
            if matches!(
                error.downcast_ref::<SatsPathError>(),
                Some(SatsPathError::AliasNotFound(_))
            ) =>
        {
            // Serialize the re-check and insert so two concurrent requests cannot
            // both observe "not registered" and create duplicate invites.
            let _guard = state.mutation_lock.lock().await;
            // An absent profile is not enough: an alias may have a transparency
            // history (including a revocation), a pending local wallet profile,
            // or a legacy entry. None of those should receive a second invite.
            match never_registered_locally(state, &body.recipient) {
                Ok(true) => invite_response(state, &body),
                Ok(false) => SendResponse::NoRoute {
                    reason: "recipient alias already exists locally without a payable profile"
                        .into(),
                },
                Err(e) => SendResponse::NoRoute {
                    reason: e.to_string(),
                },
            }
        }
        Err(error) => SendResponse::NoRoute {
            reason: format!("transparency verification failed: {error}"),
        },
    }
}

fn never_registered_locally(state: &AppState, alias: &str) -> Result<bool> {
    if load_wallet(&state.home)?
        .alias
        .as_deref()
        .is_some_and(|wallet_alias| {
            canonical_identifier(wallet_alias) == canonical_identifier(alias)
        })
    {
        return Ok(false);
    }
    let identifier_hash = satspath_core::privacy::identifier_hash(alias);
    let store = TransactionalTransparencyStore::open(&state.home)?;
    if store.profile(alias)?.is_some() || !store.load_log()?.history(&identifier_hash).is_empty() {
        return Ok(false);
    }
    // Do not create a second invite while one is still pending. Expired or
    // cancelled invites may be replaced; claimed/created/email-sent invites may not.
    let invites =
        satspath_core::InviteStore::open(&state.home)?.get_by_identifier_hash(&identifier_hash);
    if invites.iter().any(|invite| {
        !matches!(
            invite.status,
            satspath_core::InviteStatus::Expired | satspath_core::InviteStatus::Cancelled
        )
    }) {
        return Ok(false);
    }
    // A legacy entry is *not* a payable resolution, but suppress an invitation
    // for an already registered alias. Corrupt legacy data fails closed here.
    let registry_path = state.home.join("registry.json");
    if registry_path.try_exists()?
        && satspath_core::registry::Registry::open(&state.home)?.is_registered(alias)
    {
        return Ok(false);
    }
    Ok(true)
}

fn invite_response(state: &AppState, body: &SendRequest) -> SendResponse {
    let secret_opt = load_wallet(&state.home).ok().and_then(|w| {
        w.identity_pubkey
            .and_then(|pk| crate::handlers::wallet::load_identity_key(&state.home, &pk).ok())
    });
    let invite = satspath_core::create_invite(
        &body.recipient,
        body.amount_sats,
        secret_opt.as_ref(),
        86400,
    );
    let mut store = match satspath_core::InviteStore::open(&state.home) {
        Ok(store) => store,
        Err(e) => {
            return SendResponse::NoRoute {
                reason: e.to_string(),
            }
        }
    };
    let invite_count = match store.list() {
        Ok(invites) => invites.len(),
        Err(e) => {
            return SendResponse::NoRoute {
                reason: e.to_string(),
            }
        }
    };
    if invite_count >= MAX_STORED_INVITES {
        if let Err(e) = store.prune_expired() {
            return SendResponse::NoRoute {
                reason: e.to_string(),
            };
        }
        let remaining = match store.list() {
            Ok(invites) => invites.len(),
            Err(e) => {
                return SendResponse::NoRoute {
                    reason: e.to_string(),
                }
            }
        };
        if remaining >= MAX_STORED_INVITES {
            return SendResponse::NoRoute {
                reason: "invite store is full; wait for pending invites to expire".into(),
            };
        }
    }
    let sender_fp = secret_opt
        .as_ref()
        .map(|sk| {
            let secp = secp256k1::Secp256k1::new();
            hex::encode(secp256k1::PublicKey::from_secret_key(&secp, sk).serialize())
        })
        .unwrap_or_else(|| "local-sender".to_string());
    let mut record = satspath_core::create_signed_invite_record(
        &body.recipient,
        body.amount_sats,
        None,
        sender_fp,
        86400,
        secret_opt.as_ref(),
    );
    if let Some(ref id) = invite.invite_id {
        record.invite_id = id.clone();
    }
    if let Err(e) = store.insert(record) {
        return SendResponse::NoRoute {
            reason: e.to_string(),
        };
    }
    let email = build_email_invite(&body.recipient, body.amount_sats, &invite.claim_url);
    SendResponse::Invite {
        mode: "preview_only",
        experimental: true,
        recipient_hint: mask_identifier(&body.recipient),
        amount_sats: body.amount_sats,
        claim_url: invite.claim_url,
        email,
        safety: safety_status(),
    }
}

/// Legacy injected resolver exercised only by older unit tests. The HTTP route
/// always uses the transparent SQLite resolver above, never this profile-only API.
#[cfg(test)]
pub(crate) async fn send_response_with_resolver(
    state: &AppState,
    body: SendRequest,
    resolver: &(impl ProfileResolver + Sync),
) -> SendResponse {
    if let Err(e) = validate_amount_sats(body.amount_sats) {
        return SendResponse::NoRoute {
            reason: e.to_string(),
        };
    }
    match resolver.resolve_alias(&body.recipient).await {
        Ok(signed) => {
            if !matches!(
                satspath_core::crypto::verify_signed_profile(&signed),
                Ok(true)
            ) {
                return SendResponse::InvalidSignature {
                    recipient: mask_identifier(&body.recipient),
                };
            }
            let fee = fetch_fee_estimate().await;
            let routing_ok = body.routing_ok.unwrap_or(true);
            let payable_methods =
                payable_methods(&signed.profile.methods, body.amount_sats, &state.network);
            match select_priority_route(
                body.amount_sats,
                &fee.unwrap_or_default(),
                &payable_methods,
                routing_ok,
            ) {
                Some(decision) => {
                    let payload = match send_payload_for(&decision.method, body.amount_sats)
                        .and_then(|payload| {
                            validate_payload(
                                &decision.method,
                                &payload,
                                &state.network,
                                Some(body.amount_sats),
                            )?;
                            Ok(payload)
                        }) {
                        Ok(p) => p,
                        Err(e) => {
                            return SendResponse::NoRoute {
                                reason: e.to_string(),
                            }
                        }
                    };
                    let qr = match qr_svg(&payload) {
                        Ok(q) => q,
                        Err(e) => {
                            return SendResponse::NoRoute {
                                reason: e.to_string(),
                            }
                        }
                    };
                    SendResponse::Ok {
                        mode: "preview_only",
                        rail: decision.method.method_name().to_string(),
                        reason: decision.reason,
                        recipient: mask_identifier(&body.recipient),
                        profile_signature_verified: true,
                        identifier_verified: false,
                        identifier_verification:
                            "identifier-only; no inbox/domain ownership proof in this response",
                        amount_sats: body.amount_sats,
                        payload,
                        qr_svg: qr,
                        safety: safety_status(),
                    }
                }
                None => SendResponse::NoRoute {
                    reason: "recipient exposes no safely payable rail".to_string(),
                },
            }
        }
        Err(SatsPathError::AliasNotFound(_)) => {
            let secret_opt = load_wallet(&state.home).ok().and_then(|w| {
                w.identity_pubkey.and_then(|pk| {
                    crate::handlers::wallet::load_identity_key(&state.home, &pk).ok()
                })
            });
            let invite = satspath_core::create_invite(
                &body.recipient,
                body.amount_sats,
                secret_opt.as_ref(),
                86400,
            );

            // Persist invite record to InviteStore
            if let Ok(mut store) = satspath_core::InviteStore::open(&state.home) {
                let sender_fp = secret_opt
                    .as_ref()
                    .map(|sk| {
                        let secp = secp256k1::Secp256k1::new();
                        let pk = secp256k1::PublicKey::from_secret_key(&secp, sk);
                        hex::encode(pk.serialize())
                    })
                    .unwrap_or_else(|| "local-sender".to_string());

                let mut record = satspath_core::create_signed_invite_record(
                    &body.recipient,
                    body.amount_sats,
                    None,
                    sender_fp,
                    86400,
                    secret_opt.as_ref(),
                );
                if let Some(ref iid) = invite.invite_id {
                    record.invite_id = iid.clone();
                }
                let _ = store.insert(record);
            }

            let email = build_email_invite(&body.recipient, body.amount_sats, &invite.claim_url);
            SendResponse::Invite {
                mode: "preview_only",
                experimental: true,
                recipient_hint: mask_identifier(&body.recipient),
                amount_sats: body.amount_sats,
                claim_url: invite.claim_url,
                email,
                safety: safety_status(),
            }
        }
        Err(error) => SendResponse::NoRoute {
            reason: error.to_string(),
        },
    }
}

/// Retain only signed-profile methods that can produce a validated payable QR.
#[cfg(test)]
fn payable_methods(
    methods: &[PaymentMethod],
    amount_sats: u64,
    network: &str,
) -> Vec<PaymentMethod> {
    methods
        .iter()
        .filter(|method| {
            send_payload_for(method, amount_sats)
                .and_then(|payload| validate_payload(method, &payload, network, Some(amount_sats)))
                .is_ok()
        })
        .cloned()
        .collect()
}

/// Build an experimental invite for an alias without a usable signed profile.
pub(crate) fn build_email_invite(
    recipient: &str,
    amount_sats: u64,
    claim_url: &str,
) -> EmailInvite {
    let subject = "Someone wants to send you Bitcoin with SatsPath".to_string();
    let body = format!(
        r"Someone wants to send you {amount_sats} sats with SatsPath.

No funds have moved. This link is only an invitation preview, not a payment:

{claim_url}

[EXPERIMENTAL] Claiming is disabled without a real alias-control verifier;
the opt-in devnet/regtest mock does not prove email/domain ownership.
SatsPath does not move funds or sign Bitcoin transactions for you."
    );
    let mailto = format!(
        "mailto:{}?subject={}&body={}",
        recipient,
        pct(&subject),
        pct(&body)
    );
    EmailInvite {
        to: recipient.to_string(),
        subject,
        body,
        mailto,
    }
}

/// A payable pointer for a method, including the amount where the URI supports it.
#[cfg(test)]
/// Encode an amount-bound payment pointer for subsequent handoff validation.
pub(crate) fn send_payload_for(method: &PaymentMethod, amount_sats: u64) -> Result<String> {
    let payload = match method {
        PaymentMethod::Lightning {
            lightning_address: Some(a),
            ..
        } => a.clone(),
        PaymentMethod::Lightning { lnurl: Some(u), .. } => u.clone(),
        PaymentMethod::Onchain {
            address,
            silent_payment_pubkey,
            ..
        } => match (silent_payment_pubkey, address) {
            (Some(sp), Some(addr)) => {
                format!("bitcoin:{addr}?sp={sp}&amount={}", fmt_btc(amount_sats))
            }
            (Some(sp), None) => {
                format!("bitcoin:?sp={sp}&amount={}", fmt_btc(amount_sats))
            }
            (None, Some(addr)) => {
                format!("bitcoin:{addr}?amount={}", fmt_btc(amount_sats))
            }
            (None, None) => {
                anyhow::bail!("on-chain method has no address or silent payment pubkey")
            }
        },
        PaymentMethod::Ark { .. } => satspath_router::build_qr_payload(method, amount_sats)?,
        _ => anyhow::bail!("selected method has no payable pointer"),
    };
    assert_no_private_material(&payload)?;
    Ok(payload)
}

/// Save the profile; enabled transports independently manage publication.
pub(crate) fn broadcast(state: &AppState) -> Result<serde_json::Value> {
    let mut wallet = load_wallet(&state.home)?;
    if wallet.alias.is_none() {
        anyhow::bail!("set your profile first (alias + methods) before broadcasting");
    }
    ensure_signed_profile(&state.home, &mut wallet, &state.network)?;
    Ok(
        serde_json::json!({ "broadcasting": false, "status": "Profile saved. Enabled transports manage publication; saving is not proof of network availability." }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppState;
    use crate::handlers::wallet::{load_or_create_identity, save_wallet};
    use crate::rate_limit::{RateLimiter, RateLimiterConfig};
    use satspath_core::{BitcoinNetwork, TransactionalTransparencyStore};
    use satspath_router::fees::FeeEstimate;
    use std::{path::Path, sync::Arc};

    fn test_state(home: &Path) -> AppState {
        AppState {
            p2p: crate::p2p::Bridge::new(false),
            home: home.to_owned(),
            bind: "127.0.0.1:0".parse().unwrap(),
            allowed_hosts: vec![],
            network: "devnet".into(),
            open_ui: false,
            auth_token: "test_auth_token".into(),
            allow_mock_alias_verification: false,
            mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
            anchor_lock: Arc::new(tokio::sync::Mutex::new(())),
            rate_limiter: Arc::new(RateLimiter::new(RateLimiterConfig::default())),
            is_tls: false,
        }
    }

    fn request(recipient: &str) -> SendRequest {
        SendRequest {
            recipient: recipient.into(),
            amount_sats: 25_000,
            routing_ok: Some(true),
        }
    }

    fn invite_count(home: &Path) -> usize {
        satspath_core::InviteStore::open(home)
            .unwrap()
            .list()
            .unwrap()
            .len()
    }

    /// Builds a test [`PaymentMethod::Onchain`] on mainnet.
    fn onchain(address: &str) -> PaymentMethod {
        PaymentMethod::Onchain {
            label: "On-chain".into(),
            network: BitcoinNetwork::Mainnet,
            address: Some(address.into()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        }
    }

    /// Verifies that `payable_methods` skips unpayable preferred rails before route selection.
    #[test]
    fn send_skips_unpayable_preferred_rails_before_selecting_route() {
        let good = onchain("1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
        let methods = vec![
            onchain("invalid-address"),
            PaymentMethod::Lightning {
                label: "Lightning".into(),
                lightning_address: Some("alice@example.com".into()),
                lnurl: None,
                bolt12: None,
                receiver_pubkey: None,
            },
            good.clone(),
        ];
        let payable = payable_methods(&methods, 21_000, "mainnet");
        assert_eq!(payable, vec![good.clone()]);

        // High fees would pick Lightning first, but its static pointer has no
        // amount-bound invoice. The router's last resort is the valid on-chain QR.
        let high_fee = FeeEstimate {
            fastest_fee: 40,
            ..FeeEstimate::default()
        };
        let selected = select_priority_route(21_000, &high_fee, &payable, true).unwrap();
        assert_eq!(selected.rail, "onchain");
        assert_eq!(selected.method, good);
        assert!(validate_payload(
            &selected.method,
            &send_payload_for(&selected.method, 21_000).unwrap(),
            "mainnet",
            Some(21_000)
        )
        .is_ok());
    }

    /// Verifies that `payable_methods` returns empty when every method is unpayable.
    #[test]
    fn send_has_no_route_when_every_method_is_unpayable() {
        let methods = [PaymentMethod::Lightning {
            label: "Lightning".into(),
            lightning_address: Some("alice@example.com".into()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        }];
        assert!(payable_methods(&methods, 21_000, "mainnet").is_empty());
        assert!(payable_methods(
            &[onchain("1BoatSLRHtKNngkdXEeobR76b53LETtpyT")],
            21_000,
            "devnet"
        )
        .is_empty());
    }

    /// Persisted profiles remain resolvable after restart but require method ownership proofs.
    #[tokio::test]
    async fn send_reads_sqlite_profile_before_and_after_restart_but_requires_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let mut wallet = load_or_create_identity(dir.path()).unwrap();
        wallet.alias = Some("alice@example.com".into());
        save_wallet(dir.path(), &wallet).unwrap();
        let profile = crate::handlers::profile::update_profile(
            &state,
            crate::types::ProfileUpdateRequest {
                ark_address: None,
                ark_asp_pubkey: None,
                alias: Some("alice@example.com".into()),
                lightning_address: Some("alice@example.com".into()),
                onchain_address: None,
                onchain_pubkey: None,
                silent_payment_address: None,
                ark_server: None,
                ark_pubkey: None,
                remove_methods: vec![],
                recovery_policy: None,
            },
        )
        .unwrap();
        assert!(profile.signature_valid.unwrap());
        assert!(!dir.path().join("registry.json").exists());

        for state in [state, test_state(dir.path())] {
            let resolved = resolve_profile(&state, "alice@example.com").unwrap();
            assert!(resolved.verification.profile_signature_verified);
            assert!(resolved.verification.transparency_inclusion_verified);
            assert!(resolved.verification.key_continuity_verified);
            assert!(!resolved.verification.payment_methods_verified);
            let response = send_response(&state, request("alice@example.com")).await;
            assert!(
                matches!(response, SendResponse::NoRoute { ref reason } if reason.contains("ownership proof")),
                "{response:?}"
            );
            assert_eq!(
                invite_count(dir.path()),
                0,
                "an existing alias is never re-invited"
            );
        }
    }

    /// Definitively absent aliases can be invited, but claimed aliases cannot be reinvited.
    #[tokio::test]
    async fn unknown_alias_invites_once_then_claimed_sqlite_alias_cannot_be_reinvited() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = test_state(dir.path());
        // Claiming an email alias needs a real verifier in production; the
        // dev-only mock is explicitly enabled only for this test fixture.
        state.allow_mock_alias_verification = true;
        load_or_create_identity(dir.path()).unwrap();
        let response = send_response(&state, request("carol@example.com")).await;
        let SendResponse::Invite { claim_url, .. } = response else {
            panic!("unknown alias should get an invite: {response:?}");
        };
        let id = claim_url
            .split("invite_id=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();
        assert_eq!(invite_count(dir.path()), 1);
        let duplicate = send_response(&state, request("carol@example.com")).await;
        assert!(
            matches!(duplicate, SendResponse::NoRoute { ref reason } if reason.contains("already exists locally")),
            "{duplicate:?}"
        );
        assert_eq!(
            invite_count(dir.path()),
            1,
            "a pending invite must not be duplicated"
        );
        crate::handlers::claim::claim_invite_handler(
            &state,
            crate::types::ClaimRequest {
                invite_id: id.into(),
                alias: "carol@example.com".into(),
                signed_profile: None,
                lightning_address: Some("carol@example.com".into()),
                onchain_address: None,
                onchain_pubkey: None,
                silent_payment_address: None,
                ark_server: None,
                ark_pubkey: None,
            },
        )
        .unwrap();
        assert!(!dir.path().join("registry.json").exists());
        for state in [state, test_state(dir.path())] {
            let response = send_response(&state, request("carol@example.com")).await;
            assert!(
                matches!(response, SendResponse::NoRoute { ref reason } if reason.contains("ownership proof")),
                "{response:?}"
            );
            assert_eq!(invite_count(dir.path()), 1);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_unknown_alias_sends_create_one_invite() {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(test_state(dir.path()));
        load_or_create_identity(dir.path()).unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let spawn = |state: Arc<AppState>, barrier: Arc<tokio::sync::Barrier>| {
            tokio::spawn(async move {
                barrier.wait().await;
                send_response(&state, request("dave@example.com")).await
            })
        };
        let (a, b) = tokio::join!(
            spawn(state.clone(), barrier.clone()),
            spawn(state.clone(), barrier.clone())
        );
        let responses = [a.unwrap(), b.unwrap()];
        assert_eq!(
            responses
                .iter()
                .filter(|response| matches!(response, SendResponse::Invite { .. }))
                .count(),
            1
        );
        assert_eq!(
            responses
                .iter()
                .filter(|response| matches!(response, SendResponse::NoRoute { .. }))
                .count(),
            1
        );
        assert_eq!(invite_count(dir.path()), 1);
    }

    #[tokio::test]
    async fn send_fails_closed_for_legacy_only_and_corrupt_sqlite_profiles() {
        use satspath_core::{
            crypto::{generate_identity_keypair, sign_profile},
            registry::Registry,
            PaymentProfile,
        };
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let kp = generate_identity_keypair();
        Registry::open(dir.path())
            .unwrap()
            .register_profile(
                sign_profile(
                    PaymentProfile {
                        alias: "legacy@example.com".into(),
                        identity_pubkey: hex::encode(kp.public_key.serialize()),
                        methods: vec![PaymentMethod::Lightning {
                            label: "LN".into(),
                            lightning_address: Some("legacy@example.com".into()),
                            lnurl: None,
                            bolt12: None,
                            receiver_pubkey: None,
                        }],
                        updated_at: crate::types::now(),
                        expires_at: None,
                        sequence: Some(0),
                        preferences: vec![],
                        nonce: None,
                        rotation: None,
                        method_verifications: vec![],
                        hybrid_pubkey: None,
                        pqc_required: false,
                        revoked: false,
                        recovery_policy: None,
                        recovery: None,
                    },
                    &kp.secret_key,
                )
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            send_response(&state, request("legacy@example.com")).await,
            SendResponse::NoRoute { .. }
        ));
        assert_eq!(invite_count(dir.path()), 0);

        let mut wallet = load_or_create_identity(dir.path()).unwrap();
        wallet.alias = Some("alice@example.com".into());
        wallet.lightning_address = Some("alice@example.com".into());
        crate::handlers::profile::sign_and_store(dir.path(), &mut wallet, "devnet").unwrap();
        save_wallet(dir.path(), &wallet).unwrap();
        // A tampered signature must never fall through to another resolver or an invite.
        let db = dir.path().join("satspath-transparency-v1.sqlite3");
        let connection = rusqlite::Connection::open(db).unwrap();
        let stored = TransactionalTransparencyStore::open(dir.path())
            .unwrap()
            .profile("alice@example.com")
            .unwrap()
            .unwrap();
        let mut forged = stored;
        forged.signature = "00".repeat(64);
        connection
            .execute(
                "UPDATE profiles SET profile_json=?1 WHERE identifier_hash=?2",
                (
                    serde_json::to_string(&forged).unwrap(),
                    satspath_core::privacy::identifier_hash("alice@example.com"),
                ),
            )
            .unwrap();
        assert!(matches!(
            send_response(&state, request("alice@example.com")).await,
            SendResponse::NoRoute { .. }
        ));
        assert_eq!(invite_count(dir.path()), 0);
    }

    #[test]
    fn repeated_broadcast_keeps_sqlite_signature_sequence_and_checkpoint_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = load_or_create_identity(dir.path()).unwrap();
        wallet.alias = Some("alice@example.com".into());
        wallet.lightning_address = Some("alice@example.com".into());
        save_wallet(dir.path(), &wallet).unwrap();

        let mut first_signature = None;
        for iteration in 0..3 {
            let state = test_state(dir.path()); // New state models a daemon restart.
            broadcast(&state).unwrap();
            assert!(!dir.path().join("registry.json").exists());
            let store = TransactionalTransparencyStore::open(dir.path()).unwrap();
            let profile = store.profile("alice@example.com").unwrap().unwrap();
            assert_eq!(
                profile.profile.sequence,
                Some(0),
                "broadcast #{iteration} mutated sequence"
            );
            let log = store.load_log().unwrap();
            assert_eq!(log.events().len(), 1);
            assert_eq!(log.checkpoints().len(), 1);
            if iteration == 0 {
                // The next broadcast must not overwrite the original signature.
                first_signature = Some(profile.signature);
            } else {
                assert_eq!(profile.signature, *first_signature.as_ref().unwrap());
            }
        }
        // A changed wallet method still produces exactly one legitimate update.
        wallet.lightning_address = Some("alice2@example.com".into());
        save_wallet(dir.path(), &wallet).unwrap();
        broadcast(&test_state(dir.path())).unwrap();
        broadcast(&test_state(dir.path())).unwrap();
        let store = TransactionalTransparencyStore::open(dir.path()).unwrap();
        assert_eq!(
            store
                .profile("alice@example.com")
                .unwrap()
                .unwrap()
                .profile
                .sequence,
            Some(1)
        );
        assert_eq!(store.load_log().unwrap().events().len(), 2);
    }
}
