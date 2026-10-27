//! Claim handlers: inspect invite, claim invite, list invites, list notifications.

use anyhow::Result;
use satspath_core::crypto::verify_message_signature;
use satspath_core::privacy::identifier_hash;
use satspath_core::profile::{ClaimNotification, InviteRecord, InviteStatus};
use satspath_core::InviteStore;

use crate::config::{AppState, WalletState};
use crate::handlers::profile::{apply_method_updates, sign_and_store};
use crate::handlers::wallet::load_or_create_identity;
use crate::types::{ClaimRequest, ClaimResponse, InspectInviteResponse, ProfileUpdateRequest};

pub(crate) fn inspect_invite_handler(
    state: &AppState,
    invite_id: &str,
) -> Result<InspectInviteResponse> {
    let store = InviteStore::open(&state.home)?;
    let invite = store
        .get(invite_id)
        .ok_or_else(|| anyhow::anyhow!("invite '{}' not found", invite_id))?;

    let now = chrono::Utc::now().timestamp();
    let is_expired = now >= invite.expires_at || invite.status == InviteStatus::Expired;
    let is_claimable = ensure_invite_claim_enabled(state).is_ok()
        && !is_expired
        && invite.status != InviteStatus::ClaimedWithPublicProfile
        && invite.status != InviteStatus::Cancelled;

    let sender_verified =
        if let (Some(sig), Some(pubkey)) = (&invite.sender_signature, &invite.sender_pubkey) {
            let message = format!(
                "SatsPath Invite v1\nalias_hash={}\namount_sats={}\ncreated_at={}\nexpires_at={}",
                invite.identifier_hash, invite.amount_sats, invite.created_at, invite.expires_at
            );
            verify_message_signature(&message, sig, pubkey).unwrap_or(false)
        } else {
            false
        };

    Ok(InspectInviteResponse {
        invite_id: invite.invite_id,
        identifier_hash: invite.identifier_hash,
        display_hint: invite.display_hint,
        amount_sats: invite.amount_sats,
        memo: invite.memo,
        status: invite.status,
        is_expired,
        is_claimable,
        created_at: invite.created_at,
        expires_at: invite.expires_at,
        sender_verified,
        sender_pubkey: invite.sender_pubkey,
    })
}

/// An invite ID (also returned by public /v1/send) and a matching alias hash do
/// not establish control of an email address or domain. No production alias
/// attestation is implemented for this endpoint. Keep the gate ahead of every
/// store or wallet access, including the externally signed profile path.
fn ensure_invite_claim_enabled(state: &AppState) -> Result<()> {
    if !state.allow_mock_alias_verification {
        anyhow::bail!(
            "invite claiming is disabled: no real email/domain alias-control verifier is configured; an invite ID, matching alias hash or profile signature is not proof of alias control (development only: --dev-mock-alias-verification on devnet/regtest)"
        );
    }
    if !matches!(
        state.network.trim().to_ascii_lowercase().as_str(),
        "devnet" | "regtest"
    ) {
        anyhow::bail!(
            "insecure mock invite claiming is allowed only on devnet/regtest, never on mainnet or testnet; real alias attestation is not implemented"
        );
    }
    Ok(())
}

/// Claim an invite only in explicit development mock mode after the router's auth gate.
pub(crate) fn claim_invite_handler(state: &AppState, body: ClaimRequest) -> Result<ClaimResponse> {
    ensure_invite_claim_enabled(state)?;
    // A signature over the profile proves possession of its identity key, not
    // control of the alias; it cannot authorize a transparency NameEvent either.
    // The wire request has no independently signed event or alias attestation.
    if body.signed_profile.is_some() {
        anyhow::bail!(
            "externally signed profiles cannot be claimed here: a profile signature does not prove alias control or authorize a NameEvent"
        );
    }
    if body.invite_id.trim().is_empty() {
        anyhow::bail!("missing invite_id");
    }
    if body.alias.trim().is_empty() {
        anyhow::bail!("missing alias");
    }

    if !state
        .home
        .join(satspath_core::invite_store::INVITES_FILE)
        .try_exists()?
    {
        anyhow::bail!("invite '{}' not found", body.invite_id);
    }
    let mut store = InviteStore::open(&state.home)?;
    let invite = store
        .get(&body.invite_id)
        .ok_or_else(|| anyhow::anyhow!("invite '{}' not found", body.invite_id))?;

    let expected_hash = identifier_hash(&body.alias);
    if invite.identifier_hash != expected_hash {
        anyhow::bail!(
            "alias '{}' does not match invite recipient identifier",
            body.alias
        );
    }

    let now = chrono::Utc::now().timestamp();
    if now >= invite.expires_at || invite.status == InviteStatus::Expired {
        anyhow::bail!("invite has expired");
    }

    if invite.status == InviteStatus::ClaimedWithPublicProfile {
        anyhow::bail!("invite has already been claimed");
    }

    if invite.status == InviteStatus::Cancelled {
        anyhow::bail!("invite has been cancelled");
    }

    // Verify sender signature if present
    if let (Some(sig), Some(pubkey)) = (&invite.sender_signature, &invite.sender_pubkey) {
        let message = format!(
            "SatsPath Invite v1\nalias_hash={}\namount_sats={}\ncreated_at={}\nexpires_at={}",
            invite.identifier_hash, invite.amount_sats, invite.created_at, invite.expires_at
        );
        if !verify_message_signature(&message, sig, pubkey)? {
            anyhow::bail!("invalid sender signature on invite");
        }
    }

    // Validate the public receive methods before initializing an identity: an
    // invalid claim must not create a wallet as a side effect of rejection.
    // Keep the claim profile separate from the operator's wallet so a mock
    // claim cannot rewrite the sender/operator alias or receive methods.
    let mut wallet = WalletState {
        alias: Some(body.alias.clone()),
        ..WalletState::default()
    };

    let update_req = ProfileUpdateRequest {
        alias: Some(body.alias.clone()),
        lightning_address: body.lightning_address,
        onchain_address: body.onchain_address,
        onchain_pubkey: body.onchain_pubkey,
        silent_payment_address: body.silent_payment_address,
        ark_server: body.ark_server,
        ark_pubkey: body.ark_pubkey,
        remove_methods: vec![],
        recovery_policy: None,
    };

    apply_method_updates(&mut wallet, &state.network, update_req, false)?;
    if crate::types::build_methods(&wallet, &state.network).is_empty() {
        anyhow::bail!("profile needs at least one public receive method");
    }
    // Development-only: the daemon's local identity key is NOT evidence of
    // control of the email/domain alias. Do not enable this path on real networks.
    let identity = load_or_create_identity(&state.home)?;
    wallet.identity_pubkey = identity.identity_pubkey;
    wallet.created_at = identity.created_at;
    wallet.updated_at = Some(now);
    sign_and_store(&state.home, &mut wallet, &state.network)?;
    let receiver_pubkey = wallet.identity_pubkey.unwrap_or_default();

    // Transition invite to ClaimedWithPublicProfile and create notification
    store.claim(&body.invite_id, &receiver_pubkey)?;

    Ok(ClaimResponse {
        status: "claimed".into(),
        invite_id: body.invite_id,
        alias: body.alias,
        amount_sats: invite.amount_sats,
        profile_pubkey: receiver_pubkey,
        claimed_at: now,
        message: "DEVELOPMENT ONLY: insecure mock claim; receiver profile published without email/domain alias-control attestation. Do not treat its signature as proof of alias ownership".into(),
    })
}

pub(crate) fn list_invites_handler(state: &AppState) -> Result<Vec<InviteRecord>> {
    let mut store = InviteStore::open(&state.home)?;
    store.list()
}

pub(crate) fn list_notifications_handler(state: &AppState) -> Result<Vec<ClaimNotification>> {
    let store = InviteStore::open(&state.home)?;
    Ok(store.notifications().to_vec())
}

pub(crate) fn mark_notification_read_handler(
    state: &AppState,
    notification_id: &str,
) -> Result<serde_json::Value> {
    let mut store = InviteStore::open(&state.home)?;
    store.mark_notification_read(notification_id)?;
    Ok(serde_json::json!({
        "status": "ok",
        "notification_id": notification_id,
        "read": true
    }))
}

pub(crate) fn mark_all_notifications_read_handler(state: &AppState) -> Result<serde_json::Value> {
    let mut store = InviteStore::open(&state.home)?;
    store.mark_all_notifications_read()?;
    Ok(serde_json::json!({
        "status": "ok",
        "all_read": true
    }))
}
