//! Single-use HTTPS domain authorization for real registration and invite claims.
//! Domain administration is not mailbox access. Only public material is fetched.

use anyhow::{ensure, Result};
use satspath_core::{
    crypto::{generate_identity_keypair, generate_nonce, sign_profile, verify_signed_profile},
    privacy::{canonical_identifier, identifier_hash},
    transparency::{profile_hash, AliasAuthorization},
    IdentifierAttestation, IdentifierVerificationMethod, InviteRecord, InviteStatus, InviteStore,
    NameAction, NameEvent, PaymentProfile, SignedPaymentProfile, TransactionalTransparencyStore,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    config::{AppState, WalletState},
    handlers::{
        profile::apply_method_updates,
        transparency::load_or_create_transparency_operator,
        wallet::{load_identity_key, load_wallet, save_identity_key, save_wallet},
    },
    types::{build_methods, now, ProfileUpdateRequest},
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegistrationRequest {
    pub alias: String,
    #[serde(deserialize_with = "registration_methods")]
    pub methods: ProfileUpdateRequest,
    pub invite_id: Option<String>,
}

fn registration_methods<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<ProfileUpdateRequest, D::Error> {
    let value = Value::deserialize(deserializer)?;
    if value.get("alias").is_some() {
        return Err(serde::de::Error::custom(
            "methods must not contain a second alias, even null",
        ));
    }
    serde_json::from_value(value).map_err(serde::de::Error::custom)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegistrationVerifyRequest {
    pub alias: String,
    pub challenge_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct PendingRegistration {
    challenge_id: String,
    url: String,
    expires_at: i64,
    wallet: WalletState,
    wallet_before: WalletState,
    signed_profile: SignedPaymentProfile,
    event: NameEvent,
    invite: Option<InviteRecord>,
    network: String,
}

impl PendingRegistration {
    fn body(&self) -> Result<String> {
        // This commits the exact candidate profile and unsigned event, including
        // action, sequence, predecessor and invitation. There is no attestation
        // hash yet: the verifier creates that receipt only after the HTTPS fetch.
        Ok(serde_json::to_string(&json!({
            "protocol": "satspath-domain-authorization.v1",
            "challenge_id": self.challenge_id,
            "expires_at": self.expires_at,
            "identifier_hash": identifier_hash(&self.signed_profile.profile.alias),
            "identity_pubkey": self.signed_profile.profile.identity_pubkey,
            "profile_hash": profile_hash(&self.signed_profile)?,
            "signed_profile": self.signed_profile,
            "event": self.event,
            "invite_id": self.invite.as_ref().map(|invite| &invite.invite_id),
            "network": self.network,
        }))?)
    }
}

pub(crate) fn create_registration(state: &AppState, body: RegistrationRequest) -> Result<Value> {
    ensure!(
        body.methods.alias.is_none(),
        "methods must not contain a second alias"
    );
    let alias = canonical_identifier(&body.alias);
    let name = satspath_core::bip353::parse_bip353_name(&alias)?;
    let url = format!(
        "https://{}/.well-known/satspath/authorization/{}",
        name.domain,
        identifier_hash(&alias)
    );
    satspath_core::ssrf::validate_url(&url, false)?;
    let before = load_wallet(&state.home)?;
    if body.invite_id.is_none() {
        ensure!(
            before.alias.as_deref().is_none_or(|old| old == alias),
            "local wallet already has another alias; use a separate receiver home"
        );
    }
    let mut wallet = WalletState {
        alias: Some(alias.clone()),
        ..before.clone()
    };
    // Claims deliberately start with an independent receiver identity and methods.
    if body.invite_id.is_some() {
        wallet = WalletState {
            alias: Some(alias.clone()),
            ..WalletState::default()
        };
    }
    apply_method_updates(&mut wallet, &state.network, body.methods, false)?;
    ensure!(
        !build_methods(&wallet, &state.network).is_empty(),
        "at least one receive method is required"
    );
    let store = TransactionalTransparencyStore::open(&state.home)?;
    let invite = body
        .invite_id
        .as_deref()
        .map(|id| checked_invite(state, &store, id, &alias))
        .transpose()?;
    // First authorization is registration only. Existing aliases use the normal
    // owner-signed lifecycle, not a domain challenge that could replace a key.
    ensure!(store.profile(&alias)?.is_none(), "alias already registered");
    let log = store.load_log()?;
    ensure!(
        log.history(&identifier_hash(&alias)).is_empty(),
        "alias has prior history; registration cannot replace it"
    );
    let secret = if invite.is_some() {
        let key = generate_identity_keypair();
        wallet.identity_pubkey = Some(hex::encode(key.public_key.serialize()));
        key.secret_key
    } else {
        load_identity_key(
            &state.home,
            before
                .identity_pubkey
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("initialize daemon identity first"))?,
        )?
    };
    let time = now();
    wallet.created_at = Some(time);
    wallet.updated_at = Some(time);
    let signed = sign_profile(
        PaymentProfile {
            alias,
            identity_pubkey: wallet
                .identity_pubkey
                .clone()
                .expect("initialized identity"),
            methods: build_methods(&wallet, &state.network),
            sequence: Some(0),
            updated_at: time,
            expires_at: Some(time + 30 * 86400),
            nonce: Some(generate_nonce()),
            preferences: vec!["onchain".into()],
            rotation: None,
            recovery: None,
            recovery_policy: wallet.recovery_policy.clone(),
            method_verifications: vec![],
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
        },
        &secret,
    )?;
    let event = NameEvent {
        version: 1,
        identifier_hash: identifier_hash(&signed.profile.alias),
        action: NameAction::Register,
        identity_pubkey: signed.profile.identity_pubkey.clone(),
        profile_hash: profile_hash(&signed)?,
        sequence: 0,
        previous_event_hash: None,
        created_at: time,
        identifier_attestation_hash: None,
        removed_method_hashes: vec![],
        rotation: None,
        recovery_policy: signed.profile.recovery_policy.clone(),
        recovery: None,
        owner_signature: String::new(),
    };
    let pending = PendingRegistration {
        challenge_id: generate_nonce(),
        url,
        expires_at: time + 600,
        wallet,
        wallet_before: before,
        signed_profile: signed,
        event,
        invite,
        network: state.network.clone(),
    };
    let payload = pending.body()?;
    ensure!(
        payload.len() <= 16 * 1024,
        "authorization body exceeds 16 KiB"
    );
    store.save_alias_challenge(
        &pending.challenge_id,
        &serde_json::to_string(&pending)?,
        pending.expires_at,
        time,
    )?;
    if pending.invite.is_some() {
        save_identity_key(&state.home, &secret)?;
    }
    Ok(json!({
        "challenge_id": pending.challenge_id, "expires_at": pending.expires_at,
        "verification_method": "https_domain", "url": pending.url, "body": payload,
        "instruction": "Serve body exactly at url over valid HTTPS, then verify using challenge_id. This authorizes the alias as domain administrator; it does not prove mailbox access.",
    }))
}

fn checked_invite(
    state: &AppState,
    store: &TransactionalTransparencyStore,
    id: &str,
    alias: &str,
) -> Result<InviteRecord> {
    ensure!(
        store.claimed_invite(id)?.is_none(),
        "invite has already been claimed"
    );
    let invite = InviteStore::open(&state.home)?
        .get(id)
        .ok_or_else(|| anyhow::anyhow!("invite not found"))?;
    ensure!(
        invite.identifier_hash == identifier_hash(alias),
        "alias does not match invite"
    );
    ensure!(
        invite.expires_at > now()
            && matches!(
                invite.status,
                InviteStatus::Created | InviteStatus::EmailSent
            ),
        "invite expired, cancelled or already claimed"
    );
    if let (Some(signature), Some(pubkey)) = (&invite.sender_signature, &invite.sender_pubkey) {
        let message = format!(
            "SatsPath Invite v1\nalias_hash={}\namount_sats={}\ncreated_at={}\nexpires_at={}",
            invite.identifier_hash, invite.amount_sats, invite.created_at, invite.expires_at
        );
        ensure!(
            satspath_core::crypto::verify_message_signature(&message, signature, pubkey)?,
            "invalid sender signature"
        );
    }
    Ok(invite)
}

pub(crate) async fn verify_registration(
    state: &AppState,
    request: RegistrationVerifyRequest,
) -> Result<Value> {
    let store = TransactionalTransparencyStore::open_read_only(&state.home)?;
    let raw = store
        .alias_challenge(&request.challenge_id, now())?
        .ok_or_else(|| anyhow::anyhow!("challenge expired, unknown or already consumed"))?;
    let pending: PendingRegistration = serde_json::from_str(&raw)?;
    ensure!(
        canonical_identifier(&request.alias) == pending.signed_profile.profile.alias,
        "challenge alias mismatch"
    );
    ensure!(
        state.network == pending.network,
        "challenge network changed"
    );
    let client = {
        #[cfg(test)]
        if let Some(client) = &state.alias_test_client {
            client.clone()
        } else {
            satspath_core::ssrf::pinned_http_client(&pending.url, false).await?
        }
        #[cfg(not(test))]
        satspath_core::ssrf::pinned_http_client(&pending.url, false).await?
    };
    let response = client.get(&pending.url).send().await?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "domain challenge fetch must return HTTP 200 without redirects"
    );
    let bytes = satspath_core::ssrf::read_bounded_response(response, 16 * 1024).await?;
    ensure!(
        bytes == pending.body()?.as_bytes(),
        "domain challenge body does not authorize this registration"
    );
    // Fetches hold no mutation lock. Recheck all state and expiry after acquiring it.
    let _guard = state.mutation_lock.lock().await;
    finish_registration(state, &raw, pending)
}

fn finish_registration(state: &AppState, raw: &str, pending: PendingRegistration) -> Result<Value> {
    ensure!(
        pending.expires_at > now(),
        "challenge expired during verification"
    );
    let store = TransactionalTransparencyStore::open(&state.home)?;
    let alias = &pending.signed_profile.profile.alias;
    ensure!(
        verify_signed_profile(&pending.signed_profile)?,
        "invalid candidate signature"
    );
    ensure!(store.profile(alias)?.is_none(), "alias already registered");
    if pending.invite.is_none() {
        ensure!(
            serde_json::to_value(load_wallet(&state.home)?)?
                == serde_json::to_value(&pending.wallet_before)?,
            "wallet changed after challenge creation"
        );
    }
    let mut claimed = pending.invite.clone();
    if let Some(invite) = &mut claimed {
        let current = checked_invite(state, &store, &invite.invite_id, alias)?;
        ensure!(
            serde_json::to_value(&current)? == serde_json::to_value(&*invite)?,
            "invite changed after challenge creation"
        );
        invite.status = InviteStatus::ClaimedWithPublicProfile;
        invite.claimed_at = Some(now());
        invite.claimed_profile_pubkey =
            Some(pending.signed_profile.profile.identity_pubkey.clone());
    }
    let operator = load_or_create_transparency_operator(&state.home)?;
    let mut attestation = IdentifierAttestation {
        version: 1,
        identifier_hash: pending.event.identifier_hash.clone(),
        identity_pubkey: pending.event.identity_pubkey.clone(),
        profile_hash: pending.event.profile_hash.clone(),
        nonce: pending.challenge_id.clone(),
        issued_at: now(),
        expires_at: pending
            .signed_profile
            .profile
            .expires_at
            .expect("bounded candidate expiry"),
        method: IdentifierVerificationMethod::Domain,
        verifier_pubkey: hex::encode(
            secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &operator)
                .serialize(),
        ),
        verifier_signature: String::new(),
    };
    attestation.sign(&operator)?;
    let mut event = pending.event;
    event.identifier_attestation_hash = Some(attestation.attestation_hash()?);
    event.sign(&load_identity_key(&state.home, &event.identity_pubkey)?)?;
    let log = store.load_log()?;
    let candidate = log.prepare_append(event.clone(), &pending.signed_profile)?;
    let checkpoint = candidate.prepare_checkpoint(&operator)?;
    let wallet_json = serde_json::to_string(&pending.wallet)?;
    store.commit_authorized_profile(
        &pending.signed_profile,
        &event,
        &checkpoint,
        AliasAuthorization {
            challenge_id: &pending.challenge_id,
            challenge_json: raw,
            attestation: &attestation,
            claimed_invite: claimed.as_ref(),
            local_wallet_json: claimed.is_none().then_some(wallet_json.as_str()),
            now: now(),
        },
    )?;
    if claimed.is_none() {
        recover_registration_wallet(state)?;
    }
    Ok(
        json!({"status": "registered", "verification_method": "https_domain",
        "signed_profile": pending.signed_profile, "identifier_attestation": attestation,
        "claimed_invite": claimed, "moves_funds": false}),
    )
}

/// Replay only an atomic self-registration mirror, never arbitrary wallet edits.
pub(crate) fn recover_registration_wallet(state: &AppState) -> Result<()> {
    let store = TransactionalTransparencyStore::open(&state.home)?;
    if let Some((raw, profile)) = store.registration_wallet()? {
        let wallet: WalletState = serde_json::from_str(&raw)?;
        let current = load_wallet(&state.home)?;
        ensure!(
            current.identity_pubkey == wallet.identity_pubkey,
            "registration recovery cannot replace the local identity"
        );
        ensure!(
            serde_json::to_value(store.profile(&profile.profile.alias)?)?
                == serde_json::to_value(Some(&profile))?,
            "registration recovery profile changed"
        );
        ensure!(
            wallet.alias.as_deref() == Some(&profile.profile.alias)
                && build_methods(&wallet, &state.network) == profile.profile.methods,
            "registration mirror mismatch"
        );
        save_wallet(&state.home, &wallet)?;
        store.clear_registration_wallet(&raw)?;
    }
    Ok(())
}

/// Public receive state for a locally authorized receiver, separate from the
/// operator wallet. The exact round-trip prevents dropping unsupported fields.
pub(crate) fn claimed_profile_wallet(state: &AppState, alias: &str) -> Result<WalletState> {
    let store = TransactionalTransparencyStore::open_read_only(&state.home)?;
    let signed = store
        .profile(alias)?
        .ok_or_else(|| anyhow::anyhow!("claimed profile not found"))?;
    ensure!(
        !signed.profile.revoked && verify_signed_profile(&signed)?,
        "inactive claimed profile"
    );
    ensure!(
        store
            .claimed_invites()?
            .iter()
            .any(|receipt| receipt.identifier_hash == identifier_hash(alias)
                && receipt.claimed_profile_pubkey.as_deref()
                    == Some(&signed.profile.identity_pubkey)),
        "alias is not an authorized local receiver claim"
    );
    let mut wallet = WalletState {
        alias: Some(signed.profile.alias.clone()),
        identity_pubkey: Some(signed.profile.identity_pubkey.clone()),
        recovery_policy: signed.profile.recovery_policy.clone(),
        ..Default::default()
    };
    for method in &signed.profile.methods {
        match method {
            satspath_core::PaymentMethod::Onchain {
                address,
                silent_payment_pubkey,
                pubkey_hint,
                ..
            } => {
                wallet.onchain_address = address.clone();
                wallet.silent_payment_address = silent_payment_pubkey.clone();
                wallet.onchain_pubkey = pubkey_hint.clone();
            }
            satspath_core::PaymentMethod::Lightning {
                lightning_address, ..
            } => wallet.lightning_address = lightning_address.clone(),
            satspath_core::PaymentMethod::Ark {
                server,
                pubkey,
                opaque_uri,
                ..
            } => {
                wallet.ark_server = Some(server.clone());
                wallet.ark_pubkey = Some(pubkey.clone());
                wallet.ark_address = opaque_uri.clone();
            }
            _ => anyhow::bail!("unsupported receiver method"),
        }
    }
    ensure!(
        build_methods(&wallet, &state.network) == signed.profile.methods,
        "claimed methods cannot be represented without changes"
    );
    Ok(wallet)
}

/// Configured public claim page, or the actual local dashboard (never a placeholder).
pub(crate) fn claim_url(state: &AppState, invite_id: &str) -> Result<String> {
    let base = std::env::var("SATSPATH_CLAIM_BASE_URL").unwrap_or_else(|_| {
        format!(
            "{}://{}/claim",
            if state.is_tls { "https" } else { "http" },
            state.bind
        )
    });
    configured_claim_url(&base, invite_id)
}

fn configured_claim_url(base: &str, invite_id: &str) -> Result<String> {
    let mut url = url::Url::parse(base)?;
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.query().is_none(),
        "claim base must not contain credentials, fragment or query"
    );
    if url.scheme() != "https" {
        ensure!(
            url.scheme() == "http"
                && url.host_str().is_some_and(|host| host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())),
            "public claim base requires HTTPS"
        );
    }
    ensure!(
        url.path().ends_with("/claim"),
        "claim base must point to the served /claim page"
    );
    url.query_pairs_mut().append_pair("invite_id", invite_id);
    Ok(url.into())
}

#[cfg(test)]
mod tests;
