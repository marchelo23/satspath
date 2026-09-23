//! Profile handlers: update, challenge/verify, key rotation.

use anyhow::Result;
use satspath_core::{
    crypto::{generate_identity_keypair, sign_profile, verify_signed_profile},
    NameAction, NameEvent, PaymentProfile, SatsPathError, TransactionalTransparencyStore,
};

use crate::config::{AppState, WalletState};
use crate::handlers::transparency::load_or_create_transparency_operator;
use crate::handlers::wallet::{
    load_identity_key, load_or_create_identity, load_wallet, save_identity_key, save_wallet,
};
use crate::types::{
    build_methods, now, AliasRequest, KeyRotationResponse, ProfileResponse, ProfileUpdateRequest,
    VerifyRequest,
};

pub(crate) fn profile_response(state: &AppState) -> Result<ProfileResponse> {
    let wallet = load_wallet(&state.home)?;
    let signed_profile = match wallet.alias.as_deref() {
        Some(alias) => TransactionalTransparencyStore::open(&state.home)
            .and_then(|store| store.profile(alias))
            .ok()
            .flatten(),
        None => None,
    };
    let signature_valid = signed_profile
        .as_ref()
        .map(verify_signed_profile)
        .transpose()?;
    Ok(ProfileResponse {
        wallet,
        signed_profile,
        signature_valid,
    })
}

pub(crate) fn update_profile(
    state: &AppState,
    body: ProfileUpdateRequest,
) -> Result<ProfileResponse> {
    let mut wallet = load_or_create_identity(&state.home)?;
    // Alias must be verified first through /v1/profile/verify
    if let Some(alias) = &body.alias {
        if Some(alias.clone()) != wallet.alias {
            anyhow::bail!("alias must be verified through /v1/profile/challenge and /v1/profile/verify before updating");
        }
    }
    apply_method_updates(&mut wallet, &state.network, body, true)?;
    sign_and_store(&state.home, &mut wallet, &state.network)?;
    save_wallet(&state.home, &wallet)?;
    profile_response(state)
}

pub(crate) fn create_challenge(_state: &AppState, body: AliasRequest) -> Result<serde_json::Value> {
    use satspath_core::platform::{EmailVerifier, MockEmailVerifier};
    let verifier = MockEmailVerifier {
        now: chrono::Utc::now().timestamp(),
        ttl_seconds: 600,
    };
    let challenge = verifier.create_challenge(&body.alias)?;
    Ok(serde_json::json!({
        "challenge_id": challenge.challenge_id,
        "message": "A mock verification code was sent. (MOCK: use the email address itself as the token)",
    }))
}

pub(crate) fn verify_challenge(state: &AppState, body: VerifyRequest) -> Result<ProfileResponse> {
    use satspath_core::platform::{EmailVerifier, MockEmailVerifier};
    let verifier = MockEmailVerifier {
        now: chrono::Utc::now().timestamp(),
        ttl_seconds: 600,
    };
    let verified = verifier.verify_challenge(&body.token)?;

    if verified.identifier_hash != satspath_core::privacy::identifier_hash(&body.alias) {
        anyhow::bail!("invalid verification token for this alias");
    }

    let mut wallet = load_or_create_identity(&state.home)?;
    wallet.alias = Some(body.alias);
    wallet.updated_at = Some(chrono::Utc::now().timestamp());

    // Only sign and store if there are methods already. Otherwise just save the wallet state.
    if wallet.lightning_address.is_some()
        || wallet.onchain_address.is_some()
        || wallet.ark_server.is_some()
    {
        sign_and_store(&state.home, &mut wallet, &state.network)?;
    }
    save_wallet(&state.home, &wallet)?;
    profile_response(state)
}

pub(crate) fn update_profile_methods(
    state: &AppState,
    body: ProfileUpdateRequest,
) -> Result<ProfileResponse> {
    let mut wallet = load_or_create_identity(&state.home)?;
    if wallet.alias.is_none() {
        anyhow::bail!("set alias first with PUT /v1/profile");
    }
    apply_method_updates(&mut wallet, &state.network, body, false)?;
    sign_and_store(&state.home, &mut wallet, &state.network)?;
    save_wallet(&state.home, &wallet)?;
    profile_response(state)
}

pub(crate) fn apply_method_updates(
    wallet: &mut WalletState,
    network: &str,
    body: ProfileUpdateRequest,
    allow_empty: bool,
) -> Result<()> {
    use satspath_core::validation::{
        validate_bitcoin_address, validate_compressed_pubkey, validate_lightning_address,
    };
    let has_method = body.lightning_address.is_some()
        || body.onchain_address.is_some()
        || body.onchain_pubkey.is_some()
        || body.ark_server.is_some()
        || body.ark_pubkey.is_some()
        || !body.remove_methods.is_empty();
    if !allow_empty && !has_method {
        anyhow::bail!("provide at least one receive method");
    }

    for method in &body.remove_methods {
        match method.as_str() {
            "lightning" => wallet.lightning_address = None,
            "onchain" => {
                wallet.onchain_address = None;
                wallet.onchain_pubkey = None;
            }
            "ark" => {
                wallet.ark_server = None;
                wallet.ark_pubkey = None;
            }
            _ => anyhow::bail!("unknown payment method removal: {method}"),
        }
    }
    if let Some(addr) = body.lightning_address {
        validate_lightning_address(&addr)?;
        wallet.lightning_address = Some(addr);
    }
    if let Some(addr) = body.onchain_address {
        validate_bitcoin_address(&addr, crate::types::bitcoin_network(network))?;
        wallet.onchain_address = Some(addr);
    }
    if let Some(pubkey) = body.onchain_pubkey {
        validate_compressed_pubkey(&pubkey)?;
        wallet.onchain_pubkey = Some(pubkey);
    }
    if wallet.onchain_pubkey.is_some() && wallet.onchain_address.is_none() {
        anyhow::bail!("onchain_pubkey is a hint; provide onchain_address too");
    }
    match (body.ark_server, body.ark_pubkey) {
        (Some(server), Some(pubkey)) => {
            satspath_core::ark::validate_ark_server_url(&server)?;
            validate_compressed_pubkey(&pubkey)?;
            wallet.ark_server = Some(server);
            wallet.ark_pubkey = Some(pubkey);
        }
        (None, None) => {}
        _ => anyhow::bail!("ark_server and ark_pubkey must be provided together"),
    }
    wallet.updated_at = Some(now());
    Ok(())
}

pub(crate) fn sign_and_store(
    home: &std::path::Path,
    wallet: &mut WalletState,
    network: &str,
) -> Result<()> {
    use satspath_core::{transparency::payment_method_descriptor_hash, PaymentMethod};
    let alias = wallet
        .alias
        .clone()
        .ok_or_else(|| anyhow::anyhow!("profile alias is required"))?;
    let identity_pubkey = wallet
        .identity_pubkey
        .clone()
        .ok_or_else(|| anyhow::anyhow!("identity is not initialized"))?;
    let methods = build_methods(wallet, network);
    if methods.is_empty() {
        anyhow::bail!("profile needs at least one public receive method");
    }

    let store = TransactionalTransparencyStore::open(home)?;
    let existing = store.profile(&alias)?;
    let log = store.load_log()?;
    let history: Vec<_> = log
        .history(&satspath_core::privacy::identifier_hash(&alias))
        .into_iter()
        .cloned()
        .collect();
    let next_sequence = satspath_core::next_identifier_sequence(existing.as_ref(), &history)?;

    let secret = load_identity_key(home, &identity_pubkey)?;
    let t = now();
    let profile = PaymentProfile {
        sequence: Some(next_sequence),
        alias: alias.clone(),
        identity_pubkey,
        methods,
        updated_at: t,
        expires_at: Some(t + 30 * 24 * 3600), // default 30-day expiry per spec section 28
        preferences: vec!["lightning".into(), "ark".into(), "onchain".into()],
        nonce: Some(satspath_core::crypto::generate_nonce()),
        rotation: None,
        method_verifications: vec![],
        hybrid_pubkey: None,
        pqc_required: false,
        revoked: false,
    };
    let signed = sign_profile(profile, &secret)?;
    let new_descriptors: std::collections::HashSet<_> = signed
        .profile
        .methods
        .iter()
        .map(PaymentMethod::ownership_descriptor)
        .collect();
    let removed_method_hashes = existing
        .as_ref()
        .map(|old| {
            old.profile
                .methods
                .iter()
                .map(PaymentMethod::ownership_descriptor)
                .filter(|descriptor| !new_descriptors.contains(descriptor))
                .map(|descriptor| payment_method_descriptor_hash(&descriptor))
                .collect()
        })
        .unwrap_or_default();
    let previous_event_hash = history.last().map(|event| event.event_hash()).transpose()?;
    let mut event = NameEvent {
        version: 1,
        identifier_hash: satspath_core::privacy::identifier_hash(&alias),
        action: if history.is_empty() {
            NameAction::Register
        } else {
            NameAction::UpdateProfile
        },
        identity_pubkey: signed.profile.identity_pubkey.clone(),
        profile_hash: satspath_core::transparency::profile_hash(&signed)?,
        sequence: next_sequence,
        previous_event_hash,
        created_at: t,
        identifier_attestation_hash: None,
        removed_method_hashes,
        rotation: signed.profile.rotation.clone(),
        owner_signature: String::new(),
    };
    event.sign(&secret)?;
    let candidate = log.prepare_append(event.clone(), &signed)?;
    let operator = load_or_create_transparency_operator(home)?;
    let checkpoint = candidate.prepare_checkpoint(&operator)?;
    store.commit_profile_event_checkpoint(&alias, &signed, &event, &checkpoint)?;
    Ok(())
}

pub(crate) fn rotate_profile_key(state: &AppState) -> Result<KeyRotationResponse> {
    use satspath_core::crypto::fingerprint_pubkey;
    let mut wallet = load_wallet(&state.home)?;
    let alias = wallet
        .alias
        .clone()
        .ok_or_else(|| anyhow::anyhow!("profile alias is required"))?;
    let old_pubkey = wallet
        .identity_pubkey
        .clone()
        .ok_or_else(|| anyhow::anyhow!("identity is not initialized"))?;
    let old_secret = load_identity_key(&state.home, &old_pubkey)?;
    let store = TransactionalTransparencyStore::open(&state.home)?;
    let existing = store
        .profile(&alias)?
        .ok_or_else(|| SatsPathError::AliasNotFound(alias.clone()))?;
    if existing.profile.identity_pubkey != old_pubkey || !verify_signed_profile(&existing)? {
        anyhow::bail!("active key does not control the current signed profile");
    }
    let log = store.load_log()?;
    let identifier_hash = satspath_core::privacy::identifier_hash(&alias);
    let history: Vec<_> = log.history(&identifier_hash).into_iter().cloned().collect();
    let sequence = satspath_core::next_identifier_sequence(Some(&existing), &history)?;
    let previous_event_hash = history
        .last()
        .ok_or_else(|| anyhow::anyhow!("rotation requires existing history"))?
        .signed_event_hash()?;
    let new_key = generate_identity_keypair();
    let unsigned = satspath_core::rotate_identity_key(
        &existing,
        &old_secret,
        &new_key.secret_key,
        &previous_event_hash,
        sequence,
    )?;
    let signed = sign_profile(unsigned.profile, &new_key.secret_key)?;
    let mut event = NameEvent {
        version: 1,
        identifier_hash,
        action: NameAction::RotateKey,
        identity_pubkey: signed.profile.identity_pubkey.clone(),
        profile_hash: satspath_core::transparency::profile_hash(&signed)?,
        sequence,
        previous_event_hash: Some(previous_event_hash),
        created_at: now(),
        identifier_attestation_hash: None,
        removed_method_hashes: Vec::new(),
        rotation: signed.profile.rotation.clone(),
        owner_signature: String::new(),
    };
    event.sign(&old_secret)?;
    let candidate = log.prepare_append(event.clone(), &signed)?;
    let operator = load_or_create_transparency_operator(&state.home)?;
    let checkpoint = candidate.prepare_checkpoint(&operator)?;
    // Store a recoverable key backup before commit, but do not make it active.
    save_identity_key(&state.home, &new_key.secret_key)?;
    store.commit_profile_event_checkpoint(&alias, &signed, &event, &checkpoint)?;
    wallet.identity_pubkey = Some(signed.profile.identity_pubkey.clone());
    wallet.updated_at = Some(now());
    save_wallet(&state.home, &wallet)?;
    Ok(KeyRotationResponse {
        alias,
        sequence,
        previous_fingerprint: fingerprint_pubkey(&old_pubkey)?,
        new_fingerprint: fingerprint_pubkey(&signed.profile.identity_pubkey)?,
        event_hash: event.signed_event_hash()?,
        checkpoint_hash: checkpoint.checkpoint_hash()?,
    })
}

pub(crate) fn ensure_signed_profile(
    home: &std::path::Path,
    wallet: &mut WalletState,
    network: &str,
) -> Result<()> {
    use satspath_core::registry::Registry;
    if let Some(alias) = wallet.alias.as_deref() {
        if let Ok(signed) = Registry::open(home)?.resolve_alias(alias) {
            if verify_signed_profile(signed)? {
                return Ok(());
            }
        }
    }
    sign_and_store(home, wallet, network)?;
    save_wallet(home, wallet)?;
    Ok(())
}
