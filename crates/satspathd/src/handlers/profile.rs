//! Profile handlers: update, challenge/verify, key rotation.

use anyhow::Result;
use satspath_core::{
    crypto::{generate_identity_keypair, sign_profile, verify_signed_profile},
    IdentifierAttestation, NameAction, NameEvent, PaymentProfile, SatsPathError,
    TransactionalTransparencyStore,
};

use crate::config::{AppState, WalletState};
use crate::handlers::transparency::load_or_create_transparency_operator;
use crate::handlers::wallet::{
    load_identity_key, load_or_create_identity, load_wallet, save_identity_key, save_wallet,
};
use crate::types::{
    build_methods, now, AliasRequest, KeyRecoveryResponse, KeyRotationResponse,
    ProfileRecoverRequest, ProfileResponse, ProfileUpdateRequest, VerifyRequest,
};

pub(crate) fn profile_response(state: &AppState) -> Result<ProfileResponse> {
    let wallet = load_wallet(&state.home)?;
    let signed_profile = stored_profile(state, &wallet)?;
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

/// Read the reconciled store without allowing public GET requests to sign changes.
pub(crate) fn stored_profile(
    state: &AppState,
    wallet: &WalletState,
) -> Result<Option<satspath_core::SignedPaymentProfile>> {
    let Some(alias) = wallet.alias.as_deref() else {
        return Ok(None);
    };
    let signed = TransactionalTransparencyStore::open(&state.home)?.profile(alias)?;
    if let Some(existing) = &signed {
        if !existing.profile.revoked
            && existing.profile.methods != build_methods(wallet, &state.network)
        {
            anyhow::bail!("stored profile methods are stale; restart the daemon to reconcile them");
        }
    }
    Ok(signed.filter(|signed| !signed.profile.revoked))
}

/// Run before serving requests, or under the authenticated mutation lock.
/// Commit replacements and revocations so other store readers cannot use stale rails.
pub(crate) fn reconcile_stored_profile(state: &AppState, wallet: &mut WalletState) -> Result<()> {
    let Some(alias) = wallet.alias.clone() else {
        return Ok(());
    };
    let store = TransactionalTransparencyStore::open(&state.home)?;
    let signed = store.profile(&alias)?;
    if let Some(existing) = &signed {
        if !existing.profile.revoked
            && existing.profile.methods != build_methods(wallet, &state.network)
        {
            store_current_profile(&state.home, wallet, &state.network, true)?;
        }
    }
    Ok(())
}

pub(crate) fn update_profile(
    state: &AppState,
    body: ProfileUpdateRequest,
) -> Result<ProfileResponse> {
    super::onboarding::recover_registration_wallet(state)?;
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

/// The daemon does not ship a production alias verifier. The mocked verifier
/// proves nothing, so both alias endpoints fail closed unless the operator
/// explicitly opted into the development-only mock on devnet/regtest.
fn ensure_mock_alias_verification_allowed(state: &AppState) -> Result<()> {
    if !state.allow_mock_alias_verification {
        anyhow::bail!(
            "alias verification is not configured on this daemon; no alias can be verified (development only: start with --dev-mock-alias-verification)"
        );
    }
    if !matches!(
        state.network.trim().to_ascii_lowercase().as_str(),
        "devnet" | "regtest"
    ) {
        anyhow::bail!(
            "the insecure mock alias verifier is allowed only on devnet/regtest, never on public Bitcoin networks"
        );
    }
    Ok(())
}

pub(crate) fn create_challenge(state: &AppState, body: AliasRequest) -> Result<serde_json::Value> {
    ensure_mock_alias_verification_allowed(state)?;
    use satspath_core::platform::{EmailVerifier, MockEmailVerifier};
    let verifier = MockEmailVerifier {
        now: chrono::Utc::now().timestamp(),
        ttl_seconds: 600,
    };
    let challenge = verifier.create_challenge(&body.alias)?;
    Ok(serde_json::json!({
        "challenge_id": challenge.challenge_id,
        "message": "A mock verification code was sent. (DEVELOPMENT ONLY: use the email address itself as the token)",
    }))
}

pub(crate) fn verify_challenge(state: &AppState, body: VerifyRequest) -> Result<ProfileResponse> {
    ensure_mock_alias_verification_allowed(state)?;
    use satspath_core::platform::{EmailVerifier, MockEmailVerifier};
    let verifier = MockEmailVerifier {
        now: chrono::Utc::now().timestamp(),
        ttl_seconds: 600,
    };
    let verified = verifier.verify_challenge(&body.token)?;

    if verified.identifier_hash != satspath_core::privacy::identifier_hash(&body.alias) {
        anyhow::bail!("invalid verification token for this alias");
    }

    super::onboarding::recover_registration_wallet(state)?;
    let mut wallet = load_or_create_identity(&state.home)?;
    wallet.alias = Some(body.alias);
    wallet.updated_at = Some(chrono::Utc::now().timestamp());

    if !build_methods(&wallet, &state.network).is_empty() {
        sign_and_store(&state.home, &mut wallet, &state.network)?;
    } else {
        // A legacy offer-only profile must be revoked, not left active in SQLite.
        reconcile_stored_profile(state, &mut wallet)?;
    }
    save_wallet(&state.home, &wallet)?;
    profile_response(state)
}

pub(crate) fn update_profile_methods(
    state: &AppState,
    body: ProfileUpdateRequest,
) -> Result<ProfileResponse> {
    super::onboarding::recover_registration_wallet(state)?;
    let mut wallet = load_or_create_identity(&state.home)?;
    if wallet.alias.is_none() {
        anyhow::bail!("set alias first with PUT /v1/profile");
    }
    apply_method_updates(&mut wallet, &state.network, body, false)?;
    sign_and_store(&state.home, &mut wallet, &state.network)?;
    save_wallet(&state.home, &wallet)?;
    profile_response(state)
}

/// Validate receive-method updates against the daemon network before storing them.
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
        || body.silent_payment_address.is_some()
        || body.ark_server.is_some()
        || body.ark_pubkey.is_some()
        || body.ark_address.is_some()
        || body.ark_asp_pubkey.is_some()
        || !body.remove_methods.is_empty()
        || body.recovery_policy.is_some();
    if !allow_empty && !has_method {
        anyhow::bail!("provide at least one receive method");
    }

    if let Some(policy) = body.recovery_policy {
        policy.validate()?;
        wallet.recovery_policy = Some(policy);
    }

    for method in &body.remove_methods {
        match method.as_str() {
            "lightning" => wallet.lightning_address = None,
            "onchain" => {
                wallet.onchain_address = None;
                wallet.onchain_pubkey = None;
                wallet.silent_payment_address = None;
            }
            "silent_payment" => wallet.silent_payment_address = None,
            "ark" => {
                wallet.ark_server = None;
                wallet.ark_pubkey = None;
                wallet.ark_address = None;
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
    if let Some(sp) = body.silent_payment_address {
        if sp.trim() != sp {
            anyhow::bail!("Silent Payment address must not contain surrounding whitespace");
        }
        let net = match crate::types::bitcoin_network(network) {
            satspath_core::BitcoinNetwork::Mainnet => bitcoin::Network::Bitcoin,
            satspath_core::BitcoinNetwork::Regtest => bitcoin::Network::Regtest,
            _ => bitcoin::Network::Testnet,
        };
        satspath_handoff::silent(&sp, net).map_err(|e| anyhow::anyhow!(e))?;
        wallet.silent_payment_address = Some(sp);
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
            // Updating a legacy receiver cannot retain a stale contract address.
            wallet.ark_address = None;
        }
        (None, None) => {}
        _ => anyhow::bail!("ark_server and ark_pubkey must be provided together"),
    }
    match (body.ark_address, body.ark_asp_pubkey) {
        (Some(address), Some(asp_pubkey)) => {
            validate_compressed_pubkey(&asp_pubkey)?;
            let (_, operator, _) = satspath_router::ark_receive::decode_ark_address(&address)?;
            let expected = bitcoin::secp256k1::PublicKey::from_slice(&hex::decode(asp_pubkey)?)?
                .x_only_public_key()
                .0;
            if operator != expected {
                anyhow::bail!("Ark address operator does not match the pinned ASP key");
            }
            wallet.ark_address = Some(address);
            let method = build_methods(wallet, network)
                .into_iter()
                .find(|m| matches!(m, satspath_core::PaymentMethod::Ark { .. }))
                .ok_or_else(|| anyhow::anyhow!("Ark address requires server and output pubkey"))?;
            satspath_router::ark_receive::ark_receive_payload(&method, network, None)?;
        }
        (None, None) => {}
        _ => anyhow::bail!("ark_address and ark_asp_pubkey must be provided together"),
    }
    wallet.updated_at = Some(now());
    Ok(())
}

pub(crate) fn sign_and_store(
    home: &std::path::Path,
    wallet: &mut WalletState,
    network: &str,
) -> Result<()> {
    store_current_profile(home, wallet, network, false)
}

/// Attach public proof material only. Call under the router's mutation lock.
pub(crate) fn attach_method_proof(
    state: &AppState,
    body: crate::types::MethodProofRequest,
) -> Result<ProfileResponse> {
    use satspath_core::ownership::{ProofType, VerificationStatus};
    super::onboarding::recover_registration_wallet(state)?;
    let mut wallet = load_wallet(&state.home)?;
    wallet.alias = wallet
        .alias
        .as_deref()
        .map(satspath_core::privacy::canonical_identifier);
    if let Some(alias) = body.alias {
        let alias = satspath_core::privacy::canonical_identifier(&alias);
        if wallet.alias.as_deref() != Some(&alias) {
            wallet = super::onboarding::claimed_profile_wallet(state, &alias)?;
        }
    }
    let existing = stored_profile(state, &wallet)?
        .ok_or_else(|| anyhow::anyhow!("active profile is required"))?;
    if !verify_signed_profile(&existing)?
        || wallet.identity_pubkey.as_deref() != Some(&existing.profile.identity_pubkey)
    {
        anyhow::bail!("wallet identity or stored profile signature mismatch");
    }
    satspath_core::crypto::check_profile_expiry(&existing.profile)?;
    let verification = body.verification;
    satspath_core::validate_method_verification(&verification)?;
    let (issued, expiry) = match &verification.status {
        VerificationStatus::Verified {
            proof_type: ProofType::OnchainAddressSignature | ProofType::ArkPubkeySignature,
            verified_at,
            expires_at: Some(expiry),
            ..
        } => (*verified_at, *expiry),
        _ => {
            anyhow::bail!("an externally signed onchain/Ark proof with explicit expiry is required")
        }
    };
    let t = now();
    if issued > t || t.saturating_sub(issued) > 600 {
        anyhow::bail!("proof issuance must be within the last 600 seconds, not in the future");
    }
    if expiry <= t || expiry.saturating_sub(issued) > 30 * 24 * 3600 {
        anyhow::bail!("proof must be unexpired and valid for at most 30 days");
    }
    let method = existing
        .profile
        .methods
        .iter()
        .find(|method| method.ownership_descriptor() == verification.method_descriptor)
        .ok_or_else(|| anyhow::anyhow!("proof does not match a current payment method"))?;
    satspath_core::verify_method_verification(
        method,
        &existing.profile.identity_pubkey,
        &verification,
        t,
        None,
    )?;
    if existing.profile.method_verifications.iter().any(|old| {
        old.method_descriptor == verification.method_descriptor
            && matches!(&old.status, VerificationStatus::Verified { verified_at, .. } if *verified_at >= issued)
    }) {
        anyhow::bail!("proof replay or stale renewal: issuance must advance");
    }
    store_current_profile_with_proof(
        &state.home,
        &mut wallet,
        &state.network,
        false,
        Some(verification),
    )?;
    let signed_profile = stored_profile(state, &wallet)?;
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

fn store_current_profile(
    home: &std::path::Path,
    wallet: &mut WalletState,
    network: &str,
    revoke_if_empty: bool,
) -> Result<()> {
    store_current_profile_with_proof(home, wallet, network, revoke_if_empty, None)
}

fn store_current_profile_with_proof(
    home: &std::path::Path,
    wallet: &mut WalletState,
    network: &str,
    revoke_if_empty: bool,
    verification: Option<satspath_core::ownership::MethodVerification>,
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
    let revoked = methods.is_empty() && revoke_if_empty;
    if methods.is_empty() && !revoked {
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
    // Descriptors do not include every payment field. Preserve evidence only for
    // exactly unchanged methods under the same identity, never after revocation.
    let mut method_verifications = existing
        .as_ref()
        .filter(|old| {
            !old.profile.revoked && old.profile.identity_pubkey == identity_pubkey && !revoked
        })
        .map(|old| {
            old.profile
                .method_verifications
                .iter()
                .filter(|proof| {
                    methods.iter().any(|method| {
                        method.ownership_descriptor() == proof.method_descriptor
                            && old.profile.methods.contains(method)
                    })
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    if let Some(proof) = verification {
        satspath_core::upsert_method_verification(&mut method_verifications, proof);
    }
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
        method_verifications,
        hybrid_pubkey: None,
        pqc_required: false,
        revoked,
        recovery_policy: wallet.recovery_policy.clone().or_else(|| {
            existing
                .as_ref()
                .and_then(|old| old.profile.recovery_policy.clone())
        }),
        recovery: None,
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
        action: if revoked {
            NameAction::Revoke
        } else if history.is_empty() {
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
        recovery_policy: signed.profile.recovery_policy.clone(),
        recovery: signed.profile.recovery.clone(),
        owner_signature: String::new(),
    };
    let operator = load_or_create_transparency_operator(home)?;
    let operator_pubkey = hex::encode(
        secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &operator).serialize(),
    );
    // Preserve a current local domain grant only for the same identity. Owner
    // updates cannot extend its validity or confer authority on a replacement key.
    let existing_attestation = if !revoked {
        history
            .last()
            .and_then(|previous| previous.identifier_attestation_hash.as_deref())
            .map(|hash| store.identifier_attestation(hash))
            .transpose()?
            .flatten()
    } else {
        None
    };
    let attestation = eligible_attestation(
        existing_attestation,
        &signed.profile.identity_pubkey,
        &event.identifier_hash,
        history.last(),
        &operator_pubkey,
        t,
    )?;
    let attestation = if let Some(mut old) = attestation {
        old.profile_hash = event.profile_hash.clone();
        old.nonce = satspath_core::crypto::generate_nonce();
        old.issued_at = t;
        old.sign(&operator)?;
        event.identifier_attestation_hash = Some(old.attestation_hash()?);
        Some(old)
    } else {
        None
    };
    event.sign(&secret)?;
    let candidate = log.prepare_append(event.clone(), &signed)?;
    let checkpoint = candidate.prepare_checkpoint(&operator)?;
    if let Some(attestation) = attestation {
        store.commit_attested_profile(&signed, &event, &checkpoint, &attestation)?;
    } else {
        store.commit_profile_event_checkpoint(&alias, &signed, &event, &checkpoint)?;
    }
    Ok(())
}

pub(crate) fn eligible_attestation(
    attestation: Option<IdentifierAttestation>,
    expected_identity_pubkey: &str,
    expected_identifier_hash: &str,
    previous_event: Option<&NameEvent>,
    expected_operator_pubkey: &str,
    now: i64,
) -> Result<Option<IdentifierAttestation>> {
    let Some(attestation) = attestation else {
        return Ok(None);
    };

    if attestation.expires_at <= now {
        return Ok(None);
    }

    if attestation.identity_pubkey != expected_identity_pubkey {
        tracing::warn!(
            expected = expected_identity_pubkey,
            actual = %attestation.identity_pubkey,
            "existing grant rejected: identity public key mismatch"
        );
        return Ok(None);
    }

    if attestation.identifier_hash != expected_identifier_hash {
        tracing::warn!(
            expected = expected_identifier_hash,
            actual = %attestation.identifier_hash,
            "existing grant rejected: identifier hash mismatch"
        );
        return Ok(None);
    }

    let Some(previous) = previous_event else {
        tracing::warn!("existing grant rejected: missing previous transparency event");
        return Ok(None);
    };

    if previous.profile_hash != attestation.profile_hash {
        tracing::warn!(
            expected = %previous.profile_hash,
            actual = %attestation.profile_hash,
            "existing grant rejected: history profile hash mismatch"
        );
        return Ok(None);
    }

    let attestation_hash = match attestation.attestation_hash() {
        Ok(hash) => hash,
        Err(e) => {
            tracing::warn!("existing grant rejected: failed to compute attestation hash: {e}");
            return Ok(None);
        }
    };

    if previous.identifier_attestation_hash.as_deref() != Some(attestation_hash.as_str()) {
        tracing::warn!(
            expected = ?previous.identifier_attestation_hash,
            actual = %attestation_hash,
            "existing grant rejected: history attestation hash mismatch"
        );
        return Ok(None);
    }

    if attestation.method != satspath_core::IdentifierVerificationMethod::Domain {
        tracing::warn!(
            method = ?attestation.method,
            "existing grant rejected: verification method is not Domain"
        );
        return Ok(None);
    }

    if attestation.verifier_pubkey != expected_operator_pubkey {
        tracing::warn!(
            expected = expected_operator_pubkey,
            actual = %attestation.verifier_pubkey,
            "existing grant rejected: operator verifier pubkey mismatch"
        );
        return Ok(None);
    }

    match attestation.verify(now) {
        Ok(true) => Ok(Some(attestation)),
        Ok(false) => {
            tracing::warn!("existing grant rejected: invalid verifier signature");
            Ok(None)
        }
        Err(e) => {
            tracing::warn!("existing grant rejected: attestation verification error: {e}");
            Ok(None)
        }
    }
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
    let mut unsigned = satspath_core::rotate_identity_key(
        &existing,
        &old_secret,
        &new_key.secret_key,
        &previous_event_hash,
        sequence,
    )?;
    // Method challenges bind the previous identity; rotation cannot renew them.
    unsigned.profile.method_verifications.clear();
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
        recovery_policy: signed.profile.recovery_policy.clone(),
        recovery: signed.profile.recovery.clone(),
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

/// Body-only recovery request checks. These need no store access, so they run before
/// any O(log size) transparency replay on the unauthenticated recovery route.
pub(crate) fn validate_recovery_request_shape(body: &ProfileRecoverRequest) -> Result<()> {
    let signed = &body.signed_profile;
    if signed.profile.alias != body.alias {
        anyhow::bail!("signed profile alias mismatch");
    }
    if !verify_signed_profile(signed)? {
        anyhow::bail!("signed profile signature is invalid");
    }
    if signed.profile.recovery.as_ref() != Some(&body.proof) {
        anyhow::bail!("profile recovery object does not match submitted proof");
    }
    if signed.profile.rotation.is_some() {
        anyhow::bail!("recovery profile must not contain a key rotation");
    }
    if signed.profile.recovery_policy.is_none() {
        anyhow::bail!("recovered profile must carry a recovery_policy; policies cannot be removed");
    }
    satspath_core::validation::validate_public_profile(&signed.profile)?;
    Ok(())
}

pub(crate) fn recover_profile_key(
    state: &AppState,
    body: ProfileRecoverRequest,
) -> Result<KeyRecoveryResponse> {
    use satspath_core::crypto::fingerprint_pubkey;
    use satspath_core::recovery::verify_key_recovery;

    validate_recovery_request_shape(&body)?;

    let alias = body.alias;
    let proof = body.proof;
    let signed = body.signed_profile;

    let store = TransactionalTransparencyStore::open(&state.home)?;
    let existing = store
        .profile(&alias)?
        .ok_or_else(|| SatsPathError::AliasNotFound(alias.clone()))?;

    // Cryptographically verify the recovery proof against the identifier's committed policy
    if !verify_key_recovery(&existing, &signed)? {
        anyhow::bail!("recovery proof failed verification against existing profile/policy");
    }

    let log = store.load_log()?;
    let identifier_hash = satspath_core::privacy::identifier_hash(&alias);
    let history: Vec<_> = log.history(&identifier_hash).into_iter().cloned().collect();
    let sequence = satspath_core::next_identifier_sequence(Some(&existing), &history)?;

    if signed.profile.sequence != Some(sequence) || proof.sequence != sequence {
        anyhow::bail!("recovery sequence mismatch: expected {sequence}");
    }

    let previous_event = history
        .last()
        .ok_or_else(|| anyhow::anyhow!("recovery requires existing history"))?;
    let previous_event_hash = previous_event.signed_event_hash()?;

    if proof.previous_event_hash != previous_event_hash {
        anyhow::bail!("proof previous_event_hash mismatch");
    }

    let current_time = now();
    let created_at = if let Some(client_time) = body.event_created_at {
        if client_time.abs_diff(current_time) > 300 {
            anyhow::bail!("client event timestamp out of allowable window (+/- 300s)");
        }
        client_time
    } else {
        if body.event_signature.is_some() {
            anyhow::bail!("event_created_at is required when providing a remote event_signature");
        }
        current_time
    };

    let mut event = NameEvent {
        version: 1,
        identifier_hash,
        action: NameAction::RecoverKey,
        identity_pubkey: signed.profile.identity_pubkey.clone(),
        profile_hash: satspath_core::transparency::profile_hash(&signed)?,
        sequence,
        previous_event_hash: Some(previous_event_hash),
        created_at,
        identifier_attestation_hash: None,
        removed_method_hashes: Vec::new(),
        rotation: None,
        recovery_policy: signed.profile.recovery_policy.clone(),
        recovery: Some(proof.clone()),
        owner_signature: String::new(),
    };

    if let Ok(new_secret) = load_identity_key(&state.home, &signed.profile.identity_pubkey) {
        event.sign(&new_secret)?;
    } else if let Some(sig) = body.event_signature {
        event.owner_signature = sig;
    } else {
        anyhow::bail!(
            "event_signature is required when new identity private key is not present in local keystore"
        );
    }

    let candidate = log.prepare_append(event.clone(), &signed)?;
    let operator = load_or_create_transparency_operator(&state.home)?;
    let checkpoint = candidate.prepare_checkpoint(&operator)?;
    store.commit_profile_event_checkpoint(&alias, &signed, &event, &checkpoint)?;

    let mut wallet = load_wallet(&state.home)
        .map_err(|e| anyhow::anyhow!("recovery committed but wallet could not be loaded: {e}"))?;
    if wallet.alias.as_deref() == Some(&alias)
        && load_identity_key(&state.home, &signed.profile.identity_pubkey).is_ok()
    {
        wallet.identity_pubkey = Some(signed.profile.identity_pubkey.clone());
        wallet.recovery_policy = signed.profile.recovery_policy.clone();
        wallet.updated_at = Some(now());
        save_wallet(&state.home, &wallet)
            .map_err(|e| anyhow::anyhow!("recovery committed but wallet update failed: {e}"))?;
    }

    Ok(KeyRecoveryResponse {
        alias,
        sequence,
        previous_fingerprint: fingerprint_pubkey(&existing.profile.identity_pubkey)?,
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
    use satspath_core::{crypto::check_profile_expiry, privacy::identifier_hash, CheckpointStore};
    let alias = wallet
        .alias
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("profile alias is required"))?;
    // SQLite is the authoritative profile + event + checkpoint store. The
    // legacy registry.json is not written by sign_and_store and must not decide
    // whether broadcast needs to sign another profile.
    let store = TransactionalTransparencyStore::open(home)?;
    let existing = store.profile(alias)?;
    let log = store.load_log()?;
    let history: Vec<_> = log
        .history(&identifier_hash(alias))
        .into_iter()
        .cloned()
        .collect();
    if let Some(signed) = existing {
        if signed.profile.alias != alias || !verify_signed_profile(&signed)? {
            anyhow::bail!("stored profile alias or signature is invalid");
        }
        if signed.profile.revoked {
            anyhow::bail!("revoked profile cannot be broadcast");
        }
        // An expired profile may be renewed, but only after its signature,
        // history, checkpoint and wallet binding have been verified below.
        let expired = check_profile_expiry(&signed.profile).is_err();
        satspath_core::transparency::verify_identifier_history(&history)?;
        let latest = history
            .last()
            .ok_or_else(|| anyhow::anyhow!("profile has no transparency history"))?;
        if !satspath_core::transparency::verify_event_profile(latest, &signed)? {
            anyhow::bail!("profile does not match its latest transparency event");
        }
        let event_hash = latest.event_hash()?;
        let inclusion = log.inclusion(&event_hash, None)?;
        let checkpoint = log
            .checkpoints()
            .last()
            .ok_or_else(|| anyhow::anyhow!("transparency checkpoint unavailable"))?;
        satspath_core::transparency::verify_checkpoint_inclusion(
            &event_hash,
            &inclusion,
            checkpoint,
        )?;
        if let Some(pin) = CheckpointStore::new(home)
            .load()?
            .iter()
            .find(|pin| pin.log_id == checkpoint.log_id)
        {
            let consistency = (pin.tree_size < checkpoint.log_size)
                .then(|| log.consistency(pin.tree_size, checkpoint.log_size))
                .transpose()?;
            satspath_core::transparency::verify_checkpoint_transition(
                pin,
                checkpoint,
                consistency.as_ref(),
            )?;
        }
        if wallet.identity_pubkey.as_deref() != Some(&signed.profile.identity_pubkey) {
            anyhow::bail!(
                "wallet identity differs from the committed profile; use key rotation or recovery"
            );
        }
        let recovery_policy = wallet
            .recovery_policy
            .as_ref()
            .or(signed.profile.recovery_policy.as_ref());
        if !expired
            && signed.profile.methods == build_methods(wallet, network)
            && recovery_policy == signed.profile.recovery_policy.as_ref()
        {
            // In particular, do not renew nonce, expiry or sequence simply
            // because registry.json is absent (also after a daemon restart).
            return Ok(());
        }
    } else if !history.is_empty() {
        anyhow::bail!("alias has transparency history but no active profile");
    }
    sign_and_store(home, wallet, network)?;
    save_wallet(home, wallet)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use satspath_core::IdentifierVerificationMethod;

    fn test_keypair() -> (secp256k1::SecretKey, String) {
        let kp = generate_identity_keypair();
        (kp.secret_key, hex::encode(kp.public_key.serialize()))
    }

    fn sample_grant(
        operator_sec: &secp256k1::SecretKey,
        operator_pub: &str,
        identity_pub: &str,
        identifier_hash: &str,
        profile_hash: &str,
        issued_at: i64,
        expires_at: i64,
    ) -> IdentifierAttestation {
        let mut grant = IdentifierAttestation {
            version: 1,
            identifier_hash: identifier_hash.to_string(),
            identity_pubkey: identity_pub.to_string(),
            profile_hash: profile_hash.to_string(),
            nonce: satspath_core::crypto::generate_nonce(),
            issued_at,
            expires_at,
            method: IdentifierVerificationMethod::Domain,
            verifier_pubkey: operator_pub.to_string(),
            verifier_signature: String::new(),
        };
        grant.sign(operator_sec).unwrap();
        grant
    }

    fn sample_event(
        identifier_hash: &str,
        identity_pub: &str,
        profile_hash: &str,
        attestation_hash: Option<String>,
        created_at: i64,
    ) -> NameEvent {
        NameEvent {
            version: 1,
            identifier_hash: identifier_hash.to_string(),
            action: NameAction::Register,
            identity_pubkey: identity_pub.to_string(),
            profile_hash: profile_hash.to_string(),
            sequence: 1,
            previous_event_hash: None,
            created_at,
            identifier_attestation_hash: attestation_hash,
            removed_method_hashes: vec![],
            rotation: None,
            recovery_policy: None,
            recovery: None,
            owner_signature: String::new(),
        }
    }

    #[test]
    fn eligible_attestation_returns_none_for_none() {
        let (_, operator_pub) = test_keypair();
        let (_, identity_pub) = test_keypair();
        let res =
            eligible_attestation(None, &identity_pub, "hash", None, &operator_pub, 1000).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn eligible_attestation_accepts_valid_grant() {
        let (operator_sec, operator_pub) = test_keypair();
        let (_, identity_pub) = test_keypair();
        let identifier_hash = satspath_core::privacy::identifier_hash("alice@example.com");
        let profile_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let now = 1_700_000_000;
        let grant = sample_grant(
            &operator_sec,
            &operator_pub,
            &identity_pub,
            &identifier_hash,
            profile_hash,
            now - 60,
            now + 3600,
        );
        let attestation_hash = grant.attestation_hash().unwrap();
        let prev = sample_event(
            &identifier_hash,
            &identity_pub,
            profile_hash,
            Some(attestation_hash),
            now - 60,
        );

        let res = eligible_attestation(
            Some(grant.clone()),
            &identity_pub,
            &identifier_hash,
            Some(&prev),
            &operator_pub,
            now,
        )
        .unwrap();
        assert_eq!(res, Some(grant));
    }

    #[test]
    fn eligible_attestation_rejects_expired_grant() {
        let (operator_sec, operator_pub) = test_keypair();
        let (_, identity_pub) = test_keypair();
        let identifier_hash = satspath_core::privacy::identifier_hash("alice@example.com");
        let profile_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let now = 1_700_000_000;
        let grant = sample_grant(
            &operator_sec,
            &operator_pub,
            &identity_pub,
            &identifier_hash,
            profile_hash,
            now - 3600,
            now - 60,
        );
        let attestation_hash = grant.attestation_hash().unwrap();
        let prev = sample_event(
            &identifier_hash,
            &identity_pub,
            profile_hash,
            Some(attestation_hash),
            now - 3600,
        );

        let res = eligible_attestation(
            Some(grant),
            &identity_pub,
            &identifier_hash,
            Some(&prev),
            &operator_pub,
            now,
        )
        .unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn eligible_attestation_rejects_identity_mismatch() {
        let (operator_sec, operator_pub) = test_keypair();
        let (_, identity_pub) = test_keypair();
        let identifier_hash = satspath_core::privacy::identifier_hash("alice@example.com");
        let profile_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let now = 1_700_000_000;
        let grant = sample_grant(
            &operator_sec,
            &operator_pub,
            &identity_pub,
            &identifier_hash,
            profile_hash,
            now - 60,
            now + 3600,
        );
        let attestation_hash = grant.attestation_hash().unwrap();
        let prev = sample_event(
            &identifier_hash,
            &identity_pub,
            profile_hash,
            Some(attestation_hash),
            now - 60,
        );

        let res = eligible_attestation(
            Some(grant),
            "other_identity_pubkey",
            &identifier_hash,
            Some(&prev),
            &operator_pub,
            now,
        )
        .unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn eligible_attestation_rejects_identifier_mismatch() {
        let (operator_sec, operator_pub) = test_keypair();
        let (_, identity_pub) = test_keypair();
        let identifier_hash = satspath_core::privacy::identifier_hash("alice@example.com");
        let profile_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let now = 1_700_000_000;
        let grant = sample_grant(
            &operator_sec,
            &operator_pub,
            &identity_pub,
            &identifier_hash,
            profile_hash,
            now - 60,
            now + 3600,
        );
        let attestation_hash = grant.attestation_hash().unwrap();
        let prev = sample_event(
            &identifier_hash,
            &identity_pub,
            profile_hash,
            Some(attestation_hash),
            now - 60,
        );

        let res = eligible_attestation(
            Some(grant),
            &identity_pub,
            "different_identifier_hash",
            Some(&prev),
            &operator_pub,
            now,
        )
        .unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn eligible_attestation_rejects_missing_previous_event() {
        let (operator_sec, operator_pub) = test_keypair();
        let (_, identity_pub) = test_keypair();
        let identifier_hash = satspath_core::privacy::identifier_hash("alice@example.com");
        let profile_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let now = 1_700_000_000;
        let grant = sample_grant(
            &operator_sec,
            &operator_pub,
            &identity_pub,
            &identifier_hash,
            profile_hash,
            now - 60,
            now + 3600,
        );

        let res = eligible_attestation(
            Some(grant),
            &identity_pub,
            &identifier_hash,
            None,
            &operator_pub,
            now,
        )
        .unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn eligible_attestation_rejects_history_profile_hash_mismatch() {
        let (operator_sec, operator_pub) = test_keypair();
        let (_, identity_pub) = test_keypair();
        let identifier_hash = satspath_core::privacy::identifier_hash("alice@example.com");
        let profile_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let now = 1_700_000_000;
        let grant = sample_grant(
            &operator_sec,
            &operator_pub,
            &identity_pub,
            &identifier_hash,
            profile_hash,
            now - 60,
            now + 3600,
        );
        let attestation_hash = grant.attestation_hash().unwrap();
        let prev = sample_event(
            &identifier_hash,
            &identity_pub,
            "mismatched_profile_hash",
            Some(attestation_hash),
            now - 60,
        );

        let res = eligible_attestation(
            Some(grant),
            &identity_pub,
            &identifier_hash,
            Some(&prev),
            &operator_pub,
            now,
        )
        .unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn eligible_attestation_rejects_history_attestation_hash_mismatch() {
        let (operator_sec, operator_pub) = test_keypair();
        let (_, identity_pub) = test_keypair();
        let identifier_hash = satspath_core::privacy::identifier_hash("alice@example.com");
        let profile_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let now = 1_700_000_000;
        let grant = sample_grant(
            &operator_sec,
            &operator_pub,
            &identity_pub,
            &identifier_hash,
            profile_hash,
            now - 60,
            now + 3600,
        );
        let prev = sample_event(
            &identifier_hash,
            &identity_pub,
            profile_hash,
            Some("mismatched_attestation_hash".to_string()),
            now - 60,
        );

        let res = eligible_attestation(
            Some(grant),
            &identity_pub,
            &identifier_hash,
            Some(&prev),
            &operator_pub,
            now,
        )
        .unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn eligible_attestation_rejects_non_domain_method() {
        let (operator_sec, operator_pub) = test_keypair();
        let (_, identity_pub) = test_keypair();
        let identifier_hash = satspath_core::privacy::identifier_hash("alice@example.com");
        let profile_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let now = 1_700_000_000;
        let mut grant = sample_grant(
            &operator_sec,
            &operator_pub,
            &identity_pub,
            &identifier_hash,
            profile_hash,
            now - 60,
            now + 3600,
        );
        grant.method = IdentifierVerificationMethod::Email;
        grant.sign(&operator_sec).unwrap();

        let attestation_hash = grant.attestation_hash().unwrap();
        let prev = sample_event(
            &identifier_hash,
            &identity_pub,
            profile_hash,
            Some(attestation_hash),
            now - 60,
        );

        let res = eligible_attestation(
            Some(grant),
            &identity_pub,
            &identifier_hash,
            Some(&prev),
            &operator_pub,
            now,
        )
        .unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn eligible_attestation_rejects_operator_key_mismatch() {
        let (operator_sec, operator_pub) = test_keypair();
        let (_, identity_pub) = test_keypair();
        let identifier_hash = satspath_core::privacy::identifier_hash("alice@example.com");
        let profile_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let now = 1_700_000_000;
        let grant = sample_grant(
            &operator_sec,
            &operator_pub,
            &identity_pub,
            &identifier_hash,
            profile_hash,
            now - 60,
            now + 3600,
        );
        let attestation_hash = grant.attestation_hash().unwrap();
        let prev = sample_event(
            &identifier_hash,
            &identity_pub,
            profile_hash,
            Some(attestation_hash),
            now - 60,
        );

        let res = eligible_attestation(
            Some(grant),
            &identity_pub,
            &identifier_hash,
            Some(&prev),
            "other_operator_pubkey",
            now,
        )
        .unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn eligible_attestation_rejects_invalid_signature() {
        let (operator_sec, operator_pub) = test_keypair();
        let (_, identity_pub) = test_keypair();
        let identifier_hash = satspath_core::privacy::identifier_hash("alice@example.com");
        let profile_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let now = 1_700_000_000;
        let mut grant = sample_grant(
            &operator_sec,
            &operator_pub,
            &identity_pub,
            &identifier_hash,
            profile_hash,
            now - 60,
            now + 3600,
        );
        grant.verifier_signature = "00".repeat(64);

        let attestation_hash = grant.attestation_hash().unwrap();
        let prev = sample_event(
            &identifier_hash,
            &identity_pub,
            profile_hash,
            Some(attestation_hash),
            now - 60,
        );

        let res = eligible_attestation(
            Some(grant),
            &identity_pub,
            &identifier_hash,
            Some(&prev),
            &operator_pub,
            now,
        )
        .unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn eligible_attestation_rejects_verification_error() {
        let (operator_sec, operator_pub) = test_keypair();
        let (_, identity_pub) = test_keypair();
        let identifier_hash = satspath_core::privacy::identifier_hash("alice@example.com");
        let profile_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let now = 1_700_000_000;
        let mut grant = sample_grant(
            &operator_sec,
            &operator_pub,
            &identity_pub,
            &identifier_hash,
            profile_hash,
            now - 60,
            now + 3600,
        );
        // An invalid nonce length (< 32 chars) triggers TransparencyError::InvalidAttestation
        grant.nonce = "too_short".to_string();
        grant.sign(&operator_sec).unwrap();

        let attestation_hash = grant.attestation_hash().unwrap();
        let prev = sample_event(
            &identifier_hash,
            &identity_pub,
            profile_hash,
            Some(attestation_hash),
            now - 60,
        );

        let res = eligible_attestation(
            Some(grant),
            &identity_pub,
            &identifier_hash,
            Some(&prev),
            &operator_pub,
            now,
        )
        .unwrap();
        assert!(res.is_none());
    }

    fn setup_pending_registration_wallet(
        home: &std::path::Path,
        alias: &str,
    ) -> (AppState, WalletState, WalletState) {
        setup_pending_registration_wallet_with_address(home, alias, "bcrt1qtest")
    }

    fn setup_pending_registration_wallet_with_address(
        home: &std::path::Path,
        alias: &str,
        onchain_address: &str,
    ) -> (AppState, WalletState, WalletState) {
        let store = TransactionalTransparencyStore::open(home).unwrap();
        let predecessor = load_or_create_identity(home).unwrap();
        save_wallet(home, &predecessor).unwrap();

        let secret =
            load_identity_key(home, predecessor.identity_pubkey.as_deref().unwrap()).unwrap();
        let mut successor = predecessor.clone();
        successor.alias = Some(alias.to_string());
        successor.onchain_address = Some(onchain_address.to_string());

        let signed = sign_profile(
            PaymentProfile {
                sequence: Some(0),
                alias: alias.to_string(),
                identity_pubkey: successor.identity_pubkey.clone().unwrap(),
                methods: build_methods(&successor, "devnet"),
                updated_at: 1_700_000_000,
                expires_at: Some(1_800_000_000),
                preferences: vec!["onchain".into()],
                nonce: Some("12345678901234567890123456789012".to_string()),
                rotation: None,
                method_verifications: vec![],
                hybrid_pubkey: None,
                pqc_required: false,
                revoked: false,
                recovery_policy: None,
                recovery: None,
            },
            &secret,
        )
        .unwrap();

        let operator = load_or_create_transparency_operator(home).unwrap();
        let mut event = NameEvent {
            version: 1,
            identifier_hash: satspath_core::privacy::identifier_hash(alias),
            action: NameAction::Register,
            identity_pubkey: successor.identity_pubkey.clone().unwrap(),
            profile_hash: satspath_core::transparency::profile_hash(&signed).unwrap(),
            sequence: 0,
            previous_event_hash: None,
            created_at: 1_700_000_000,
            identifier_attestation_hash: None,
            removed_method_hashes: vec![],
            rotation: None,
            recovery_policy: None,
            recovery: None,
            owner_signature: String::new(),
        };
        event.sign(&secret).unwrap();
        let log = store.load_log().unwrap();
        let candidate = log.prepare_append(event.clone(), &signed).unwrap();
        let checkpoint = candidate.prepare_checkpoint(&operator).unwrap();
        store
            .commit_profile_event_checkpoint(alias, &signed, &event, &checkpoint)
            .unwrap();

        let wallet_json = serde_json::to_string(&successor).unwrap();
        let profile_json = serde_json::to_string(&signed).unwrap();
        let predecessor_json = serde_json::to_string(&predecessor).unwrap();

        let db = rusqlite::Connection::open(home.join("satspath-transparency-v1.sqlite3")).unwrap();
        db.execute(
            "INSERT INTO registration_wallet(id,wallet_json,profile_json,predecessor_json) VALUES (1,?1,?2,?3)",
            rusqlite::params![wallet_json, profile_json, predecessor_json],
        )
        .unwrap();

        let state = AppState {
            alias_test_client: None,
            p2p: crate::p2p::Bridge::new(false),
            home: home.to_path_buf(),
            bind: "127.0.0.1:0".parse().unwrap(),
            allowed_hosts: vec![],
            network: "devnet".to_string(),
            open_ui: false,
            auth_token: "test".to_string(),
            allow_mock_alias_verification: true,
            mutation_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            anchor_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            rate_limiter: std::sync::Arc::new(crate::rate_limit::RateLimiter::new(
                crate::rate_limit::RateLimiterConfig::default(),
            )),
            is_tls: false,
        };

        (state, predecessor, successor)
    }

    #[test]
    fn update_profile_recovers_registration_wallet_before_editing() {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, successor) =
            setup_pending_registration_wallet(dir.path(), "alice@example.com");

        let store = TransactionalTransparencyStore::open(dir.path()).unwrap();
        assert!(store.registration_wallet().unwrap().is_some());

        let req = ProfileUpdateRequest {
            alias: Some("alice@example.com".to_string()),
            lightning_address: Some("alice@example.com".to_string()),
            onchain_address: None,
            onchain_pubkey: None,
            silent_payment_address: None,
            ark_address: None,
            ark_server: None,
            ark_pubkey: None,
            ark_asp_pubkey: None,
            remove_methods: vec![],
            recovery_policy: None,
        };

        let resp = update_profile(&state, req).unwrap();
        assert_eq!(resp.wallet.alias.as_deref(), Some("alice@example.com"));
        assert_eq!(
            resp.wallet.lightning_address.as_deref(),
            Some("alice@example.com")
        );
        assert_eq!(resp.wallet.onchain_address, successor.onchain_address);
        assert!(store.registration_wallet().unwrap().is_none());
    }

    #[test]
    fn update_profile_methods_recovers_registration_wallet_before_editing() {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, successor) =
            setup_pending_registration_wallet(dir.path(), "alice@example.com");

        let store = TransactionalTransparencyStore::open(dir.path()).unwrap();
        assert!(store.registration_wallet().unwrap().is_some());

        let req = ProfileUpdateRequest {
            alias: None,
            lightning_address: Some("alice@example.com".to_string()),
            onchain_address: None,
            onchain_pubkey: None,
            silent_payment_address: None,
            ark_address: None,
            ark_server: None,
            ark_pubkey: None,
            ark_asp_pubkey: None,
            remove_methods: vec![],
            recovery_policy: None,
        };

        let resp = update_profile_methods(&state, req).unwrap();
        assert_eq!(resp.wallet.alias.as_deref(), Some("alice@example.com"));
        assert_eq!(
            resp.wallet.lightning_address.as_deref(),
            Some("alice@example.com")
        );
        assert_eq!(resp.wallet.onchain_address, successor.onchain_address);
        assert!(store.registration_wallet().unwrap().is_none());
    }

    #[test]
    fn verify_challenge_recovers_registration_wallet_before_editing() {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, successor) =
            setup_pending_registration_wallet(dir.path(), "alice@example.com");

        let store = TransactionalTransparencyStore::open(dir.path()).unwrap();
        assert!(store.registration_wallet().unwrap().is_some());

        let req = VerifyRequest {
            alias: "bob@example.com".to_string(),
            token: "bob@example.com".to_string(),
        };

        let resp = verify_challenge(&state, req).unwrap();
        assert_eq!(resp.wallet.alias.as_deref(), Some("bob@example.com"));
        assert_eq!(resp.wallet.onchain_address, successor.onchain_address);
        let signed = resp
            .signed_profile
            .as_ref()
            .expect("signed profile must be present");
        assert_eq!(signed.profile.alias, "bob@example.com");
        assert!(store.registration_wallet().unwrap().is_none());
    }

    #[test]
    fn attach_method_proof_recovers_registration_wallet_before_editing() {
        use crate::types::MethodProofRequest;
        use satspath_core::ownership::{build_signature_attestation, ProofType};

        let dir = tempfile::tempdir().unwrap();
        let spending = generate_identity_keypair();
        let pk =
            bitcoin::CompressedPublicKey::from_slice(&spending.public_key.serialize()).unwrap();
        let onchain_address = bitcoin::Address::p2wpkh(&pk, bitcoin::Network::Testnet).to_string();

        let (state, _, successor) = setup_pending_registration_wallet_with_address(
            dir.path(),
            "alice@example.com",
            &onchain_address,
        );

        let store = TransactionalTransparencyStore::open(dir.path()).unwrap();
        assert!(store.registration_wallet().unwrap().is_some());

        let method = build_methods(&successor, "devnet")
            .into_iter()
            .find(|m| matches!(m, satspath_core::PaymentMethod::Onchain { .. }))
            .unwrap();
        let issued = now() - 10;
        let proof = build_signature_attestation(
            &method,
            successor.identity_pubkey.as_deref().unwrap(),
            ProofType::OnchainAddressSignature,
            &spending.secret_key,
            issued,
            Some(issued + 3600),
        )
        .unwrap();

        let resp = attach_method_proof(
            &state,
            MethodProofRequest {
                alias: Some("alice@example.com".to_string()),
                verification: proof,
            },
        )
        .unwrap();

        assert_eq!(resp.wallet.alias.as_deref(), Some("alice@example.com"));
        assert_eq!(resp.wallet.onchain_address, successor.onchain_address);
        assert!(store.registration_wallet().unwrap().is_none());
        let signed = resp
            .signed_profile
            .as_ref()
            .expect("signed profile must be present");
        assert_eq!(signed.profile.alias, "alice@example.com");
        assert_eq!(signed.profile.method_verifications.len(), 1);
    }
}
