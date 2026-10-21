//! Integration tests for resolver disagreement, downgrade refusal, and durable TOFU continuity.

use async_trait::async_trait;
use satspath_core::crypto::{sign_profile, verify_signed_profile};
use satspath_core::resolver::{ChainResolver, ProfileResolver, ResolverRole};
use satspath_core::{
    BitcoinNetwork, KeyRotation, PaymentMethod, PaymentProfile, SatsPathError, SignedPaymentProfile,
};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

/// Deterministic test resolver returning a preconfigured profile or error.
struct StaticResolver(satspath_core::Result<SignedPaymentProfile>);

#[async_trait]
impl ProfileResolver for StaticResolver {
    /// Returns the static profile result configured for this test source.
    async fn resolve_alias(&self, _: &str) -> satspath_core::Result<SignedPaymentProfile> {
        match &self.0 {
            Ok(profile) => Ok(profile.clone()),
            Err(SatsPathError::AliasNotFound(message)) => {
                Err(SatsPathError::AliasNotFound(message.clone()))
            }
            Err(SatsPathError::NetworkError(message)) => {
                Err(SatsPathError::NetworkError(message.clone()))
            }
            Err(error) => panic!("unsupported test error: {error}"),
        }
    }
}

/// Builds and signs a test [`SignedPaymentProfile`] for `alice@example.com`.
fn signed_profile(key: &SecretKey, sequence: u64, address: &str) -> SignedPaymentProfile {
    let pubkey = PublicKey::from_secret_key(&Secp256k1::new(), key);
    sign_profile(
        PaymentProfile {
            alias: "alice@example.com".into(),
            identity_pubkey: pubkey.to_string(),
            methods: vec![PaymentMethod::Onchain {
                label: "bitcoin".into(),
                network: BitcoinNetwork::Testnet,
                address: Some(address.into()),
                silent_payment_pubkey: None,
                pubkey_hint: None,
                descriptor_hint: None,
                address_list: vec![],
            }],
            updated_at: 1_700_000_000,
            expires_at: None,
            sequence: Some(sequence),
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
        key,
    )
    .unwrap()
}

/// Verifies that matching resolver sources produce a deterministic observation report and valid signature.
#[tokio::test]
async fn matching_sources_return_deterministic_report_and_signed_profile() {
    let signed = signed_profile(&SecretKey::from_slice(&[1; 32]).unwrap(), 7, "tb1qexample");
    let build_resolver = || {
        let dir = tempfile::tempdir().unwrap();
        let resolver = ChainResolver::with_continuity_dir(dir.path())
            .push_authoritative("https", StaticResolver(Ok(signed.clone())))
            .push_supplementary("nostr", StaticResolver(Ok(signed.clone())))
            .with_continuity_pin(signed.profile.identity_pubkey.clone(), 7);
        (dir, resolver)
    };
    let (_dir1, first_resolver) = build_resolver();
    let (_dir2, second_resolver) = build_resolver();
    let first = first_resolver
        .resolve_with_report("alice@example.com")
        .await
        .unwrap();
    let second = second_resolver
        .resolve_with_report("alice@example.com")
        .await
        .unwrap();
    assert!(verify_signed_profile(&first.profile).unwrap());
    assert_eq!(first.observations, second.observations);
    assert_eq!(first.observations[0].role, ResolverRole::Authoritative);
    assert_eq!(first.observations[1].source, "nostr");
    assert!(first
        .observations
        .iter()
        .all(|observation| observation.found));
}

/// Verifies that repeating resolution of an unchanged sequenced profile on one shared
/// continuity directory and resolver succeeds and returns identical observations.
#[tokio::test]
async fn repeat_resolution_with_shared_continuity_dir_succeeds_for_unchanged_sequenced_profile() {
    let signed = signed_profile(&SecretKey::from_slice(&[1; 32]).unwrap(), 7, "tb1qexample");
    let dir = tempfile::tempdir().unwrap();
    let resolver = ChainResolver::with_continuity_dir(dir.path())
        .push_authoritative("https", StaticResolver(Ok(signed.clone())))
        .push_supplementary("nostr", StaticResolver(Ok(signed.clone())))
        .with_continuity_pin(signed.profile.identity_pubkey.clone(), 7);

    let first = resolver
        .resolve_with_report("alice@example.com")
        .await
        .unwrap();
    let second = resolver
        .resolve_with_report("alice@example.com")
        .await
        .unwrap();
    assert!(verify_signed_profile(&first.profile).unwrap());
    assert!(verify_signed_profile(&second.profile).unwrap());
    assert_eq!(first.observations, second.observations);
}

/// Verifies that conflicting or forged profiles across resolver sources fail closed.
#[tokio::test]
async fn conflict_vectors_fail_closed() {
    let key = SecretKey::from_slice(&[1; 32]).unwrap();
    let other = SecretKey::from_slice(&[2; 32]).unwrap();
    let base = signed_profile(&key, 7, "tb1qexample");
    let cases = [
        (signed_profile(&other, 7, "tb1qexample"), "disagrees"),
        (signed_profile(&key, 6, "tb1qexample"), "disagrees"),
        (signed_profile(&key, 7, "tb1qother"), "disagrees"),
    ];
    for (conflict, message) in cases {
        let dir = tempfile::tempdir().unwrap();
        let resolver = ChainResolver::with_continuity_dir(dir.path())
            .push_authoritative("https", StaticResolver(Ok(base.clone())))
            .push_supplementary("nostr", StaticResolver(Ok(conflict)));
        assert!(resolver
            .resolve_alias("alice@example.com")
            .await
            .unwrap_err()
            .to_string()
            .contains(message));
    }
    let mut invalid = base.clone();
    invalid.profile.methods.clear();
    let dir = tempfile::tempdir().unwrap();
    let resolver = ChainResolver::with_continuity_dir(dir.path())
        .push_authoritative("https", StaticResolver(Ok(invalid)));
    assert!(matches!(
        resolver.resolve_alias("alice@example.com").await,
        Err(SatsPathError::InvalidSignature)
    ));

    let mut forged_revocation = base.clone();
    forged_revocation.profile.revoked = true;
    let dir = tempfile::tempdir().unwrap();
    let resolver = ChainResolver::with_continuity_dir(dir.path())
        .push_authoritative("https", StaticResolver(Ok(forged_revocation)));
    assert!(matches!(
        resolver.resolve_alias("alice@example.com").await,
        Err(SatsPathError::InvalidSignature)
    ));

    let mut forged_expiry = base.clone();
    forged_expiry.profile.expires_at = Some(1);
    let dir = tempfile::tempdir().unwrap();
    let resolver = ChainResolver::with_continuity_dir(dir.path())
        .push_authoritative("https", StaticResolver(Ok(forged_expiry)));
    assert!(matches!(
        resolver.resolve_alias("alice@example.com").await,
        Err(SatsPathError::InvalidSignature)
    ));

    let mut expired = base.clone().profile;
    expired.expires_at = Some(1);
    let dir = tempfile::tempdir().unwrap();
    let resolver = ChainResolver::with_continuity_dir(dir.path()).push_authoritative(
        "https",
        StaticResolver(Ok(sign_profile(expired, &key).unwrap())),
    );
    assert!(resolver.resolve_alias("alice@example.com").await.is_err());
}

/// Verifies that source outages and explicit continuity pins refuse silent downgrades.
#[tokio::test]
async fn outages_and_pins_never_trigger_downgrade() {
    let key = SecretKey::from_slice(&[1; 32]).unwrap();
    let base = signed_profile(&key, 7, "tb1qexample");
    let unavailable = || StaticResolver(Err(SatsPathError::NetworkError("blocked".into())));
    let dir = tempfile::tempdir().unwrap();
    let resolver = ChainResolver::with_continuity_dir(dir.path())
        .push_authoritative("https", unavailable())
        .push_supplementary("nostr", StaticResolver(Ok(base.clone())));
    assert!(resolver
        .resolve_alias("alice@example.com")
        .await
        .unwrap_err()
        .to_string()
        .contains("refusing downgrade"));
    let dir = tempfile::tempdir().unwrap();
    let resolver = ChainResolver::with_continuity_dir(dir.path())
        .push_authoritative("https", StaticResolver(Ok(base.clone())))
        .push_supplementary("nostr", unavailable());
    assert!(resolver.resolve_alias("alice@example.com").await.is_err());
    let dir = tempfile::tempdir().unwrap();
    let resolver = ChainResolver::with_continuity_dir(dir.path())
        .push_supplementary("nostr", StaticResolver(Ok(base.clone())));
    assert!(resolver.resolve_alias("alice@example.com").await.is_err());
    let dir = tempfile::tempdir().unwrap();
    let resolver = ChainResolver::with_continuity_dir(dir.path())
        .push_authoritative("https", StaticResolver(Ok(base.clone())))
        .with_continuity_pin(base.profile.identity_pubkey.clone(), 8);
    assert!(resolver
        .resolve_alias("alice@example.com")
        .await
        .unwrap_err()
        .to_string()
        .contains("stale"));
    let dir = tempfile::tempdir().unwrap();
    let resolver = ChainResolver::with_continuity_dir(dir.path())
        .push_authoritative("https", StaticResolver(Ok(base.clone())))
        .with_continuity_pin("different-key".into(), 7);
    assert!(matches!(
        resolver.resolve_alias("alice@example.com").await,
        Err(SatsPathError::UnauthorizedKeyReplacement)
    ));
    let dir = tempfile::tempdir().unwrap();
    let resolver = ChainResolver::with_continuity_dir(dir.path())
        .push_authoritative("https", StaticResolver(Ok(base.clone())))
        .with_required_capabilities(vec!["onchain:testnet:tb1qprevious".into()]);
    assert!(resolver
        .resolve_alias("alice@example.com")
        .await
        .unwrap_err()
        .to_string()
        .contains("suppressed"));
    let dir = tempfile::tempdir().unwrap();
    let resolver = ChainResolver::with_continuity_dir(dir.path())
        .push_authoritative(
            "https",
            StaticResolver(Err(SatsPathError::AliasNotFound(
                "alice@example.com".into(),
            ))),
        )
        .push_authoritative("bip353", StaticResolver(Ok(base)));
    assert!(resolver.resolve_alias("alice@example.com").await.is_ok());
}

/// Verifies that TOFU continuity persists across `ChainResolver` restarts and enforces key
/// rotation, sequence monotonicity, same-sequence immutability, and revocation tombstones.
#[tokio::test]
async fn durable_continuity_enforces_rotation_sequence_and_revocation_across_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let key1 = SecretKey::from_slice(&[1; 32]).unwrap();
    let key2 = SecretKey::from_slice(&[2; 32]).unwrap();
    let v1 = signed_profile(&key1, 4, "tb1qinitial");

    // 1. First resolution pins identity key and sequence 4 on disk.
    let resolver = ChainResolver::with_continuity_dir(dir.path())
        .push_authoritative("https", StaticResolver(Ok(v1.clone())));
    assert!(resolver.resolve_alias("₿alice@example.com").await.is_ok());

    // 2. Fresh resolver after restart rejects same-sequence mutation with different payload.
    let mutated_same_seq = signed_profile(&key1, 4, "tb1qmutated");
    let resolver = ChainResolver::with_continuity_dir(dir.path())
        .push_authoritative("https", StaticResolver(Ok(mutated_same_seq)));
    assert!(matches!(
        resolver.resolve_alias("alice@example.com").await,
        Err(SatsPathError::RegistryError(msg)) if msg.contains("sequence number 4 not greater than existing 4")
    ));

    // 3. Fresh resolver rejects sequence rollback (3 < 4).
    let rollback = signed_profile(&key1, 3, "tb1qinitial");
    let resolver = ChainResolver::with_continuity_dir(dir.path())
        .push_authoritative("https", StaticResolver(Ok(rollback)));
    assert!(matches!(
        resolver.resolve_alias("alice@example.com").await,
        Err(SatsPathError::RegistryError(msg)) if msg.contains("sequence number 3 not greater than existing 4")
    ));

    // 4. Fresh resolver rejects unauthorized key replacement.
    let unauthorized = signed_profile(&key2, 5, "tb1qattacker");
    let resolver = ChainResolver::with_continuity_dir(dir.path())
        .push_authoritative("https", StaticResolver(Ok(unauthorized)));
    assert!(matches!(
        resolver.resolve_alias("alice@example.com").await,
        Err(SatsPathError::UnauthorizedKeyReplacement)
    ));

    // 5. Authorized key rotation with valid dual proof advances the pin to key2 at sequence 5.
    let pubkey2 = PublicKey::from_secret_key(&Secp256k1::new(), &key2).to_string();
    let mut rotated_profile = signed_profile(&key2, 5, "tb1qrotated").profile;
    rotated_profile.rotation = Some(
        KeyRotation::create(
            satspath_core::identifier_hash("alice@example.com"),
            v1.profile.identity_pubkey.clone(),
            &key1,
            pubkey2,
            &key2,
            "prev-event".into(),
            5,
        )
        .unwrap(),
    );
    let rotated_signed = sign_profile(rotated_profile, &key2).unwrap();
    let resolver = ChainResolver::with_continuity_dir(dir.path())
        .push_authoritative("https", StaticResolver(Ok(rotated_signed)));
    assert!(resolver.resolve_alias("alice@example.com").await.is_ok());

    // 6. Authenticated revocation on primary source halts immediately before stale fallback
    // and persists a permanent tombstone across resolver restarts.
    let mut revoked_profile = signed_profile(&key2, 6, "tb1qrotated").profile;
    revoked_profile.revoked = true;
    let revoked_signed = sign_profile(revoked_profile, &key2).unwrap();
    let stale_fallback = signed_profile(&key2, 5, "tb1qrotated");
    let resolver = ChainResolver::with_continuity_dir(dir.path())
        .push_authoritative("https", StaticResolver(Ok(revoked_signed)))
        .push_supplementary("nostr", StaticResolver(Ok(stale_fallback.clone())));
    assert!(matches!(
        resolver.resolve_alias("alice@example.com").await,
        Err(SatsPathError::RegistryError(msg)) if msg.contains("revoked")
    ));

    // 7. Subsequent resolution with a fresh resolver rejects even an unrevoked higher-sequence
    // profile because the revocation tombstone is persisted in SQLite.
    let post_revocation = signed_profile(&key2, 7, "tb1qresurrected");
    let resolver = ChainResolver::with_continuity_dir(dir.path())
        .push_authoritative("https", StaticResolver(Ok(post_revocation)));
    assert!(matches!(
        resolver.resolve_alias("₿alice@example.com").await,
        Err(SatsPathError::RegistryError(msg)) if msg.contains("revoked")
    ));
}
