use async_trait::async_trait;

use crate::crypto::{canonical_profile_bytes, check_profile_expiry, verify_signed_profile};
use crate::privacy::canonical_identifier;
use crate::{Result, SatsPathError, SignedPaymentProfile};
use serde::{Deserialize, Serialize};

use crate::transparency::{
    IdentifierAttestation, MerkleConsistencyProof, MerkleInclusionProof, NameEvent,
    TransparencyCheckpoint,
};
use crate::{MethodTrust, TrustTier};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResolverSource {
    LocalRegistry,
    Http,
    Bip353,
    Nostr,
    P2p,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationStates {
    pub profile_signature_verified: bool,
    pub identifier_verified: bool,
    pub key_continuity_verified: bool,
    pub transparency_inclusion_verified: bool,
    pub checkpoint_binding_verified: bool,
    pub checkpoint_consistency_verified: bool,
    pub operator_continuity_verified: bool,
    pub payment_methods_verified: bool,
    pub payment_method_states: Vec<PaymentMethodVerificationState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMethodVerificationState {
    pub descriptor: String,
    pub verified: bool,
    pub trust_tier: Option<TrustTier>,
    pub reason: String,
}

/// Evaluate ownership verification states for every payment method in `profile` at `now`.
pub fn verify_payment_method_states(
    profile: &crate::PaymentProfile,
    now: i64,
) -> Vec<PaymentMethodVerificationState> {
    profile
        .methods
        .iter()
        .map(|method| {
            let descriptor = method.ownership_descriptor();
            let matches = profile
                .method_verifications
                .iter()
                .filter(|proof| proof.method_descriptor == descriptor)
                .count();
            if matches > 1 {
                return PaymentMethodVerificationState {
                    descriptor,
                    verified: false,
                    trust_tier: None,
                    reason: "duplicate ownership proofs".into(),
                };
            }
            match crate::evaluate_method_trust_for_profile(profile, method, now, None) {
                MethodTrust::Verified(tier) => PaymentMethodVerificationState {
                    descriptor,
                    verified: true,
                    trust_tier: Some(tier),
                    reason: format!("valid {} ownership proof", tier.label()),
                },
                MethodTrust::SelfAsserted => PaymentMethodVerificationState {
                    descriptor,
                    verified: false,
                    trust_tier: Some(TrustTier::SelfAsserted),
                    reason: "self-attestation is not independent ownership proof".into(),
                },
                MethodTrust::NeedsNetworkCheck(tier) => PaymentMethodVerificationState {
                    descriptor,
                    verified: false,
                    trust_tier: Some(tier),
                    reason: "domain proof requires fresh network verification".into(),
                },
                MethodTrust::Unverified => PaymentMethodVerificationState {
                    descriptor,
                    verified: false,
                    trust_tier: None,
                    reason: "ownership proof missing or bound to another descriptor".into(),
                },
                MethodTrust::Expired => PaymentMethodVerificationState {
                    descriptor,
                    verified: false,
                    trust_tier: None,
                    reason: "ownership proof expired".into(),
                },
                MethodTrust::Invalid(reason) => PaymentMethodVerificationState {
                    descriptor,
                    verified: false,
                    trust_tier: None,
                    reason,
                },
            }
        })
        .collect()
}

/// A resolved profile bundled with its transparency log event, proofs, and verification state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedTransparentProfile {
    pub signed_profile: SignedPaymentProfile,
    pub latest_event: NameEvent,
    pub inclusion_proof: MerkleInclusionProof,
    pub checkpoint: TransparencyCheckpoint,
    pub consistency_proof: Option<MerkleConsistencyProof>,
    pub identifier_attestation: Option<IdentifierAttestation>,
    pub resolver_source: ResolverSource,
    pub verification: VerificationStates,
}

/// A resolver capable of resolving a SatsPath alias to a `SignedPaymentProfile`.
///
/// Implementations could be local (e.g. `LocalRegistryResolver`) or remote
/// (e.g. `HttpResolver` for NIP-05 style public resolution).
#[async_trait]
pub trait ProfileResolver {
    /// Attempt to resolve the alias to a signed profile.
    ///
    /// # Returns
    /// - `Ok(SignedPaymentProfile)` if the alias is found.
    /// - `Err(SatsPathError::AliasNotFound)` if the alias is explicitly not found.
    /// - `Err(SatsPathError::NetworkError)` (or similar) on fetch failure.
    async fn resolve_alias(&self, alias: &str) -> Result<SignedPaymentProfile>;

    /// Resolve `alias` as a member of a [`ChainResolver`] that commits continuity
    /// atomically after all configured sources have been validated.
    async fn resolve_for_chain(&self, alias: &str) -> Result<SignedPaymentProfile> {
        self.resolve_alias(alias).await
    }

    /// Return the continuity storage directory configured on this resolver, if any.
    fn continuity_dir(&self) -> Option<&std::path::Path> {
        None
    }
}

/// Whether a source is eligible to establish the alias or only corroborate it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolverRole {
    Authoritative,
    Supplementary,
}

/// Per-source outcome recorded by [`ChainResolver::resolve_with_report`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolverObservation {
    pub source: String,
    pub role: ResolverRole,
    pub found: bool,
}

/// Report returned alongside an agreed, signed profile. A rejection returns
/// `ResolverDisagreement` or the original error, never a payable candidate.
#[derive(Debug, Clone)]
pub struct ResolutionReport {
    pub profile: SignedPaymentProfile,
    pub observations: Vec<ResolverObservation>,
}

struct ResolverEntry {
    source: String,
    role: ResolverRole,
    resolver: Box<dyn ProfileResolver + Send + Sync>,
}

/// Construct an isolated default continuity directory when none is supplied.
fn default_chain_continuity_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("SATSPATH_DIR") {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            return std::path::PathBuf::from(trimmed);
        }
    }
    std::env::temp_dir().join(format!("satspath-continuity-{}", uuid::Uuid::new_v4()))
}

/// A strict composite resolver. All configured sources are queried in order;
/// an outage, invalid signature, divergent key, stale sequence or different
/// capability set blocks payment instead of silently choosing a fallback.
/// Configure only sources actually expected for this identifier.
pub struct ChainResolver {
    resolvers: Vec<ResolverEntry>,
    continuity_dir: std::path::PathBuf,
    explicit_continuity_dir: bool,
    pinned_key: Option<String>,
    minimum_sequence: Option<u64>,
    required_capabilities: Vec<String>,
}

impl ChainResolver {
    /// Construct an empty resolver chain with mandatory continuity enforcement.
    pub fn new() -> Self {
        Self {
            resolvers: Vec::new(),
            continuity_dir: default_chain_continuity_dir(),
            explicit_continuity_dir: false,
            pinned_key: None,
            minimum_sequence: None,
            required_capabilities: Vec::new(),
        }
    }

    /// Construct a resolver chain persisting continuity state and revocations in `dir`.
    pub fn with_continuity_dir(dir: impl Into<std::path::PathBuf>) -> Self {
        Self {
            continuity_dir: dir.into(),
            explicit_continuity_dir: true,
            ..Self::new()
        }
    }

    /// Append an authoritative resolver with a default positional source name.
    pub fn push<R: ProfileResolver + Send + Sync + 'static>(mut self, resolver: R) -> Self {
        if !self.explicit_continuity_dir {
            if let Some(dir) = resolver.continuity_dir() {
                self.continuity_dir = dir.to_path_buf();
                self.explicit_continuity_dir = true;
            }
        }
        let source = format!("resolver-{}", self.resolvers.len());
        self.resolvers.push(ResolverEntry {
            source,
            role: ResolverRole::Authoritative,
            resolver: Box::new(resolver),
        });
        self
    }

    /// Register a source which may establish identity on first contact.
    pub fn push_authoritative<R: ProfileResolver + Send + Sync + 'static>(
        mut self,
        source: impl Into<String>,
        resolver: R,
    ) -> Self {
        if !self.explicit_continuity_dir {
            if let Some(dir) = resolver.continuity_dir() {
                self.continuity_dir = dir.to_path_buf();
                self.explicit_continuity_dir = true;
            }
        }
        self.resolvers.push(ResolverEntry {
            source: source.into(),
            role: ResolverRole::Authoritative,
            resolver: Box::new(resolver),
        });
        self
    }

    /// Register an additional source which can corroborate but not establish
    /// identity on its own. Its absence is permitted; its outage is not.
    pub fn push_supplementary<R: ProfileResolver + Send + Sync + 'static>(
        mut self,
        source: impl Into<String>,
        resolver: R,
    ) -> Self {
        if !self.explicit_continuity_dir {
            if let Some(dir) = resolver.continuity_dir() {
                self.continuity_dir = dir.to_path_buf();
                self.explicit_continuity_dir = true;
            }
        }
        self.resolvers.push(ResolverEntry {
            source: source.into(),
            role: ResolverRole::Supplementary,
            resolver: Box::new(resolver),
        });
        self
    }

    /// Set the currently trusted identity key and minimum observed sequence.
    /// Updating a pin after rotation requires independently verified history;
    /// a single resolver's rotation claim never updates it automatically.
    pub fn with_continuity_pin(mut self, key: String, sequence: u64) -> Self {
        self.pinned_key = Some(key);
        self.minimum_sequence = Some(sequence);
        self
    }

    /// Descriptors previously accepted by the wallet. A source suppressing
    /// any of them cannot silently force a lower-capability payment route.
    pub fn with_required_capabilities(mut self, descriptors: Vec<String>) -> Self {
        self.required_capabilities = descriptors;
        self
    }

    /// Resolve `alias` across all configured sources, enforcing signature validity,
    /// continuity, capability preservation, and byte-identical payload agreement.
    pub async fn resolve_with_report(&self, alias: &str) -> Result<ResolutionReport> {
        let strip = |s: &str| {
            let unprefixed = s.trim().strip_prefix('₿').unwrap_or(s.trim()).trim();
            if let Some((user, domain)) = unprefixed.split_once('@') {
                canonical_identifier(&format!("{}@{}", user.trim(), domain.trim()))
            } else {
                canonical_identifier(unprefixed)
            }
        };
        let canonical = strip(alias);
        crate::resolvers::continuity::check_revocation(&self.continuity_dir, &canonical)?;

        let mut observations = Vec::with_capacity(self.resolvers.len());
        let mut agreed: Option<Vec<u8>> = None;
        let mut selected = None;
        for entry in &self.resolvers {
            match entry.resolver.resolve_for_chain(alias).await {
                Ok(signed) => {
                    let profile = &signed.profile;
                    // Never treat unauthenticated revocation, expiry or alias
                    // claims as authoritative protocol outcomes.
                    if !verify_signed_profile(&signed)? {
                        return Err(SatsPathError::InvalidSignature);
                    }
                    if strip(&profile.alias) != canonical {
                        return Err(SatsPathError::ResolverDisagreement(format!(
                            "{} returned alias {} instead of {}",
                            entry.source, profile.alias, alias
                        )));
                    }
                    if profile.revoked {
                        if self
                            .pinned_key
                            .as_ref()
                            .is_some_and(|key| key != &profile.identity_pubkey)
                            || agreed.is_some()
                        {
                            return Err(SatsPathError::ResolverDisagreement(
                                "revocation conflicts with the resolved identity".into(),
                            ));
                        }
                        if crate::resolvers::continuity::has_pin(&self.continuity_dir, &canonical)?
                        {
                            crate::resolvers::continuity::accept_profile(
                                &self.continuity_dir,
                                &signed,
                            )?;
                        }
                        return Err(SatsPathError::RegistryError(format!(
                            "Alias {} has been revoked",
                            profile.alias
                        )));
                    }
                    if check_profile_expiry(profile).is_err() {
                        return Err(SatsPathError::ResolverDisagreement(format!(
                            "{} returned an expired profile",
                            entry.source
                        )));
                    }
                    if self
                        .pinned_key
                        .as_ref()
                        .is_some_and(|key| key != &profile.identity_pubkey)
                    {
                        return Err(SatsPathError::UnauthorizedKeyReplacement);
                    }
                    if self
                        .minimum_sequence
                        .is_some_and(|seq| profile.sequence.is_none_or(|n| n < seq))
                    {
                        return Err(SatsPathError::ResolverDisagreement(format!(
                            "{} returned a stale sequence",
                            entry.source
                        )));
                    }
                    if !self.required_capabilities.iter().all(|descriptor| {
                        profile
                            .methods
                            .iter()
                            .any(|method| method.ownership_descriptor() == *descriptor)
                    }) {
                        return Err(SatsPathError::ResolverDisagreement(format!(
                            "{} suppressed a pinned payment capability",
                            entry.source
                        )));
                    }
                    crate::resolvers::continuity::validate_candidate(
                        &self.continuity_dir,
                        &signed,
                    )?;
                    // Equality of the entire signed payload also detects
                    // capability suppression, replay and equal-sequence forks.
                    let bytes = canonical_profile_bytes(profile)?;
                    if agreed.as_ref().is_some_and(|prev| prev != &bytes) {
                        return Err(SatsPathError::ResolverDisagreement(format!(
                            "{} disagrees on identity, sequence or capabilities",
                            entry.source
                        )));
                    }
                    agreed = Some(bytes);
                    if selected.is_none() && entry.role == ResolverRole::Authoritative {
                        selected = Some(signed);
                    }
                    observations.push(ResolverObservation {
                        source: entry.source.clone(),
                        role: entry.role,
                        found: true,
                    });
                }
                Err(SatsPathError::AliasNotFound(_)) => observations.push(ResolverObservation {
                    source: entry.source.clone(),
                    role: entry.role,
                    found: false,
                }),
                Err(SatsPathError::NetworkError(reason)) => {
                    return Err(SatsPathError::NetworkError(format!(
                        "{} unavailable; refusing downgrade: {reason}",
                        entry.source
                    )));
                }
                Err(error) => return Err(error),
            }
        }
        let profile = selected.ok_or_else(|| {
            if agreed.is_some() {
                SatsPathError::ResolverDisagreement(
                    "only supplementary sources returned a profile".into(),
                )
            } else {
                SatsPathError::AliasNotFound(alias.into())
            }
        })?;
        crate::resolvers::continuity::accept_profile(&self.continuity_dir, &profile)?;
        Ok(ResolutionReport {
            profile,
            observations,
        })
    }
}

impl Default for ChainResolver {
    /// Construct an empty [`ChainResolver`].
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProfileResolver for ChainResolver {
    /// Resolve `alias` and return the agreed signed payment profile.
    async fn resolve_alias(&self, alias: &str) -> Result<SignedPaymentProfile> {
        Ok(self.resolve_with_report(alias).await?.profile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip353::{DnsTxtRecord, MockDnsTxtResolver};
    use crate::crypto::{generate_identity_keypair, sign_profile};
    use crate::profile::{PaymentMethod, PaymentProfile};
    use crate::resolvers::bip353::Bip353Resolver;
    use std::sync::Arc;

    struct MockResolver {
        should_succeed: bool,
        returned_alias: Option<String>,
    }

    #[async_trait]
    impl ProfileResolver for MockResolver {
        /// Return a signed mock profile or `AliasNotFound` depending on `should_succeed`.
        async fn resolve_alias(&self, alias: &str) -> Result<SignedPaymentProfile> {
            if self.should_succeed {
                let kp = generate_identity_keypair();
                let pubkey_hex = hex::encode(kp.public_key.serialize());
                let profile_alias = self
                    .returned_alias
                    .clone()
                    .unwrap_or_else(|| alias.to_string());
                let profile = PaymentProfile {
                    alias: profile_alias.clone(),
                    identity_pubkey: pubkey_hex,
                    methods: vec![PaymentMethod::Lightning {
                        label: "LN".into(),
                        lightning_address: Some(profile_alias),
                        lnurl: None,
                        bolt12: None,
                        receiver_pubkey: None,
                    }],
                    updated_at: 1_700_000_000,
                    expires_at: None,
                    sequence: None,
                    preferences: vec![],
                    nonce: None,
                    rotation: None,
                    method_verifications: Vec::new(),
                    hybrid_pubkey: None,
                    pqc_required: false,
                    revoked: false,
                    recovery_policy: None,
                    recovery: None,
                };
                Ok(sign_profile(profile, &kp.secret_key).unwrap())
            } else {
                Err(SatsPathError::AliasNotFound(alias.to_string()))
            }
        }
    }

    /// Verify that `ChainResolver` falls through `AliasNotFound` to the next authoritative source.
    #[tokio::test]
    async fn chain_resolver_success() {
        let chain = ChainResolver::new()
            .push(MockResolver {
                should_succeed: false,
                returned_alias: None,
            })
            .push(MockResolver {
                should_succeed: true,
                returned_alias: None,
            });

        let res = chain.resolve_alias("test@domain.com").await;
        assert!(res.is_ok());
        assert_eq!(res.unwrap().profile.alias, "test@domain.com");
    }

    /// Verify that `ChainResolver` returns `AliasNotFound` when all sources report absence.
    #[tokio::test]
    async fn chain_resolver_failure() {
        let chain = ChainResolver::new()
            .push(MockResolver {
                should_succeed: false,
                returned_alias: None,
            })
            .push(MockResolver {
                should_succeed: false,
                returned_alias: None,
            });

        let res = chain.resolve_alias("test@domain.com").await;
        assert!(res.is_err());
    }

    /// Verify that `ChainResolver` rejects a profile whose alias does not match the requested alias.
    #[tokio::test]
    async fn chain_resolver_rejects_substituted_alias() {
        // We ask the mock resolver to succeed, which always returns a profile
        // for "test@domain.com".
        let chain = ChainResolver::new().push(MockResolver {
            should_succeed: true,
            returned_alias: Some("test@domain.com".to_string()),
        });

        // But we request "alice@domain.com".
        // The resolver will return "test@domain.com", which should trigger
        // the SEC-02 Profile Substitution Attack mitigation.
        let res = chain.resolve_alias("alice@domain.com").await;

        assert!(res.is_err());
        let err = res.unwrap_err().to_string();
        assert!(
            err.contains("resolver disagreement"),
            "Expected security failure message, got: {}",
            err
        );
        assert!(err.contains("alice@domain.com"));
        assert!(err.contains("test@domain.com"));
    }

    /// Verify that a `₿`-prefixed request matches an otherwise identical unprefixed profile alias.
    #[tokio::test]
    async fn chain_resolver_accepts_prefixed_request_for_unprefixed_profile() {
        let chain = ChainResolver::new().push_authoritative(
            "https",
            MockResolver {
                should_succeed: true,
                returned_alias: Some("alice@example.com".to_string()),
            },
        );

        let report = chain
            .resolve_with_report("₿alice@example.com")
            .await
            .unwrap();
        assert_eq!(report.profile.profile.alias, "alice@example.com");
        assert!(report.observations[0].found);
    }

    /// Verify that definitive BIP-353 absence allows HTTPS fallback, while unsigned DNS records fail closed.
    #[tokio::test]
    async fn chain_resolver_allows_definitive_bip353_absence_but_blocks_unsigned_dns() {
        let dir = tempfile::tempdir().unwrap();
        let empty_dns = MockDnsTxtResolver::new();
        let bip353_absent = Bip353Resolver::with_dns_resolver(Arc::new(empty_dns), dir.path());

        let chain = ChainResolver::with_continuity_dir(dir.path())
            .push_authoritative("bip353", bip353_absent)
            .push_authoritative(
                "https",
                MockResolver {
                    should_succeed: true,
                    returned_alias: Some("alice@example.com".to_string()),
                },
            );

        let report = chain
            .resolve_with_report("₿alice@example.com")
            .await
            .unwrap();
        assert_eq!(report.profile.profile.alias, "alice@example.com");
        assert!(!report.observations[0].found);
        assert!(report.observations[1].found);

        // An existing unsigned DNS record must fail closed with DnssecUnavailable and never fall back.
        let dir_unsigned = tempfile::tempdir().unwrap();
        let mut unsigned_dns = MockDnsTxtResolver::new();
        unsigned_dns.insert(
            "alice.user._bitcoin-payment.example.com",
            DnsTxtRecord {
                strings: vec!["bitcoin:?lno=lno1qoffer".into()],
                dnssec_validated: false,
                ttl_seconds: Some(60),
            },
        );
        let bip353_unsigned =
            Bip353Resolver::with_dns_resolver(Arc::new(unsigned_dns), dir_unsigned.path());
        let chain_unsigned = ChainResolver::with_continuity_dir(dir_unsigned.path())
            .push_authoritative("bip353", bip353_unsigned)
            .push_authoritative(
                "https",
                MockResolver {
                    should_succeed: true,
                    returned_alias: Some("alice@example.com".to_string()),
                },
            );
        assert!(matches!(
            chain_unsigned.resolve_alias("₿alice@example.com").await,
            Err(SatsPathError::DnssecUnavailable)
        ));

        // Non-bitcoin TXT records at the name produce SatsPathError::Bip353 and must NOT fall through.
        let dir_non_bitcoin = tempfile::tempdir().unwrap();
        let mut non_bitcoin_dns = MockDnsTxtResolver::new();
        non_bitcoin_dns.insert(
            "alice.user._bitcoin-payment.example.com",
            DnsTxtRecord {
                strings: vec!["v=spf1 -all".into()],
                dnssec_validated: true,
                ttl_seconds: Some(60),
            },
        );
        let bip353_non_bitcoin =
            Bip353Resolver::with_dns_resolver(Arc::new(non_bitcoin_dns), dir_non_bitcoin.path());
        let chain_non_bitcoin = ChainResolver::with_continuity_dir(dir_non_bitcoin.path())
            .push_authoritative("bip353", bip353_non_bitcoin)
            .push_authoritative(
                "https",
                MockResolver {
                    should_succeed: true,
                    returned_alias: Some("alice@example.com".to_string()),
                },
            );
        assert!(matches!(
            chain_non_bitcoin.resolve_alias("₿alice@example.com").await,
            Err(SatsPathError::Bip353(_))
        ));
    }

    /// Verify that a first-contact revoked BIP-353 profile fails closed without persisting a tombstone,
    /// and that revocations conflicting with `pinned_key` or an agreed profile fail with `ResolverDisagreement`.
    #[tokio::test]
    async fn first_contact_bip353_revocation_does_not_persist_tombstone() {
        let dir = tempfile::tempdir().unwrap();
        let attacker = generate_identity_keypair();
        let attacker_pub = hex::encode(attacker.public_key.serialize());
        let revoked_profile = PaymentProfile {
            alias: "alice@example.com".into(),
            identity_pubkey: attacker_pub.clone(),
            methods: Vec::new(),
            updated_at: 1_700_000_000,
            expires_at: None,
            sequence: Some(1),
            preferences: vec![],
            nonce: None,
            rotation: None,
            method_verifications: Vec::new(),
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: true,
            recovery_policy: None,
            recovery: None,
        };
        let signed_revoked = sign_profile(revoked_profile, &attacker.secret_key).unwrap();

        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/profile")
            .with_status(200)
            .with_body(serde_json::to_string(&signed_revoked).unwrap())
            .create_async()
            .await;
        let mut dns = MockDnsTxtResolver::new();
        dns.insert(
            "alice.user._bitcoin-payment.example.com",
            DnsTxtRecord {
                strings: vec![format!("bitcoin:?sp-profile={}/profile", server.url())],
                dnssec_validated: true,
                ttl_seconds: Some(60),
            },
        );
        let bip353 = Bip353Resolver::with_dns_resolver(Arc::new(dns.clone()), dir.path())
            .with_allow_private_profile_url(true);
        let chain =
            ChainResolver::with_continuity_dir(dir.path()).push_authoritative("bip353", bip353);
        assert!(matches!(
            chain.resolve_alias("₿alice@example.com").await,
            Err(SatsPathError::RegistryError(msg)) if msg.contains("revoked")
        ));

        // A fresh ChainResolver using the same directory must not encounter a persisted tombstone.
        let fresh_chain = ChainResolver::with_continuity_dir(dir.path()).push_authoritative(
            "https",
            MockResolver {
                should_succeed: true,
                returned_alias: Some("alice@example.com".to_string()),
            },
        );
        let resolved = fresh_chain
            .resolve_alias("₿alice@example.com")
            .await
            .expect("first-contact revocation must not poison empty continuity store");
        assert_eq!(resolved.profile.alias, "alice@example.com");

        // Conflicting with an explicit pinned_key must return ResolverDisagreement.
        let dir_pinned = tempfile::tempdir().unwrap();
        let bip353_pinned = Bip353Resolver::with_dns_resolver(Arc::new(dns), dir_pinned.path())
            .with_allow_private_profile_url(true);
        let chain_pinned = ChainResolver::with_continuity_dir(dir_pinned.path())
            .push_authoritative("bip353", bip353_pinned)
            .with_continuity_pin("different-pinned-key".into(), 1);
        assert!(matches!(
            chain_pinned.resolve_alias("₿alice@example.com").await,
            Err(SatsPathError::ResolverDisagreement(_))
        ));
    }
}
