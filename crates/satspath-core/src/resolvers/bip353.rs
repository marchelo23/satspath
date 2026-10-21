//! BIP-353 local cryptographic DNSSEC validation engine and resolver adapter.
//!
//! Provides local cryptographic DNSSEC chain validation rooted in bundled IANA/ICANN
//! root trust anchors (historical KSK `19036`, standby KSK `20326`, and active KSK `38696`),
//! ensuring that BIP-353 payment instructions (`₿user@domain`) are cryptographically
//! verified locally rather than trusting an upstream recursive resolver's AD bit.
//!
//! # Security Invariants
//! - **Root Trust Anchors**: Bundled KSK `38696` is decoded and verified for key tag `38696`
//!   at initialization; any decoding failure panics immediately.
//! - **Fail-Closed Strict Policy**: Unsigned zones (missing `DS` or `RRSIG`) and tampered
//!   zones (`Bogus` signatures or expired validity windows) fail closed under [`DnssecPolicy::Strict`].
//! - **No Synthetic Profiles**: DNS TXT payment instructions without an authenticated `sp-profile`
//!   pointer return [`SatsPathError::Bip353Unauthenticated`] in [`ProfileResolver::resolve_alias`]
//!   and never synthesize ephemeral `secp256k1` profile signatures.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures_util::Stream;
use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts,
};
use hickory_resolver::name_server::{GenericConnector, NameServerPool, TokioRuntimeProvider};
use hickory_resolver::proto::error::ProtoError;
use hickory_resolver::proto::op::{Query, ResponseCode};
use hickory_resolver::proto::rr::dnssec::public_key::Rsa;
use hickory_resolver::proto::rr::dnssec::rdata::{DNSSECRData, DNSKEY, DS, RRSIG};
use hickory_resolver::proto::rr::dnssec::{Algorithm, TrustAnchor, Verifier};
use hickory_resolver::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_resolver::proto::xfer::dnssec_dns_handle::verify_nsec;
use hickory_resolver::proto::xfer::{
    DnsHandle, DnsRequest, DnsRequestOptions, DnsResponse, DnssecDnsHandle, FirstAnswer,
    RetryDnsHandle,
};

use crate::bip353::{
    parse_bip353_name, resolve_bip353_with, Bip353Resolution, DnsTxtRecord, DnsTxtResolver,
    DnssecPolicy,
};
use crate::resolver::ProfileResolver;
use crate::{Result, SatsPathError, SignedPaymentProfile};

/// Base64-encoded RFC 3110 RSA public key for the active ICANN Root KSK (Key Tag `38696`, KSK-2024).
pub const ICANN_ROOT_KSK_38696_B64: &str = "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=";

/// Expected RFC 4034 key tag for the active ICANN Root KSK (`38696`).
pub const ICANN_ROOT_KSK_38696_TAG: u16 = 38696;

/// Expected RFC 4034 key tag for the ICANN Root KSK-2017 (`20326`).
pub const ICANN_ROOT_KSK_20326_TAG: u16 = 20326;

/// Return the set of trusted IANA/ICANN DNSSEC root trust anchors.
///
/// Combines Hickory's default root trust anchors (KSK `19036` and KSK `20326`)
/// with the explicitly bundled active ICANN KSK (Key Tag `38696`).
///
/// # Panics
/// Panics if the embedded KSK `38696` base64 string or RSA public key bytes fail to parse
/// or if the computed RFC 4034 key tag does not equal `38696`.
pub fn root_trust_anchors() -> TrustAnchor {
    let mut anchor = TrustAnchor::default();
    let ksk_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        ICANN_ROOT_KSK_38696_B64,
    )
    .expect("embedded ICANN root KSK 38696 base64 must decode");
    let rsa = Rsa::from_public_bytes(&ksk_bytes)
        .expect("embedded ICANN root KSK 38696 must parse as a valid RSA public key");
    anchor.insert_trust_anchor(&rsa);
    let dnskey = DNSKEY::new(true, true, false, Algorithm::RSASHA256, ksk_bytes);
    let key_tag = dnskey
        .calculate_key_tag()
        .expect("embedded ICANN root KSK 38696 must have a computable key tag");
    assert_eq!(
        key_tag, ICANN_ROOT_KSK_38696_TAG,
        "embedded ICANN root KSK key tag must equal 38696"
    );
    anchor
}

/// Construct a resilient multi-provider recursive resolver configuration.
///
/// Configures Cloudflare (`1.0.0.1`, `1.1.1.1`), Quad9 (`9.9.9.9`, `149.112.112.112`),
/// and Google (`8.8.8.8`, `8.8.4.4`) over both TCP and UDP so oversized DNSSEC responses
/// and UDP-restricted networks are handled reliably.
pub fn default_resolver_config() -> ResolverConfig {
    let mut config = ResolverConfig::new();
    let servers = [
        (IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 53),
        (IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        (IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 53),
        (IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)), 53),
        (IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        (IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53),
    ];
    for (ip, port) in servers {
        config.add_name_server(NameServerConfig {
            socket_addr: SocketAddr::new(ip, port),
            protocol: Protocol::Tcp,
            tls_dns_name: None,
            trust_negative_responses: false,
            bind_addr: None,
        });
        config.add_name_server(NameServerConfig {
            socket_addr: SocketAddr::new(ip, port),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
            bind_addr: None,
        });
    }
    config
}

// ─── Embedded Cryptographic DNSSEC Chain Validator ──────────────────────────────

/// Represents a single zone link in a DNSSEC authentication chain (RFC 4034 / RFC 4035).
#[derive(Debug, Clone)]
pub struct DnssecZoneLink {
    /// Canonical zone apex name (e.g. `.`, `com.`, `satspath.dev.`).
    pub zone_name: Name,
    /// `DNSKEY` resource records at `zone_name`.
    pub dnskey_records: Vec<Record>,
    /// `RRSIG` records covering the `DNSKEY` RRset at `zone_name`.
    pub dnskey_rrsigs: Vec<RRSIG>,
    /// `DS` resource records in the parent zone delegating to `zone_name` (empty for root `.`).
    pub parent_ds_records: Vec<Record>,
    /// `RRSIG` records covering `parent_ds_records` signed by the parent zone's `DNSKEY`.
    pub parent_ds_rrsigs: Vec<RRSIG>,
}

/// Accept an RRset if any signature from `expected_signer` verifies with a trusted zone key.
///
/// `now` is Unix time in seconds; inception and expiration are inclusive.
/// Missing records or signatures return `DnssecUnavailable`. If no eligible
/// signature verifies, returns `NetworkError`, including for expired signatures.
fn verify_rrset_signatures(
    owner_name: &Name,
    expected_signer: &Name,
    records: &[Record],
    rrsigs: &[RRSIG],
    trusted_zone_keys: &[DNSKEY],
    now: u32,
) -> Result<()> {
    if records.is_empty() {
        return Err(SatsPathError::DnssecUnavailable);
    }
    if rrsigs.is_empty() {
        return Err(SatsPathError::DnssecUnavailable);
    }

    for rrsig in rrsigs {
        if rrsig.signer_name() != expected_signer {
            continue;
        }
        let inception = rrsig.sig_inception();
        let expiration = rrsig.sig_expiration();
        if now < inception || now > expiration {
            continue;
        }

        for dnskey in trusted_zone_keys {
            if !dnskey.zone_key() || dnskey.revoke() {
                continue;
            }
            if dnskey.algorithm() != rrsig.algorithm() {
                continue;
            }
            let Ok(tag) = dnskey.calculate_key_tag() else {
                continue;
            };
            if tag != rrsig.key_tag() {
                continue;
            }
            if dnskey
                .verify_rrsig(owner_name, DNSClass::IN, rrsig, records)
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    Err(SatsPathError::NetworkError(format!(
        "DNSSEC RRSIG cryptographic verification failed for `{owner_name}` (signer `{expected_signer}`)"
    )))
}

/// Cryptographically validate a complete DNSSEC trust chain from the root `TrustAnchor`
/// across all zone delegations (`DNSKEY` -> `DS` -> `DNSKEY`) down to the leaf `TXT` RRset.
///
/// `chain` must be ordered from the root to the leaf zone; `txt_owner` identifies
/// the final RRset. `now` is Unix time in seconds. Returns matching TXT records
/// with UTF-8 character-strings, TTLs in seconds, and `dnssec_validated = true`.
/// This does not validate the TXT payload as a payment instruction.
///
/// Enforces:
/// - Root `DNSKEY` membership in `trust_anchor` and self-signature verification.
/// - Non-empty `DS` delegation records for every child zone, signed by the parent zone's `DNSKEY`.
/// - Cryptographic `DS::covers` digest matching against child `DNSKEY`s.
/// - `RRSIG` validity window (`sig_inception <= now <= sig_expiration`) and signature verification
///   for every `DNSKEY`, `DS`, and leaf `TXT` RRset.
///
/// # Errors
/// Returns [`SatsPathError::DnssecUnavailable`] for an empty chain, missing records
/// or signatures, no usable zone keys, or no matching TXT records. Returns
/// [`SatsPathError::NetworkError`] when no root key is anchored, no child key matches
/// an authenticated `DS`, or no eligible signature verifies (including outside its
/// validity window). Returns [`SatsPathError::Bip353`] for non-UTF-8 TXT data.
pub fn verify_dnssec_zone_chain(
    trust_anchor: &TrustAnchor,
    chain: &[DnssecZoneLink],
    txt_owner: &Name,
    txt_records: &[Record],
    txt_rrsigs: &[RRSIG],
    now: u32,
) -> Result<Vec<DnsTxtRecord>> {
    if chain.is_empty() || txt_records.is_empty() || txt_rrsigs.is_empty() {
        return Err(SatsPathError::DnssecUnavailable);
    }

    let mut parent_validated_keys: Vec<DNSKEY> = Vec::new();

    for (idx, link) in chain.iter().enumerate() {
        let zone_dnskeys: Vec<DNSKEY> = link
            .dnskey_records
            .iter()
            .filter_map(|r| match r.data() {
                Some(RData::DNSSEC(DNSSECRData::DNSKEY(k))) if k.zone_key() && !k.revoke() => {
                    Some(k.clone())
                }
                _ => None,
            })
            .collect();

        if zone_dnskeys.is_empty() {
            return Err(SatsPathError::DnssecUnavailable);
        }

        if idx == 0 {
            // Root zone: at least one DNSKEY must be in the TrustAnchor and verify the root DNSKEY RRset
            let anchored_keys: Vec<DNSKEY> = zone_dnskeys
                .iter()
                .filter(|k| trust_anchor.contains_dnskey_bytes(k.public_key()))
                .cloned()
                .collect();

            if anchored_keys.is_empty() {
                return Err(SatsPathError::NetworkError(
                    "DNSSEC validation failed: root DNSKEY not found in trust anchors".into(),
                ));
            }

            verify_rrset_signatures(
                &link.zone_name,
                &link.zone_name,
                &link.dnskey_records,
                &link.dnskey_rrsigs,
                &anchored_keys,
                now,
            )?;
            parent_validated_keys = zone_dnskeys;
        } else {
            let parent_zone = &chain[idx - 1].zone_name;
            if !parent_zone.zone_of(&link.zone_name) {
                return Err(SatsPathError::NetworkError(format!(
                    "DNSSEC validation failed: zone `{}` is not a subdomain of parent zone `{}`",
                    link.zone_name, parent_zone
                )));
            }
            if link.parent_ds_records.is_empty() || link.parent_ds_rrsigs.is_empty() {
                return Err(SatsPathError::DnssecUnavailable);
            }

            // 1. Verify parent RRSIG over the DS RRset
            verify_rrset_signatures(
                &link.zone_name,
                parent_zone,
                &link.parent_ds_records,
                &link.parent_ds_rrsigs,
                &parent_validated_keys,
                now,
            )?;

            let ds_list: Vec<&DS> = link
                .parent_ds_records
                .iter()
                .filter_map(|r| match r.data() {
                    Some(RData::DNSSEC(DNSSECRData::DS(ds))) => Some(ds),
                    _ => None,
                })
                .collect();

            // 2. Find child DNSKEYs covered by at least one authenticated DS record
            let ds_covered_keys: Vec<DNSKEY> = zone_dnskeys
                .iter()
                .filter(|k| {
                    let Ok(key_tag) = k.calculate_key_tag() else {
                        return false;
                    };
                    ds_list.iter().any(|ds| {
                        ds.key_tag() == key_tag
                            && ds.algorithm() == k.algorithm()
                            && ds.covers(&link.zone_name, k).unwrap_or(false)
                    })
                })
                .cloned()
                .collect();

            if ds_covered_keys.is_empty() {
                return Err(SatsPathError::NetworkError(format!(
                    "DNSSEC validation failed: no DNSKEY in `{}` matches parent DS record",
                    link.zone_name
                )));
            }

            // 3. Verify child DNSKEY RRset RRSIG using the DS-authenticated child KSK
            verify_rrset_signatures(
                &link.zone_name,
                &link.zone_name,
                &link.dnskey_records,
                &link.dnskey_rrsigs,
                &ds_covered_keys,
                now,
            )?;

            parent_validated_keys = zone_dnskeys;
        }
    }

    let leaf_zone = &chain.last().expect("chain is non-empty").zone_name;
    if !leaf_zone.zone_of(txt_owner) {
        return Err(SatsPathError::NetworkError(format!(
            "DNSSEC validation failed: TXT owner `{}` is not within leaf zone `{}`",
            txt_owner, leaf_zone
        )));
    }
    verify_rrset_signatures(
        txt_owner,
        leaf_zone,
        txt_records,
        txt_rrsigs,
        &parent_validated_keys,
        now,
    )?;

    let mut out = Vec::new();
    for record in txt_records {
        if record.name() != txt_owner || record.record_type() != RecordType::TXT {
            continue;
        }
        if let Some(txt) = record.data().and_then(|d| d.as_txt()) {
            let mut strings = Vec::new();
            for part in txt.iter() {
                let s = std::str::from_utf8(part)
                    .map_err(|_| SatsPathError::Bip353("TXT record is not UTF-8".into()))?;
                strings.push(s.to_string());
            }
            out.push(DnsTxtRecord {
                strings,
                dnssec_validated: true,
                ttl_seconds: Some(record.ttl()),
            });
        }
    }

    if out.is_empty() {
        return Err(SatsPathError::DnssecUnavailable);
    }

    Ok(out)
}

// ─── Dynamic DnsHandle Wrapper for HickoryDnssecTxtResolver ─────────────────────

type DnsResponseStream =
    Pin<Box<dyn Stream<Item = std::result::Result<DnsResponse, ProtoError>> + Send>>;

/// Type-erased [`DnsHandle`] allowing [`HickoryDnssecTxtResolver`] to wrap either the
/// production multi-provider network pool or an in-process authoritative DNSSEC test fixture.
#[derive(Clone)]
pub struct SharedDnsHandle {
    send_fn: Arc<dyn Fn(DnsRequest) -> DnsResponseStream + Send + Sync>,
    txt_responses: Arc<Mutex<HashMap<Name, DnsResponse>>>,
}

impl SharedDnsHandle {
    /// Wrap any [`DnsHandle`] implementation into a [`SharedDnsHandle`].
    pub fn new<H, E>(handle: H) -> Self
    where
        H: DnsHandle<Error = E> + Send + Sync + Unpin + 'static,
        E: std::error::Error + Send + 'static,
    {
        use futures_util::{StreamExt, TryStreamExt};
        let txt_responses: Arc<Mutex<HashMap<Name, DnsResponse>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let captured = Arc::clone(&txt_responses);
        Self {
            send_fn: Arc::new(move |req: DnsRequest| {
                let txt_qname = req
                    .queries()
                    .first()
                    .filter(|q| q.query_type() == RecordType::TXT)
                    .map(|q| q.name().clone());
                let captured = Arc::clone(&captured);
                Box::pin(
                    handle
                        .send(req)
                        .map_err(|e| ProtoError::from(e.to_string()))
                        .inspect(move |res| {
                            if let (Some(qname), Ok(resp)) = (&txt_qname, res) {
                                if let Ok(mut guard) = captured.lock() {
                                    guard.insert(qname.clone(), resp.clone());
                                }
                            }
                        }),
                )
            }),
            txt_responses,
        }
    }

    /// Take the most recent raw `TXT` response captured for `name`.
    fn take_txt_response(&self, name: &Name) -> Option<DnsResponse> {
        self.txt_responses
            .lock()
            .ok()
            .and_then(|mut guard| guard.remove(name))
    }
}

impl DnsHandle for SharedDnsHandle {
    type Response = DnsResponseStream;
    type Error = ProtoError;

    /// Forward a query through the wrapped DNS transport.
    fn send<R: Into<DnsRequest>>(&self, request: R) -> Self::Response {
        (self.send_fn)(request.into())
    }
}

/// Decode an RFC 4648 Section 7 (`base32hex` / `BASE32_DNSSEC`) label into raw hash bytes.
fn decode_base32hex(input: &str) -> Option<Vec<u8>> {
    if input.is_empty() {
        return None;
    }
    let mut buffer = 0u32;
    let mut bits = 0u8;
    let mut out = Vec::with_capacity((input.len() * 5) / 8);
    for byte in input.bytes() {
        let val = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'v' => byte - b'a' + 10,
            b'A'..=b'V' => byte - b'A' + 10,
            _ => return None,
        };
        buffer = (buffer << 5) | u32::from(val);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    if bits > 0 && buffer != 0 {
        return None;
    }
    Some(out)
}

/// Check whether `hash` lies strictly inside the cyclic NSEC3 interval `(owner, next)`.
fn nsec3_interval_covers(owner: &[u8], next: &[u8], hash: &[u8]) -> bool {
    if owner.len() != next.len() || owner.len() != hash.len() {
        return false;
    }
    if owner < next {
        owner < hash && hash < next
    } else {
        hash > owner || hash < next
    }
}

/// Verify that `records` has at least one valid `RRSIG` from `expected_signer` under `trusted_keys`.
fn verify_rrset_with_trusted_keys(
    owner_name: &Name,
    expected_signer: &Name,
    records: &[Record],
    rrsigs: &[RRSIG],
    trusted_keys: &[DNSKEY],
    now: u32,
) -> bool {
    if records.is_empty() || rrsigs.is_empty() {
        return false;
    }
    for rrsig in rrsigs {
        if rrsig.signer_name() != expected_signer {
            continue;
        }
        let inception = rrsig.sig_inception();
        let expiration = rrsig.sig_expiration();
        if now < inception || now > expiration {
            continue;
        }
        for dnskey in trusted_keys {
            if !dnskey.zone_key() || dnskey.revoke() || dnskey.algorithm() != rrsig.algorithm() {
                continue;
            }
            let Ok(tag) = dnskey.calculate_key_tag() else {
                continue;
            };
            if tag != rrsig.key_tag() {
                continue;
            }
            if dnskey
                .verify_rrsig(owner_name, DNSClass::IN, rrsig, records)
                .is_ok()
            {
                return true;
            }
        }
    }
    false
}

/// Verify that `response` carries a DNSSEC-authenticated `SOA` and `NSEC` denial of existence.
fn verify_nsec_negative_response(query: &Query, response: &DnsResponse) -> bool {
    if !matches!(
        response.response_code(),
        ResponseCode::NoError | ResponseCode::NXDomain
    ) || !response.answers().is_empty()
    {
        return false;
    }
    let Some(soa_name) = response
        .name_servers()
        .iter()
        .find(|rr| rr.record_type() == RecordType::SOA)
        .map(Record::name)
    else {
        return false;
    };
    if !soa_name.zone_of(query.name()) {
        return false;
    }
    let nsecs: Vec<&Record> = response
        .name_servers()
        .iter()
        .filter(|rr| rr.record_type() == RecordType::NSEC && soa_name.zone_of(rr.name()))
        .collect();
    if nsecs.is_empty() {
        return false;
    }
    if response.response_code() == ResponseCode::NXDomain
        && nsecs.iter().any(|nsec| nsec.name() == query.name())
    {
        return false;
    }
    if response.response_code() == ResponseCode::NoError {
        if let Some(exact) = nsecs.iter().find(|nsec| nsec.name() == query.name()) {
            let Some(RData::DNSSEC(DNSSECRData::NSEC(rdata))) = exact.data() else {
                return false;
            };
            if rdata.type_bit_maps().contains(&RecordType::CNAME) {
                return false;
            }
        }
    }
    verify_nsec(query, soa_name, &nsecs)
}

/// Maximum number of NSEC3 records accepted in a single denial-of-existence proof.
const MAX_NSEC3_RECORDS: usize = 8;

/// Maximum NSEC3 hash iterations permitted per RFC 9276 to mitigate algorithmic complexity attacks.
const MAX_NSEC3_ITERATIONS: u16 = 100;

/// Verify RFC 5155 `NSEC3` denial of existence over pre-authenticated `NSEC3` records.
fn verify_nsec3_coverage(
    query: &Query,
    soa_name: &Name,
    response_code: ResponseCode,
    nsec3_records: &[Record],
) -> bool {
    if nsec3_records.is_empty() || nsec3_records.len() > MAX_NSEC3_RECORDS {
        return false;
    }

    struct ParsedNsec3<'a> {
        owner_hash: Vec<u8>,
        rdata: &'a hickory_resolver::proto::rr::dnssec::rdata::NSEC3,
    }

    let mut parsed = Vec::with_capacity(nsec3_records.len());
    for record in nsec3_records {
        if record.name().base_name() != *soa_name
            || record.name().num_labels() != soa_name.num_labels() + 1
        {
            return false;
        }
        let Some(first_label) = record
            .name()
            .iter()
            .next()
            .and_then(|label| std::str::from_utf8(label).ok())
        else {
            return false;
        };
        let Some(owner_hash) = decode_base32hex(first_label) else {
            return false;
        };
        let Some(RData::DNSSEC(DNSSECRData::NSEC3(rdata))) = record.data() else {
            return false;
        };
        if rdata.iterations() > MAX_NSEC3_ITERATIONS {
            return false;
        }
        if owner_hash.is_empty() || owner_hash.len() != rdata.next_hashed_owner_name().len() {
            return false;
        }
        parsed.push(ParsedNsec3 { owner_hash, rdata });
    }
    if parsed.is_empty() {
        return false;
    }

    let hash_name = |entry: &ParsedNsec3<'_>, target: &Name| -> Option<Vec<u8>> {
        entry
            .rdata
            .hash_algorithm()
            .hash(entry.rdata.salt(), target, entry.rdata.iterations())
            .ok()
            .map(|digest| digest.as_ref().to_vec())
    };

    match response_code {
        ResponseCode::NoError => parsed.iter().any(|entry| {
            let Some(qhash) = hash_name(entry, query.name()) else {
                return false;
            };
            entry.owner_hash == qhash
                && !entry.rdata.type_bit_maps().contains(&query.query_type())
                && !entry.rdata.type_bit_maps().contains(&RecordType::CNAME)
        }),
        ResponseCode::NXDomain => {
            // 1. QNAME must not match any NSEC3 owner hash.
            for entry in &parsed {
                let Some(qhash) = hash_name(entry, query.name()) else {
                    return false;
                };
                if entry.owner_hash == qhash {
                    return false;
                }
            }

            // Helper to check if any NSEC3 record covers a target name.
            let find_covering_entry = |target: &Name, require_no_opt_out: bool| -> bool {
                parsed.iter().any(|entry| {
                    if require_no_opt_out && entry.rdata.opt_out() {
                        return false;
                    }
                    hash_name(entry, target).is_some_and(|h| {
                        nsec3_interval_covers(
                            &entry.owner_hash,
                            entry.rdata.next_hashed_owner_name(),
                            &h,
                        )
                    })
                })
            };

            // 2. Candidate ancestor pairs (child, parent_of_child) from QNAME up to soa_name.
            let mut candidates = Vec::new();
            let mut curr = query.name().clone();
            while curr != *soa_name && soa_name.zone_of(&curr) {
                let parent = curr.base_name();
                candidates.push((curr, parent.clone()));
                curr = parent;
            }

            // 3. Find Closest Encloser (CE) and Next Closer (NC).
            let mut ce_and_nc = None;
            for (nc_cand, ce_cand) in &candidates {
                let ce_exists = parsed
                    .iter()
                    .any(|entry| hash_name(entry, ce_cand).is_some_and(|h| entry.owner_hash == h));
                if ce_exists {
                    ce_and_nc = Some((ce_cand.clone(), nc_cand.clone()));
                    break;
                }
            }

            let Some((ce, nc)) = ce_and_nc else {
                return false;
            };

            // 4. Next Closer (NC) must be covered by an NSEC3 record without Opt-Out.
            // RFC 5155 §8.4: The NSEC3 RR covering next closer name MUST NOT have Opt-Out set for NXDOMAIN.
            if !find_covering_entry(&nc, true) {
                return false;
            }

            // 5. Wildcard at Closest Encloser (*.CE) must not exist and must be covered.
            let Ok(wildcard) = Name::from_ascii(format!("*.{ce}")) else {
                return false;
            };
            for entry in &parsed {
                let Some(wchash) = hash_name(entry, &wildcard) else {
                    return false;
                };
                if entry.owner_hash == wchash {
                    return false;
                }
            }
            if !find_covering_entry(&wildcard, true) {
                return false;
            }

            true
        }
        _ => false,
    }
}

/// A local DNSSEC-validating DNS TXT resolver backed by Hickory's [`DnssecDnsHandle`].
///
/// Performs full cryptographic signature and trust-chain verification locally
/// against bundled ICANN root trust anchors.
#[derive(Clone)]
pub struct HickoryDnssecTxtResolver {
    handle: DnssecDnsHandle<SharedDnsHandle>,
    raw_handle: SharedDnsHandle,
    clock: Option<Arc<dyn Fn() -> u32 + Send + Sync>>,
}

impl Default for HickoryDnssecTxtResolver {
    /// Construct the default resolver with strict DNSSEC validation.
    fn default() -> Self {
        Self::new()
    }
}

impl HickoryDnssecTxtResolver {
    /// Construct a resolver with the default multi-provider pool and bundled root trust anchors.
    pub fn new() -> Self {
        Self::with_config(default_resolver_config(), root_trust_anchors())
            .expect("bundled DNS server addresses must be public")
    }

    /// Construct a resolver with custom server configuration and trust anchors.
    /// Reject private or reserved DNS destinations before constructing any transport.
    pub fn with_config(config: ResolverConfig, anchor: TrustAnchor) -> Result<Self> {
        for server in config.name_servers() {
            if crate::ssrf::is_private_or_reserved_ip(server.socket_addr.ip()) {
                return Err(SatsPathError::ValidationError(format!(
                    "Blocked DNS server IP: {}",
                    server.socket_addr.ip()
                )));
            }
        }
        let mut opts = ResolverOpts::default();
        opts.validate = true;
        opts.attempts = 3;
        opts.timeout = std::time::Duration::from_secs(5);
        let conn_provider = GenericConnector::new(TokioRuntimeProvider::new());
        let pool = NameServerPool::from_config(
            NameServerConfigGroup::from(config.name_servers().to_vec()),
            opts.clone(),
            conn_provider,
        );
        let client = RetryDnsHandle::new(pool, opts.attempts);
        Ok(Self::from_dns_handle(client, anchor))
    }

    /// Construct a validating resolver wrapping an arbitrary [`DnsHandle`] and [`TrustAnchor`].
    ///
    /// Useful for deterministic in-process authoritative DNSSEC testing without external network calls.
    pub fn with_dns_handle<H, E>(handle: H, anchor: TrustAnchor) -> Self
    where
        H: DnsHandle<Error = E> + Send + Sync + Unpin + 'static,
        E: std::error::Error + Send + 'static,
    {
        Self::from_dns_handle(handle, anchor)
    }

    /// Construct a validating resolver with a custom clock function for deterministic validation.
    pub fn with_dns_handle_and_clock<H, E, F>(handle: H, anchor: TrustAnchor, clock: F) -> Self
    where
        H: DnsHandle<Error = E> + Send + Sync + Unpin + 'static,
        E: std::error::Error + Send + 'static,
        F: Fn() -> u32 + Send + Sync + 'static,
    {
        let mut resolver = Self::from_dns_handle(handle, anchor);
        resolver.clock = Some(Arc::new(clock));
        resolver
    }

    /// Attach a custom clock function to this resolver.
    pub fn with_clock<F: Fn() -> u32 + Send + Sync + 'static>(mut self, clock: F) -> Self {
        self.clock = Some(Arc::new(clock));
        self
    }

    /// Return the current validation time in seconds since UNIX epoch.
    pub fn now(&self) -> u32 {
        if let Some(ref clock) = self.clock {
            clock()
        } else {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0)
        }
    }

    /// Wrap a prevalidated network pool or an explicitly injected test transport.
    fn from_dns_handle<H, E>(handle: H, anchor: TrustAnchor) -> Self
    where
        H: DnsHandle<Error = E> + Send + Sync + Unpin + 'static,
        E: std::error::Error + Send + 'static,
    {
        let shared = SharedDnsHandle::new(handle);
        let dnssec_handle = DnssecDnsHandle::with_trust_anchor(shared.clone(), anchor);
        Self {
            handle: dnssec_handle,
            raw_handle: shared,
            clock: None,
        }
    }

    /// Cryptographically validate an `NSEC3` negative response against the zone's `DNSKEY`s.
    async fn verify_nsec3_negative_response(
        &self,
        query: &Query,
        raw_response: &DnsResponse,
    ) -> bool {
        if !matches!(
            raw_response.response_code(),
            ResponseCode::NoError | ResponseCode::NXDomain
        ) || !raw_response.answers().is_empty()
        {
            return false;
        }
        let soa_records: Vec<Record> = raw_response
            .name_servers()
            .iter()
            .filter(|rr| rr.record_type() == RecordType::SOA)
            .cloned()
            .collect();
        let Some(soa_first) = soa_records.first() else {
            return false;
        };
        let soa_name = soa_first.name().clone();
        if !soa_name.zone_of(query.name()) || soa_records.iter().any(|rr| rr.name() != &soa_name) {
            return false;
        }
        let nsec3_records: Vec<Record> = raw_response
            .name_servers()
            .iter()
            .filter(|rr| rr.record_type() == RecordType::NSEC3)
            .cloned()
            .collect();
        if nsec3_records.is_empty() || nsec3_records.len() > MAX_NSEC3_RECORDS {
            return false;
        }
        let rrsigs: Vec<(Name, RRSIG)> = raw_response
            .name_servers()
            .iter()
            .filter_map(|rr| match rr.data() {
                Some(RData::DNSSEC(DNSSECRData::RRSIG(sig))) => {
                    Some((rr.name().clone(), sig.clone()))
                }
                _ => None,
            })
            .collect();
        let Ok(dnskey_resp) = self
            .handle
            .lookup(
                Query::query(soa_name.clone(), RecordType::DNSKEY),
                DnsRequestOptions::default(),
            )
            .first_answer()
            .await
        else {
            return false;
        };
        let trusted_keys: Vec<DNSKEY> = dnskey_resp
            .answers()
            .iter()
            .filter(|rr| rr.name() == &soa_name)
            .filter_map(|rr| match rr.data() {
                Some(RData::DNSSEC(DNSSECRData::DNSKEY(key)))
                    if key.zone_key() && !key.revoke() =>
                {
                    Some(key.clone())
                }
                _ => None,
            })
            .collect();
        if trusted_keys.is_empty() {
            return false;
        }
        let now = self.now();
        let soa_rrsigs: Vec<RRSIG> = rrsigs
            .iter()
            .filter(|(owner, sig)| owner == &soa_name && sig.type_covered() == RecordType::SOA)
            .map(|(_, sig)| sig.clone())
            .collect();
        if !verify_rrset_with_trusted_keys(
            &soa_name,
            &soa_name,
            &soa_records,
            &soa_rrsigs,
            &trusted_keys,
            now,
        ) {
            return false;
        }
        let mut nsec3_by_owner: HashMap<Name, Vec<Record>> = HashMap::new();
        for record in &nsec3_records {
            nsec3_by_owner
                .entry(record.name().clone())
                .or_default()
                .push(record.clone());
        }
        for (owner, records) in &nsec3_by_owner {
            let owner_rrsigs: Vec<RRSIG> = rrsigs
                .iter()
                .filter(|(sig_owner, sig)| {
                    sig_owner == owner && sig.type_covered() == RecordType::NSEC3
                })
                .map(|(_, sig)| sig.clone())
                .collect();
            if !verify_rrset_with_trusted_keys(
                owner,
                &soa_name,
                records,
                &owner_rrsigs,
                &trusted_keys,
                now,
            ) {
                return false;
            }
        }
        verify_nsec3_coverage(
            query,
            &soa_name,
            raw_response.response_code(),
            &nsec3_records,
        )
    }
}

#[async_trait]
impl DnsTxtResolver for HickoryDnssecTxtResolver {
    /// Query and cryptographically verify `TXT` records at `fqdn` using [`DnssecDnsHandle`].
    ///
    /// Treats names without a trailing dot as absolute. Returns UTF-8 TXT
    /// character-strings, TTLs in seconds, and `dnssec_validated = true`.
    /// Authenticated `NXDOMAIN` or `NODATA` responses proven by valid `NSEC` or
    /// `NSEC3` records return `AliasNotFound`. Invalid names or non-UTF-8 data
    /// return `Bip353`. Missing signatures or unverifiable results return
    /// `DnssecUnavailable`; other lookup or validation failures return `NetworkError`.
    async fn query_txt(&self, fqdn: &str) -> Result<Vec<DnsTxtRecord>> {
        let name_str = if fqdn.ends_with('.') {
            fqdn.to_string()
        } else {
            format!("{fqdn}.")
        };
        let name = Name::from_ascii(&name_str)
            .map_err(|e| SatsPathError::Bip353(format!("invalid DNS name `{fqdn}`: {e}")))?;

        let query = Query::query(name.clone(), RecordType::TXT);
        let stream = self
            .handle
            .lookup(query.clone(), DnsRequestOptions::default());
        let response = match stream.first_answer().await {
            Ok(response) => {
                let _ = self.raw_handle.take_txt_response(&name);
                response
            }
            Err(e) => {
                let raw_response = self.raw_handle.take_txt_response(&name);
                let msg = e.to_string();
                if msg.contains("could not validate negative response with NSEC") {
                    if let Some(raw) = raw_response {
                        if self.verify_nsec3_negative_response(&query, &raw).await {
                            return Err(SatsPathError::AliasNotFound(fqdn.to_string()));
                        }
                    }
                }
                if msg.contains("rrsigs are not present")
                    || msg.contains("rrsigs is empty")
                    || msg.contains("no results to verify")
                {
                    return Err(SatsPathError::DnssecUnavailable);
                }
                return Err(SatsPathError::NetworkError(format!(
                    "DNSSEC validation failed for `{fqdn}`: {msg}"
                )));
            }
        };

        if !matches!(
            response.response_code(),
            ResponseCode::NoError | ResponseCode::NXDomain
        ) {
            return Err(SatsPathError::NetworkError(format!(
                "DNSSEC validation failed for `{fqdn}`: response code {:?}",
                response.response_code()
            )));
        }

        let mut final_owner = name.clone();
        let mut visited = HashSet::new();
        visited.insert(final_owner.clone());
        for _ in 0..16 {
            let next_target = response.answers().iter().find_map(|record| {
                if record.name() == &final_owner && record.record_type() == RecordType::CNAME {
                    record
                        .data()
                        .and_then(|d| d.as_cname())
                        .map(|c| c.0.clone())
                } else {
                    None
                }
            });
            match next_target {
                Some(target) => {
                    if !visited.insert(target.clone()) {
                        break;
                    }
                    final_owner = target;
                }
                None => break,
            }
        }

        let mut out = Vec::new();
        if response.response_code() == ResponseCode::NoError {
            for record in response.answers() {
                if record.name() != &final_owner || record.record_type() != RecordType::TXT {
                    continue;
                }
                if let Some(txt) = record.data().and_then(|d| d.as_txt()) {
                    let mut strings = Vec::new();
                    for part in txt.iter() {
                        let s = std::str::from_utf8(part)
                            .map_err(|_| SatsPathError::Bip353("TXT record is not UTF-8".into()))?;
                        strings.push(s.to_string());
                    }
                    out.push(DnsTxtRecord {
                        strings,
                        // DnssecDnsHandle::verify_all_rrsets filters response.answers() to only
                        // RRsets whose RRSIG + DNSKEY + DS chain passed cryptographic verification.
                        dnssec_validated: true,
                        ttl_seconds: Some(record.ttl()),
                    });
                }
            }
        }

        if out.is_empty() {
            if verify_nsec_negative_response(&query, &response) {
                return Err(SatsPathError::AliasNotFound(fqdn.to_string()));
            }
            if response.response_code() == ResponseCode::NXDomain {
                return Err(SatsPathError::NetworkError(format!(
                    "DNSSEC validation failed for `{fqdn}`: unverified NXDomain"
                )));
            }
            return Err(SatsPathError::DnssecUnavailable);
        }

        Ok(out)
    }
}

/// BIP-353 payment instruction resolver and adapter for the SatsPath resolver chain.
///
/// DNS payment instructions alone cannot authenticate a SatsPath profile identity key,
/// so [`ProfileResolver::resolve_alias`] returns [`SatsPathError::Bip353Unauthenticated`]
/// unless the DNSSEC-validated record carries an `sp-profile` pointer that passes
/// [`crate::bip353::verify_bip353_ownership`].
pub struct Bip353Resolver {
    dnssec_required: bool,
    dns: Arc<dyn DnsTxtResolver + Send + Sync>,
    continuity_dir: std::path::PathBuf,
    allow_private_profile_url: bool,
}

impl Default for Bip353Resolver {
    /// Construct the default resolver with strict DNSSEC validation.
    fn default() -> Self {
        Self::new(crate::default_data_dir())
    }
}

impl Bip353Resolver {
    /// Construct a BIP-353 resolver backed by [`HickoryDnssecTxtResolver`] storing continuity
    /// in the provided application data directory.
    pub fn new(continuity_dir: impl Into<std::path::PathBuf>) -> Self {
        Self::with_dns_resolver(Arc::new(HickoryDnssecTxtResolver::new()), continuity_dir)
    }

    /// Construct a BIP-353 resolver backed by a custom [`DnsTxtResolver`].
    ///
    /// The backend must truthfully report DNSSEC validation; strict policy rejects
    /// records marked unvalidated. Profile resolution stores continuity in
    /// `continuity_dir`.
    pub fn with_dns_resolver(
        dns: Arc<dyn DnsTxtResolver + Send + Sync>,
        continuity_dir: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            dnssec_required: true,
            dns,
            continuity_dir: continuity_dir.into(),
            allow_private_profile_url: false,
        }
    }

    /// Allow private or loopback IP sp-profile URLs (for integration testing with mock servers).
    #[doc(hidden)]
    pub fn with_allow_private_profile_url(mut self, allow: bool) -> Self {
        self.allow_private_profile_url = allow;
        self
    }

    /// Store TOFU pins, sequences and revocations in this application's data directory.
    pub fn with_continuity_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.continuity_dir = dir.into();
        self
    }

    /// Whether DNSSEC validation is required by this resolver (`true`).
    pub fn dnssec_required(&self) -> bool {
        self.dnssec_required
    }

    /// Resolve a BIP-353 name to its DNSSEC-validated payment instruction under [`DnssecPolicy::Strict`].
    ///
    /// # Errors
    /// Fails closed if DNSSEC validation fails or is unavailable. Name, TXT lookup,
    /// and payment URI validation errors propagate from [`resolve_bip353_with`].
    pub async fn resolve_instruction(&self, name: &str) -> Result<Bip353Resolution> {
        let now = chrono::Utc::now().timestamp();
        resolve_bip353_with(self.dns.as_ref(), name, DnssecPolicy::Strict, now).await
    }
}

#[async_trait]
impl DnsTxtResolver for Bip353Resolver {
    /// Delegate TXT lookup to the configured backend, returning its records and errors unchanged.
    async fn query_txt(&self, fqdn: &str) -> Result<Vec<DnsTxtRecord>> {
        self.dns.query_txt(fqdn).await
    }
}

/// Resolve a `₿`-prefixed alias and fetch its DNSSEC-authenticated `sp-profile`.
///
/// Returns `AliasNotFound` for unsupported or malformed aliases,
/// `Bip353Unauthenticated` when no profile URL is present, and
/// `OwnershipProofInvalid` when the fetched profile fails ownership verification.
/// DNS, URI parsing, HTTP profile validation, and ownership-check errors propagate.
/// Continuity and revocation enforcement are left to the caller.
pub async fn resolve_alias_with(
    resolver: &(impl DnsTxtResolver + Sync + ?Sized),
    alias: &str,
) -> Result<SignedPaymentProfile> {
    resolve_alias_with_allow_private(resolver, alias, false).await
}

/// Resolve a `₿`-prefixed alias and fetch its DNSSEC-authenticated `sp-profile`,
/// optionally allowing private or loopback profile URLs in test environments.
pub async fn resolve_alias_with_allow_private(
    resolver: &(impl DnsTxtResolver + Sync + ?Sized),
    alias: &str,
    allow_private: bool,
) -> Result<SignedPaymentProfile> {
    if !alias.starts_with('₿') {
        return Err(SatsPathError::AliasNotFound(alias.to_string()));
    }
    let _name =
        parse_bip353_name(alias).map_err(|_| SatsPathError::AliasNotFound(alias.to_string()))?;
    let now = chrono::Utc::now().timestamp();
    let resolution = match resolve_bip353_with(resolver, alias, DnssecPolicy::Strict, now).await {
        Ok(resolution) => resolution,
        Err(SatsPathError::AliasNotFound(_)) => {
            return Err(SatsPathError::AliasNotFound(alias.to_string()));
        }
        Err(err) => return Err(err),
    };

    let parsed = crate::bip321::parse_bip321(&resolution.bitcoin_uri)?;
    if let Some(profile_url) = parsed.sp_profile {
        #[cfg(feature = "std")]
        {
            if !allow_private {
                crate::ssrf::validate_url(&profile_url, false)?;
            }
            let http_resolver = crate::resolvers::http::HttpResolver::new();
            let signed = http_resolver.fetch_verified_profile(&profile_url).await?;

            // If sp-profile-hash is present in the URI, enforce that the fetched profile matches.
            if let Some(expected_hash) = &parsed.sp_profile_hash {
                use sha2::Digest;
                let signed_hash = crate::crypto::signed_profile_hash(&signed)?;
                let profile_bytes = crate::crypto::canonical_profile_bytes(&signed.profile)?;
                let profile_hash = hex::encode(sha2::Sha256::digest(&profile_bytes));
                let expected = expected_hash.trim().to_ascii_lowercase();
                if expected != signed_hash && expected != profile_hash {
                    return Err(SatsPathError::OwnershipProofInvalid(
                        "BIP-353 sp-profile-hash mismatch against fetched profile".into(),
                    ));
                }
            }

            if crate::bip353::verify_bip353_ownership(&resolution, &signed)? {
                return Ok(signed);
            }
            return Err(SatsPathError::OwnershipProofInvalid(
                "BIP-353 sp-profile ownership verification failed".into(),
            ));
        }
    }

    // ProfileResolver cannot represent unsigned payment instructions. A local
    // signature would invent an identity and reset profile continuity on every
    // lookup. Fail closed with Bip353Unauthenticated when no sp-profile is present.
    Err(SatsPathError::Bip353Unauthenticated)
}

#[async_trait]
impl ProfileResolver for Bip353Resolver {
    /// Authenticate the DNS pointer and persist continuity before exposing a profile.
    ///
    /// Requires a `₿`-prefixed alias and an authenticated `sp-profile` URL.
    /// Opens or creates the continuity store, checks stored revocations before DNS
    /// lookup, and applies the registry update policy to the fetched profile.
    /// A verified revocation is persisted before returning `RegistryError`.
    /// Alias, DNS, profile validation, transition, and storage errors propagate.
    async fn resolve_alias(&self, alias: &str) -> Result<SignedPaymentProfile> {
        let signed = self.resolve_for_chain(alias).await?;
        if signed.profile.revoked {
            if super::continuity::has_pin(&self.continuity_dir, &signed.profile.alias)? {
                super::continuity::accept_profile(&self.continuity_dir, &signed)?;
            }
            return Err(SatsPathError::RegistryError(format!(
                "Alias {} has been revoked",
                signed.profile.alias
            )));
        }
        super::continuity::accept_profile(&self.continuity_dir, &signed)?;
        Ok(signed)
    }

    /// Authenticate the DNS pointer and check stored revocations while deferring
    /// pin advancement to [`crate::resolver::ChainResolver`].
    async fn resolve_for_chain(&self, alias: &str) -> Result<SignedPaymentProfile> {
        if !alias.starts_with('₿') {
            return Err(SatsPathError::AliasNotFound(alias.to_string()));
        }
        let name = parse_bip353_name(alias)
            .map_err(|_| SatsPathError::AliasNotFound(alias.to_string()))?;
        super::continuity::check_revocation(
            &self.continuity_dir,
            &format!("{}@{}", name.user, name.domain),
        )?;
        resolve_alias_with_allow_private(self.dns.as_ref(), alias, self.allow_private_profile_url)
            .await
    }

    /// Return the configured continuity storage directory for this resolver.
    fn continuity_dir(&self) -> Option<&std::path::Path> {
        Some(&self.continuity_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip353::MockDnsTxtResolver;

    /// Production DNS configuration must never contact internal or reserved endpoints.
    #[test]
    fn rejects_nonpublic_dns_servers() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "192.0.2.1",
            "224.0.0.1",
            "240.0.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
        ] {
            let mut config = default_resolver_config();
            config.add_name_server(NameServerConfig::new(
                SocketAddr::new(ip.parse().unwrap(), 53),
                Protocol::Udp,
            ));
            assert!(
                matches!(
                    HickoryDnssecTxtResolver::with_config(config, root_trust_anchors()),
                    Err(SatsPathError::ValidationError(_))
                ),
                "{ip}"
            );
        }
        assert!(HickoryDnssecTxtResolver::with_config(
            default_resolver_config(),
            root_trust_anchors()
        )
        .is_ok());
    }

    /// Build authenticated TXT responses without external DNS traffic.
    fn resolver(records: &[&[&str]]) -> MockDnsTxtResolver {
        let mut resolver = MockDnsTxtResolver::new();
        for strings in records {
            resolver.insert(
                "alice.user._bitcoin-payment.example.com",
                DnsTxtRecord {
                    strings: strings.iter().map(|s| s.to_string()).collect(),
                    dnssec_validated: true,
                    ttl_seconds: Some(60),
                },
            );
        }
        resolver
    }

    #[tokio::test]
    async fn invalid_aliases_remain_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let resolver = Bip353Resolver::new(tmp.path());
        for alias in [
            "alice@example.com",
            "₿@example.com",
            "₿alice@",
            "₿alice@example.com@other.com",
            "₿₿alice@example.com",
            "₿ali.ce@example.com",
            "₿alice@-example.com",
            "₿alice@example..com",
            "₿álîce@example.com",
        ] {
            assert!(matches!(
                resolver.resolve_alias(alias).await,
                Err(SatsPathError::AliasNotFound(value)) if value == alias
            ));
        }
    }

    #[tokio::test]
    async fn chunked_dns_instructions_never_become_a_signed_profile() {
        let resolver = resolver(&[&["unrelated TXT"], &["bit", "coin:?lno=lno1", "offer"]]);
        for alias in ["₿alice@example.com", "₿alice @ example.com"] {
            for _ in 0..2 {
                assert!(matches!(
                    resolve_alias_with(&resolver, alias).await,
                    Err(SatsPathError::Bip353Unauthenticated)
                ));
            }
        }
    }

    #[tokio::test]
    async fn rejects_ambiguous_records_including_chunked_schemes() {
        let resolver = resolver(&[
            &["bitcoin:?lno=lno1first"],
            &["bit", "coin:?lno=lno1second"],
        ]);
        assert!(matches!(
            resolve_alias_with(&resolver, "₿alice@example.com").await,
            Err(SatsPathError::Bip353(message)) if message.contains("multiple")
        ));
    }

    #[tokio::test]
    async fn does_not_join_separate_resource_records() {
        let resolver = resolver(&[&["bit"], &["coin:?lno=lno1offer"]]);
        assert!(matches!(
            resolve_alias_with(&resolver, "₿alice@example.com").await,
            Err(SatsPathError::Bip353(message)) if message.contains("no bitcoin:")
        ));
    }

    #[tokio::test]
    async fn validates_reconstructed_payload_before_profile_resolution() {
        let required = resolver(&[&["bitcoin:?lno=lno1offer&req-", "future=1"]]);
        assert!(matches!(
            resolve_alias_with(&required, "₿alice@example.com").await,
            Err(SatsPathError::InvalidPaymentUri(_))
        ));
        let private = resolver(&[&["bitcoin:?lno=lno1offer&note=x", "prv123"]]);
        assert!(matches!(
            resolve_alias_with(&private, "₿alice@example.com").await,
            Err(SatsPathError::PrivateMaterialRejected(_))
        ));
    }
}
