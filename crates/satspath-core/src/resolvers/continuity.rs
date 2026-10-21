//! Durable resolver identity pins, serialized across threads and processes by SQLite.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use crate::privacy::{canonical_identifier, identifier_hash, validate_ascii_identifier};
use crate::registry::Registry;
use crate::{Result, SatsPathError, SignedPaymentProfile};

/// Strip at most one leading `₿` and return the canonical ASCII identifier.
fn normalize_alias(alias: &str) -> String {
    let trimmed = alias.trim();
    let unprefixed = trimmed.strip_prefix('₿').unwrap_or(trimmed).trim();
    if let Some((user, domain)) = unprefixed.split_once('@') {
        canonical_identifier(&format!("{}@{}", user.trim(), domain.trim()))
    } else {
        canonical_identifier(unprefixed)
    }
}

/// Validate a signed profile's structure, expiry, public material, and signature
/// while allowing at most one leading `₿` on the profile alias.
fn validate_signed_candidate(signed: &SignedPaymentProfile) -> Result<String> {
    let trimmed = signed.profile.alias.trim();
    if let Some(unprefixed) = trimmed.strip_prefix('₿') {
        validate_ascii_identifier(unprefixed)?;
        let canonical = canonical_identifier(unprefixed);
        if unprefixed != canonical {
            return Err(SatsPathError::RegistryError(
                "canonical profile alias does not match requested registry key".into(),
            ));
        }
        crate::validation::validate_compressed_pubkey(&signed.profile.identity_pubkey)?;
        crate::crypto::check_profile_expiry(&signed.profile)?;
        let canonical_bytes = crate::crypto::canonical_profile_bytes(&signed.profile)?;
        let canonical_text = std::str::from_utf8(&canonical_bytes)
            .map_err(|e| SatsPathError::SerializationError(e.to_string()))?;
        crate::validation::assert_no_private_material(canonical_text)?;
        if !crate::crypto::verify_signed_profile(signed)? {
            return Err(SatsPathError::InvalidSignature);
        }
        Ok(canonical)
    } else {
        Registry::validate_profile_write(&signed.profile.alias, signed)?;
        Ok(canonical_identifier(&signed.profile.alias))
    }
}

/// Validate a candidate transition against the stored pin without mutating SQLite.
pub(crate) fn validate_candidate(dir: &Path, signed: &SignedPaymentProfile) -> Result<()> {
    let canonical = validate_signed_candidate(signed)?;
    let connection = open_store(dir)?;
    let key = identifier_hash(&canonical);
    let previous: Option<String> = connection
        .query_row(
            "SELECT signed FROM profiles WHERE alias_hash = ?1",
            [&key],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage_error)?;
    let previous: Option<SignedPaymentProfile> = previous
        .map(|json| serde_json::from_str(&json))
        .transpose()?;
    validate_transition_rules(&canonical, signed, previous.as_ref())
}

/// Enforce key continuity, sequence progression, and same-sequence immutability.
fn validate_transition_rules(
    canonical: &str,
    signed: &SignedPaymentProfile,
    previous: Option<&SignedPaymentProfile>,
) -> Result<()> {
    if let Some(prev) = previous {
        let same_bytes = crate::crypto::canonical_profile_bytes(&prev.profile)?
            == crate::crypto::canonical_profile_bytes(&signed.profile)?;
        // Re-observing the exact profile is neither a rollback nor a fork.
        if !prev.profile.revoked && !signed.profile.revoked && same_bytes {
            return Ok(());
        }
        if prev.profile.sequence.is_none()
            && signed.profile.sequence.is_none()
            && !signed.profile.revoked
            && !same_bytes
        {
            return Err(SatsPathError::RegistryError(
                "Update rejected: profile mutated without sequence progression".into(),
            ));
        }
    }
    Registry::validate_profile_transition(canonical, signed, previous)
}

/// Return whether `dir` already holds an authorized continuity record for `alias`.
pub(crate) fn has_pin(dir: &Path, alias: &str) -> Result<bool> {
    let canonical = normalize_alias(alias);
    let connection = open_store(dir)?;
    let previous: Option<String> = connection
        .query_row(
            "SELECT signed FROM profiles WHERE alias_hash = ?1",
            [identifier_hash(&canonical)],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage_error)?;
    Ok(previous.is_some())
}

/// Atomically check and persist a fetched profile using the registry's update policy.
/// A verified revocation is committed as a tombstone and then returned as an error.
///
/// `dir` holds the continuity database and is created if missing. Propagates
/// profile-write and transition validation errors; storage failures return
/// `RegistryError`, and JSON errors propagate as `JsonError`.
pub(crate) fn accept_profile(dir: &Path, signed: &SignedPaymentProfile) -> Result<()> {
    let canonical = validate_signed_candidate(signed)?;
    let mut connection = open_store(dir)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(storage_error)?;
    let key = identifier_hash(&canonical);
    let previous: Option<String> = tx
        .query_row(
            "SELECT signed FROM profiles WHERE alias_hash = ?1",
            [&key],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage_error)?;
    let previous: Option<SignedPaymentProfile> = previous
        .map(|json| serde_json::from_str(&json))
        .transpose()?;
    validate_transition_rules(&canonical, signed, previous.as_ref())?;
    let json = serde_json::to_string(signed)?;
    tx.execute(
        "INSERT INTO profiles (alias_hash, signed) VALUES (?1, ?2)
         ON CONFLICT(alias_hash) DO UPDATE SET signed = excluded.signed",
        rusqlite::params![key, json],
    )
    .map_err(storage_error)?;
    tx.commit().map_err(storage_error)?;
    if signed.profile.revoked {
        return Err(SatsPathError::RegistryError(
            "BIP-353 identity has been revoked".into(),
        ));
    }
    Ok(())
}

/// Check durable tombstones before any network error could trigger resolver fallback.
///
/// `alias` is normalized by stripping at most one leading `₿`. Opens or creates
/// the store in `dir`; an unknown or unrevoked alias succeeds. Revocations and
/// storage failures return `RegistryError`; malformed stored profiles return `JsonError`.
pub(crate) fn check_revocation(dir: &Path, alias: &str) -> Result<()> {
    let canonical = normalize_alias(alias);
    let connection = open_store(dir)?;
    let previous: Option<String> = connection
        .query_row(
            "SELECT signed FROM profiles WHERE alias_hash = ?1",
            [identifier_hash(&canonical)],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage_error)?;
    if let Some(json) = previous {
        let signed: SignedPaymentProfile = serde_json::from_str(&json)?;
        if signed.profile.revoked {
            return Err(SatsPathError::RegistryError(
                "BIP-353 identity has been revoked".into(),
            ));
        }
    }
    Ok(())
}

/// Open the persistent store and configure a bounded wait for concurrent writers.
/// Creates `dir` and the table if needed, with a five-second SQLite busy timeout.
/// Filesystem and SQLite failures
/// return `RegistryError`.
fn open_store(dir: &Path) -> Result<Connection> {
    std::fs::create_dir_all(dir).map_err(|e| SatsPathError::RegistryError(e.to_string()))?;
    let connection =
        Connection::open(dir.join("bip353-continuity.sqlite3")).map_err(storage_error)?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(storage_error)?;
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS profiles (alias_hash TEXT PRIMARY KEY, signed TEXT NOT NULL);",
    ).map_err(storage_error)?;
    Ok(connection)
}

/// Storage failures must stop the resolver chain instead of permitting fallback.
fn storage_error(error: rusqlite::Error) -> SatsPathError {
    SatsPathError::RegistryError(format!("BIP-353 continuity storage failed: {error}"))
}
