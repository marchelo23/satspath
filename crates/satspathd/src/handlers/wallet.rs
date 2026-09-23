//! Wallet persistence: load/save wallet state and identity keys.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use satspath_core::crypto::generate_identity_keypair;
use satspath_core::validation::assert_no_private_material;

use crate::config::{WalletState, IDENTITY_SUBDIR};
use crate::http::write_owner_only_file;

pub(crate) fn load_or_create_identity(home: &Path) -> Result<WalletState> {
    let mut wallet = load_wallet(home)?;
    if wallet.identity_pubkey.is_some() {
        return Ok(wallet);
    }
    let kp = generate_identity_keypair();
    let pubkey = hex::encode(kp.public_key.serialize());
    save_identity_key(home, &kp.secret_key)?;
    wallet.identity_pubkey = Some(pubkey);
    wallet.created_at = Some(crate::types::now());
    wallet.updated_at = Some(crate::types::now());
    save_wallet(home, &wallet)?;
    Ok(wallet)
}

pub(crate) fn load_wallet(home: &Path) -> Result<WalletState> {
    let path = crate::config::wallet_path(home);
    if !path.exists() {
        return Ok(WalletState::default());
    }
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

pub(crate) fn save_wallet(home: &Path, wallet: &WalletState) -> Result<()> {
    fs::create_dir_all(home)?;
    let json = serde_json::to_string_pretty(wallet)?;
    assert_no_private_material(&json)?;
    write_owner_only_file(&crate::config::wallet_path(home), json.as_bytes())?;
    Ok(())
}

pub(crate) fn save_identity_key(home: &Path, secret_key: &secp256k1::SecretKey) -> Result<PathBuf> {
    let secp = secp256k1::Secp256k1::new();
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, secret_key);
    let dir = home.join(IDENTITY_SUBDIR);
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.key", hex::encode(pubkey.serialize())));
    write_owner_only_file(&path, hex::encode(secret_key.secret_bytes()).as_bytes())?;
    Ok(path)
}

pub(crate) fn load_identity_key(
    home: &Path,
    identity_pubkey: &str,
) -> Result<secp256k1::SecretKey> {
    let path = home
        .join(IDENTITY_SUBDIR)
        .join(format!("{identity_pubkey}.key"));
    let hex_secret = fs::read_to_string(&path)
        .with_context(|| format!("reading identity key at {}", path.display()))?;
    let bytes = hex::decode(hex_secret.trim())?;
    let secret = secp256k1::SecretKey::from_slice(&bytes)?;
    let secp = secp256k1::Secp256k1::new();
    let actual = secp256k1::PublicKey::from_secret_key(&secp, &secret);
    if hex::encode(actual.serialize()) != identity_pubkey {
        anyhow::bail!("identity key file does not match wallet identity pubkey");
    }
    Ok(secret)
}
