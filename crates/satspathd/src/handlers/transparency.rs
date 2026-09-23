//! Transparency log handlers: checkpoints, events, proofs, anchors, namespace.

use std::fs;
use std::path::Path;

use anyhow::Result;
use satspath_core::{MerkleConsistencyProof, TransactionalTransparencyStore, TransparencyLog};
use serde::Serialize;

use crate::config::AppState;
use crate::http::write_owner_only_file;

pub(crate) fn transparency_log(state: &AppState) -> Result<TransparencyLog> {
    transparency_log_at(&state.home)
}

pub(crate) fn transparency_log_at(home: &Path) -> Result<TransparencyLog> {
    Ok(TransactionalTransparencyStore::open(home)?.load_log()?)
}

pub(crate) fn load_or_create_transparency_operator(home: &Path) -> Result<secp256k1::SecretKey> {
    let dir = home.join("transparency");
    fs::create_dir_all(&dir)?;
    let path = dir.join("operator.key");
    if path.exists() {
        let bytes = hex::decode(fs::read_to_string(path)?.trim())?;
        return secp256k1::SecretKey::from_slice(&bytes).map_err(Into::into);
    }
    let key = satspath_core::crypto::generate_identity_keypair().secret_key;
    write_owner_only_file(&path, hex::encode(key.secret_bytes()).as_bytes())?;
    Ok(key)
}

pub(crate) fn query_u64(url: &str, name: &str) -> Option<u64> {
    url.split_once('?')?.1.split('&').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        (key == name).then(|| value.parse().ok()).flatten()
    })
}

pub(crate) fn query_str(url: &str, name: &str) -> Option<String> {
    url.split_once('?')?.1.split('&').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        if key == name {
            url::form_urlencoded::parse(part.as_bytes())
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.into_owned())
                .or_else(|| Some(value.to_string()))
        } else {
            None
        }
    })
}

pub(crate) fn paginated<T: Clone + Serialize>(url: &str, items: &[T]) -> serde_json::Value {
    let offset = query_u64(url, "offset")
        .unwrap_or(0)
        .min(items.len() as u64) as usize;
    let limit = query_u64(url, "limit").unwrap_or(50).clamp(1, 200) as usize;
    let page: Vec<_> = items.iter().skip(offset).take(limit).cloned().collect();
    serde_json::json!({"items": page, "offset": offset, "limit": limit, "total": items.len()})
}

pub(crate) fn consistency_from_query(
    state: &AppState,
    url: &str,
) -> Result<MerkleConsistencyProof> {
    let from = query_u64(url, "from").ok_or_else(|| anyhow::anyhow!("missing from tree size"))?;
    let to = query_u64(url, "to").ok_or_else(|| anyhow::anyhow!("missing to tree size"))?;
    Ok(transparency_log(state)?.consistency(from, to)?)
}

pub(crate) async fn anchor_latest_checkpoint(
    state: &AppState,
) -> Result<satspath_core::TransparencyBitcoinAnchor> {
    let log = transparency_log(state)?;
    let checkpoint = log
        .checkpoints()
        .last()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no checkpoint to anchor"))?;
    let checkpoint_hash = checkpoint.checkpoint_hash()?;
    let client = satspath_core::transparency::RegtestAnchorClient::from_env()?;
    let anchor = client.anchor_checkpoint(&checkpoint_hash).await?;
    if !anchor.verified {
        anyhow::bail!("regtest anchor could not be verified after confirmation");
    }
    let operator = load_or_create_transparency_operator(&state.home)?;
    let mut anchored = checkpoint;
    anchored.bitcoin_anchor = Some(anchor.clone());
    anchored.sign(&operator)?;
    TransactionalTransparencyStore::open(&state.home)?
        .replace_latest_checkpoint(&checkpoint_hash, &anchored)?;
    Ok(anchor)
}

pub(crate) fn namespace_descriptor(
    state: &AppState,
) -> Result<satspath_core::transparency::NamespaceDescriptor> {
    let domain =
        std::env::var("SATSPATH_AUTHORITY_DOMAIN").unwrap_or_else(|_| "localhost".to_string());
    let wallet = crate::handlers::wallet::load_wallet(&state.home)?;
    let authority_pubkey = wallet.identity_pubkey.clone().unwrap_or_else(|| {
        "0000000000000000000000000000000000000000000000000000000000000000".to_string()
    });
    let log = transparency_log(state).ok();
    let log_id = log
        .as_ref()
        .map(|l| l.log_id().to_string())
        .unwrap_or_else(|| format!("satspath:{domain}"));
    let endpoint_urls = if let Ok(custom_url) = std::env::var("SATSPATH_AUTHORITY_URL") {
        vec![custom_url]
    } else if domain != "localhost" {
        vec![format!("https://{domain}/v2")]
    } else {
        vec![format!("http://{}/v2", state.bind)]
    };
    let quorum = std::env::var("SATSPATH_WITNESS_QUORUM")
        .ok()
        .and_then(|q| q.parse::<u8>().ok())
        .unwrap_or(1);
    let now = chrono::Utc::now().timestamp();

    Ok(satspath_core::transparency::NamespaceDescriptor {
        version: 2,
        domain,
        log_id,
        authority_pubkey,
        endpoint_urls,
        witness_quorum: quorum,
        witness_pubkeys: vec![],
        valid_from: now,
        expires_at: now + 30 * 86400,
        signature: String::new(),
    })
}
