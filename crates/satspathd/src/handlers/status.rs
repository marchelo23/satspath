//! Status, node, and profile response handlers.

use anyhow::Result;
use satspath_core::{crypto::fingerprint_pubkey, TransactionalTransparencyStore};

use crate::config::AppState;
use crate::handlers::profile::profile_response;
use crate::handlers::wallet::load_wallet;
use crate::types::{safety_status, NodeResponse, StatusResponse};

pub(crate) fn node_response(state: &AppState) -> Result<NodeResponse> {
    Ok(NodeResponse {
        status: status_response(state)?,
        profile: profile_response(state)?,
    })
}

pub(crate) fn status_response(state: &AppState) -> Result<StatusResponse> {
    let wallet = load_wallet(&state.home)?;
    let mut methods = Vec::new();
    if let Some(alias) = wallet.alias.as_deref() {
        if let Ok(store) = TransactionalTransparencyStore::open(&state.home) {
            if let Ok(Some(signed)) = store.profile(alias) {
                methods = signed
                    .profile
                    .methods
                    .clone()
                    .into_iter()
                    .map(|m| m.method_name().to_string())
                    .collect();
            }
        }
    }

    let identity_fingerprint = wallet
        .identity_pubkey
        .as_deref()
        .map(fingerprint_pubkey)
        .transpose()?;
    Ok(StatusResponse {
        daemon: "satspathd",
        version: env!("CARGO_PKG_VERSION"),
        bind: state.bind.to_string(),
        network: state.network.clone(),
        home: state.home.display().to_string(),
        wallet_initialized: wallet.identity_pubkey.is_some(),
        alias: wallet.alias,
        identity_fingerprint,
        methods,
        safety: safety_status(),
        rate_limit: state.rate_limiter.stats(),
        is_tls: state.is_tls,
        behind_proxy: state.rate_limiter.trust_proxy_headers(),
    })
}

pub(crate) fn print_startup_status(state: &AppState) -> Result<()> {
    let status = status_response(state)?;
    println!("satspathd node starting");
    println!("  bind: {}", status.bind);
    println!("  network: {}", status.network);
    println!("  home: {}", status.home);
    println!(
        "  identity: {}",
        status
            .identity_fingerprint
            .as_deref()
            .unwrap_or("(not initialized)")
    );
    println!(
        "  alias: {}",
        status.alias.as_deref().unwrap_or("(not configured)")
    );
    println!(
        "  methods: {}",
        if status.methods.is_empty() {
            "(none)".into()
        } else {
            status.methods.join(", ")
        }
    );
    println!(
        "  rate limit: burst={}, rate={:.1}/s, max_body={}B, behind_proxy={}",
        status.rate_limit.burst_capacity,
        status.rate_limit.refill_rate_per_sec,
        status.rate_limit.max_body_bytes,
        status.rate_limit.trust_proxy_headers
    );
    println!(
        "  transport: scheme={}, tls={}, behind_proxy={}",
        if status.is_tls { "https" } else { "http" },
        status.is_tls,
        status.behind_proxy
    );
    println!("  safety: profile node only; no funds moved, no Bitcoin tx signing, no broadcast");
    Ok(())
}
