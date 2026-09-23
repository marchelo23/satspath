//! HTTP server lifecycle: TLS setup, serve loop, binding security audit.

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tiny_http::Server;

use crate::config::AppState;
use crate::router::handle_request;
use crate::ui::open_browser;

pub(crate) fn audit_binding_security(
    bind: SocketAddr,
    is_tls: bool,
    behind_proxy: bool,
    require_tls_or_proxy: bool,
) -> Result<()> {
    let is_loopback = bind.ip().is_loopback();
    if !is_loopback && !is_tls && !behind_proxy {
        if require_tls_or_proxy {
            anyhow::bail!(
                "Security violation: satspathd cannot bind to non-loopback address {} without \
                 native TLS (--tls-cert/--tls-key) or reverse proxy trust (--behind-proxy). \
                 Failing closed (--require-tls-or-proxy is active).",
                bind
            );
        } else {
            eprintln!("\n{}", "!".repeat(80));
            eprintln!("SECURITY WARNING: INSECURE CLEARTEXT BINDING DETECTED!");
            eprintln!("satspathd is binding to non-loopback address {bind} without TLS or --behind-proxy.");
            eprintln!("Authentication tokens and sensitive profile mutations will be transmitted in cleartext.");
            eprintln!(
                "Adversaries on the local network can intercept admin tokens and alter profiles."
            );
            eprintln!("RECOMMENDATIONS:");
            eprintln!("  1. Production: Run behind a TLS reverse proxy (Nginx/Caddy) and pass --behind-proxy.");
            eprintln!("  2. Standalone: Provide TLS certificates via --tls-cert and --tls-key.");
            eprintln!("  3. Local development: Bind to 127.0.0.1:9737.");
            eprintln!("{}\n", "!".repeat(80));
        }
    }
    Ok(())
}

pub(crate) async fn serve(state: AppState, tls_config: Option<(PathBuf, PathBuf)>) -> Result<()> {
    let scheme = if tls_config.is_some() {
        "https"
    } else {
        "http"
    };
    let server = if let Some((cert_path, key_path)) = tls_config {
        let certificate = fs::read(&cert_path)
            .with_context(|| format!("reading TLS certificate from {}", cert_path.display()))?;
        let private_key = fs::read(&key_path)
            .with_context(|| format!("reading TLS private key from {}", key_path.display()))?;
        let ssl_config = tiny_http::SslConfig {
            certificate,
            private_key,
        };
        Arc::new(Server::https(state.bind, ssl_config).map_err(|e| {
            anyhow::anyhow!(
                "could not start HTTPS server on {}: {e}\n\nVerify certificate and private key formats.",
                state.bind
            )
        })?)
    } else {
        Arc::new(Server::http(state.bind).map_err(|e| {
            anyhow::anyhow!(
                "could not bind {}: {e}\n\nThe address may already be in use by another \
                 satspathd instance. Stop it, or choose another port with \
                 `--bind 127.0.0.1:<port>`.",
                state.bind
            )
        })?)
    };
    let url = format!("{scheme}://{}/", state.bind);
    println!("Wallet UI -> {url}");
    if state.open_ui {
        open_browser(&url);
    }
    let state = Arc::new(state);
    serve_server(state, server).await
}

pub(crate) async fn serve_server(state: Arc<AppState>, server: Arc<Server>) -> Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<tiny_http::Request>(64);
    let srv = Arc::clone(&server);
    tokio::task::spawn_blocking(move || {
        for request in srv.incoming_requests() {
            if tx.blocking_send(request).is_err() {
                break;
            }
        }
    });

    let semaphore = Arc::new(tokio::sync::Semaphore::new(64));
    while let Some(request) = rx.recv().await {
        let state = Arc::clone(&state);
        let sem = Arc::clone(&semaphore);
        tokio::spawn(async move {
            let _permit = match sem.acquire_owned().await {
                Ok(p) => p,
                Err(_) => return,
            };
            if let Err(e) = handle_request(request, &state).await {
                eprintln!("request error: {e}");
            }
        });
    }
    Ok(())
}
