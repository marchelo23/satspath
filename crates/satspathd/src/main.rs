//! `satspathd` is a local receiver-profile daemon.
//!
//! It manages SatsPath profile identity and public receive pointers only. It
//! does not move funds, sign Bitcoin transactions, broadcast transactions, or
//! store Bitcoin wallet seeds/spending keys.

mod v2_api;

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use qrcode::{Color, QrCode};
use satspath_core::ark::validate_ark_server_url;
use satspath_core::bip321::{parse_bip321, ParsedBip321Uri};
use satspath_core::bip353::{resolve_bip353_with, Bip353Resolution, DnssecPolicy, DohTxtResolver};
use satspath_core::crypto::{
    fingerprint_pubkey, generate_identity_keypair, sign_profile, verify_signed_profile,
};
use satspath_core::privacy::mask_identifier;
use satspath_core::registry::Registry;
use satspath_core::resolver::ChainResolver;
use satspath_core::resolver::ProfileResolver as _;
use satspath_core::resolvers::{bip353::Bip353Resolver, http::HttpResolver, nostr::NostrResolver};
use satspath_core::validation::{
    assert_no_private_material, validate_amount_sats, validate_bitcoin_address,
    validate_compressed_pubkey, validate_lightning_address,
};
use satspath_core::{
    BitcoinNetwork, CheckpointStore, MerkleConsistencyProof, MerkleInclusionProof, NameAction,
    NameEvent, PaymentMethod, PaymentProfile, ResolvedTransparentProfile, ResolverSource,
    SatsPathError, SignedPaymentProfile, TransactionalTransparencyStore, TransparencyLog,
    VerificationStates,
};
use satspath_router::fees::fetch_fee_estimate;
use satspath_router::select_priority_route;
use satspath_router::QuoteResponse;
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

const DEFAULT_BIND: &str = "127.0.0.1:9737";
const DEFAULT_NETWORK: &str = "devnet";
const WALLET_FILE: &str = "wallet.json";
const IDENTITY_SUBDIR: &str = "identity";

#[derive(Parser)]
#[command(
    name = "satspathd",
    about = "Local SatsPath receiver-profile daemon",
    version = "0.1.0"
)]
struct Cli {
    /// HTTP bind address. Defaults to SATSPATHD_BIND or 127.0.0.1:9737.
    #[arg(long)]
    bind: Option<String>,
    /// SatsPath network label. Defaults to SATSPATH_NETWORK or devnet.
    #[arg(long)]
    network: Option<String>,
    /// SatsPath home directory. Defaults to SATSPATH_HOME or ~/.satspath.
    #[arg(long)]
    home: Option<PathBuf>,
    /// Do not open the wallet UI in a browser on startup.
    #[arg(long)]
    no_open: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct WalletState {
    #[serde(skip_serializing_if = "Option::is_none")]
    alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lightning_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    onchain_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    onchain_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ark_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ark_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<i64>,
}

#[derive(Clone)]
struct AppState {
    home: PathBuf,
    bind: SocketAddr,
    network: String,
    open_ui: bool,
    auth_token: String,
    mutation_lock: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    daemon: &'static str,
    version: &'static str,
    bind: String,
    network: String,
    home: String,
    wallet_initialized: bool,
    alias: Option<String>,
    identity_fingerprint: Option<String>,
    methods: Vec<String>,
    safety: SafetyStatus,
}

#[derive(Debug, Serialize)]
struct NodeResponse {
    status: StatusResponse,
    profile: ProfileResponse,
}

#[derive(Debug, Serialize)]
struct SafetyStatus {
    moves_funds: bool,
    signs_bitcoin_transactions: bool,
    broadcasts_transactions: bool,
    stores_wallet_seeds_or_spending_keys: bool,
    manages_signed_profiles: bool,
}

#[derive(Debug, Deserialize)]
struct ProfileUpdateRequest {
    alias: Option<String>,
    lightning_address: Option<String>,
    onchain_address: Option<String>,
    onchain_pubkey: Option<String>,
    ark_server: Option<String>,
    ark_pubkey: Option<String>,
    #[serde(default)]
    remove_methods: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AliasRequest {
    alias: String,
}

#[derive(Debug, Deserialize)]
struct VerifyRequest {
    alias: String,
    token: String,
}

#[derive(Debug, Deserialize)]
struct QuoteRequest {
    recipient: String,
    amount_sats: u64,
}

#[derive(Debug, Deserialize)]
struct PayRequest {
    recipient: String,
    amount_sats: u64,
    #[serde(default)]
    memo: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DnsResolveRequest {
    name: String,
    #[serde(default)]
    allow_insecure_dns_for_dev: bool,
}

#[derive(Debug, Serialize)]
struct ProfileResponse {
    wallet: WalletState,
    signed_profile: Option<SignedPaymentProfile>,
    signature_valid: Option<bool>,
}

#[derive(Debug, Serialize)]
struct PreviewResponse<T: Serialize> {
    mode: &'static str,
    warnings: Vec<&'static str>,
    quote: T,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum PayResponse {
    WalletHandoff {
        decision_protocol: &'static str,
        recipient: String,
        amount_sats: u64,
        quote: QuoteResponse,
        payment_payload: String,
        qr_svg: String,
        handoff: WalletHandoff,
        safety: SafetyStatus,
    },
    InviteCreated {
        decision_protocol: &'static str,
        recipient_hint: String,
        amount_sats: u64,
        quote: QuoteResponse,
        safety: SafetyStatus,
    },
    NoRoute {
        decision_protocol: &'static str,
        reason: String,
        quote: QuoteResponse,
        safety: SafetyStatus,
    },
    InvalidSignature {
        decision_protocol: &'static str,
        quote: QuoteResponse,
        safety: SafetyStatus,
    },
}

#[derive(Debug, Serialize)]
struct WalletHandoff {
    mode: &'static str,
    instruction: &'static str,
    opens_external_wallet: bool,
    daemon_executes_payment: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
enum DnsResolveResponse {
    Ok {
        resolution: Bip353Resolution,
        parsed: ParsedBip321Uri,
    },
    Error {
        name: String,
        error: String,
        strict_mode: bool,
    },
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Deserialize)]
struct InclusionVerifyRequest {
    event_hash: String,
    proof: MerkleInclusionProof,
    checkpoint: satspath_core::TransparencyCheckpoint,
}

#[derive(Debug, Deserialize)]
struct ConsistencyVerifyRequest {
    proof: MerkleConsistencyProof,
}

#[derive(Debug, Serialize)]
struct KeyRotationResponse {
    alias: String,
    sequence: u64,
    previous_fingerprint: String,
    new_fingerprint: String,
    event_hash: String,
    checkpoint_hash: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let bind = cli
        .bind
        .or_else(|| std::env::var("SATSPATHD_BIND").ok())
        .unwrap_or_else(|| DEFAULT_BIND.to_string())
        .parse::<SocketAddr>()
        .context("invalid bind address")?;
    let network = cli
        .network
        .or_else(|| std::env::var("SATSPATH_NETWORK").ok())
        .unwrap_or_else(|| DEFAULT_NETWORK.to_string());
    let home = cli
        .home
        .or_else(|| std::env::var_os("SATSPATH_HOME").map(PathBuf::from))
        .unwrap_or_else(default_home);

    fs::create_dir_all(&home).context("creating SATSPATH_HOME")?;

    // SEC-04: Daemon API Authorization
    let macaroon_path = home.join("admin.macaroon");
    let auth_token = if let Ok(token) = std::env::var("SATSPATHD_AUTH_TOKEN") {
        let t = token.trim().to_string();
        if t.len() != 64 || hex::decode(&t).is_err() {
            anyhow::bail!(
                "SATSPATHD_AUTH_TOKEN must be a valid 64-character hex string (32 bytes)"
            );
        }
        t
    } else if !macaroon_path.exists() {
        use secp256k1::rand::RngCore;
        let mut token = [0u8; 32];
        secp256k1::rand::thread_rng().fill_bytes(&mut token);
        let token_hex = hex::encode(token);
        write_owner_only_file(&macaroon_path, token_hex.as_bytes())
            .context("writing admin.macaroon")?;
        token_hex
    } else {
        let content = fs::read_to_string(&macaroon_path).context("reading admin.macaroon")?;
        let t = content.trim().to_string();
        if t.len() != 64 || hex::decode(&t).is_err() {
            anyhow::bail!("admin.macaroon must be a valid 64-character hex string (32 bytes)");
        }
        t
    };

    load_or_create_identity(&home)?;

    let state = AppState {
        home,
        bind,
        network,
        open_ui: !cli.no_open,
        auth_token,
        mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
    };

    print_startup_status(&state)?;
    serve(state).await
}

async fn serve(state: AppState) -> Result<()> {
    let server = Arc::new(Server::http(state.bind).map_err(|e| {
        anyhow::anyhow!(
            "could not bind {}: {e}\n\nThe address may already be in use by another \
             satspathd instance. Stop it, or choose another port with \
             `--bind 127.0.0.1:<port>`.",
            state.bind
        )
    })?);
    let url = format!("http://{}/", state.bind);
    println!("Wallet UI → {url}");
    if state.open_ui {
        open_browser(&url);
    }
    let state = Arc::new(state);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Request>(64);
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

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn check_auth(request: &Request, expected_token: &str) -> anyhow::Result<()> {
    if expected_token.is_empty() {
        anyhow::bail!("Unauthorized: Admin auth token is not configured (fail-closed)");
    }
    for header in request.headers() {
        if header.field.equiv("Authorization") {
            let val = header.value.as_str();
            if let Some(bearer) = val.strip_prefix("Bearer ") {
                if constant_time_eq(bearer.trim().as_bytes(), expected_token.as_bytes()) {
                    return Ok(());
                }
            }
        }
    }
    anyhow::bail!("Unauthorized: Invalid or missing Bearer token");
}

async fn handle_request(mut request: Request, state: &AppState) -> Result<()> {
    let method = request.method().clone();
    let raw_url = request.url().to_string();
    let path = raw_url.split('?').next().unwrap_or("/").to_string();

    let is_mutation = !matches!(method, Method::Get | Method::Head | Method::Options);
    let is_public_mutation = path == "/v1/receive"
        || path == "/v1/send"
        || path == "/v1/dns/resolve"
        || path == "/v1/transparency/verify/inclusion";

    if is_mutation && !is_public_mutation {
        if let Err(e) = check_auth(&request, &state.auth_token) {
            let _ = request.respond(json_error(StatusCode(401), e));
            return Ok(());
        }
    }

    let response = match (method.clone(), path.as_str()) {
        (Method::Options, _) => empty_response(StatusCode(204)),
        (Method::Get, "/") => html_response(INDEX_HTML),
        (Method::Post, "/v1/receive") => match read_json::<ReceiveRequest>(&mut request) {
            Ok(body) => json_result(StatusCode(200), receive_view(state, body)),
            Err(e) => json_error(StatusCode(400), e),
        },
        (Method::Post, "/v1/send") => match read_json::<SendRequest>(&mut request) {
            Ok(body) => json_response(StatusCode(200), &send_response(state, body).await),
            Err(e) => json_error(StatusCode(400), e),
        },
        (Method::Post, "/v1/broadcast") => json_result(StatusCode(200), broadcast(state)),
        (Method::Get, "/health") => {
            json_response(StatusCode(200), &serde_json::json!({"ok": true}))
        }
        (Method::Get, v2_api::routes::HEALTH) => {
            let (checkpoint_age, log_ok) = match transparency_log(state) {
                Ok(log) => {
                    let latest = log.checkpoints().last().map(|c| c.created_at).unwrap_or(0);
                    let now = chrono::Utc::now().timestamp();
                    let age = if latest == 0 { 0 } else { now - latest };
                    (age, true)
                }
                Err(_) => (-1, false),
            };
            let resp = v2_api::build_health_response(checkpoint_age, log_ok, 1);
            let status = if resp.status == "healthy" {
                StatusCode(200)
            } else {
                StatusCode(503)
            };
            json_response(status, &resp)
        }
        (Method::Get, "/.well-known/satspath-authority")
        | (Method::Get, v2_api::routes::NAMESPACE) => {
            json_result(StatusCode(200), namespace_descriptor(state))
        }
        (Method::Get, "/v1/node") => json_result(StatusCode(200), node_response(state)),
        (Method::Get, "/v1/status") => json_result(StatusCode(200), status_response(state)),
        (Method::Get, "/v1/profile") => json_result(StatusCode(200), profile_response(state)),
        (Method::Get, "/v1/transparency/status") => json_result(
            StatusCode(200),
            transparency_log(state).and_then(|log| log.status().map_err(Into::into)),
        ),
        (Method::Get, "/v1/transparency/checkpoints") => json_result(
            StatusCode(200),
            transparency_log(state).map(|log| paginated(&raw_url, log.checkpoints())),
        ),
        (Method::Get, "/v1/transparency/events") => json_result(
            StatusCode(200),
            transparency_log(state).map(|log| paginated(&raw_url, log.events())),
        ),
        (Method::Get, p) if p.starts_with("/v1/transparency/checkpoints/") => {
            let hash = p.trim_start_matches("/v1/transparency/checkpoints/");
            json_result(
                StatusCode(200),
                transparency_log(state).and_then(|log| {
                    log.checkpoints()
                        .iter()
                        .find(|c| c.checkpoint_hash().ok().as_deref() == Some(hash))
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("checkpoint not found"))
                }),
            )
        }
        (Method::Get, p) if p.starts_with("/v1/transparency/events/") => {
            let hash = p.trim_start_matches("/v1/transparency/events/");
            json_result(
                StatusCode(200),
                transparency_log(state).and_then(|log| {
                    log.event(hash).map_err(Into::into).and_then(|e| {
                        e.cloned()
                            .ok_or_else(|| SatsPathError::AliasNotFound(hash.into()))
                            .map_err(Into::into)
                    })
                }),
            )
        }
        (Method::Get, p) if p.starts_with("/v1/transparency/identifiers/") => {
            let identifier = p.trim_start_matches("/v1/transparency/identifiers/");
            json_result(StatusCode(200), transparency_log(state).map(|log| {
                let events: Vec<_> = log.history(identifier).into_iter().cloned().collect();
                serde_json::json!({"identifier_hash": identifier, "latest": events.last(), "history": events})
            }))
        }
        (Method::Get, p) if p.starts_with("/v1/transparency/inclusion/") => {
            let hash = p.trim_start_matches("/v1/transparency/inclusion/");
            json_result(
                StatusCode(200),
                transparency_log(state)
                    .and_then(|log| log.inclusion(hash, None).map_err(Into::into)),
            )
        }
        (Method::Get, p) if p.starts_with("/v1/transparency/anchors/") => {
            let txid = p.trim_start_matches("/v1/transparency/anchors/");
            json_result(
                StatusCode(200),
                transparency_log(state).and_then(|log| {
                    log.checkpoints()
                        .iter()
                        .filter_map(|c| c.bitcoin_anchor.as_ref())
                        .find(|a| a.txid == txid)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("anchor not found"))
                }),
            )
        }
        (Method::Post, "/v1/transparency/anchors") => match anchor_latest_checkpoint(state).await {
            Ok(anchor) => json_response(StatusCode(200), &anchor),
            Err(e) => json_error(StatusCode(400), e),
        },
        (Method::Get, "/v1/transparency/consistency") => {
            json_result(StatusCode(200), consistency_from_query(state, &raw_url))
        }
        (Method::Post, "/v1/transparency/verify/inclusion") => {
            match read_json::<InclusionVerifyRequest>(&mut request).and_then(|body| {
                satspath_core::transparency::verify_checkpoint_inclusion(
                    &body.event_hash,
                    &body.proof,
                    &body.checkpoint,
                )
                .map(|_| true)
                .map_err(Into::into)
            }) {
                Ok(valid) => json_response(StatusCode(200), &serde_json::json!({"valid": valid})),
                Err(e) => json_error(StatusCode(400), e),
            }
        }
        (Method::Post, "/v1/transparency/verify/consistency") => {
            match read_json::<ConsistencyVerifyRequest>(&mut request).and_then(|body| {
                satspath_core::transparency::verify_consistency_proof(&body.proof)
                    .map_err(Into::into)
            }) {
                Ok(valid) => json_response(StatusCode(200), &serde_json::json!({"valid": valid})),
                Err(e) => json_error(StatusCode(400), e),
            }
        }
        (Method::Put, "/v1/profile") | (Method::Post, "/v1/profile") => {
            let _guard = state.mutation_lock.lock().await;
            match read_json::<ProfileUpdateRequest>(&mut request)
                .and_then(|body| update_profile(state, body))
            {
                Ok(resp) => json_response(StatusCode(200), &resp),
                Err(e) => json_error(StatusCode(400), e),
            }
        }
        (Method::Post, "/v1/profile/challenge") => {
            match read_json::<AliasRequest>(&mut request)
                .and_then(|body| create_challenge(state, body))
            {
                Ok(resp) => json_response(StatusCode(200), &resp),
                Err(e) => json_error(StatusCode(400), e),
            }
        }
        (Method::Post, "/v1/profile/verify") => {
            let _guard = state.mutation_lock.lock().await;
            match read_json::<VerifyRequest>(&mut request)
                .and_then(|body| verify_challenge(state, body))
            {
                Ok(resp) => json_response(StatusCode(200), &resp),
                Err(e) => json_error(StatusCode(400), e),
            }
        }
        (Method::Post, "/v1/profile/methods") => {
            let _guard = state.mutation_lock.lock().await;
            match read_json::<ProfileUpdateRequest>(&mut request)
                .and_then(|body| update_profile_methods(state, body))
            {
                Ok(resp) => json_response(StatusCode(200), &resp),
                Err(e) => json_error(StatusCode(400), e),
            }
        }
        (Method::Post, "/v1/profile/rotate-key") => {
            let _guard = state.mutation_lock.lock().await;
            match rotate_profile_key(state) {
                Ok(response) => json_response(StatusCode(200), &response),
                Err(error) => json_error(StatusCode(400), error),
            }
        }
        (Method::Post, "/v1/resolve") => match read_json::<AliasRequest>(&mut request)
            .and_then(|body| resolve_profile(state, &body.alias))
        {
            Ok(profile) => json_response(StatusCode(200), &profile),
            Err(e) => json_error(StatusCode(404), e),
        },
        (Method::Post, "/v1/quote") => match read_json::<QuoteRequest>(&mut request) {
            Ok(body) => json_response(StatusCode(200), &quote_response(state, body).await),
            Err(e) => json_error(StatusCode(400), e),
        },
        (Method::Post, "/v1/pay") => match read_json::<PayRequest>(&mut request) {
            Ok(body) => json_response(StatusCode(200), &pay_response(state, body).await),
            Err(e) => json_error(StatusCode(400), e),
        },
        (Method::Post, "/v1/dns/resolve") => match read_json::<DnsResolveRequest>(&mut request) {
            Ok(body) => json_response(StatusCode(200), &dns_resolve_response(body).await),
            Err(e) => json_error(StatusCode(400), e),
        },
        (Method::Post, "/v1/preview") => match read_json::<QuoteRequest>(&mut request) {
            Ok(body) => {
                let quote = quote_response(state, body).await;
                json_response(
                    StatusCode(200),
                    &PreviewResponse {
                        mode: "preview_only",
                        warnings: safety_warnings(),
                        quote,
                    },
                )
            }
            Err(e) => json_error(StatusCode(400), e),
        },
        _ => json_error(StatusCode(404), anyhow::anyhow!("endpoint not found")),
    };
    request.respond(response)?;
    Ok(())
}

fn transparency_log(state: &AppState) -> Result<TransparencyLog> {
    transparency_log_at(&state.home)
}

fn query_u64(url: &str, name: &str) -> Option<u64> {
    url.split_once('?')?.1.split('&').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        (key == name).then(|| value.parse().ok()).flatten()
    })
}

fn paginated<T: Clone + Serialize>(url: &str, items: &[T]) -> serde_json::Value {
    let offset = query_u64(url, "offset")
        .unwrap_or(0)
        .min(items.len() as u64) as usize;
    let limit = query_u64(url, "limit").unwrap_or(50).clamp(1, 200) as usize;
    let page: Vec<_> = items.iter().skip(offset).take(limit).cloned().collect();
    serde_json::json!({"items": page, "offset": offset, "limit": limit, "total": items.len()})
}

fn consistency_from_query(state: &AppState, url: &str) -> Result<MerkleConsistencyProof> {
    let from = query_u64(url, "from").ok_or_else(|| anyhow::anyhow!("missing from tree size"))?;
    let to = query_u64(url, "to").ok_or_else(|| anyhow::anyhow!("missing to tree size"))?;
    Ok(transparency_log(state)?.consistency(from, to)?)
}

async fn anchor_latest_checkpoint(
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

fn update_profile(state: &AppState, body: ProfileUpdateRequest) -> Result<ProfileResponse> {
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

fn create_challenge(_state: &AppState, body: AliasRequest) -> Result<serde_json::Value> {
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

fn verify_challenge(state: &AppState, body: VerifyRequest) -> Result<ProfileResponse> {
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

fn update_profile_methods(state: &AppState, body: ProfileUpdateRequest) -> Result<ProfileResponse> {
    let mut wallet = load_or_create_identity(&state.home)?;
    if wallet.alias.is_none() {
        anyhow::bail!("set alias first with PUT /v1/profile");
    }
    apply_method_updates(&mut wallet, &state.network, body, false)?;
    sign_and_store(&state.home, &mut wallet, &state.network)?;
    save_wallet(&state.home, &wallet)?;
    profile_response(state)
}

fn apply_method_updates(
    wallet: &mut WalletState,
    network: &str,
    body: ProfileUpdateRequest,
    allow_empty: bool,
) -> Result<()> {
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
        validate_bitcoin_address(&addr, bitcoin_network(network))?;
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
            validate_ark_server_url(&server)?;
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

fn sign_and_store(home: &Path, wallet: &mut WalletState, network: &str) -> Result<()> {
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
        expires_at: Some(t + 30 * 24 * 3600), // default 30-day expiry per spec §28
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
                .map(|descriptor| {
                    satspath_core::transparency::payment_method_descriptor_hash(&descriptor)
                })
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

fn transparency_log_at(home: &Path) -> Result<TransparencyLog> {
    Ok(TransactionalTransparencyStore::open(home)?.load_log()?)
}

fn load_or_create_transparency_operator(home: &Path) -> Result<secp256k1::SecretKey> {
    let dir = home.join("transparency");
    fs::create_dir_all(&dir)?;
    let path = dir.join("operator.key");
    if path.exists() {
        let bytes = hex::decode(fs::read_to_string(path)?.trim())?;
        return secp256k1::SecretKey::from_slice(&bytes).map_err(Into::into);
    }
    let key = generate_identity_keypair().secret_key;
    write_owner_only_file(&path, hex::encode(key.secret_bytes()).as_bytes())?;
    Ok(key)
}

fn rotate_profile_key(state: &AppState) -> Result<KeyRotationResponse> {
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

fn resolve_profile(state: &AppState, alias: &str) -> Result<ResolvedTransparentProfile> {
    let store = TransactionalTransparencyStore::open(&state.home)?;
    let signed = store
        .profile(alias)?
        .ok_or_else(|| SatsPathError::AliasNotFound(alias.into()))?;
    let profile_signature_verified = verify_signed_profile(&signed)?;
    if !profile_signature_verified {
        anyhow::bail!("stored profile signature is invalid");
    }
    let log = transparency_log(state)?;
    let identifier_hash = satspath_core::privacy::identifier_hash(alias);
    let history: Vec<_> = log.history(&identifier_hash).into_iter().cloned().collect();
    satspath_core::transparency::verify_identifier_history(&history)?;
    let latest_event = history
        .last()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("profile has no transparency history"))?;
    if !satspath_core::transparency::verify_event_profile(&latest_event, &signed)? {
        anyhow::bail!("profile does not match its latest transparency event");
    }
    let event_hash = latest_event.event_hash()?;
    let inclusion_proof = log.inclusion(&event_hash, None)?;
    let checkpoint = log
        .checkpoints()
        .last()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("transparency checkpoint unavailable"))?;
    satspath_core::transparency::verify_checkpoint_inclusion(
        &event_hash,
        &inclusion_proof,
        &checkpoint,
    )?;
    let transparency_inclusion_verified = true;
    let pins = CheckpointStore::new(&state.home).load()?;
    let pinned = pins.iter().find(|p| p.log_id == checkpoint.log_id);
    let consistency_proof = pinned
        .filter(|p| p.tree_size < checkpoint.log_size)
        .map(|p| log.consistency(p.tree_size, checkpoint.log_size))
        .transpose()?;
    if let Some(pin) = pinned {
        satspath_core::transparency::verify_checkpoint_transition(
            pin,
            &checkpoint,
            consistency_proof.as_ref(),
        )?;
    }
    CheckpointStore::new(&state.home).pin(&checkpoint)?;
    let payment_method_states = satspath_core::verify_payment_method_states(&signed.profile, now());
    let payment_methods_verified = !payment_method_states.is_empty()
        && payment_method_states.iter().all(|state| state.verified);
    let identifier_attestation = latest_event
        .identifier_attestation_hash
        .as_deref()
        .map(|hash| store.identifier_attestation(hash))
        .transpose()?
        .flatten();
    let trusted_verifiers: Vec<satspath_core::TrustedVerifier> =
        std::env::var("SATSPATH_TRUSTED_VERIFIERS_JSON")
            .ok()
            .map(|json| serde_json::from_str(&json))
            .transpose()
            .context("invalid SATSPATH_TRUSTED_VERIFIERS_JSON")?
            .unwrap_or_default();
    let identifier_verified = identifier_attestation
        .as_ref()
        .map(|attestation| {
            satspath_core::transparency::verify_attestation_binding(
                attestation,
                &latest_event,
                &trusted_verifiers,
                now(),
            )
        })
        .transpose()?
        .unwrap_or(false);
    Ok(ResolvedTransparentProfile {
        signed_profile: signed,
        latest_event,
        inclusion_proof,
        checkpoint,
        consistency_proof,
        identifier_attestation,
        resolver_source: ResolverSource::LocalRegistry,
        verification: VerificationStates {
            profile_signature_verified,
            identifier_verified,
            key_continuity_verified: true,
            transparency_inclusion_verified,
            checkpoint_binding_verified: true,
            checkpoint_consistency_verified: true,
            operator_continuity_verified: true,
            payment_methods_verified,
            payment_method_states,
        },
    })
}

async fn quote_response(state: &AppState, body: QuoteRequest) -> satspath_router::QuoteResponse {
    if let Err(e) = validate_amount_sats(body.amount_sats) {
        return satspath_router::QuoteResponse::NoRoute {
            reason: e.to_string(),
        };
    }
    let resolved = match resolve_profile(state, &body.recipient) {
        Ok(resolved) => resolved,
        Err(error) => {
            return satspath_router::QuoteResponse::NoRoute {
                reason: format!("transparency verification failed: {error}"),
            }
        }
    };
    let allowed: Vec<String> = resolved
        .verification
        .payment_method_states
        .iter()
        .filter(|state| state.verified)
        .map(|state| state.descriptor.clone())
        .collect();
    satspath_router::quote_verified_profile(
        resolved.signed_profile,
        &body.recipient,
        body.amount_sats,
        &allowed,
    )
    .await
}

async fn pay_response(state: &AppState, body: PayRequest) -> PayResponse {
    if let Err(e) = validate_amount_sats(body.amount_sats) {
        let quote = QuoteResponse::NoRoute {
            reason: e.to_string(),
        };
        return PayResponse::NoRoute {
            decision_protocol: "satspathd.v1",
            reason: e.to_string(),
            quote,
            safety: safety_status(),
        };
    }
    if let Some(memo) = &body.memo {
        if let Err(e) = assert_no_private_material(memo) {
            let quote = QuoteResponse::NoRoute {
                reason: e.to_string(),
            };
            return PayResponse::NoRoute {
                decision_protocol: "satspathd.v1",
                reason: e.to_string(),
                quote,
                safety: safety_status(),
            };
        }
    }

    let quote = quote_response(
        state,
        QuoteRequest {
            recipient: body.recipient.clone(),
            amount_sats: body.amount_sats,
        },
    )
    .await;

    match quote.clone() {
        QuoteResponse::Ok { qr, .. } => match qr_svg(&qr) {
            Ok(qr_svg) => PayResponse::WalletHandoff {
                decision_protocol: "satspathd.v1",
                recipient: body.recipient,
                amount_sats: body.amount_sats,
                quote,
                payment_payload: qr,
                qr_svg,
                handoff: WalletHandoff {
                    mode: "external_wallet",
                    instruction: "Open or scan payment_payload with a wallet you control.",
                    opens_external_wallet: true,
                    daemon_executes_payment: false,
                },
                safety: safety_status(),
            },
            Err(e) => PayResponse::NoRoute {
                decision_protocol: "satspathd.v1",
                reason: e.to_string(),
                quote,
                safety: safety_status(),
            },
        },
        QuoteResponse::NotRegistered { .. } => PayResponse::InviteCreated {
            decision_protocol: "satspathd.v1",
            recipient_hint: mask_identifier(&body.recipient),
            amount_sats: body.amount_sats,
            quote,
            safety: safety_status(),
        },
        QuoteResponse::NoRoute { reason } => PayResponse::NoRoute {
            decision_protocol: "satspathd.v1",
            reason,
            quote,
            safety: safety_status(),
        },
        QuoteResponse::InvalidSignature { .. } => PayResponse::InvalidSignature {
            decision_protocol: "satspathd.v1",
            quote,
            safety: safety_status(),
        },
    }
}

async fn dns_resolve_response(body: DnsResolveRequest) -> DnsResolveResponse {
    let policy = if body.allow_insecure_dns_for_dev {
        DnssecPolicy::DevInsecure
    } else {
        DnssecPolicy::Strict
    };
    let resolver = DohTxtResolver::new();
    match resolve_bip353_with(&resolver, &body.name, policy, now()).await {
        Ok(resolution) => match parse_bip321(&resolution.bitcoin_uri) {
            Ok(parsed) => DnsResolveResponse::Ok { resolution, parsed },
            Err(e) => DnsResolveResponse::Error {
                name: body.name,
                error: e.to_string(),
                strict_mode: policy == DnssecPolicy::Strict,
            },
        },
        Err(e) => DnsResolveResponse::Error {
            name: body.name,
            error: e.to_string(),
            strict_mode: policy == DnssecPolicy::Strict,
        },
    }
}

fn profile_response(state: &AppState) -> Result<ProfileResponse> {
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

fn node_response(state: &AppState) -> Result<NodeResponse> {
    Ok(NodeResponse {
        status: status_response(state)?,
        profile: profile_response(state)?,
    })
}

fn status_response(state: &AppState) -> Result<StatusResponse> {
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
    })
}

fn safety_status() -> SafetyStatus {
    SafetyStatus {
        moves_funds: false,
        signs_bitcoin_transactions: false,
        broadcasts_transactions: false,
        stores_wallet_seeds_or_spending_keys: false,
        manages_signed_profiles: true,
    }
}

fn resolver_chain(home: &Path) -> ChainResolver {
    let mut chain = ChainResolver::new();
    if let Ok(registry) = Registry::open(home) {
        chain = chain.push(registry);
    }
    chain
        .push(Bip353Resolver::new())
        .push(HttpResolver::new())
        .push(NostrResolver::new())
}

fn build_methods(wallet: &WalletState, network: &str) -> Vec<PaymentMethod> {
    let mut methods = Vec::new();
    if let Some(addr) = &wallet.lightning_address {
        methods.push(PaymentMethod::Lightning {
            label: "Lightning Address".into(),
            lightning_address: Some(addr.clone()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        });
    }
    if let Some(addr) = &wallet.onchain_address {
        methods.push(PaymentMethod::Onchain {
            label: format!("Bitcoin ({})", network),
            network: bitcoin_network(network),
            address: Some(addr.clone()),
            silent_payment_pubkey: None,
            pubkey_hint: wallet.onchain_pubkey.clone(),
            descriptor_hint: None,
            address_list: vec![],
        });
    }
    if let (Some(server), Some(pubkey)) = (&wallet.ark_server, &wallet.ark_pubkey) {
        methods.push(PaymentMethod::Ark {
            label: "Ark".into(),
            server: server.clone(),
            pubkey: pubkey.clone(),
            vtxo_pointer: None,
            opaque_uri: None,
            proof: None,
            expires_at: None,
        });
    }
    methods
}

fn load_or_create_identity(home: &Path) -> Result<WalletState> {
    let mut wallet = load_wallet(home)?;
    if wallet.identity_pubkey.is_some() {
        return Ok(wallet);
    }
    let kp = generate_identity_keypair();
    let pubkey = hex::encode(kp.public_key.serialize());
    save_identity_key(home, &kp.secret_key)?;
    wallet.identity_pubkey = Some(pubkey);
    wallet.created_at = Some(now());
    wallet.updated_at = Some(now());
    save_wallet(home, &wallet)?;
    Ok(wallet)
}

fn load_wallet(home: &Path) -> Result<WalletState> {
    let path = wallet_path(home);
    if !path.exists() {
        return Ok(WalletState::default());
    }
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

fn save_wallet(home: &Path, wallet: &WalletState) -> Result<()> {
    fs::create_dir_all(home)?;
    let json = serde_json::to_string_pretty(wallet)?;
    assert_no_private_material(&json)?;
    write_owner_only_file(&wallet_path(home), json.as_bytes())?;
    Ok(())
}

fn save_identity_key(home: &Path, secret_key: &secp256k1::SecretKey) -> Result<PathBuf> {
    let secp = secp256k1::Secp256k1::new();
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, secret_key);
    let dir = home.join(IDENTITY_SUBDIR);
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.key", hex::encode(pubkey.serialize())));
    write_owner_only_file(&path, hex::encode(secret_key.secret_bytes()).as_bytes())?;
    Ok(path)
}

fn load_identity_key(home: &Path, identity_pubkey: &str) -> Result<secp256k1::SecretKey> {
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

fn write_owner_only_file(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    use secp256k1::rand::RngCore;
    let mut rand_bytes = [0u8; 16];
    secp256k1::rand::thread_rng().fill_bytes(&mut rand_bytes);
    let tmp_path = parent.join(format!(".tmp-{}", hex::encode(rand_bytes)));
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&tmp_path)?;
        file.write_all(content)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&tmp_path, content)?;
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}

fn namespace_descriptor(
    state: &AppState,
) -> Result<satspath_core::transparency::NamespaceDescriptor> {
    let domain =
        std::env::var("SATSPATH_AUTHORITY_DOMAIN").unwrap_or_else(|_| "localhost".to_string());
    let wallet = load_wallet(&state.home)?;
    let authority_pubkey = wallet.identity_pubkey.clone().unwrap_or_else(|| {
        "0000000000000000000000000000000000000000000000000000000000000000".to_string()
    });
    let log = transparency_log(state).ok();
    let log_id = log
        .as_ref()
        .map(|l| l.log_id().to_string())
        .unwrap_or_else(|| format!("satspath:{domain}"));
    let endpoint_urls = authority_endpoint_urls(
        std::env::var("SATSPATH_AUTHORITY_URL").ok(),
        &domain,
        state.bind,
    );
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

fn authority_endpoint_urls(
    custom_url: Option<String>,
    domain: &str,
    bind: SocketAddr,
) -> Vec<String> {
    if let Some(custom_url) = custom_url
        .as_deref()
        .map(str::trim)
        .filter(|url| !url.is_empty())
    {
        return vec![custom_url.to_owned()];
    }

    if domain != "localhost" {
        vec![format!("https://{domain}/v2")]
    } else {
        vec![format!("http://{bind}/v2")]
    }
}

fn print_startup_status(state: &AppState) -> Result<()> {
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
    println!("  safety: profile node only; no funds moved, no Bitcoin tx signing, no broadcast");
    Ok(())
}

const MAX_JSON_BODY_BYTES: u64 = 1024 * 1024; // 1 MB limit to prevent DoS

fn read_json<T: for<'de> Deserialize<'de>>(request: &mut Request) -> Result<T> {
    use std::io::Read;
    let mut body = String::new();
    let mut reader = request.as_reader().take(MAX_JSON_BODY_BYTES);
    reader.read_to_string(&mut body)?;
    if body.trim().is_empty() {
        anyhow::bail!("request body must be JSON");
    }
    Ok(serde_json::from_str(&body)?)
}

fn json_result<T: Serialize>(
    status: StatusCode,
    result: Result<T>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    match result {
        Ok(value) => json_response(status, &value),
        Err(e) => json_error(status, e),
    }
}

// ─── Receive wallet UI ─────────────────────────────────────────────────────────

const INDEX_HTML: &str = include_str!("index.html");

#[derive(Debug, Serialize)]
struct ReceiveView {
    /// Masked alias, e.g. `r***@gmail.com` — the raw identifier is never exposed.
    alias: String,
    rail: String,
    payload: String,
    qr_svg: String,
}

#[derive(Debug, Deserialize)]
struct ReceiveRequest {
    rail: Option<String>,
    amount_sats: Option<u64>,
}
/// Compute the wallet owner's preferred receive QR, entirely locally. Prefers
/// Lightning → on-chain → Ark. Returns a reusable (amount-less) receive pointer.
fn receive_view(state: &AppState, req: ReceiveRequest) -> Result<ReceiveView> {
    let wallet = load_wallet(&state.home)?;
    let alias = wallet
        .alias
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no profile yet — set one via POST /v1/profile"))?;
    let methods = build_methods(&wallet, &state.network);

    let method = if let Some(req_rail) = req.rail {
        let req_rail = req_rail.to_lowercase();
        methods
            .into_iter()
            .find(|m| m.method_name().to_lowercase() == req_rail)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "requested rail '{}' is not configured in your profile",
                    req_rail
                )
            })?
    } else {
        methods
            .iter()
            .find(|m| matches!(m, PaymentMethod::Lightning { .. }))
            .or_else(|| {
                methods
                    .iter()
                    .find(|m| matches!(m, PaymentMethod::Onchain { .. }))
            })
            .or_else(|| {
                methods
                    .iter()
                    .find(|m| matches!(m, PaymentMethod::Ark { .. }))
            })
            .ok_or_else(|| {
                anyhow::anyhow!("no receive methods — add one via POST /v1/profile/methods")
            })?
            .clone()
    };

    let mut payload = receive_payload_for(&method)?;

    // Append amount if requested
    if let Some(sats) = req.amount_sats {
        if matches!(method, PaymentMethod::Onchain { .. }) {
            payload = format!("{}?amount={}", payload, fmt_btc(sats));
        } else if matches!(method, PaymentMethod::Ark { .. }) {
            payload = format!("{}&amount={}", payload, sats);
        }
        // Note: Lightning Address/LNURL doesn't support amount in the static string.
    }

    Ok(ReceiveView {
        alias: mask_identifier(&alias),
        rail: method.method_name().to_string(),
        qr_svg: qr_svg(&payload)?,
        payload,
    })
}

/// A public, amount-less receive pointer for a method.
fn receive_payload_for(method: &PaymentMethod) -> Result<String> {
    let payload = match method {
        PaymentMethod::Lightning {
            lightning_address: Some(addr),
            ..
        } => addr.clone(),
        PaymentMethod::Lightning {
            lnurl: Some(url), ..
        } => url.clone(),
        PaymentMethod::Onchain {
            address,
            silent_payment_pubkey,
            ..
        } => {
            let target = silent_payment_pubkey
                .clone()
                .unwrap_or_else(|| address.clone().unwrap_or_default());
            format!("bitcoin:{target}")
        }
        PaymentMethod::Ark { server, pubkey, .. } => {
            format!("satspath:ark?server={server}&pubkey={pubkey}")
        }
        _ => anyhow::bail!("selected method has no receive pointer"),
    };
    assert_no_private_material(&payload)?;
    Ok(payload)
}

/// Render a payload as a self-contained black-and-white SVG QR.
fn qr_svg(data: &str) -> Result<String> {
    let code = QrCode::new(data.as_bytes()).map_err(|e| anyhow::anyhow!("QR encode: {e}"))?;
    let width = code.width();
    let colors = code.to_colors();
    let quiet = 4usize;
    let size = width + quiet * 2;
    let mut rects = String::new();
    for y in 0..width {
        for x in 0..width {
            if colors[y * width + x] == Color::Dark {
                rects.push_str(&format!(
                    "<rect x='{}' y='{}' width='1' height='1'/>",
                    x + quiet,
                    y + quiet
                ));
            }
        }
    }
    Ok(format!(
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {size} {size}' \
         shape-rendering='crispEdges'><rect width='100%' height='100%' fill='#fff'/>\
         <g fill='#000'>{rects}</g></svg>"
    ))
}

fn html_response(body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let ct = Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
        .expect("static header");
    let xcto =
        Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..]).expect("static header");
    let xfo = Header::from_bytes(&b"X-Frame-Options"[..], &b"DENY"[..]).expect("static header");
    let csp = Header::from_bytes(
        &b"Content-Security-Policy"[..],
        &b"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"[..],
    )
    .expect("static header");

    Response::from_data(body.as_bytes().to_vec())
        .with_status_code(StatusCode(200))
        .with_header(ct)
        .with_header(xcto)
        .with_header(xfo)
        .with_header(csp)
        .with_header(cors_origin_header())
}

/// Best-effort open of the default browser. Never fails the daemon.
fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let (cmd, args): (&str, Vec<&str>) = ("open", vec![url]);
    #[cfg(target_os = "linux")]
    let (cmd, args): (&str, Vec<&str>) = ("xdg-open", vec![url]);
    #[cfg(target_os = "windows")]
    let (cmd, args): (&str, Vec<&str>) = ("cmd", vec!["/C", "start", "", url]);
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let (cmd, args): (&str, Vec<&str>) = ("", vec![]);
    if !cmd.is_empty() {
        let _ = Command::new(cmd).args(args).spawn();
    }
}

fn json_response<T: Serialize>(
    status: StatusCode,
    value: &T,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body =
        serde_json::to_vec_pretty(value).unwrap_or_else(|_| b"{\"error\":\"json\"}".to_vec());
    Response::from_data(body)
        .with_status_code(status)
        .with_header(json_header())
        .with_header(cors_origin_header())
        .with_header(cors_methods_header())
        .with_header(cors_headers_header())
}

fn empty_response(status: StatusCode) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_data(Vec::new())
        .with_status_code(status)
        .with_header(cors_origin_header())
        .with_header(cors_methods_header())
        .with_header(cors_headers_header())
}

fn json_error(status: StatusCode, error: anyhow::Error) -> Response<std::io::Cursor<Vec<u8>>> {
    json_response(
        status,
        &ErrorResponse {
            error: error.to_string(),
        },
    )
}

fn json_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("valid static header")
}

fn cors_origin_header() -> Header {
    // SEC-CORS: Restrict to local daemon UI and Arkade wallet origins.
    // Override via SATSPATHD_CORS_ORIGIN env var for custom deployments.
    let origin = std::env::var("SATSPATHD_CORS_ORIGIN").unwrap_or_else(|_| {
        "http://localhost:5173, http://localhost:3000, http://127.0.0.1:5173, https://app.arkade.money".to_string()
    });
    // Note: Access-Control-Allow-Origin only supports a single origin value or '*'.
    // For multiple origins, the server should echo back the request Origin if it's
    // in the allowed list. Since tiny_http doesn't give us per-request headers easily,
    // we use the first allowed origin as default. In production, use a reverse proxy
    // (nginx/caddy) for proper multi-origin CORS.
    let first_origin = origin
        .split(',')
        .next()
        .unwrap_or("http://localhost:5173")
        .trim();
    Header::from_bytes(&b"Access-Control-Allow-Origin"[..], first_origin.as_bytes())
        .expect("valid static header")
}

fn cors_methods_header() -> Header {
    Header::from_bytes(
        &b"Access-Control-Allow-Methods"[..],
        &b"GET, POST, OPTIONS"[..],
    )
    .expect("valid static header")
}

fn cors_headers_header() -> Header {
    Header::from_bytes(
        &b"Access-Control-Allow-Headers"[..],
        &b"Content-Type, Authorization, X-Request-Id"[..],
    )
    .expect("valid static header")
}

fn safety_warnings() -> Vec<&'static str> {
    vec![
        "satspathd does not move funds",
        "satspathd does not sign Bitcoin transactions",
        "satspathd does not broadcast transactions",
        "payment execution happens in an external wallet",
    ]
}

fn wallet_path(home: &Path) -> PathBuf {
    home.join(WALLET_FILE)
}

fn default_home() -> PathBuf {
    // Prefer a `.satspath/` in the current directory (e.g. a wallet created with
    // `satspath wallet ...`) so the daemon serves the same profile seamlessly;
    // otherwise fall back to the per-user `~/.satspath`.
    let local = PathBuf::from(".satspath");
    if local.is_dir() {
        return local;
    }
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".satspath")
    } else {
        local
    }
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn bitcoin_network(network: &str) -> BitcoinNetwork {
    match network.to_ascii_lowercase().as_str() {
        "mainnet" | "bitcoin" => BitcoinNetwork::Mainnet,
        "regtest" => BitcoinNetwork::Regtest,
        // devnet uses testnet-form receive addresses until a distinct core
        // network enum is added.
        _ => BitcoinNetwork::Testnet,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_creation_persists_public_wallet_state_only() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = load_or_create_identity(dir.path()).unwrap();
        assert!(wallet.identity_pubkey.is_some());
        let raw = fs::read_to_string(wallet_path(dir.path())).unwrap();
        assert!(!raw.contains("xprv"));
        assert!(!raw.contains("mnemonic"));
        assert!(!raw.contains("secret_key"));
    }

    fn test_state(home: &Path) -> AppState {
        AppState {
            home: home.to_owned(),
            bind: "127.0.0.1:0".parse().unwrap(),
            network: "devnet".into(),
            open_ui: false,
            auth_token: "test_auth_token".into(),
            mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    #[test]
    fn authority_endpoint_urls_trim_custom_url_and_fall_back_when_blank() {
        let bind = "127.0.0.1:9737".parse().unwrap();

        assert_eq!(
            authority_endpoint_urls(
                Some("  https://authority.example/v2  ".to_string()),
                "authority.example",
                bind,
            ),
            vec!["https://authority.example/v2"]
        );
        assert_eq!(
            authority_endpoint_urls(Some(" \t\n ".to_string()), "authority.example", bind),
            vec!["https://authority.example/v2"]
        );
        assert_eq!(
            authority_endpoint_urls(Some(String::new()), "localhost", bind),
            vec!["http://127.0.0.1:9737/v2"]
        );
    }

    #[tokio::test]
    async fn quote_rejects_profile_without_transparency() {
        let dir = tempfile::tempdir().unwrap();
        let key = generate_identity_keypair();
        let profile = PaymentProfile {
            alias: "alice@example.com".into(),
            identity_pubkey: hex::encode(key.public_key.serialize()),
            methods: vec![PaymentMethod::Lightning {
                label: "LN".into(),
                lightning_address: Some("alice@example.com".into()),
                lnurl: None,
                bolt12: None,
                receiver_pubkey: None,
            }],
            updated_at: now(),
            expires_at: None,
            sequence: Some(0),
            preferences: vec![],
            nonce: None,
            rotation: None,
            method_verifications: vec![],
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
        };
        Registry::open(dir.path())
            .unwrap()
            .register_profile(sign_profile(profile, &key.secret_key).unwrap())
            .unwrap();
        let response = quote_response(
            &test_state(dir.path()),
            QuoteRequest {
                recipient: "alice@example.com".into(),
                amount_sats: 1_000,
            },
        )
        .await;
        assert!(
            matches!(response, QuoteResponse::NoRoute { ref reason } if reason.contains("transparency verification failed"))
        );
    }

    #[tokio::test]
    async fn quote_pay_and_preview_use_transparent_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = load_or_create_identity(dir.path()).unwrap();
        wallet.alias = Some("alice@example.com".into());
        wallet.lightning_address = Some("alice@example.com".into());
        sign_and_store(dir.path(), &mut wallet, "devnet").unwrap();
        let state = test_state(dir.path());
        let quote = quote_response(
            &state,
            QuoteRequest {
                recipient: "alice@example.com".into(),
                amount_sats: 1_000,
            },
        )
        .await;
        assert!(
            matches!(quote, QuoteResponse::NoRoute { ref reason } if reason.contains("ownership proof"))
        );
        let preview = quote_response(
            &state,
            QuoteRequest {
                recipient: "alice@example.com".into(),
                amount_sats: 1_000,
            },
        )
        .await;
        assert!(matches!(preview, QuoteResponse::NoRoute { .. }));
        let pay = pay_response(
            &state,
            PayRequest {
                recipient: "alice@example.com".into(),
                amount_sats: 1_000,
                memo: None,
            },
        )
        .await;
        assert!(matches!(pay, PayResponse::NoRoute { .. }));
    }

    #[test]
    fn rotation_sequence_is_consistent_across_profile_event_and_registry() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = load_or_create_identity(dir.path()).unwrap();
        wallet.alias = Some("alice@example.com".into());
        wallet.lightning_address = Some("alice@example.com".into());
        sign_and_store(dir.path(), &mut wallet, "devnet").unwrap();
        save_wallet(dir.path(), &wallet).unwrap();
        let response = rotate_profile_key(&test_state(dir.path())).unwrap();
        let store = TransactionalTransparencyStore::open(dir.path()).unwrap();
        let profile = store.profile("alice@example.com").unwrap().unwrap();
        let log = store.load_log().unwrap();
        let latest = log.events().last().unwrap();
        assert_eq!(response.sequence, 1);
        assert_eq!(profile.profile.sequence, Some(latest.sequence));
        assert_eq!(latest.rotation.as_ref().unwrap().sequence, latest.sequence);
    }

    #[test]
    fn profile_signing_writes_resolvable_signed_profile() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = load_or_create_identity(dir.path()).unwrap();
        wallet.alias = Some("alice@example.com".into());
        wallet.lightning_address = Some("alice@example.com".into());
        sign_and_store(dir.path(), &mut wallet, "devnet").unwrap();

        let signed = TransactionalTransparencyStore::open(dir.path())
            .unwrap()
            .profile("alice@example.com")
            .unwrap()
            .unwrap();
        assert!(verify_signed_profile(&signed).unwrap());
        assert_eq!(signed.profile.methods.len(), 1);
    }

    #[test]
    fn onchain_pubkey_is_saved_as_pubkey_hint() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = load_or_create_identity(dir.path()).unwrap();
        wallet.alias = Some("alice@example.com".into());
        wallet.onchain_address = Some("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn".into());
        wallet.onchain_pubkey =
            Some("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into());
        sign_and_store(dir.path(), &mut wallet, "devnet").unwrap();

        let signed = TransactionalTransparencyStore::open(dir.path())
            .unwrap()
            .profile("alice@example.com")
            .unwrap()
            .unwrap();
        match &signed.profile.methods[0] {
            PaymentMethod::Onchain { pubkey_hint, .. } => {
                assert_eq!(pubkey_hint.as_deref(), wallet.onchain_pubkey.as_deref());
            }
            other => panic!("expected on-chain method, got {other:?}"),
        }
    }
}

// ─── Send flow (priority routing + experimental email invite) ──────────────────

#[derive(Debug, Deserialize)]
struct SendRequest {
    recipient: String,
    amount_sats: u64,
    /// Model Lightning routing health (defaults to healthy).
    #[serde(default)]
    routing_ok: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
enum SendResponse {
    Ok {
        mode: &'static str,
        rail: String,
        reason: String,
        recipient: String,
        profile_signature_verified: bool,
        identifier_verified: bool,
        identifier_verification: &'static str,
        amount_sats: u64,
        payload: String,
        qr_svg: String,
        safety: SafetyStatus,
    },
    Invite {
        mode: &'static str,
        experimental: bool,
        recipient_hint: String,
        amount_sats: u64,
        claim_url: String,
        email: EmailInvite,
        safety: SafetyStatus,
    },
    InvalidSignature {
        recipient: String,
    },
    NoRoute {
        reason: String,
    },
}

#[derive(Debug, Serialize)]
struct EmailInvite {
    to: String,
    subject: String,
    body: String,
    mailto: String,
}

/// Resolve the recipient, pick a rail by the on-chain -> Lightning -> Ark
/// priority, and return the best QR. If the recipient is not registered, return
/// an EXPERIMENTAL email invite (no funds move; the recipient claims locally).
async fn send_response(state: &AppState, body: SendRequest) -> SendResponse {
    if let Err(e) = validate_amount_sats(body.amount_sats) {
        return SendResponse::NoRoute {
            reason: e.to_string(),
        };
    }
    let resolver = resolver_chain(&state.home);
    match resolver.resolve_alias(&body.recipient).await {
        Ok(signed) => {
            if !matches!(verify_signed_profile(&signed), Ok(true)) {
                return SendResponse::InvalidSignature {
                    recipient: mask_identifier(&body.recipient),
                };
            }
            let fee = fetch_fee_estimate().await;
            let routing_ok = body.routing_ok.unwrap_or(true);
            match select_priority_route(
                body.amount_sats,
                &fee.unwrap_or_default(),
                &signed.profile.methods,
                routing_ok,
            ) {
                Some(decision) => {
                    let payload = match send_payload_for(&decision.method, body.amount_sats) {
                        Ok(p) => p,
                        Err(e) => {
                            return SendResponse::NoRoute {
                                reason: e.to_string(),
                            }
                        }
                    };
                    let qr = match qr_svg(&payload) {
                        Ok(q) => q,
                        Err(e) => {
                            return SendResponse::NoRoute {
                                reason: e.to_string(),
                            }
                        }
                    };
                    SendResponse::Ok {
                        mode: "preview_only",
                        rail: decision.rail.to_string(),
                        reason: decision.reason,
                        recipient: mask_identifier(&body.recipient),
                        profile_signature_verified: true,
                        identifier_verified: false,
                        identifier_verification:
                            "identifier-only; no inbox/domain ownership proof in this response",
                        amount_sats: body.amount_sats,
                        payload,
                        qr_svg: qr,
                        safety: safety_status(),
                    }
                }
                None => SendResponse::NoRoute {
                    reason: "recipient exposes no usable rail".to_string(),
                },
            }
        }
        Err(_) => {
            let invite =
                satspath_core::create_invite(&body.recipient, body.amount_sats, None, 86400);
            let email = build_email_invite(&body.recipient, body.amount_sats, &invite.claim_url);
            SendResponse::Invite {
                mode: "preview_only",
                experimental: true,
                recipient_hint: mask_identifier(&body.recipient),
                amount_sats: body.amount_sats,
                claim_url: invite.claim_url,
                email,
                safety: safety_status(),
            }
        }
    }
}

fn build_email_invite(recipient: &str, amount_sats: u64, claim_url: &str) -> EmailInvite {
    let subject = "You were sent Bitcoin with SatsPath".to_string();
    let body = format!(
        r"Someone wants to send you {amount_sats} sats with SatsPath.

Press the button to download the SatsPath wallet and receive your funds
locally. You generate your own keys; nobody custodies them:

{claim_url}

[EXPERIMENTAL] SatsPath does not move funds or sign transactions for you."
    );
    let mailto = format!(
        "mailto:{}?subject={}&body={}",
        recipient,
        pct(&subject),
        pct(&body)
    );
    EmailInvite {
        to: recipient.to_string(),
        subject,
        body,
        mailto,
    }
}

/// A payable pointer for a method, including the amount where the URI supports it.
fn send_payload_for(method: &PaymentMethod, amount_sats: u64) -> Result<String> {
    let payload = match method {
        PaymentMethod::Lightning {
            lightning_address: Some(a),
            ..
        } => a.clone(),
        PaymentMethod::Lightning { lnurl: Some(u), .. } => u.clone(),
        PaymentMethod::Onchain {
            address,
            silent_payment_pubkey,
            ..
        } => {
            let target = silent_payment_pubkey
                .clone()
                .unwrap_or_else(|| address.clone().unwrap_or_default());
            format!("bitcoin:{target}?amount={}", fmt_btc(amount_sats))
        }
        PaymentMethod::Ark { server, pubkey, .. } => {
            format!("satspath:ark?server={server}&pubkey={pubkey}&amount={amount_sats}")
        }
        _ => anyhow::bail!("selected method has no payable pointer"),
    };
    assert_no_private_material(&payload)?;
    Ok(payload)
}

/// P2P is now exclusively Nostr. The broadcast endpoint triggers a re-sign.
fn broadcast(state: &AppState) -> Result<serde_json::Value> {
    let mut wallet = load_wallet(&state.home)?;
    if wallet.alias.is_none() {
        anyhow::bail!("set your profile first (alias + methods) before broadcasting");
    }
    ensure_signed_profile(&state.home, &mut wallet, &state.network)?;
    Ok(
        serde_json::json!({ "broadcasting": true, "status": "Nostr is the exclusive P2P layer. Profile saved." }),
    )
}

fn ensure_signed_profile(home: &Path, wallet: &mut WalletState, network: &str) -> Result<()> {
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

fn fmt_btc(sats: u64) -> String {
    format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000)
}

/// Minimal percent-encoding for mailto: query components.
fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
