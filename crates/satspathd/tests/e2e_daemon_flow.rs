//! Black-box end-to-end tests for the `satspathd` HTTP API.
//!
//! Every test spawns the real daemon binary on a random loopback port with an
//! isolated `--home`, then drives it only through HTTP — exactly like a wallet
//! or dashboard would.
//!
//! Test groups (selected by name prefix in CI):
//! - no prefix:      must pass on every PR (`cargo test -p satspathd --test e2e_daemon_flow`).
//! - `regtest_`:     `#[ignore]`; needs Bitcoin Core regtest (`SATSPATH_BITCOIN_RPC_*`).
//! - `live_`:        `#[ignore]`; touches the public internet (DNSSEC, ASPs).
//! - `acceptance_`:  `#[ignore]`; executable specs for rails that are NOT yet wired into
//!   the daemon (Silent Payments, BOLT12, Ark). Each one names its tracking issue. When
//!   an issue is implemented, remove its `#[ignore]` so the test becomes a gate.
#![cfg(unix)]

use std::{
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use bitcoin::{
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    Address, CompressedPublicKey, Network,
};
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};

const TOKEN: &str = "5a7b5a7b5a7b5a7b5a7b5a7b5a7b5a7b5a7b5a7b5a7b5a7b5a7b5a7b5a7b5a7b";
const ALIAS: &str = "alice@example.com";

// ─── Harness ────────────────────────────────────────────────────────────────

struct TestDaemon {
    child: Child,
    base: String,
    http: Client,
    _home: tempfile::TempDir,
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl TestDaemon {
    /// Spawn `satspathd` on `network` with the dev-only mock alias verifier.
    fn spawn(network: &str) -> Self {
        Self::spawn_with_env(network, &[])
    }

    fn spawn_with_env(network: &str, extra_env: &[(&str, String)]) -> Self {
        for attempt in 0..5 {
            let home = tempfile::tempdir().expect("tempdir");
            let listener = TcpListener::bind("127.0.0.1:0").expect("free port");
            let address = listener.local_addr().expect("local addr");
            drop(listener);

            let mut command = Command::new(env!("CARGO_BIN_EXE_satspathd"));
            command
                .env_clear()
                .env("PATH", std::env::var("PATH").unwrap_or_default())
                .env("SATSPATHD_AUTH_TOKEN", TOKEN)
                .env("TOKIO_WORKER_THREADS", "2")
                // Keep live fee lookups out of the default suite.
                .env("SATSPATH_FEE_SOURCES", "")
                .args(["--no-open", "--dev-mock-alias-verification"])
                .args(["--bind", &address.to_string()])
                .args(["--network", network, "--home"])
                .arg(home.path())
                .stdout(Stdio::null())
                .stderr(if std::env::var_os("SATSPATH_E2E_VERBOSE").is_some() {
                    Stdio::inherit()
                } else {
                    Stdio::null()
                });
            for (key, value) in extra_env {
                command.env(key, value);
            }
            let mut child = command.spawn().expect("spawn satspathd");

            let deadline = Instant::now() + Duration::from_secs(5);
            let mut ready = false;
            while Instant::now() < deadline {
                if let Ok(Some(_status)) = child.try_wait() {
                    break;
                }
                if TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_ok() {
                    ready = true;
                    break;
                }
                thread::sleep(Duration::from_millis(25));
            }

            if ready {
                return Self {
                    child,
                    base: format!("http://{address}"),
                    http: Client::builder()
                        .timeout(Duration::from_secs(30))
                        .build()
                        .expect("reqwest client"),
                    _home: home,
                };
            }

            let _ = child.kill();
            let _ = child.wait();
            if attempt == 4 {
                panic!("satspathd failed to start and listen after 5 attempts");
            }
        }
        unreachable!()
    }

    fn home(&self) -> &Path {
        self._home.path()
    }

    async fn get(&self, path: &str) -> (StatusCode, Value) {
        let resp = self
            .http
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .expect("GET");
        decode(resp).await
    }

    async fn get_text(&self, path: &str) -> (StatusCode, String) {
        let resp = self
            .http
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .expect("GET");
        let status = resp.status();
        (status, resp.text().await.expect("body"))
    }

    async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let resp = self
            .http
            .post(format!("{}{path}", self.base))
            .json(&body)
            .send()
            .await
            .expect("POST");
        decode(resp).await
    }

    async fn post_auth(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let resp = self
            .http
            .post(format!("{}{path}", self.base))
            .bearer_auth(TOKEN)
            .json(&body)
            .send()
            .await
            .expect("POST");
        decode(resp).await
    }

    async fn put_with_token(&self, path: &str, token: Option<&str>, body: Value) -> StatusCode {
        let mut req = self.http.put(format!("{}{path}", self.base)).json(&body);
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        req.send().await.expect("PUT").status()
    }

    /// Verify `alias` via the dev mock verifier (token == alias).
    async fn verify_alias(&self, alias: &str) {
        let (status, body) = self
            .post_auth("/v1/profile/challenge", json!({ "alias": alias }))
            .await;
        assert_eq!(status, StatusCode::OK, "challenge: {body}");
        let (status, body) = self
            .post_auth(
                "/v1/profile/verify",
                json!({ "alias": alias, "token": alias }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "verify: {body}");
        assert_eq!(body["wallet"]["alias"], alias);
    }

    /// Verify the alias and publish a signed profile with a regtest on-chain address.
    async fn bootstrap_onchain_profile(&self) -> String {
        self.verify_alias(ALIAS).await;
        let address = regtest_address(1);
        let (status, body) = self
            .post_auth("/v1/profile/methods", json!({ "onchain_address": address }))
            .await;
        assert_eq!(status, StatusCode::OK, "methods: {body}");
        assert_eq!(body["signature_valid"], true, "{body}");
        address
    }
}

async fn decode(resp: reqwest::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let text = resp.text().await.expect("body");
    let value = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (status, value)
}

fn pubkey(seed: u8) -> PublicKey {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[seed; 32]).expect("valid secret key");
    PublicKey::from_secret_key(&secp, &sk)
}

fn regtest_address(seed: u8) -> String {
    Address::p2wpkh(&CompressedPublicKey(pubkey(seed)), Network::Regtest).to_string()
}

// ─── PR gate: must always pass ──────────────────────────────────────────────

#[tokio::test]
async fn daemon_boots_and_reports_non_custodial_safety() {
    let d = TestDaemon::spawn("regtest");

    let (status, _) = d.get_text("/health").await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = d.get("/v1/status").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["network"], "regtest");
    let safety = &body["safety"];
    assert_eq!(safety["moves_funds"], false, "{body}");
    assert_eq!(safety["signs_bitcoin_transactions"], false, "{body}");
    assert_eq!(safety["broadcasts_transactions"], false, "{body}");
    assert_eq!(
        safety["stores_wallet_seeds_or_spending_keys"], false,
        "{body}"
    );
}

#[tokio::test]
async fn mutating_routes_require_bearer_token() {
    let d = TestDaemon::spawn("regtest");
    let body = json!({ "onchain_address": regtest_address(1) });

    assert_eq!(
        d.put_with_token("/v1/profile", None, body.clone()).await,
        StatusCode::UNAUTHORIZED
    );
    let wrong = "0".repeat(64);
    assert_eq!(
        d.put_with_token("/v1/profile", Some(&wrong), body).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn profile_lifecycle_produces_verifiable_transparency_log() {
    let d = TestDaemon::spawn("regtest");
    let address = d.bootstrap_onchain_profile().await;

    // Receive: amount-bound BIP-21 on the daemon's network.
    let (status, body) = d
        .post(
            "/v1/receive",
            json!({ "rail": "onchain", "amount_sats": 21_000 }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rail"], "Onchain");
    assert_eq!(
        body["payload"],
        format!("bitcoin:{address}?amount=0.00021000")
    );
    assert!(body["qr_svg"].as_str().unwrap_or("").contains("<svg"));

    // Transparency: the profile publication is logged and checkpointed.
    let (status, log) = d.get("/v1/transparency/status").await;
    assert_eq!(status, StatusCode::OK, "{log}");
    assert_eq!(log["log_size"], 1, "{log}");
    assert_eq!(log["registered_identifiers"], 1, "{log}");
    let checkpoint_hash = log["latest_checkpoint_hash"]
        .as_str()
        .expect("checkpoint after publication")
        .to_string();

    let (status, events) = d.get("/v1/transparency/events").await;
    assert_eq!(status, StatusCode::OK, "{events}");
    let event: satspath_core::NameEvent =
        serde_json::from_value(items(&events).first().cloned().expect("register event"))
            .expect("NameEvent JSON");
    assert!(matches!(event.action, satspath_core::NameAction::Register));
    let event_hash = event.event_hash().expect("event hash");

    let (status, proof) = d
        .get(&format!("/v1/transparency/inclusion/{event_hash}"))
        .await;
    assert_eq!(status, StatusCode::OK, "{proof}");
    let (status, checkpoint) = d
        .get(&format!("/v1/transparency/checkpoints/{checkpoint_hash}"))
        .await;
    assert_eq!(status, StatusCode::OK, "{checkpoint}");
    let (status, verdict) = d
        .post(
            "/v1/transparency/verify/inclusion",
            json!({ "event_hash": event_hash, "proof": proof, "checkpoint": checkpoint }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{verdict}");
    assert_eq!(
        verdict["valid"], true,
        "inclusion proof rejected: {verdict}"
    );

    // Proof-carrying S2S v2 resolution of our own alias.
    let (status, resolved) = d
        .get(&format!(
            "/v2/resolve?identifier={}",
            ALIAS.replace('@', "%40")
        ))
        .await;
    assert_eq!(status, StatusCode::OK, "{resolved}");

    // Key rotation appends a new event and keeps the log consistent.
    let (status, rotation) = d.post_auth("/v1/profile/rotate-key", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{rotation}");
    assert_ne!(
        rotation["previous_fingerprint"], rotation["new_fingerprint"],
        "{rotation}"
    );
    let (status, profile) = d.get("/v1/profile").await;
    assert_eq!(status, StatusCode::OK, "{profile}");
    assert_eq!(profile["signature_valid"], true, "{profile}");

    let (status, log_after) = d.get("/v1/transparency/status").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        log_after["log_size"], 2,
        "rotation must append: {log_after}"
    );
    assert_eq!(log_after["key_rotations"], 1, "{log_after}");
    let (status, consistency) = d.get("/v1/transparency/consistency?from=1&to=2").await;
    assert_eq!(status, StatusCode::OK, "{consistency}");
}

#[tokio::test]
async fn send_to_unknown_alias_never_returns_payable_route() {
    let d = TestDaemon::spawn("regtest");
    d.bootstrap_onchain_profile().await;
    let (status, body) = d
        .post(
            "/v1/send",
            json!({ "recipient": "nobody@unknown.invalid", "amount_sats": 10_000 }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(
        body["status"], "ok",
        "unknown alias must not be payable: {body}"
    );
}

#[tokio::test]
async fn dns_resolve_rejects_malformed_names() {
    let d = TestDaemon::spawn("regtest");
    let (status, body) = d
        .post("/v1/dns/resolve", json!({ "name": "not a bip353 name" }))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "error", "{body}");
    assert_eq!(body["strict_mode"], true, "{body}");
}

#[tokio::test]
async fn metrics_exposes_prometheus_text() {
    let d = TestDaemon::spawn("regtest");
    let _ = d.get_text("/health").await;
    let (status, text) = d.get_text("/metrics").await;
    assert_eq!(status, StatusCode::OK);
    assert!(text.contains("# TYPE"), "not Prometheus exposition: {text}");
}

// ─── regtest_: Bitcoin Core required ────────────────────────────────────────

/// Full daemon flow ending in a Catena `OP_RETURN` anchor on Bitcoin Core regtest.
/// CI: `.github/workflows/daemon-e2e.yml` job `daemon-regtest-anchor`.
#[tokio::test]
#[ignore = "needs Bitcoin Core regtest: set SATSPATH_BITCOIN_RPC_URL/USER/PASSWORD"]
async fn regtest_profile_checkpoint_is_anchored_on_chain() {
    let rpc_env: Vec<(&str, String)> = [
        "SATSPATH_BITCOIN_NETWORK",
        "SATSPATH_BITCOIN_RPC_URL",
        "SATSPATH_BITCOIN_RPC_USER",
        "SATSPATH_BITCOIN_RPC_PASSWORD",
    ]
    .into_iter()
    .map(|k| {
        (
            k,
            std::env::var(k).unwrap_or_else(|_| panic!("{k} must be set")),
        )
    })
    .collect();
    let d = TestDaemon::spawn_with_env("regtest", &rpc_env);
    d.bootstrap_onchain_profile().await;

    let (status, anchor) = d.post_auth("/v1/transparency/anchors", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{anchor}");
    let txid = anchor["txid"].as_str().expect("anchor txid").to_string();
    assert_eq!(txid.len(), 64, "{anchor}");

    let (status, fetched) = d.get(&format!("/v1/transparency/anchors/{txid}")).await;
    assert_eq!(status, StatusCode::OK, "{fetched}");

    let (status, chain) = d.get("/v1/transparency/catena/chain").await;
    assert_eq!(status, StatusCode::OK, "{chain}");
    assert!(chain.to_string().contains(&txid), "{chain}");
    let _ = d.home();
}

// ─── live_: public internet required ────────────────────────────────────────

/// BIP-353 end-to-end through the daemon with Strict DNSSEC against a real,
/// signed zone. Override the name with `SATSPATH_LIVE_BIP353_NAME`.
#[tokio::test]
#[ignore = "live DNSSEC lookup on the public internet"]
async fn live_bip353_strict_dnssec_resolution_through_daemon() {
    let name = std::env::var("SATSPATH_LIVE_BIP353_NAME")
        .unwrap_or_else(|_| "matt@mattcorallo.com".to_string());
    let d = TestDaemon::spawn("regtest");
    let (status, body) = d.post("/v1/dns/resolve", json!({ "name": name })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["status"], "ok",
        "strict DNSSEC resolution failed: {body}"
    );
    assert!(
        body.to_string().contains("bitcoin:"),
        "resolution must carry a BIP-21 URI: {body}"
    );
}

// ─── acceptance_: executable specs for unfinished rails ─────────────────────

/// Spec — Silent Payments (BIP-352) as a first-class daemon receive method.
///
/// Today `ProfileUpdateRequest` has no Silent Payment field, `build_methods`
/// hard-codes `silent_payment_pubkey: None`, and `receive_payload_for` would
/// emit the non-standard `bitcoin:sp1...` form. Required: accept and validate
/// a network-matching `sp`/`tsp`/`sprt` address, sign it into the profile, and
/// emit a BIP-321 `bitcoin:?sp=` URI.
#[tokio::test]
#[ignore = "acceptance: Silent Payments daemon receive method not implemented yet"]
async fn acceptance_silent_payment_receive_method() {
    let d = TestDaemon::spawn("regtest");
    d.verify_alias(ALIAS).await;
    let sp = satspath_router::silent_payments::create_silent_payment_address_for_network(
        &pubkey(2),
        &pubkey(3),
        Network::Regtest,
    )
    .expect("sprt address");
    assert!(sp.starts_with("sprt1"));

    let (status, body) = d
        .post_auth(
            "/v1/profile/methods",
            json!({ "silent_payment_address": sp }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["wallet"]["silent_payment_address"], sp, "{body}");
    assert!(
        body["signed_profile"].to_string().contains(&sp),
        "SP address must be covered by the profile signature: {body}"
    );

    // Mainnet SP address on a regtest daemon must be rejected.
    let mainnet_sp =
        satspath_router::silent_payments::create_silent_payment_address(&pubkey(2), &pubkey(3))
            .unwrap();
    let (status, _) = d
        .post_auth(
            "/v1/profile/methods",
            json!({ "silent_payment_address": mainnet_sp }),
        )
        .await;
    assert_ne!(status, StatusCode::OK, "cross-network SP address accepted");

    let (status, body) = d.post("/v1/receive", json!({ "rail": "onchain" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["payload"], format!("bitcoin:?sp={sp}"), "{body}");
}

/// Spec — BOLT12 offers as a first-class daemon receive method.
///
/// Today `ProfileUpdateRequest` has no offer field and `build_methods` hard-codes
/// `bolt12: None`. Required: accept an `lno1…` offer, validate it with
/// `satspath_handoff::bolt12` against the daemon network, sign it into the
/// profile, and emit a BIP-321 `bitcoin:?lno=` URI.
#[tokio::test]
#[ignore = "acceptance: BOLT12 daemon receive method not implemented yet"]
async fn acceptance_bolt12_offer_receive_method() {
    use satspath_core::bolt12::{encode_bolt12_bech32_checksumless, encode_tlv_stream, TlvRecord};
    let chain = bitcoin::blockdata::constants::ChainHash::using_genesis_block(Network::Regtest);
    let offer = encode_bolt12_bech32_checksumless(
        "lno",
        &encode_tlv_stream(&[
            TlvRecord {
                tag: 2,
                value: chain.as_bytes().to_vec(),
            },
            TlvRecord {
                tag: 10,
                value: b"satspath e2e".to_vec(),
            },
            TlvRecord {
                tag: 22,
                value: pubkey(4).serialize().to_vec(),
            },
        ]),
    )
    .expect("regtest offer");
    satspath_handoff::bolt12(&offer, Some(Network::Regtest), 1).expect("fixture is valid");

    let d = TestDaemon::spawn("regtest");
    d.verify_alias(ALIAS).await;
    let (status, body) = d
        .post_auth("/v1/profile/methods", json!({ "bolt12_offer": offer }))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["signed_profile"].to_string().contains(&offer),
        "{body}"
    );

    let (status, body) = d.post("/v1/receive", json!({ "rail": "bolt12" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["payload"], format!("bitcoin:?lno={offer}"), "{body}");
}

/// Spec — Ark receive pointers use a standard wallet-scannable URI.
///
/// Today the daemon emits a private `satspath:ark?server=…&pubkey=…` scheme that
/// no Ark wallet can scan, and `build_qr_payload` fails closed for Ark.
/// Required: emit a BIP-321 `bitcoin:` URI carrying an `ark=` Ark address
/// derived from / validated against the ASP (`LiveArkAspClient::get_asp_info`).
#[tokio::test]
#[ignore = "acceptance: standard Ark receive URI not implemented yet"]
async fn acceptance_ark_receive_uses_bip321_ark_param() {
    let d = TestDaemon::spawn("regtest");
    d.verify_alias(ALIAS).await;
    let (status, body) = d
        .post_auth(
            "/v1/profile/methods",
            json!({
                "ark_server": "https://ark.example.com",
                "ark_pubkey": pubkey(5).to_string(),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = d
        .post(
            "/v1/receive",
            json!({ "rail": "ark", "amount_sats": 5_000 }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let payload = body["payload"].as_str().unwrap_or_default();
    assert!(
        payload.starts_with("bitcoin:"),
        "non-standard Ark URI: {payload}"
    );
    assert!(payload.contains("ark="), "missing ark= param: {payload}");
}

// ─── helpers ────────────────────────────────────────────────────────────────

fn items(v: &Value) -> Vec<Value> {
    if let Some(arr) = v.as_array() {
        return arr.clone();
    }
    for key in ["events", "items", "data", "checkpoints"] {
        if let Some(arr) = v.get(key).and_then(Value::as_array) {
            return arr.clone();
        }
    }
    Vec::new()
}
