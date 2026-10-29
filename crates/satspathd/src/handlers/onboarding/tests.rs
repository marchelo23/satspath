//! Controlled real-TLS authorization fixture. The release binary has no test
//! CA, DNS override or transport-injection configuration. No mock alias flags.
use super::*;
use bitcoin::{Address, CompressedPublicKey, Network};
use reqwest::{Client, StatusCode};
use satspath_core::{
    ownership::{build_signature_attestation, ProofType},
    BitcoinNetwork,
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

const ALIAS: &str = "alice@example.com";
const TOKEN: &str = "abababababababababababababababababababababababababababababababab";

#[test]
fn claim_metadata_readers_never_initialize_missing_state() {
    let dir = tempfile::tempdir().unwrap();
    let absent = dir.path().join("not-created");
    assert!(
        TransactionalTransparencyStore::claimed_invite_read_only(&absent, "missing")
            .unwrap()
            .is_none()
    );
    assert!(
        TransactionalTransparencyStore::claimed_invites_read_only(&absent)
            .unwrap()
            .is_empty()
    );
    assert!(!absent.exists());
}

#[test]
fn claim_base_requires_the_served_path_and_a_safe_origin() {
    for base in [
        "https://node.example.com/claim",
        "https://node.example.com/prefix/claim",
        "http://127.0.0.1:9737/claim",
    ] {
        let url = url::Url::parse(&configured_claim_url(base, "id&injected=bad").unwrap()).unwrap();
        assert_eq!(
            url.query_pairs().collect::<Vec<_>>(),
            vec![("invite_id".into(), "id&injected=bad".into())]
        );
    }
    for base in [
        "http://node.example.com/claim",
        "https://user:password@example.com/claim",
        "https://node.example.com/claim#fragment",
        "https://node.example.com/claim?other=value",
        "https://node.example.com/not-a-claim-page",
        "ftp://node.example.com/claim",
    ] {
        assert!(configured_claim_url(base, "id").is_err(), "{base}");
    }
}

struct Domain {
    client: Client,
    untrusted_client: Client,
    body: Arc<Mutex<String>>,
    status: Arc<Mutex<u16>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Domain {
    fn start() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        let root = reqwest::Certificate::from_pem(cert.cert.pem().as_bytes()).unwrap();
        let server = tiny_http::Server::https(
            "127.0.0.1:0",
            tiny_http::SslConfig {
                certificate: cert.cert.pem().into_bytes(),
                private_key: cert.key_pair.serialize_pem().into_bytes(),
            },
        )
        .unwrap();
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(root)
            .resolve("example.com", server.server_addr().to_ip().unwrap())
            .build()
            .unwrap();
        let untrusted_client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .resolve("example.com", server.server_addr().to_ip().unwrap())
            .build()
            .unwrap();
        let body = Arc::new(Mutex::new(String::new()));
        let status = Arc::new(Mutex::new(200));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (b, s, done) = (body.clone(), status.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !done.load(std::sync::atomic::Ordering::SeqCst) {
                if let Some(request) = server.recv_timeout(Duration::from_millis(50)).unwrap() {
                    assert!(request
                        .url()
                        .starts_with("/.well-known/satspath/authorization/"));
                    let response = tiny_http::Response::from_string(b.lock().unwrap().clone())
                        .with_status_code(*s.lock().unwrap());
                    let _ = request.respond(response);
                }
            }
        });
        Self {
            client,
            untrusted_client,
            body,
            status,
            stop,
            thread: Some(thread),
        }
    }
    fn publish(&self, body: &str) {
        *self.body.lock().unwrap() = body.into();
    }
}

impl Drop for Domain {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
    }
}

struct Daemon {
    home: Arc<tempfile::TempDir>,
    state: Arc<AppState>,
    server: Arc<tiny_http::Server>,
    task: tokio::task::JoinHandle<()>,
    base: String,
}

impl Daemon {
    fn start(client: Client) -> Self {
        Self::in_home(client, Arc::new(tempfile::tempdir().unwrap()))
    }
    fn in_home(client: Client, home: Arc<tempfile::TempDir>) -> Self {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
        let bind = server.server_addr().to_ip().unwrap();
        crate::handlers::wallet::load_or_create_identity(home.path()).unwrap();
        let state = Arc::new(AppState {
            alias_test_client: Some(client),
            p2p: crate::p2p::Bridge::new(false),
            home: home.path().to_owned(),
            bind,
            allowed_hosts: vec![],
            network: "regtest".into(),
            open_ui: false,
            auth_token: TOKEN.into(),
            allow_mock_alias_verification: false,
            mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
            anchor_lock: Arc::new(tokio::sync::Mutex::new(())),
            rate_limiter: Arc::new(crate::rate_limit::RateLimiter::new(
                crate::rate_limit::RateLimiterConfig {
                    burst_capacity: 1000,
                    ..Default::default()
                },
            )),
            is_tls: false,
        });
        recover_registration_wallet(&state).unwrap();
        let (s, app) = (server.clone(), state.clone());
        let task = tokio::spawn(async move {
            let _ = crate::server::serve_server(app, s).await;
        });
        Self {
            home,
            state,
            server,
            task,
            base: format!("http://{bind}"),
        }
    }
    fn restart(&mut self) {
        self.server.unblock();
        self.task.abort();
        *self = Self::in_home(
            self.state.alias_test_client.clone().unwrap(),
            self.home.clone(),
        );
    }
    async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let response = Client::new()
            .post(format!("{}{path}", self.base))
            .bearer_auth(TOKEN)
            .json(&body)
            .send()
            .await
            .unwrap();
        (response.status(), response.json().await.unwrap())
    }
    fn snapshot(&self) -> Value {
        let store = TransactionalTransparencyStore::open_read_only(self.home.path()).unwrap();
        json!({"wallet": load_wallet(self.home.path()).unwrap(),
            "events": store.load_log().unwrap().events(), "profile": store.profile(ALIAS).unwrap(),
            "claims": store.claimed_invites().unwrap(),
            "invite_mirror": std::fs::read_to_string(self.home.path().join(satspath_core::invite_store::INVITES_FILE)).ok()})
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.server.unblock();
        self.task.abort();
    }
}

fn address(byte: u8) -> String {
    let key = bitcoin::secp256k1::SecretKey::from_slice(&[byte; 32]).unwrap();
    let pk =
        bitcoin::secp256k1::PublicKey::from_secret_key(&bitcoin::secp256k1::Secp256k1::new(), &key);
    Address::p2wpkh(&CompressedPublicKey(pk), Network::Regtest).to_string()
}

async fn challenge(d: &Daemon, invite: Option<&str>) -> Value {
    let (status, body) = d
        .post(
            "/v1/onboarding/challenge",
            json!({"alias":ALIAS,
        "methods":{"onchain_address":address(1)}, "invite_id":invite}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

async fn verify(d: &Daemon, id: &Value) -> (StatusCode, Value) {
    d.post(
        "/v1/onboarding/verify",
        json!({"alias":ALIAS, "challenge_id":id}),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn standalone_https_registration_ownership_quote_cli_approval_and_restart() {
    let domain = Domain::start();
    let mut d = Daemon::start(domain.client.clone());
    let wallet_before_registration = load_wallet(d.home.path()).unwrap();
    let pending = challenge(&d, None).await;
    domain.publish(pending["body"].as_str().unwrap());
    d.restart(); // The pending authorization itself must survive restart.
    let (status, registered) = verify(&d, &pending["challenge_id"]).await;
    assert_eq!(status, StatusCode::OK, "{registered}");
    let signed: SignedPaymentProfile =
        serde_json::from_value(registered["signed_profile"].clone()).unwrap();
    // Recreate the crash window after SQLite commit but before wallet.json
    // activation. Startup must recover only the exact committed public mirror.
    let active = load_wallet(d.home.path()).unwrap();
    let db =
        rusqlite::Connection::open(d.home.path().join("satspath-transparency-v1.sqlite3")).unwrap();
    db.execute(
        "INSERT INTO registration_wallet VALUES (1,?1,?2)",
        rusqlite::params![
            serde_json::to_string(&active).unwrap(),
            serde_json::to_string(&signed).unwrap()
        ],
    )
    .unwrap();
    save_wallet(d.home.path(), &wallet_before_registration).unwrap();
    d.restart();
    assert_eq!(
        serde_json::to_value(load_wallet(d.home.path()).unwrap()).unwrap(),
        serde_json::to_value(active).unwrap()
    );
    assert!(
        TransactionalTransparencyStore::open_read_only(d.home.path())
            .unwrap()
            .registration_wallet()
            .unwrap()
            .is_none()
    );
    let request = json!({"recipient":ALIAS,"amount_sats":21_001});
    let (_, before) = d.post("/v1/quote", request.clone()).await;
    assert_eq!(
        before["status"], "no_route",
        "identity authorization is not method ownership"
    );
    let issued = now() - 1;
    let proof = build_signature_attestation(
        &signed.profile.methods[0],
        &signed.profile.identity_pubkey,
        ProofType::OnchainAddressSignature,
        &secp256k1::SecretKey::from_slice(&[1; 32]).unwrap(),
        issued,
        Some(issued + 3600),
    )
    .unwrap();
    let (status, attached) = d
        .post("/v1/profile/methods/proof", json!({"verification":proof}))
        .await;
    assert_eq!(status, StatusCode::OK, "{attached}");
    let (status, resolved) = d.post("/v1/resolve", json!({"alias":ALIAS})).await;
    assert_eq!(status, StatusCode::OK, "{resolved}");
    for field in [
        "identifier_verified",
        "payment_methods_verified",
        "profile_signature_verified",
        "key_continuity_verified",
        "transparency_inclusion_verified",
        "checkpoint_consistency_verified",
    ] {
        assert_eq!(resolved["verification"][field], true, "{field}: {resolved}");
    }
    let (status, quote) = d.post("/v1/quote", request.clone()).await;
    assert_eq!(status, StatusCode::OK, "{quote}");
    assert_eq!(quote["status"], "ok", "{quote}");
    assert_eq!(quote["recipient"]["identifier_verified"], true);
    let payload = format!("bitcoin:{}?amount=0.00021001", address(1));
    assert_eq!(quote["qr"], payload);
    let (_, pay) = d.post("/v1/pay", request.clone()).await;
    assert_eq!(pay["status"], "wallet_handoff");
    assert_eq!(pay["payment_payload"], payload);
    assert_eq!(pay["handoff"]["daemon_executes_payment"], false);
    let (_, send) = d.post("/v1/send", request.clone()).await;
    assert_eq!(send["status"], "ok");
    assert_eq!(send["mode"], "preview_only");
    assert_eq!(send["payload"], payload);
    assert_eq!(send["identifier_verified"], true);

    // Independently consume the actual HTTP-emitted quote through the real CLI.
    let path = d.home.path().join("http-quote.json");
    std::fs::write(&path, serde_json::to_vec(&quote).unwrap()).unwrap();
    for (amount, network, success, tampered) in [
        (21_001, "regtest", true, false),
        (21_000, "regtest", false, false),
        (21_001, "mainnet", false, false),
        (21_001, "regtest", false, true),
    ] {
        let mut input = quote.clone();
        if tampered {
            input["qr"] = json!(format!("bitcoin:{}?amount=0.00021001", address(2)));
            input["selected_method"]["address"] = json!(address(2));
        }
        std::fs::write(&path, serde_json::to_vec(&input).unwrap()).unwrap();
        let output = std::process::Command::new("cargo")
            .args([
                "run",
                "--offline",
                "--quiet",
                "--locked",
                "-p",
                "satspath-cli",
                "--",
                "check-handoff",
            ])
            .arg(&path)
            .args([
                "--recipient",
                ALIAS,
                "--destination",
                &address(1),
                "--amount-sats",
                &amount.to_string(),
                "--network",
                network,
            ])
            .current_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            success,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if success {
            let checked: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(checked["approval_granted"], false);
            assert_eq!(checked["requires_host_wallet_approval"], true);
            assert_eq!(checked["payment_payload"], payload);
        }
    }
    assert_intent_policy(&d, &quote).await;
    let snapshot = d.snapshot();
    let pin = satspath_core::CheckpointStore::new(d.home.path())
        .load()
        .unwrap();
    assert!(!pin.is_empty());
    d.restart();
    assert_eq!(d.snapshot(), snapshot);
    assert_eq!(
        serde_json::to_value(
            satspath_core::CheckpointStore::new(d.home.path())
                .load()
                .unwrap()
        )
        .unwrap(),
        serde_json::to_value(pin).unwrap()
    );
    let (_, again) = d.post("/v1/quote", request).await;
    assert_eq!(again["qr"], quote["qr"]);
    assert_eq!(again["recipient"]["identifier_verified"], true);
    assert_eq!(
        verify(&d, &pending["challenge_id"]).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(d.snapshot(), snapshot);
    let production_quote = quote_after_production_process_restart(&d).await;
    assert_eq!(production_quote["qr"], quote["qr"]);
    assert_eq!(production_quote["recipient"]["identifier_verified"], true);
    d.restart();
    let (status, unrelated) = d
        .post(
            "/v1/profile/methods",
            json!({"lightning_address":"alice@example.net"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{unrelated}");
    assert_eq!(
        unrelated["signed_profile"]["profile"]["method_verifications"],
        attached["signed_profile"]["profile"]["method_verifications"]
    );
    let (_, still_payable) = d
        .post("/v1/quote", json!({"recipient":ALIAS,"amount_sats":21_001}))
        .await;
    assert_eq!(still_payable["status"], "ok", "{still_payable}");
    assert_eq!(still_payable["recipient"]["identifier_verified"], true);
    let (status, replaced) = d
        .post("/v1/profile/methods", json!({"onchain_address":address(2)}))
        .await;
    assert_eq!(status, StatusCode::OK, "{replaced}");
    d.restart();
    for path in ["/v1/quote", "/v1/pay", "/v1/send"] {
        let (_, denied) = d
            .post(path, json!({"recipient":ALIAS,"amount_sats":21_001}))
            .await;
        assert_eq!(denied["status"], "no_route", "{path}: {denied}");
    }
}

async fn assert_intent_policy(d: &Daemon, wire_quote: &Value) {
    use satspath_core::{
        transparency::{GossipObservation, WitnessCosignature},
        ResolverSource,
    };
    use satspath_router::wallet_executor::{
        prepare_payment_intent, HandoffTransparencyEvidence, HandoffTrust,
    };
    let store = TransactionalTransparencyStore::open_read_only(d.home.path()).unwrap();
    let log = store.load_log().unwrap();
    let cp = log.checkpoints().last().unwrap();
    let pins_home = tempfile::tempdir().unwrap();
    let pins = satspath_core::CheckpointStore::new(pins_home.path());
    pins.pin_verified(cp).unwrap();
    let witness = generate_identity_keypair();
    let mut sig = WitnessCosignature {
        version: 1,
        witness_id: "fixture-witness".into(),
        witness_pubkey: hex::encode(witness.public_key.serialize()),
        checkpoint_hash: cp.checkpoint_hash().unwrap(),
        tree_size: cp.log_size,
        timestamp: now(),
        signature: String::new(),
    };
    sig.signature =
        satspath_core::crypto::sign_message(&sig.signing_message(), &witness.secret_key);
    let observer = generate_identity_keypair();
    let gossip = GossipObservation::sign(cp.clone(), &observer.secret_key, now()).unwrap();
    let trust = HandoffTrust {
        checkpoints: Mutex::new(pins),
        witness_quorum: 1,
        witness_pubkeys: vec![sig.witness_pubkey.clone()],
        observer_pubkeys: vec![gossip.observer_pubkey.clone()],
    };
    let evidence = HandoffTransparencyEvidence {
        current_state_proof: log.prove_state(&identifier_hash(ALIAS)).unwrap(),
        witness_cosignatures: vec![sig],
        gossip_observations: vec![gossip],
    };
    let quote: satspath_router::QuoteResponse = serde_json::from_value(wire_quote.clone()).unwrap();
    let intent = prepare_payment_intent(
        &store,
        &trust,
        &evidence,
        &quote,
        BitcoinNetwork::Regtest,
        21_001,
        100_000,
        vec![ResolverSource::LocalRegistry],
    )
    .unwrap();
    assert_eq!(intent.destination, address(1));
    assert_eq!(intent.amount_sats, 21_001);
    assert!(intent.verification_status.identifier_verified);
    assert!(intent.clone().approve(false).is_err());
    assert_eq!(intent.clone().approve(true).unwrap().intent(), &intent);
    for (key, value) in [
        (
            "qr",
            json!(format!("bitcoin:{}?amount=0.00021001", address(2))),
        ),
        (
            "qr",
            json!(format!("bitcoin:{}?amount=0.00021000", address(1))),
        ),
    ] {
        let mut changed = wire_quote.clone();
        changed[key] = value;
        let changed = serde_json::from_value(changed).unwrap();
        assert!(prepare_payment_intent(
            &store,
            &trust,
            &evidence,
            &changed,
            BitcoinNetwork::Regtest,
            21_001,
            100_000,
            vec![ResolverSource::LocalRegistry]
        )
        .is_err());
        let approved = intent.clone().approve(true).unwrap();
        assert!(
            satspath_router::wallet_executor::execute_quote_handoff(
                &NoSpend,
                &store,
                &trust,
                &evidence,
                &changed,
                approved,
                &satspath_core::execution::ExecutionGatePolicy::testnet_default(),
            )
            .await
            .is_err(),
            "post-approval changes must fail before any host call"
        );
    }
    assert!(prepare_payment_intent(
        &store,
        &trust,
        &evidence,
        &quote,
        BitcoinNetwork::Mainnet,
        21_001,
        100_000,
        vec![ResolverSource::LocalRegistry]
    )
    .is_err());
    let disabled = satspath_core::execution::ExecutionGatePolicy {
        allow_testnet_execution: false,
        ..Default::default()
    };
    assert!(satspath_router::wallet_executor::execute_quote_handoff(
        &NoSpend,
        &store,
        &trust,
        &evidence,
        &quote,
        intent.approve(true).unwrap(),
        &disabled,
    )
    .await
    .is_err());
}

/// Reopen the no-mock registration in the actual release-code daemon binary.
/// Its build has no test CA/client field, and it receives no mock/trust override.
async fn quote_after_production_process_restart(d: &Daemon) -> Value {
    use std::process::{Command, Stdio};
    let built = Command::new("cargo")
        .args([
            "build",
            "--offline",
            "--quiet",
            "--locked",
            "-p",
            "satspathd",
        ])
        .current_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    d.server.unblock();
    d.task.abort();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bind = listener.local_addr().unwrap();
    drop(listener);
    let executable = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(format!("satspathd{}", std::env::consts::EXE_SUFFIX));
    struct Process(std::process::Child);
    impl Drop for Process {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut process = Process(
        Command::new(executable)
            .env_clear()
            .env("SATSPATHD_AUTH_TOKEN", TOKEN)
            .env("SATSPATH_FEE_SOURCES", "")
            .env("TOKIO_WORKER_THREADS", "2")
            .args([
                "--no-open",
                "--network",
                "regtest",
                "--bind",
                &bind.to_string(),
                "--home",
            ])
            .arg(d.home.path())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let base = format!("http://{bind}");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "production daemon exited during restart"
        );
        if client
            .get(format!("{base}/health"))
            .send()
            .await
            .is_ok_and(|response| response.status() == StatusCode::OK)
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "production daemon startup timed out"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let response = client
        .post(format!("{base}/v1/quote"))
        .bearer_auth(TOKEN)
        .json(&json!({"recipient":ALIAS,"amount_sats":21_001}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let quote: Value = response.json().await.unwrap();
    assert_eq!(quote["status"], "ok", "{quote}");
    quote
}

/// Contract sentinel, not a named-wallet adapter: reaching any callback fails
/// the test. No transaction, simulated receipt or settlement is manufactured.
struct NoSpend;
#[async_trait::async_trait]
impl satspath_core::execution::WalletExecutor for NoSpend {
    fn network(&self) -> BitcoinNetwork {
        BitcoinNetwork::Regtest
    }
    async fn pay_bolt11(
        &self,
        _: &str,
        _: Option<u64>,
    ) -> satspath_core::Result<satspath_core::execution::PaymentReceipt> {
        panic!("no host dispatch allowed")
    }
    async fn send_onchain(
        &self,
        _: &str,
        _: u64,
        _: Option<u64>,
    ) -> satspath_core::Result<satspath_core::execution::OnchainReceipt> {
        panic!("no host dispatch allowed")
    }
    async fn sign_and_broadcast_psbt(&self, _: &str) -> satspath_core::Result<String> {
        panic!("no host dispatch allowed")
    }
    async fn send_onchain_with_max_fee(
        &self,
        _: &str,
        _: u64,
        _: u64,
    ) -> satspath_core::Result<satspath_core::execution::OnchainReceipt> {
        panic!("no host dispatch allowed")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_domain_challenge_wrong_alias_body_redirect_and_expiry_do_not_publish() {
    let domain = Domain::start();
    let d = Daemon::start(domain.client.clone());
    let pending = challenge(&d, None).await;
    let snapshot = d.snapshot();
    let (status, _) = d
        .post(
            "/v1/onboarding/verify",
            json!({"alias":"bob@example.com","challenge_id":pending["challenge_id"]}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    for body in ["{}".to_string(), "x".repeat(16 * 1024 + 1)] {
        domain.publish(&body);
        assert_eq!(
            verify(&d, &pending["challenge_id"]).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(d.snapshot(), snapshot);
    }
    domain.publish(pending["body"].as_str().unwrap());
    *domain.status.lock().unwrap() = 302;
    assert_eq!(
        verify(&d, &pending["challenge_id"]).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(d.snapshot(), snapshot);
    *domain.status.lock().unwrap() = 200;
    let connection =
        rusqlite::Connection::open(d.home.path().join("satspath-transparency-v1.sqlite3")).unwrap();
    connection
        .execute(
            "UPDATE alias_challenges SET expires_at=?1 WHERE challenge_id=?2",
            rusqlite::params![now() - 1, pending["challenge_id"].as_str().unwrap()],
        )
        .unwrap();
    assert_eq!(
        verify(&d, &pending["challenge_id"]).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(d.snapshot(), snapshot);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn untrusted_tls_private_aliases_and_supplied_evidence_cannot_authorize() {
    let domain = Domain::start();
    let d = Daemon::start(domain.untrusted_client.clone());
    let pending = challenge(&d, None).await;
    domain.publish(pending["body"].as_str().unwrap());
    let snapshot = d.snapshot();
    assert_eq!(
        verify(&d, &pending["challenge_id"]).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(d.snapshot(), snapshot);
    let (status, _) = d
        .post(
            "/v1/onboarding/verify",
            json!({"alias":ALIAS,
        "challenge_id":pending["challenge_id"],"body":pending["body"],"dnssec_validated":true}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    for alias in [
        "alice@127.0.0.1",
        "alice@169.254.169.254",
        "alice@localhost.localdomain",
        "alice@example.com:443",
        "alice@example.com/evil",
    ] {
        let (status, body) = d
            .post(
                "/v1/onboarding/challenge",
                json!({"alias":alias,"methods":{"onchain_address":address(1)}}),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(d.snapshot(), snapshot);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn late_commit_failure_rolls_back_profile_attestation_challenge_and_claim() {
    let domain = Domain::start();
    for claiming in [false, true] {
        let d = Daemon::start(domain.client.clone());
        let id = if claiming {
            let record = satspath_core::create_invite_record(
                ALIAS,
                21_001,
                None,
                "fixture-sender".into(),
                3600,
            );
            let id = record.invite_id.clone();
            InviteStore::open(d.home.path())
                .unwrap()
                .insert(record)
                .unwrap();
            Some(id)
        } else {
            None
        };
        let pending = challenge(&d, id.as_deref()).await;
        domain.publish(pending["body"].as_str().unwrap());
        let snapshot = d.snapshot();
        let db = rusqlite::Connection::open(d.home.path().join("satspath-transparency-v1.sqlite3"))
            .unwrap();
        db.execute_batch("CREATE TRIGGER refuse_checkpoint BEFORE INSERT ON checkpoints BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
        assert_eq!(
            verify(&d, &pending["challenge_id"]).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(d.snapshot(), snapshot);
        let store = TransactionalTransparencyStore::open_read_only(d.home.path()).unwrap();
        assert!(store
            .alias_challenge(pending["challenge_id"].as_str().unwrap(), now())
            .unwrap()
            .is_some());
        assert!(store.claimed_invites().unwrap().is_empty());
        assert!(store.registration_wallet().unwrap().is_none());
        let attestations: i64 = db
            .query_row("SELECT COUNT(*) FROM identifier_attestations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(attestations, 0);
        db.execute_batch("DROP TRIGGER refuse_checkpoint").unwrap();
        assert_eq!(verify(&d, &pending["challenge_id"]).await.0, StatusCode::OK);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consumed_authorization_cannot_be_rebound_to_another_signed_candidate() {
    let domain = Domain::start();
    let d = Daemon::start(domain.client.clone());
    let challenge = challenge(&d, None).await;
    let store = TransactionalTransparencyStore::open_read_only(d.home.path()).unwrap();
    let raw = store
        .alias_challenge(challenge["challenge_id"].as_str().unwrap(), now())
        .unwrap()
        .unwrap();
    let mut changed: PendingRegistration = serde_json::from_str(&raw).unwrap();
    changed.signed_profile.profile.nonce = Some(generate_nonce());
    changed.signed_profile = sign_profile(
        changed.signed_profile.profile.clone(),
        &load_identity_key(
            d.home.path(),
            &changed.signed_profile.profile.identity_pubkey,
        )
        .unwrap(),
    )
    .unwrap();
    changed.event.profile_hash = profile_hash(&changed.signed_profile).unwrap();
    let before = d.snapshot();
    assert!(finish_registration(&d.state, &raw, changed).is_err());
    assert_eq!(d.snapshot(), before);
    assert!(store
        .alias_challenge(challenge["challenge_id"].as_str().unwrap(), now())
        .unwrap()
        .is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expired_cancelled_wrong_alias_and_changed_wallet_claims_are_rejected() {
    let domain = Domain::start();
    let d = Daemon::start(domain.client.clone());
    let mut record =
        satspath_core::create_invite_record(ALIAS, 21_001, None, "fixture-sender".into(), 3600);
    let id = record.invite_id.clone();
    let mut invites = InviteStore::open(d.home.path()).unwrap();
    invites.insert(record.clone()).unwrap();
    let before = d.snapshot();
    let (status,_)=d.post("/v1/onboarding/challenge",json!({"alias":"bob@example.com","methods":{"onchain_address":address(1)},"invite_id":id})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(d.snapshot(), before);
    let pending = challenge(&d, Some(&id)).await;
    domain.publish(pending["body"].as_str().unwrap());
    invites.cancel(&id).unwrap();
    let cancelled_before = d.snapshot();
    assert_eq!(
        verify(&d, &pending["challenge_id"]).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(d.snapshot(), cancelled_before);
    record.status = InviteStatus::Created;
    record.expires_at = now() - 1;
    invites.insert(record).unwrap();
    let expired_before = d.snapshot();
    let (status, _) = d
        .post(
            "/v1/onboarding/challenge",
            json!({"alias":ALIAS,"methods":{"onchain_address":address(1)},"invite_id":id}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(d.snapshot(), expired_before);
    let self_pending = challenge(&d, None).await;
    domain.publish(self_pending["body"].as_str().unwrap());
    let mut changed = load_wallet(d.home.path()).unwrap();
    changed.lightning_address = Some("other@example.com".into());
    save_wallet(d.home.path(), &changed).unwrap();
    let changed_before = d.snapshot();
    assert_eq!(
        verify(&d, &self_pending["challenge_id"]).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(d.snapshot(), changed_before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_domain_claim_is_atomic_separate_and_single_use() {
    let domain = Domain::start();
    let mut d = Daemon::start(domain.client.clone());
    let operator = load_wallet(d.home.path()).unwrap();
    let (_, sent) = d
        .post("/v1/send", json!({"recipient":ALIAS,"amount_sats":21_001}))
        .await;
    assert_eq!(sent["status"], "invite", "{sent}");
    let url = url::Url::parse(sent["claim_url"].as_str().unwrap()).unwrap();
    assert_eq!(url.path(), "/claim");
    assert_eq!(url.host_str(), Some("127.0.0.1"));
    let id = url
        .query_pairs()
        .find(|(key, _)| key == "invite_id")
        .unwrap()
        .1
        .into_owned();
    let pending = challenge(&d, Some(&id)).await;
    domain.publish(pending["body"].as_str().unwrap());
    let (a, b) = tokio::join!(
        verify(&d, &pending["challenge_id"]),
        verify(&d, &pending["challenge_id"])
    );
    assert_eq!(
        [a.0, b.0]
            .iter()
            .filter(|&&status| status == StatusCode::OK)
            .count(),
        1,
        "{a:?} {b:?}"
    );
    let body = if a.0 == StatusCode::OK { a.1 } else { b.1 };
    assert_ne!(
        body["signed_profile"]["profile"]["identity_pubkey"],
        json!(operator.identity_pubkey)
    );
    assert_eq!(
        serde_json::to_value(load_wallet(d.home.path()).unwrap()).unwrap(),
        serde_json::to_value(operator).unwrap()
    );
    let receiver: SignedPaymentProfile =
        serde_json::from_value(body["signed_profile"].clone()).unwrap();
    let issued = now() - 1;
    let proof = build_signature_attestation(
        &receiver.profile.methods[0],
        &receiver.profile.identity_pubkey,
        ProofType::OnchainAddressSignature,
        &secp256k1::SecretKey::from_slice(&[1; 32]).unwrap(),
        issued,
        Some(issued + 3600),
    )
    .unwrap();
    let operator_wallet = serde_json::to_value(load_wallet(d.home.path()).unwrap()).unwrap();
    let (status, attached) = d
        .post(
            "/v1/profile/methods/proof",
            json!({"alias":ALIAS,"verification":proof}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{attached}");
    assert_eq!(
        serde_json::to_value(load_wallet(d.home.path()).unwrap()).unwrap(),
        operator_wallet
    );
    // Recover a missing/stale JSON mirror from the committed SQLite receipt.
    std::fs::write(
        d.home
            .path()
            .join(satspath_core::invite_store::INVITES_FILE),
        b"{}",
    )
    .unwrap();
    d.restart();
    let (_, resolved) = d.post("/v1/resolve", json!({"alias":ALIAS})).await;
    assert_eq!(resolved["verification"]["identifier_verified"], true);
    assert_eq!(resolved["verification"]["payment_methods_verified"], true);
    let (_, quote) = d
        .post("/v1/quote", json!({"recipient":ALIAS,"amount_sats":21_001}))
        .await;
    assert_eq!(quote["status"], "ok", "{quote}");
    let response = Client::new()
        .get(format!("{}/v1/claim?invite_id={id}", d.base))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(response["is_claimable"], false);
    assert_eq!(response["status"], "claimed_with_public_profile");
    let (_, notifications) = d
        .post("/v1/invites/notifications/read-all", json!({}))
        .await;
    assert!(notifications.get("error").is_none(), "{notifications}");
    let mirror = InviteStore::open(d.home.path()).unwrap();
    assert_eq!(
        mirror.get(&id).unwrap().status,
        InviteStatus::ClaimedWithPublicProfile
    );
    assert_eq!(mirror.notifications().len(), 1);
    assert!(mirror.notifications()[0].read);
    for index in 0..8 {
        let recipient = format!("pending{index}@unknown.invalid");
        let get = Client::new()
            .get(format!("{}/v1/invites/notifications", d.base))
            .bearer_auth(TOKEN);
        let (sent, synced) = tokio::join!(
            d.post(
                "/v1/send",
                json!({"recipient":recipient,"amount_sats":1000})
            ),
            get.send()
        );
        assert_eq!(sent.1["status"], "invite", "{:?}", sent.1);
        assert_eq!(synced.unwrap().status(), StatusCode::OK);
    }
    let mut mirror = InviteStore::open(d.home.path()).unwrap();
    assert_eq!(
        mirror.list().unwrap().len(),
        9,
        "notification recovery cannot lose concurrent invites"
    );
    assert_eq!(mirror.notifications().len(), 1, "recovery is idempotent");
    let (_, failed) = d
        .post(
            "/v1/onboarding/challenge",
            json!({"alias":ALIAS,"methods":{"onchain_address":address(1)},"invite_id":id}),
        )
        .await;
    assert!(failed.get("error").is_some());
    // Public metadata inspection is a bounded indexed read, not a replay of all
    // unrelated history. Corruption must still block resolution/payment routes.
    let db = rusqlite::Connection::open(
        d.home
            .path()
            .join(satspath_core::transparency::TRANSPARENCY_DB_FILE),
    )
    .unwrap();
    db.execute("UPDATE checkpoints SET checkpoint_json='{}'", [])
        .unwrap();
    let inspection = Client::new()
        .get(format!("{}/v1/claim?invite_id={id}", d.base))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(inspection["status"], "claimed_with_public_profile");
    let (_, denied) = d
        .post("/v1/quote", json!({"recipient":ALIAS,"amount_sats":21_001}))
        .await;
    assert_eq!(
        denied["status"], "no_route",
        "corruption cannot authorize payment"
    );
}
