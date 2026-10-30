#![cfg(unix)]

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn shutdown_with_stalled_request(p2p: bool) {
    let home = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let token = "a".repeat(64);
    let mut command = Command::new(env!("CARGO_BIN_EXE_satspathd"));
    command
        .env_clear()
        .env("SATSPATHD_AUTH_TOKEN", &token)
        .env("TOKIO_WORKER_THREADS", "2")
        .args(["--no-open", "--bind", &address.to_string(), "--home"])
        .arg(home.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if p2p {
        command.arg("--p2p");
    }
    let mut daemon = Daemon(command.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut health = loop {
        assert!(
            daemon.0.try_wait().unwrap().is_none(),
            "daemon exited during startup"
        );
        if let Ok(stream) = TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            break stream;
        }
        assert!(Instant::now() < deadline, "daemon failed to listen");
        thread::sleep(Duration::from_millis(20));
    };
    health
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(
        health,
        "GET /health HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    health.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));

    let request = if p2p {
        "PUT /v1/profile"
    } else {
        "POST /v1/receive"
    };
    let authorization = if p2p {
        format!("Authorization: Bearer {token}\r\n")
    } else {
        String::new()
    };
    let mut clients = Vec::new();
    // More stalled reads than async workers must not starve signal handling.
    for _ in 0..if p2p { 1 } else { 3 } {
        let mut stalled = TcpStream::connect(address).unwrap();
        stalled
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        write!(stalled, "{request} HTTP/1.1\r\nHost: {address}\r\n{authorization}Content-Type: application/json\r\nContent-Length: 2048\r\nExpect: 100-continue\r\n\r\n").unwrap();
        let mut reader = BufReader::new(stalled.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains("100 Continue"), "{line}");
        stalled.write_all(b"{").unwrap();
        clients.push(stalled);
    }
    if p2p {
        thread::sleep(Duration::from_millis(2200));
    }
    assert!(Command::new("kill")
        .args(["-TERM", &daemon.0.id().to_string()])
        .status()
        .unwrap()
        .success());
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        if let Some(status) = daemon.0.try_wait().unwrap() {
            assert!(status.success(), "unexpected shutdown: {status}");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "SIGTERM was blocked by the incomplete HTTP body"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn sigterm_exits_with_stalled_public_request() {
    shutdown_with_stalled_request(false);
}

#[test]
fn sigterm_exits_with_mutation_lock_held_by_stalled_request() {
    shutdown_with_stalled_request(true);
}

#[tokio::test]
async fn port_zero_startup_and_claim_urls_use_the_assigned_listener_port() {
    let home = tempfile::tempdir().unwrap();
    let token = "b".repeat(64);
    let mut daemon = Daemon(
        Command::new(env!("CARGO_BIN_EXE_satspathd"))
            .env_clear()
            .env("SATSPATHD_AUTH_TOKEN", &token)
            .env("SATSPATH_FEE_SOURCES", "")
            .args(["--no-open", "--bind", "127.0.0.1:0", "--home"])
            .arg(home.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let stdout = daemon.0.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(url) = line.strip_prefix("Wallet UI -> ") {
                let _ = tx.send(url.to_owned());
            }
        }
    });
    let startup_url = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("startup UI URL");
    let url = reqwest::Url::parse(&startup_url).unwrap();
    assert_ne!(url.port(), Some(0), "startup must report the assigned port");
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap();
    assert!(client
        .get(url.join("health").unwrap())
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    // /v1/send resolves local transparency state, not DNS; this absent alias
    // deterministically creates an invite without an external resolver.
    let response: serde_json::Value = client
        .post(url.join("v1/send").unwrap())
        .bearer_auth(&token)
        .json(&serde_json::json!({"recipient":"nobody@unknown.invalid", "amount_sats":1000}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let claim_url = response["claim_url"]
        .as_str()
        .expect("send must include the claim URL");
    assert!(
        claim_url.starts_with(&format!("{startup_url}claim?invite_id=")),
        "{response}"
    );
    assert!(client
        .get(claim_url)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
}
