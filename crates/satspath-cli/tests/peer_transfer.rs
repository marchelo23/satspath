//! End-to-end P2P profile transfer through the real `satspath` binary:
//! register on "machine A" → export → import on "machine B" → resolve, and a
//! tampered profile is rejected on import.

use std::path::Path;
use std::process::Command;

/// Returns the compiled `satspath` CLI binary path.
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_satspath")
}

/// Runs the `satspath` CLI binary in `dir` with `args` and returns `(stdout, stderr, success)`.
fn run(dir: &Path, args: &[&str]) -> (String, String, bool) {
    let out = Command::new(bin())
        .args(args)
        .current_dir(dir)
        .env("SATSPATH_NOSTR_RELAYS", "")
        .env("SATSPATH_PASSWORD", "")
        .output()
        .expect("failed to run satspath binary");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.success(),
    )
}

/// Verifies exporting a signed profile on machine A and importing/showing it offline on machine B.
#[test]
fn export_then_import_across_registries() {
    // "Machine A" registers and exports.
    let a = tempfile::tempdir().unwrap();
    assert!(run(a.path(), &["init"]).2);
    assert!(
        run(
            a.path(),
            &[
                "register",
                "rodrigo@satspath.dev",
                "--ln-address",
                "trujasx@blink.sv"
            ]
        )
        .2
    );

    let (json, _e, ok) = run(a.path(), &["export", "rodrigo@satspath.dev"]);
    assert!(ok, "export failed");
    // stdout must be exactly the signed-profile JSON (redirectable to a file).
    let parsed: serde_json::Value =
        serde_json::from_str(json.trim()).expect("export must emit JSON");
    assert_eq!(parsed["profile"]["alias"], "rodrigo@satspath.dev");
    assert!(parsed.get("signature").is_some());

    let profile_file = a.path().join("rodrigo.json");
    std::fs::write(&profile_file, json.as_bytes()).unwrap();

    // "Machine B" — a fresh registry — imports and resolves.
    let b = tempfile::tempdir().unwrap();
    assert!(run(b.path(), &["init"]).2);
    let (out, err, ok) = run(b.path(), &["import", profile_file.to_str().unwrap()]);
    assert!(ok, "import failed: {err}{out}");
    assert!(out.contains("signature valid"), "import output: {out}");

    let (show, err, ok) = run(b.path(), &["show", "rodrigo@satspath.dev"]);
    assert!(ok, "locally imported profile must resolve offline: {err}");
    assert!(
        show.contains("Signature valid: yes"),
        "machine B should verify the imported profile:\n{show}"
    );
}

/// Verifies that `satspath import` rejects a tampered profile JSON.
#[test]
fn import_rejects_tampered_profile() {
    let a = tempfile::tempdir().unwrap();
    assert!(run(a.path(), &["init"]).2);
    assert!(
        run(
            a.path(),
            &["register", "rodrigo@satspath.dev", "--ln-address", "x@y.sv"]
        )
        .2
    );
    let (json, _e, ok) = run(a.path(), &["export", "rodrigo@satspath.dev"]);
    assert!(ok);

    // Tamper: change the alias inside the signed profile without re-signing.
    let tampered = json.replace("rodrigo@satspath.dev", "evil@hacker.com");
    let file = a.path().join("tampered.json");
    std::fs::write(&file, tampered.as_bytes()).unwrap();

    let b = tempfile::tempdir().unwrap();
    assert!(run(b.path(), &["init"]).2);
    let (_o, _e, ok) = run(b.path(), &["import", file.to_str().unwrap()]);
    assert!(!ok, "import must reject a tampered profile");
}
