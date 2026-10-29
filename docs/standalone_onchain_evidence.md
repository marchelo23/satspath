# Standalone on-chain acceptance evidence — #201 / #202

This document records reproducible implementation evidence, not a work plan or
external-wallet certification. Scope follows standalone phase 1 of
[#202](https://github.com/satspath/satspath/issues/202). Wallet integration,
external approval/signing/broadcast and receiving-side confirmations remain
phase 2 under #216/#171; #193/#195 are follow-ups, not prerequisites.

## Reproduce

```sh
npm ci
# Compile the independent consumer before the hermetic test invokes it offline.
cargo build -p satspath-cli
cargo test -p satspathd handlers::onboarding::tests
cargo test -p satspathd --test e2e_daemon_flow
cargo test -p satspath-cli check_handoff
cargo test -p satspathd method_proof
cargo test -p satspath-router --test wallet_executor_integration
```

The offline consumer can also be run directly. Supply the destination from
independently verified resolution, **not** by copying an untrusted quote field:

```sh
satspath check-handoff quote.json --recipient alice@example.com \
  --destination '<verified-address>' --amount-sats 21001 --network regtest
```

It validates the exact destination, amount and network against payer-supplied
bounds, including when both the quote's method and URI were modified together.
It never grants approval or verifies remote identity authority by itself.

The primary fixture is
`standalone_https_registration_ownership_quote_cli_approval_and_restart` in
[`onboarding/tests.rs`](../crates/satspathd/src/handlers/onboarding/tests.rs).
It uses HTTP routes of the real daemon implementation, an actual TLS server
with a controlled certificate/root and domain connection override **compiled
only into the unit-test harness**, and genuine identity/method/witness signatures.
It does not use `--dev-mock-alias-verification`, fake method verification,
request-supplied domain evidence, or disabled certificate verification. The
non-test daemon has no runtime test-CA or transport-override option.

Compilation may download normal Cargo dependencies. After the build, the
fixture's protocol traffic is loopback-only; the CLI consumer is invoked through
`cargo run --offline`. A separate step reopens the authorized home in the actual
**non-test daemon process**, without any mock/CA/trust override, and verifies the
same positive quote and domain-verification state. This is controlled standalone
evidence, not proof of deployment on a public domain or a wallet payment.

## #201 criterion-to-test mapping

| Criterion | Implementation and reproducible evidence |
| --- | --- |
| Initial real alias-control mechanism bound to registration and authorized event | `/v1/onboarding/challenge` prepares the signed profile and planned owner event before authorization. `/v1/onboarding/verify` fetches the exact body over HTTPS on the alias domain. The body binds profile, identity, action, sequence, predecessor, network, random challenge, expiry and optional invitation. The primary fixture verifies `identifier_verified: true`; negative fixtures reject wrong aliases, supplied evidence, untrusted TLS, private destinations, changed bodies, redirects and expiry. |
| Functional configurable claim destination | `SATSPATH_CLAIM_BASE_URL` targets the deployment's HTTPS `/claim` dashboard, with no credentials, query or fragment; only loopback binds may default to the actual local daemon page. `real_domain_claim_is_atomic_separate_and_single_use` exercises the generated URL and real claim. Dashboard registration and claim forms use the secure two-step endpoints and explicitly warn that a reload requires publishing a new challenge body. |
| Ownership attachment and renewal | Existing `method_proof_*` regressions verify genuine signatures, freshness, bounded expiry and monotonic renewal. The primary fixture attaches a real on-chain method-key signature after domain authorization and proves the method then resolves verified. Claim fixtures attach ownership through the optional receiver `alias` without rewriting the operator wallet. |
| Preservation and invalidation | Existing ownership regressions and the primary fixture preserve the exact proof across unrelated edits and invalidate replaced methods. All `quote/pay/send` paths reject the unverified replacement, including after restart; identity rotation invalidates identity-bound proofs. |
| No-mock claims, expiry/replay refusal without security-state mutation | Controlled real-TLS claim tests exercise concurrent verification and exactly one successful claim, separate receiver identity, durable inspection and recovered notifications. Late SQLite failure rolls back profile, event, checkpoint, attestation, consumed challenge, claim receipt and wallet activation. Wrong/expired/cancelled invites, stale wallet state, changed candidates and replay cannot publish. |

## #202 criterion-to-test mapping

| Criterion | Reproducible evidence |
| --- | --- |
| Profile → ownership → verified resolution → `quote/pay/send` → exact BIP-21 | The primary fixture registers without mock flags, proves `no_route` before ownership, attaches a genuine method-key proof, and checks profile/domain/ownership/continuity verification. It asserts the exact regtest destination and `21,001` satoshis across all three endpoints. The separate D1 black-box test also covers exact one-satoshi precision. |
| Independent handoff and approval-policy contract | The actual HTTP-emitted `QuoteResponse` is written to a public JSON file and consumed by the separate `satspath check-handoff` CLI process. Correct bounds pass; changed amount, destination or network fail. The CLI reports `preview_only`, `approval_granted: false`, and required host approval; it is not a remote identity-authority verifier. The same emitted quote enters native `prepare_payment_intent` with valid signed fixture witness/gossip/state-map evidence and pinned checkpoint. Refused approval, post-approval payload modification and a disabled execution policy fail before any host callback. No named-wallet adapter, simulated transaction or payment receipt is used. |
| Persistence and continuity | The fixture reopens the same home and pending challenge, tests recovery of the SQLite-committed wallet activation mirror, checks signed profile/event/claim state and checkpoint pins before reads can recreate them, then reopens the home in the non-test daemon process. The original D1 black-box fixture also restarts the real daemon binary and tests rejection persistence after destination replacement. |
| Preserve rejection and report handoff versus payment truthfully | Unverified/replaced methods yield `no_route`; malformed signatures and proof replay remain rejected. BIP-21 tampering is checked independently by the CLI and shared validator/native intent gates, not misrepresented as a modified daemon request. `/v1/pay` reports `wallet_handoff` and `daemon_executes_payment: false`; `/v1/send` reports `preview_only`. No user payment is approved, signed, broadcast or confirmed by the daemon. |

## Security and evidence boundaries

- The initial mechanism proves **domain administrator authorization**, not mailbox
  access or DNSSEC. Alias syntax is the ASCII BIP-353-compatible subset. Remote
  recipients must never receive the daemon administrator token.
- The daemon's operator issues a local `Domain` identifier attestation. Remote
  clients need their own trusted-verifier policy. An explicit local verifier
  policy replaces the default; even an empty list is never silently broadened.
  The grant expires with the
  original profile; normal updates can rebind it but cannot extend its lifetime
  or transfer it to a replacement identity. Registration cannot overwrite an
  existing alias/history; this delivery does not certify mailbox verification,
  public hosted account service, or arbitrary remote profile import.
- Claims create **local protocol identity keys**, never wallet spending keys.
  The receiver identity is separate from the operator wallet but remains managed
  in that administrator's home. Method-key proofs are independently signed by
  the external key owner. A domain grant or an invite alone cannot make a payment
  method verified.
- The old mock alias/claim endpoints remain explicitly development-only and gated.
  The D1 black-box test is still labeled mock-based; the additional HTTPS fixture
  is distinct. Witness/gossip evidence here uses controlled signing fixtures,
  not deployed independent witnesses; the existing SDK quorum gate is not relaxed.
- Husky builds/tests the independent CLI, checks formatting for both workspaces,
  runs daemon regressions and documentation/dashboard tests. The `daemon-flow`
  CI job builds the consumer and runs the full daemon suite. Full-workspace,
  Clippy, crypto-audit and external regtest results are reported separately;
  ignored/live tests and historical Core transfers do not become acceptance evidence.

## Recorded local validation

Review regressions additionally cover transactional batch notification recovery
(including failed saves and retries on the same store), receiver-key persistence
before challenge commit with rollback of only the newly created key, and a stalled
HTTP body that must not hold the mutation lock. Wallet activation retains both
predecessor and successor: intervening operator edits are rejected, an already
applied successor is cleared without rewriting, and legacy rows without a known
predecessor never overwrite a wallet. Registration rejects remove-only/metadata-only
method inputs even when the local wallet already has a receive method. Mixed-case
primary-alias proof attachment and an otherwise-valid unsigned-profile quote have
specific regression coverage.

Toolchain: `rustc 1.97.1`, `cargo 1.97.1`, Node `v22.23.2`; Linux, regtest
addresses, controlled HTTPS fixture. No public-domain deployment or external
wallet payment was exercised.

| Gate | Observed result |
| --- | --- |
| `cargo test --workspace` with offline fee sources | 829 passed, 0 failed, 8 ignored |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| Root and fuzz-workspace formatting checks | Passed |
| `audit_crypto.sh` | Passed; 0 errors/warnings; ignored external tests are not evidence |
| Documentation/dashboard Node tests | 56 passed |

Three local CodeRabbit review rounds were checked against the code. The latest
round's save-failure retry finding was fixed; its suggestion to start tracking the
root `Cargo.lock` was deferred to a separate dependency-policy change. The initial
build generates the currently ignored lockfile; nested consumers remain offline
and locked.
They are not an independent security audit or approval for real-funds use. Husky
reruns CLI/daemon, formatting and documentation/dashboard gates on commit.
