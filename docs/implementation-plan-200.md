# Issue #200 — H0: Align the capability contract

Status: implementation plan + complete H0 delivery. Tracks
<https://github.com/satspath/satspath/issues/200> (`ROADMAP.md` H0 / P0).
Baseline: `upstream/main` at `de96102` (updating the earlier `51b5f62` / `defd042`
static review after [#198](https://github.com/satspath/satspath/pull/198),
[#199](https://github.com/satspath/satspath/pull/199), and
[#209](https://github.com/satspath/satspath/pull/209)).

This delivery aligns advertised capabilities, SDK examples, and test coverage
records with actual repository behavior. It does **not** certify external wallet
interoperability, complete an independent security audit, or remove any mainnet
or experimental execution gate.

## Delivery breakdown and estimates

1. **D1 — Multi-surface capability matrix and post-#198/#199/#209 alignment (~2 hours / 0.5 engineering day).**
   - Publish a **CLI / Daemon HTTP / Browser WASM / Dashboard UI** lifecycle matrix
     in [`docs/README.md`](README.md) distinguishing **discovery**, **amountless receive**,
     **payable quotes**, **approval (`PaymentIntent`)**, and **external execution**.
   - Link every advertised capability to its authoritative source file and an
     automated test or reproducible command.
   - Explicitly identify mocks (`SATSPATH_DEV_MOCK_VERIFIER` on devnet/regtest),
     previews (browser WASM `quote`, CLI `--mainnet`, Ark ASP discovery), stubs
     (`satspath server init/check`, `dns check`, `identity *`, `migration *`,
     `proxy-workers/bolt12` dummy invoice, `satspath preview` static terminal
     trust banner), and unimplemented gates (daemon BOLT12 receive reverted in
     [#198](https://github.com/satspath/satspath/pull/198); empty daemon v2
     witness cosignatures).
   - Reconcile stale prose in [`README.md`](../README.md),
     [`docs/bolt12_handling.md`](bolt12_handling.md),
     [`docs/implementations.md`](implementations.md),
     [`examples/demo_flow.md`](../examples/demo_flow.md), and
     [`walktrough.md`](../walktrough.md).

2. **D2 — SDK examples, bridge/package paths, and #196 scope reconciliation (~2 hours / 0.5 engineering day).**
   - Add a concrete Native Rust `PaymentIntent` approval and dispatch example in
     [`docs/SDK_QUICKSTART.md`](SDK_QUICKSTART.md) demonstrating
     `quote_with_resolver` → `prepare_payment_intent` → payer confirmation →
     `PaymentIntent::approve` → `execute_quote_handoff` with
     `HostWalletSdkBridge`, `BdkOnchainBridge`, and `LdkLightningBridge`.
   - Enforce in [`docs/tests/sdk-quickstart.test.mjs`](tests/sdk-quickstart.test.mjs)
     that documented Rust symbols match
     [`crates/satspath-router/src/wallet_executor.rs`](../crates/satspath-router/src/wallet_executor.rs)
     and never bypass `PaymentIntent` via legacy `pay_bolt11` or `send_onchain`.
   - Remove the nonexistent `packages/arkade-vtxo-verification/` directory entry
     from [`docs/architecture.md`](architecture.md), fix the positional
     `satspath import received-profile.json` invocation in
     [`sdk/satspath-p2p/README.md`](../sdk/satspath-p2p/README.md), and align the
     crate header in [`crates/satspath-wasm/src/lib.rs`](../crates/satspath-wasm/src/lib.rs)
     with WASM's on-chain-only `build_qr_payload`.
   - Reconcile [#196](https://github.com/satspath/satspath/issues/196) without
     duplicating its remaining implementation scope (`docs/integrations/*`
     per-wallet guides and `satspath-conformance wallet --adapter` profiles).

3. **D3 — Ignored-test inventory and automated drift guard (~1.5 hours / 0.5 engineering day).**
   - Publish a complete inventory of all `#[ignore]` Rust tests in
     [`docs/README.md`](README.md) with ignore reason, covered capability,
     executing command or CI workflow job, and coverage classification.
   - Classify Bitcoin Core regtest tests invoked by
     [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) (`bitcoin-regtest`)
     and [`.github/workflows/daemon-e2e.yml`](../.github/workflows/daemon-e2e.yml)
     (`daemon-regtest-anchor`) as active CI coverage rather than missing coverage.
   - Add automated drift checks in
     [`docs/tests/openapi-and-docs.test.mjs`](tests/openapi-and-docs.test.mjs)
     verifying 1-to-1 parity between `#[ignore]` attributes in `crates/` (plus
     zero untracked `ignore` doctests) and the published inventory table, as well
     as existence of all workspace paths listed in [`docs/architecture.md`](architecture.md).

4. **D4 — Roadmap update, Husky pre-commit validation, and PR review (~1 hour / 0.25 engineering day).**
   - Update [`ROADMAP.md`](../ROADMAP.md) H0 checklist with reproducible evidence
     links and correct the H8 BOLT12 row to reflect the [#198](https://github.com/satspath/satspath/pull/198)
     daemon receive rollback.
   - Configure [`.husky/pre-commit`](../.husky/pre-commit) to run workspace and
     `fuzz/` formatting checks plus the Node contract, SDK quickstart, and
     dashboard test suites on every local commit.
   - Run full workspace Rust tests, Clippy, documentation checks, and
     `audit_crypto.sh`; open the pull request and request `@coderabbitai full review`.

## Security and architectural invariants preserved

- **Non-custodial boundary:** Host wallets retain spending keys, user approval,
  signing, and transaction/invoice execution. SatsPath never receives seeds,
  `xprv`/`tprv`, or Lightning macaroons.
- **Fail-closed execution gates:** Mainnet swap execution remains disabled;
  `prepare_payment_intent` and `execute_quote_handoff` continue to reject BOLT12,
  Silent Payments, Ark, and unapproved or modified quotes.
- **Distinct verification dimensions:** Signed profile ≠ alias control ≠ payment-method
  ownership ≠ payable handoff ≠ approved `PaymentIntent` ≠ executed payment.

## Reproducible validation

```sh
npm ci
node --test docs/tests/*.test.mjs crates/satspathd/tests/dashboard-auth.test.mjs
cargo fmt --all -- --check
cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
bash .agents/skills/satspath-crypto-audit/scripts/audit_crypto.sh
```
