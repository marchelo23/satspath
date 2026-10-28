# Issue #202 — positive end-to-end on-chain journey

Tracks [H2 / #202](https://github.com/satspath/satspath/issues/202).
Baseline: `upstream/main` at `82fc4bb`, including #201 D1 (#213).
This incremental delivery does **not** close #202 or certify external-wallet
interoperability. The daemon never approves, signs, or executes user payments.

## Implementation sequence

1. **D1 — ownership-gated daemon fixture (1 engineering day).** Extend the real
   HTTP daemon harness with same-home process restart. Publish an on-chain regtest
   profile, demonstrate `no_route` before ownership, attach a genuine externally
   generated method-key signature through the authenticated #201 API, and verify
   transparency-backed resolution. Assert exact BIP-21 destination, network and
   satoshi amount across `quote`, `pay` and `send`, including one-satoshi precision.
   Reject modified handoffs, proof replay, and replacement destinations without
   proof. Preserve profile, event history and checkpoint pins across restart.
   Alias setup remains explicitly dev-mocked and `identifier_verified: false`.
2. **D2 — external wallet and settlement (1 engineering day).** Add an opt-in
   loopback Bitcoin Core regtest client outside the daemon. Validate the handed-off
   destination/amount/network before presenting an explicit approval gate. Without
   approval, do not call signing/broadcast RPCs. The host wallet alone constructs,
   signs and broadcasts the transaction. Mine a block and inspect the receiving
   output and confirmations. Store separate quote, approval, signed-transaction
   and settlement evidence; never log spending keys or RPC credentials.
3. **D3 — no-mock acceptance (1 engineering day after #201 D2–D4).** Replace mock
   alias setup with real alias-control evidence; run the fixture from clean state
   and after daemon restart. Exercise refusal paths before approval/execution.
   Publish exact commands, tool versions, network, transaction ID and confirmations
   separately from hermetic preview tests. Update the capability matrix and H2
   checklist only for observed results.

## Reuse and scope reconciliation

- **#201:** reuse the ownership-proof endpoint, challenge format and durable
  transparency state. Production alias verification is a dependency, not a bypass.
- **#171:** coordinate receiver-confirmed wallet interoperability with its existing
  harness/PR #180; D1 adds daemon preview coverage, not a second wallet framework.
- **#193:** no new wallet-integration API in D1. Reuse existing `quote/pay/send`;
  the stable desktop-wallet schema remains owned by #193.
- **#195:** Sparrow UI, proxy settings and upstream proposal remain separate.
  A Core regtest fixture does not establish Sparrow interoperability.

## Validation and evidence

```sh
npm ci # prepare installs Husky; do not bypass hooks
cargo test -p satspathd --test e2e_daemon_flow onchain_owned_profile
cargo test -p satspathd
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
bash .agents/skills/satspath-crypto-audit/scripts/audit_crypto.sh
```

The existing Husky pre-commit hook runs daemon tests (including D1), formatting
for both workspaces, documentation-contract tests and dashboard tests. The
existing `daemon-flow` CI job runs D1 without Bitcoin Core or internet access.
Full-workspace/audit checks and external settlement are separate evidence; an
ignored test or a URI preview is never a successful payment.

After opening the PR, post the exact comment `@coderabbitai full review`.
Do not merge automatically or close #202: D2–D3 acceptance remains outstanding.

## D1 delivery evidence — 2026-10-28

- Added the active black-box ownership/handoff/restart fixture and extended the
  unauthenticated/wrong-token route checks to the ownership endpoint.
- `cargo test --workspace`: 813 passed, 0 failed, 8 ignored (external regtest,
  live DNSSEC and unfinished BOLT12 acceptance; ignored tests are not evidence).
- Full-workspace/all-target Clippy with `-D warnings`, both workspace formatting
  checks, 54 Node documentation/dashboard tests, and the crypto audit passed.
- The capability matrix and daemon evidence document distinguish D1 previews
  from external-wallet settlement. Existing user edits in `ROADMAP.md` are not
  included in this delivery; the H2 acceptance checklist stays pending.
