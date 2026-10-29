# Issue #205 — standalone Lightning implementation plan

## Delivery boundaries

SatsPath resolves identities and constructs verified payment handoffs. The user's
wallet owns spending keys, approval, signing and execution. Invoice retrieval is
not payment execution. Existing experimental/mainnet gates remain unchanged.

1. **D1 — verified daemon invoice retrieval (this PR, estimated one day).** Reuse
   the router's LNURL client and final handoff validator. Fetch only after profile
   signature, alias, expiry, transparency and method-ownership verification.
   Bind invoices to the authenticated receiver key, exact amount, exact BOLT11
   currency and expiry. Keep routing through `select_route_with_fees` and
   `QuoteResponse`; reject unsupported methods and retain safe fallback rails.
   Bound responses, reject ambiguous callback parameters and retain production
   HTTPS/DNS/SSRF/redirect protections. Add local Husky regression gates.
2. **D2 — cross-interface journey (estimated one day).** Add HTTP-level positive
   ownership onboarding → resolve → quote → pay/send tests, including invalid
   ownership/signature, expired profile and modified handoff cases. Align CLI
   network-aware retrieval and PaymentIntent/approval semantics. Test that invoice
   generation never produces an executed-payment state.
3. **D3 — browser and state contract (estimated one day).** Coordinate with #204
   for applicable WASM validation. Publish a tested capability matrix covering
   core, CLI, daemon and WASM. Distinguish receive pointer, payable invoice,
   approval, handoff and execution in dashboard/API/CLI. Keep unsupported raw
   LNURL and BOLT12 retrieval fail-closed until separately implemented/tested.
4. **D4 — reproducible evidence (estimated one day, endpoint availability dependent).**
   Publish a supported test-network walkthrough with endpoint, receiver public
   key, ownership evidence, exact amount and expiry. Record real endpoint evidence
   separately from deterministic mocks. Complete release gates under #207;
   third-party wallet adapters remain phase 2 (#216).

## D1 supported contract

- The daemon's verified quote path supports Lightning Addresses with an
  independently verified `receiver_pubkey`. Both `/v1/pay` and `/v1/send` consume
  that same quote pipeline and retain their existing non-executing states.
- Attached Lightning domain proofs are refreshed from the canonical well-known
  endpoint with protected, bounded transport. Duplicate, stale, mismatching or
  unavailable proofs never authorize retrieval. `/v1/resolve` remains an offline
  view and reports these methods as requiring a fresh network check. The daemon
  proof-attachment API still supports only on-chain/Ark signatures (#201);
  Lightning profiles must already carry a valid externally prepared domain proof.
- Raw LNURL, BOLT12, missing/invalid receiver keys and unauthenticated methods do
  not become payable invoices. Amount-less receive pointers remain distinct.
- Exact currencies: mainnet/bitcoin, testnet/devnet, signet, regtest. Mutinynet is
  not implicitly accepted as a Lightning currency. Legacy `fetch_invoice` retains
  its mainnet-only contract; native verified retrieval validates the configured
  currency at the final shared gate.
- Tests use local mocked HTTP only through test-only transport options; production
  never enables loopback or disables SSRF. These tests are not live endpoint or
  real-fund evidence. No browser retrieval capability is claimed by D1.

## Local validation

Run `npm ci` to install Husky. A normal `git commit` must execute `.husky/pre-commit`:
workspace/fuzz formatting, router unit tests, daemon tests, and documentation /
dashboard contract tests. Do not use `HUSKY=0` or `--no-verify`.

Additional release verification: `cargo test --workspace`,
`cargo clippy --workspace --all-targets -- -D warnings`, and
`.agents/skills/satspath-crypto-audit/scripts/audit_crypto.sh`.

This PR delivers D1 only and does not close #205. D2–D4 require separate evidence.
