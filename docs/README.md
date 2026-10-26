# Documentation and implementation status

This index distinguishes **current reference behavior**, **protocol requirements**,
and **historical evidence**. Implementation notes were checked against `defd042`;
they describe source code, not a fresh interoperability or security certification.
When behavior changes, update the linked guide and its tests in the same change.

## Start here

| Question | Current reference |
| --- | --- |
| What is implemented, and where? | [Implementation mapping](implementations.md) and the matrix below |
| How do the components fit together? | [Architecture](architecture.md) |
| How do I try the CLI? | [Local demonstration](../examples/demo_flow.md) |
| How do I integrate a wallet? | [SDK quickstart](SDK_QUICKSTART.md), [PaymentIntent](payment_intent.md) |
| What does the daemon actually accept/return? | [HTTP API](API_REFERENCE.md), [OpenAPI](openapi.yaml), and [router source](../crates/satspathd/src/router.rs) |
| How do I run it locally? | [Docker guide](docker.md) and [authority deployment limitations](../deploy/README.md) |
| What do health and metrics mean? | [Telemetry](telemetry.md) |
| What work remains? | [Project roadmap and GitHub issues](../ROADMAP.md) |

## Current capability matrix

“Implemented” below is scoped to the named component. It does not mean a
production deployment or real-wallet payment has been demonstrated.

**State paths differ:** native CLI uses `SATSPATH_DIR` or local `.satspath`;
daemon uses `--home`, then `SATSPATH_HOME`, then its default local/user home.
Do not assume `SATSPATH_DATA_DIR` configures either path just because a container
sets it. See [CLI directory selection](../crates/satspath-core/src/lib.rs) and
[daemon startup](../crates/satspathd/src/main.rs).

| Surface | Current behavior | Important limit / source |
| --- | --- | --- |
| Native resolver chain | Local authoritative registry or public BIP-353/HTTPS/Nostr sources with disagreement and downgrade checks | Not the same as daemon local resolution; [CLI construction](../crates/satspath-cli/src/commands/mod.rs), [resolver policy](resolvers.md) |
| Daemon onboarding/claims | Real alias-control verifier absent; mock opt-in only on devnet/regtest | A profile signature or invite ID is not alias attestation; [claim handler](../crates/satspathd/src/handlers/claim.rs) |
| Daemon payable quotes | Verified on-chain methods with exact amount/network; missing method ownership produces `no_route` | `/pay` returns a handoff, not a payment; [quote handler](../crates/satspathd/src/handlers/quote.rs) |
| CLI BOLT11 | Explicit LNURL invoice fetching and shared payee, amount, network, expiry validation | Not automatic daemon/WASM support; [preview](../crates/satspath-cli/src/commands/preview.rs) |
| BOLT12 | Native parsing, blinded paths and invoice-request transport abstractions; daemon amountless receive pointer | Payable handoffs remain gated; HTTP worker returns a dummy invoice; [BOLT12 guide](bolt12_handling.md) |
| Silent Payments / Ark | Public BIP-352 operations and vectors; Ark planning, ASP connector and handoff structures | Not complete daemon payable flows; pending receive acceptance tests; [E2E tests](../crates/satspathd/tests/e2e_daemon_flow.rs), [Ark limits](ark_routes.md) |
| Wallet SDK | `PaymentIntent`, single-use approval, dispatch revalidation and reference host callbacks | Host must supply current trust/evidence and fee-bound adapters; [implementation](../crates/satspath-router/src/wallet_executor.rs) |
| Browser WASM | Separate preview implementation; JS `quote` accepts a whole-number `number` | Local insertion/Nostr and resolver/serialization parity incomplete; not native DNSSEC parity; [quickstart](SDK_QUICKSTART.md) |
| Witnesses and S2S | Witness/cosigning library and `satspath-gossip` binary; local v2 envelopes | Daemon serves empty witness signatures and no envelope consistency proof; `/v2/health` reports quorum not satisfied; [server status](s2s/server-v2.md) |
| Anchoring | Authenticated opt-in operator Bitcoin Core RPC on regtest | Never use real funds; [safety boundary](mainnet_safety.md) |
| Swaps / PQC | Testnet/regtest swap scaffolding; feature-gated PQC research | Some claim paths remain unimplemented; neither is a production-readiness claim; [roadmap H8](../ROADMAP.md#h8--p2--promote-experimental-capabilities-independently) |

## Specifications are not deployment instructions

[Protocol v1](protocol.md) and the [S2S v2 specification](s2s/protocol-v2.md)
define contracts and requirements. The S2S replication, migration, DNS delegation,
and witness topology documents include target behavior beyond the current daemon.
Use [server implementation status](s2s/server-v2.md) before assuming an endpoint
or operational workflow exists. Code types and routes are the reference for the
currently shipped wire behavior; a specification excerpt is not an executable API.

## Historical evidence

- [Regtest exercise](daemon_e2e_results.md): recorded local observations; its
  disposable harness was not committed. Automated E2E tests are linked separately.
- [Security simulation log](../security_tests.md) and
  [September 2026 internal review](audit/INTERNAL_SECURITY_AUDIT_REPORT.md):
  historical reports, not current test-run attestations or an external audit.
- [Benchmarks](benchmarks.md): distinguishes traceable artifacts from unverified
  historical numbers. Do not use old estimates as current performance guarantees.
- [Earlier v0.2 planning](v02_roadmap.md): compatibility entry point to current
  status and the maintained project roadmap, not a second completion checklist.

## Documentation checks

From the repository root, with Node.js 20+:

```bash
node --test docs/tests/*.test.mjs
```

These checks cover local links, API inventory/auth documentation, and SDK wrapper
examples/contracts. Mocked examples do **not** compile WASM or establish wallet
interoperability. Rust, regtest, and external wallet evidence must remain separate.
