# SatsPath Roadmap

> Analysis baseline: `main`, commit `51b5f62`.
> Engineering proposal based on a static repository review by three agents:
> architecture/product, testing/operations, and gaps/integrations.
> This is not certification of test runs, remote CI, deployments, or interoperability.

## Goal

First deliver a reproducible, non-custodial journey:

**Identity onboarding → publication → payment-method ownership verification →
resolution → quote → explicit approval → execution by an external wallet.**

The proposed initial scope is on-chain, followed by BOLT11. BOLT12, Silent
Payments, and Ark advance through demonstrated capabilities, not merely the
presence of parsers, connectors, or handoff structures.

This document complements the [v0.2 roadmap](docs/v02_roadmap.md): it organizes
remaining product and operational work without treating component-level
primitives as completed integrations. It does not assign dates, owners, or new
release versions. GitHub issues below track the proposed work; their open status
does not imply that every underlying component is missing.

## Starting point

| Area | Existing foundation | Gap to close |
| --- | --- | --- |
| Identity | Signed profiles, rotation, and guardian recovery | Real alias attestation; onboarding/claims without mock verifiers |
| Resolution | HTTPS, Nostr, and BIP-353 with native DNSSEC validation | Evidence-carrying remote consumption in the daemon; close WASM differences |
| Routing | Verified on-chain quotes; CLI can obtain validated BOLT11 | Integrate ownership proofs and a positive daemon journey |
| Transparency | Log, state map, regtest anchoring, and witness/gossip primitives | Integrate cosignatures/quorum into the service and operate across independent authorities |
| Wallets | `PaymentIntent` and reference bridges | Reproducible external integrations with host approval and execution |
| Quality | Rust/JS CI, fuzzing, incremental conformance, and daemon E2E | Test shipping configurations/artifacts, real WASM, and compilable examples |
| Operations | Docker, metrics, logs, alerts, and guides | Canonical deployment, verifiable packaging, and rehearsed recovery |

**Key distinction:** signed profile ≠ alias control ≠ method ownership ≠ payable
handoff ≠ executed payment. The dashboard and documentation must show these
states separately.

Recorded regtest evidence demonstrates BIP-21 receive payloads and anchoring,
but `send/quote/pay` return `no_route` for methods without ownership proofs.
That does not yet demonstrate the complete positive product journey.

Sources: [README](README.md#what-works-today-what-is-experimental-and-what-has-not-been-audited),
[E2E results](docs/daemon_e2e_results.md),
[daemon tests](crates/satspathd/tests/e2e_daemon_flow.rs).

## Priorities and dependencies

- **P0:** blockers for the basic journey and a verifiable preview distribution.
- **P1:** product expansion and operational integration.
- **P2:** experimental capabilities that do not block the initial core.

Main sequence: **H0 → H1 → H2 → H4 → H5**.
H3 can run in parallel after H0; H6 requires H2 and builds on H3.
H7 requires H3 and H6, plus H4/H5 for the capabilities being advertised.
H8 is a separate workstream with capability-specific gates.

## GitHub tracking

The milestone issues track the checklists below. Existing implementation issues
are linked rather than duplicated. Dependencies describe the proposed delivery
order, not a claim that all development must happen serially.

<!-- roadmap-issues:start -->
| Milestone | Priority | Tracking issue | Existing implementation issues |
| --- | --- | --- | --- |
| H0 · Capability contract | P0 | [#200](https://github.com/satspath/satspath/issues/200) | [#196](https://github.com/satspath/satspath/issues/196) |
| H1 · Onboarding and ownership | P0 | [#201](https://github.com/satspath/satspath/issues/201) | — |
| H2 · On-chain E2E | P0 | [#202](https://github.com/satspath/satspath/issues/202) | [#171](https://github.com/satspath/satspath/issues/171), [#193](https://github.com/satspath/satspath/issues/193), [#195](https://github.com/satspath/satspath/issues/195) |
| H3 · Packaging and deployment | P0 | [#203](https://github.com/satspath/satspath/issues/203) | [#189](https://github.com/satspath/satspath/issues/189) |
| H4 · SDK/WASM and conformance | P1 | [#204](https://github.com/satspath/satspath/issues/204) | [#187](https://github.com/satspath/satspath/issues/187), [#188](https://github.com/satspath/satspath/issues/188), [#189](https://github.com/satspath/satspath/issues/189), [#196](https://github.com/satspath/satspath/issues/196) |
| H5 · Lightning and host wallets | P1 | [#205](https://github.com/satspath/satspath/issues/205) | [#171](https://github.com/satspath/satspath/issues/171), [#193](https://github.com/satspath/satspath/issues/193), [#195](https://github.com/satspath/satspath/issues/195), [#196](https://github.com/satspath/satspath/issues/196) |
| H6 · Quorum and multi-operator operations | P1 | [#206](https://github.com/satspath/satspath/issues/206) | — |
| H7 · Recovery and release gates | P1 | [#207](https://github.com/satspath/satspath/issues/207) | [#171](https://github.com/satspath/satspath/issues/171) |
| H8 · Experimental capabilities | P2 | [#208](https://github.com/satspath/satspath/issues/208) | [#171](https://github.com/satspath/satspath/issues/171), [#184](https://github.com/satspath/satspath/issues/184), [#186](https://github.com/satspath/satspath/issues/186), [#190](https://github.com/satspath/satspath/issues/190), [#191](https://github.com/satspath/satspath/issues/191), [#192](https://github.com/satspath/satspath/issues/192) |
<!-- roadmap-issues:end -->

### H0 · P0 — Align the capability contract

- [ ] Publish a CLI/daemon/WASM/dashboard matrix distinguishing discovery,
  amountless receive, payable quotes, approval, and external execution.
- [ ] Fix SDK examples bypassing `PaymentIntent`, outdated bridge names/paths,
  and claims that confuse primitives with interoperability.
- [ ] Inventory ignored tests: reason, covered capability, and executing command/job.
  Ignored regtest tests invoked by CI do not count as missing coverage.

**Acceptance:** every advertised capability links to a test or reproducible
evidence; previews and stubs are explicitly identified.

Evidence: [previous roadmap](docs/v02_roadmap.md),
[quickstart](docs/SDK_QUICKSTART.md), [PaymentIntent contract](docs/payment_intent.md),
[E2E CI](.github/workflows/daemon-e2e.yml).

### H1 · P0 — Usable onboarding and method ownership verification

- [ ] Select and implement an initial real alias-control mechanism, bound to
  registration and the authorized event; do not treat an invitation as proof.
- [ ] Replace the placeholder claim URL with a configurable, functional destination.
- [ ] Integrate payment-method ownership proof attachment and renewal into the daemon.
- [ ] Define proof preservation across unrelated edits and invalidation when the
  verified payment method changes.

**Acceptance:** onboarding and claims without mock flags; incorrect aliases,
expiration, and replay rejected without mutations; verified methods resolve as such.

Evidence: [claim](crates/satspathd/src/handlers/claim.rs),
[profiles](crates/satspathd/src/handlers/profile.rs),
[proof tooling](crates/satspath-cli/src/commands/proofs.rs).

### H2 · P0 — Positive end-to-end on-chain journey

- [ ] Automate profile → ownership → resolution → `quote/pay/send` → BIP-21
  with the exact amount and network.
- [ ] Connect the handoff to an external wallet on regtest with explicit approval.
- [ ] Verify persistence and continuity after daemon restart.
- [ ] Preserve rejection of unverified methods and modified destinations/amounts/networks.

**Acceptance:** reproducible fixture without ownership bypasses; separate evidence
of quoting, approval, wallet-signed transaction, and regtest confirmation.
The daemon neither signs nor executes user payments.

Evidence: [quote](crates/satspathd/src/handlers/quote.rs),
[handoff gates](crates/satspath-router/src/quote_response.rs),
[current E2E](crates/satspathd/tests/e2e_daemon_flow.rs).

### H3 · P0 — Reproducible preview packaging and deployment

- [ ] Define the distributable package graph, versions, and dependencies;
  validate `cargo package` and `cargo publish --dry-run` before publishing.
- [ ] Pin build inputs and define an application lockfile policy;
  gate releases on checks for the same SHA.
- [ ] Build, scan, and test the daemon image; use its actual reference in a
  canonical Compose with documented volume permissions and TLS configuration.
- [ ] Implement `server init/check` or identify them as stubs that do not
  validate a real deployment.

**Acceptance:** artifact installation in a clean environment, empty-volume startup,
state-preserving restart, and a proxy smoke test. Documentation, published image,
and container options agree.

Evidence: [publishing](.github/workflows/publish.yml),
[Docker CI](.github/workflows/docker.yml), [deployment](deploy/README.md),
[server commands](crates/satspath-cli/src/commands/server.rs).

### H4 · P1 — Consumable SDK/WASM and conformance

- [ ] Fix or explicitly scope local registry, Nostr, serialization, and BIP-353
  in WASM; test compatibility with native resolver contracts where applicable.
- [ ] Compile the TypeScript quickstart against generated declarations and install
  the resulting package in a clean project; do not document nonexistent packages.
- [ ] Add a wasm32 build and browser resolve→quote smoke test before publishing.
- [ ] Run documentation tests in CI and extend conformance with positive rotation,
  `PaymentIntent`, handoff, and authenticated conflicts, without converting SKIP to PASS.

**Acceptance:** compilable Rust/TypeScript examples, real WASM artifact testing,
and an explicit native/browser difference matrix, including DNSSEC evidence.

Evidence: [WASM resolver](crates/satspath-wasm/src/resolver.rs),
[WASM router](crates/satspath-wasm/src/router.rs),
[conformance](crates/satspath-conformance/README.md), [CI](.github/workflows/ci.yml).

### H5 · P1 — Integrated Lightning and host wallets

- [ ] Bring BOLT11 retrieval into the daemon, bound to authenticated payee,
  amount, network, and expiry, reusing existing validations.
- [ ] Integrate one on-chain and one Lightning wallet with real callbacks,
  `PaymentIntent`, user confirmation, and fee limits.
- [ ] Align the dashboard with actual alias, ownership, receive, preview, and
  payment states; do not advertise mock invitations as production claims.

**Acceptance:** reproducible BOLT11 journey on a test network and a wallet matrix
with versions/results; reject post-approval modifications.
Record mock tests separately from external interoperability.

Evidence: [handoff](crates/satspath-router/src/handoff.rs),
[wallet executor](crates/satspath-router/src/wallet_executor.rs),
[dashboard](crates/satspathd/src/index.html).

### H6 · P1 — Integrated quorum and multi-operator operations

- [ ] Connect checkpoints, witnesses, and cosignature collection/consumption;
  serve sufficient evidence for remote resolution and continuity.
- [ ] Define separate liveness, service readiness, and S2S readiness contracts;
  do not present current health responses as proof of integrated quorum.
- [ ] Test independent operators, restart, quorum loss, and disagreement.
- [ ] Verify metric freshness, rules with `promtool`, actual alert delivery,
  and dependency-failure runbooks.

**Acceptance:** repeatable multi-operator demonstration with verified signatures,
durable state, and visible failures; consumers reject insufficient evidence.

Evidence: [resolve](crates/satspathd/src/handlers/resolve.rs),
[health/routing](crates/satspathd/src/router.rs),
[witness](crates/satspath-witness/src/lib.rs),
[witness guide](docs/s2s/witness-deployment.md), [monitoring](monitoring/).

### H7 · P1 — Recoverable pilot and release gates

- [ ] Rehearse consistent backup, fresh-volume restore, and upgrade;
  compare log identity, sequences, profiles, events, checkpoints, and pins.
- [ ] Document rollback limits, secrets/state inventory, and measured RPO/RTO
  targets; test abrupt termination and disk exhaustion in a disposable lab.
- [ ] Test defaults and all-features, plus final images and packages;
  record load, latency, and storage growth.
- [ ] Publish an artifact manifest, checksums, compatibility, and limitations.
- [ ] Complete the required independent external review before recommending
  real-fund use; record scope and finding resolution.

**Acceptance:** release checklist traceable to evidence from the same commit,
rehearsed restoration, and a pilot with operational alerts. A scoped preview
does not need every experimental rail enabled.

Evidence: [persistence](crates/satspath-core/src/transparency/database.rs),
[Docker operations](docs/docker.md),
[required external review](docs/audit/EXTERNAL_CRYPTO_REVIEW_SPEC.md).

### H8 · P2 — Promote experimental capabilities independently

| Capability | Next verifiable result |
| --- | --- |
| BOLT12 | Preserve already-tested amountless receive; unify WASM/proxy contract, replace dummy invoice, and integrate a real CLN/LDK backend before enabling payment |
| Silent Payments | Persist receive descriptor, validate network and interoperable URI, enable pending acceptance, and test a host wallet; private ECDH stays in the wallet |
| Ark | Replace private URI with interoperable receive, enable pending acceptance, and test identified ASP/wallet implementations before enabling execution |
| Swaps | Matrix by type/script/network; complete or reject unimplemented claims early and test claim/refund/recovery on testnet/regtest |
| PQC | Keep a separate research workstream without production-readiness promises |

**Acceptance per capability:** automated test + reproducible example + external
evidence where applicable + documented limitations. Remove only the demonstrated
gate, without enabling other rails as a side effect. Test-network evidence must
not be presented as mainnet validation.

Evidence: [existing acceptance tests](crates/satspathd/tests/e2e_daemon_flow.rs),
[BOLT12 proxy](proxy-workers/bolt12/src/index.ts),
[WASM BOLT12 client](crates/satspath-wasm/src/bolt12.rs),
[chain swaps](crates/satspath-swaps/src/chain_swap.rs),
[reverse swaps](crates/satspath-swaps/src/reverse.rs).

## Boundaries the roadmap must not accidentally remove

- The host wallet retains spending keys, signing, and execution; SatsPath receives
  no seeds or `xprv`/`tprv`. Identity keys are a separate category.
- Current active anchoring is operator-controlled regtest; do not expand to mainnet
  or use real funds as a consequence of completing another milestone.
- Keep mainnet swaps disabled and experimental handoffs closed until their
  specific criteria are met.
- Quorum improves consistency but does not independently authenticate the initial
  alias→key binding. Do not conceal TOFU or namespace-authority dependencies.
- P2P is optional discovery, not authority to blindly import profiles.

Reference: [mainnet safety](docs/mainnet_safety.md).

## Tracking rule

Break each milestone into tasks with an owner and evidence before scheduling dates.
Check a box only when its criterion is reproducible; update the capability matrix,
linked issues, and this document when completing a milestone.

**Recommended first increment:** H0, an alias mechanism selected for H1, and a
positive H2 fixture. In parallel, rehearse H3 packaging without publishing anything.
