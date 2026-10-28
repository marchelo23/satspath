# Documentation and implementation status

This index establishes the shared **H0 capability contract**
([#200](https://github.com/satspath/satspath/issues/200),
[implementation plan](implementation-plan-200.md)) and distinguishes **current
reference behavior**, **protocol requirements**, **previews/stubs/mocks**, and
**historical evidence**. Implementation notes were checked against `de96102`
(`upstream/main`); they describe verified repository behavior, not an external
wallet interoperability certification or independent third-party security audit.
When behavior changes, update the linked guide and its automated tests in the
same change.

## Start here

| Question | Current reference |
| --- | --- |
| What is implemented, and where? | [Implementation mapping](implementations.md) and the capability matrices below |
| How do the components fit together? | [Architecture](architecture.md) |
| How do I try the CLI? | [Local demonstration](../examples/demo_flow.md) |
| How do I integrate a wallet? | [SDK quickstart](SDK_QUICKSTART.md), [PaymentIntent](payment_intent.md), and tracked third-party guides in [#196](https://github.com/satspath/satspath/issues/196) |
| What does the daemon actually accept/return? | [HTTP API](API_REFERENCE.md), [OpenAPI](openapi.yaml), and [router source](../crates/satspathd/src/router.rs) |
| How do I run it locally? | [Docker guide](docker.md) and [authority deployment limitations](../deploy/README.md) |
| What do health and metrics mean? | [Telemetry](telemetry.md) |
| What work remains? | [Project roadmap and GitHub issues](../ROADMAP.md) |

## Lifecycle capability matrix by interface

**Non-custodial boundary:** signed profile ≠ alias control ≠ payment-method
ownership ≠ amountless receive pointer ≠ payable quote ≠ approved `PaymentIntent`
≠ executed payment. Across every interface, **host wallets retain private spending
keys, user confirmation, transaction/invoice signing, and broadcast**.

**State paths differ:** native CLI uses `SATSPATH_DIR` or local `.satspath`;
daemon uses `--home`, then `SATSPATH_HOME`, then its default local/user home.
Do not assume `SATSPATH_DATA_DIR` configures either path just because a container
sets it. See [CLI directory selection](../crates/satspath-core/src/lib.rs) and
[daemon startup](../crates/satspathd/src/main.rs).

| Surface | Discovery | Amountless receive | Payable quotes | Approval | External execution |
| --- | --- | --- | --- | --- | --- |
| **CLI** (`satspath-cli`) | **Implemented:** `ChainResolver` (`Registry` local store or public BIP-353 local DNSSEC + HTTPS + Nostr with conflict/downgrade checks) and `dns resolve` ([`commands/mod.rs`](../crates/satspath-cli/src/commands/mod.rs), [`dnssec_integration.rs`](../crates/satspath-core/tests/dnssec_integration.rs)) | **Preview / Stubs:** `wallet show`, `web` (`127.0.0.1` receive UI), and `ark receive` preview pointers. **Stubs:** `server init/check`, `dns check`, `identity *`, and `migration *` print scaffold messages only ([`commands/server.rs`](../crates/satspath-cli/src/commands/server.rs)) | **Preview:** `quote --json` emits validated on-chain, Silent Payment (`sp=`), or address-backed Ark (`ark=`) BIP-21/BIP-321 URIs; human `quote` and `preview --mainnet --fetch-lnurl-invoice` also fetch and validate BOLT11 (`receiver_pubkey`, network, amount, expiry) ([`commands/quote.rs`](../crates/satspath-cli/src/commands/quote.rs), [`commands/preview.rs`](../crates/satspath-cli/src/commands/preview.rs)). **Note:** `preview` human banner prints static placeholder trust text (`3/4 online`); inspect `--json` for actual verification fields. BOLT12 payable quotes fail closed | **None in CLI:** commands emit terminal/JSON previews (`MainnetPreview`); programmatic `PaymentIntent::approve` lives in the native Rust SDK ([`wallet_executor.rs`](../crates/satspath-router/src/wallet_executor.rs)) | **External wallet only:** CLI never executes mainnet payments. User scans/opens URI or BOLT11 in a host wallet. `--experimental-swaps --testnet` and `ark ... --execute-testnet` remain testnet-only scaffolds ([`commands/pay.rs`](../crates/satspath-cli/src/commands/pay.rs)) |
| **Daemon HTTP** (`satspathd`) | **Implemented (local state):** `POST /v1/resolve` and `POST /v2/resolve` verify local SQLite transparency state; `POST /v1/dns/resolve` performs strict local DNSSEC BIP-353 resolution ([`e2e_daemon_flow.rs`](../crates/satspathd/tests/e2e_daemon_flow.rs)). **Gaps:** `/v2/resolve` serves empty `witness_cosignatures` (`/v2/health` reports quorum unsatisfied; [`v2_api.rs`](../crates/satspathd/src/v2_api.rs)); production alias attestation is absent (`SATSPATH_DEV_MOCK_VERIFIER` is devnet/regtest-only; [#201](https://github.com/satspath/satspath/issues/201)) | **Implemented (LN / On-chain / SP / Ark):** `POST /v1/receive` returns Lightning Address/HTTPS LNURL pointers, `bitcoin:<addr>`, Silent Payments `bitcoin:[<addr>]?sp=<sp>` ([#199](https://github.com/satspath/satspath/pull/199)), and wallet-supplied Ark `bitcoin:?ark=<addr>` ([#209](https://github.com/satspath/satspath/pull/209); [`handlers/send.rs`](../crates/satspathd/src/handlers/send.rs)). **Unimplemented:** daemon BOLT12 receive was reverted in [#198](https://github.com/satspath/satspath/pull/198) (ignored spec `acceptance_bolt12_offer_receive_method`) | **Implemented (ownership-gated):** `POST /v1/quote`, `POST /v1/pay`, and Bearer-protected `POST /v1/send` require local transparency inclusion **and** a verified `MethodVerification` ownership proof (`no_route` otherwise; [`handlers/quote.rs`](../crates/satspathd/src/handlers/quote.rs)). Emits amount- and network-bound on-chain, Silent Payment (`sp=`), or address-backed Ark (`ark=`) BIP-21/BIP-321 URIs. Does **not** fetch LNURL BOLT11 ([#205](https://github.com/satspath/satspath/issues/205)) and rejects BOLT12 | **None in daemon:** `/v1/pay` (`daemon_executes_payment: false`) and `/v1/send` (`mode: "preview_only"`) return unsigned handoff payloads and QR SVGs for host-wallet confirmation | **External wallet only:** daemon never holds user spending keys, signs user transactions, or broadcasts user payments (`opens_external_wallet: true`). Opt-in regtest checkpoint anchoring (`POST /v1/transparency/anchors`) uses operator loopback Bitcoin Core RPC with test coins only ([`mainnet_safety.md`](mainnet_safety.md)) |
| **Browser WASM** (`satspath-wasm`) | **Preview (separate codebase):** `ChainResolver` exported, but `LocalRegistry.add_profile` errors, Nostr relay querying is unimplemented, and browser DoH lacks native local DNSSEC chain validation ([`satspath-wasm/src/resolver.rs`](../crates/satspath-wasm/src/resolver.rs), [#187](https://github.com/satspath/satspath/issues/187), [#188](https://github.com/satspath/satspath/issues/188)). Not published to npm ([#189](https://github.com/satspath/satspath/issues/189)) | **Primitives only:** no standalone receive endpoint; exports `verify_signed_profile`, `canonical_profile_json`, `fingerprint_pubkey`, `topic_for_alias`, and host-local `derive_identity_keypair_from_seed` ([`satspath-wasm/src/crypto.rs`](../crates/satspath-wasm/src/crypto.rs)) | **Preview (standard on-chain only):** `quote(recipient, amountSats: number)` emits `bitcoin:<addr>?amount=<btc>` only when `silent_payment_pubkey` is absent; Lightning, BOLT12, Silent Payments, and Ark fail closed as `no_route` ([`satspath-wasm/src/router.rs`](../crates/satspath-wasm/src/router.rs), [`sdk-quickstart.test.mjs`](tests/sdk-quickstart.test.mjs)) | **None in WASM:** JS wrapper checks (`profile_signature_verified === true`) guard preview display only and do not implement `PaymentIntent` approval ([`SDK_QUICKSTART.md`](SDK_QUICKSTART.md)) | **External wallet only:** returns a BIP-21 URI string for a separate wallet; optional `bolt12` feature helper targets an unimplemented dummy worker (`proxy-workers/bolt12`) |
| **Dashboard UI** (`satspathd/src/index.html`) | **Implemented (local inspector):** renders `/v1/control`, `/v1/transparency/*`, client-side WebCrypto SHA-256 Merkle inclusion checks, and public `GET /v1/claim?invite_id=...`. Displays signature, authority, continuity, ownership, transparency, and anchor states separately; `Map root` is explicitly labeled `not implemented` ([`index.html`](../crates/satspathd/src/index.html), [`dashboard-auth.test.mjs`](../crates/satspathd/tests/dashboard-auth.test.mjs)) | **Implemented (via `/v1/receive`):** `Receive` tab generates QR + URI for `Auto`, `Lightning`, `On-chain`, and `Ark`. **UI form gap:** `My Profile` currently edits `alias`, `lightning_address`, `onchain_address`, `onchain_pubkey`, `ark_server`, and `ark_pubkey` only (no `silent_payment_address`, `ark_address`/`ark_asp_pubkey`, BOLT12 offer, or ownership-proof inputs; [#201](https://github.com/satspath/satspath/issues/201), [#205](https://github.com/satspath/satspath/issues/205)) | **Preview (via Bearer `/v1/send`):** `Send` tab requires unlocking with `admin.macaroon` and renders `POST /v1/send` (`mode: "preview_only"`) QR/URI or an unescrowed `mailto:` invitation ([`invite_flow.md`](invite_flow.md)) | **Operator auth only:** tab unlock authenticates local daemon admin access in memory (`Bearer`, cleared on lock/`pagehide`), **not** a wallet `PaymentIntent` spend approval ([`dashboard_authentication.md`](dashboard_authentication.md)) | **External wallet only:** UI footer and API enforce `No funds moved`; payer scans or copies the handoff payload into an external wallet |

## Component and rail capability matrix

“Implemented” below is scoped to the linked crate and test suite. It does not
imply deployed federation operations or third-party wallet certification.

| Capability / Rail | Status | Verified scope and limits | Reproducible evidence |
| --- | --- | --- | --- |
| **Native resolver chain & BIP-353 DNSSEC** | **Implemented** | Local authoritative registry or public BIP-353 (`HickoryDnssecTxtResolver` rooted at ICANN KSKs `38696`/`20326`/`19036`, `DnssecPolicy::Strict`), HTTPS, and Nostr resolvers with conflict/downgrade policy; distinct from daemon local SQLite lookup | [`resolvers.md`](resolvers.md), `cargo test -p satspath-core --test dnssec_integration` |
| **Daemon onboarding & claims** | **Preview (devnet mock only)** | Profile signature and invite records exist; production alias-control verifier is absent (`SATSPATH_DEV_MOCK_VERIFIER` restricted to devnet/regtest; tracked in [#201](https://github.com/satspath/satspath/issues/201)) | [`claim.rs`](../crates/satspathd/src/handlers/claim.rs), `cargo test -p satspathd --test e2e_daemon_flow` |
| **Daemon method ownership lifecycle (#201 D1)** | **Implemented (signature proofs only)** | Bearer-protected `POST /v1/profile/methods/proof` attaches/renews externally signed on-chain P2WPKH/key-path P2TR and Ark proofs. Fresh issuance, explicit bounded expiry and monotonic renewal are required. Unrelated edits preserve evidence; method replacement/removal and identity rotation invalidate it. No domain-proof attachment, Silent Payment ownership certification, dashboard proof input, alias attestation or payment execution is added | [`API_REFERENCE.md`](API_REFERENCE.md#payment-method-ownership-attachment), [`profile.rs`](../crates/satspathd/src/handlers/profile.rs), `cargo test -p satspathd method_proof` |
| **On-chain BIP-21 quotes & handoffs** | **Implemented** | Network-checked address validation, multi-source fee consensus, exact 8-decimal BTC amount formatting; daemon payable routes require verified `OnchainAddressSignature` ownership | [`quote.rs`](../crates/satspathd/src/handlers/quote.rs), `cargo test -p satspath-handoff -p satspath-router` |
| **Lightning (LNURL / BOLT11)** | **Implemented in CLI & SDK; pending in daemon/WASM** | Amountless pointers via daemon `/v1/receive`; BOLT11 invoice fetch + payee/network/amount/expiry validation in CLI `quote` / `preview --mainnet --fetch-lnurl-invoice` and native `LdkLightningBridge`. Not fetched by daemon or WASM ([#205](https://github.com/satspath/satspath/issues/205)) | [`preview.rs`](../crates/satspath-cli/src/commands/preview.rs), `cargo test -p satspath-cli -p satspath-router` |
| **BOLT12 offers & blinded paths** | **Primitives implemented; receive/pay gated** | Checksumless Bech32 decoding, TLV Merkle signatures, blinded paths, and `OnionMessageTransport` (`ReferenceNodeOnionTransport` is an in-process test double, not live CLN/LDK). Daemon receive is unimplemented after [#198](https://github.com/satspath/satspath/pull/198); `proxy-workers/bolt12` returns dummy `lnbc1dummy_invoice_resolved_from_bolt12_offer` with mismatched path ([`bolt12_handling.md`](bolt12_handling.md)) | [`bolt12.rs`](../crates/satspath-router/src/bolt12.rs), `cargo test -p satspath-router bolt12` |
| **Silent Payments (BIP-352)** | **Experimental (receive/URI implemented; execution gated)** | Public projections checked against all 28 official BIP-352 vector groups; daemon `/v1/profile/methods`, `/v1/receive`, and router `build_qr_payload` emit `bitcoin:[<addr>]?sp=<sp>[&amount=<btc>]` ([#199](https://github.com/satspath/satspath/pull/199)). Host ECDH, `PaymentIntent` execution, and external wallet interop remain gated ([#208](https://github.com/satspath/satspath/issues/208)) | [`silent_payments_integration.rs`](../crates/satspath-router/tests/silent_payments_integration.rs), `acceptance_silent_payment_receive_method` in [`e2e_daemon_flow.rs`](../crates/satspathd/tests/e2e_daemon_flow.rs) |
| **Ark (BIP-321 receive & ASP client)** | **Preview (receive/URI implemented; execution gated)** | Wallet-supplied Bech32m Ark address + pinned `ark_asp_pubkey` emit `bitcoin:?ark=<addr>[&amount=<btc>]` ([#209](https://github.com/satspath/satspath/pull/209)); `LiveArkAspClient` (`/v1/info` pinned to arkd v0.9.16), VTXO DAG checks, and Boarding/Forfeit/OOR structures exist ([`ark_routes.md`](ark_routes.md)). `PaymentIntent` execution and live arkd/wallet interop remain gated ([#208](https://github.com/satspath/satspath/issues/208)) | [`ark_receive.rs`](../crates/satspath-router/src/ark_receive.rs), `acceptance_ark_receive_uses_bip321_ark_param` in [`e2e_daemon_flow.rs`](../crates/satspathd/tests/e2e_daemon_flow.rs) |
| **Native Wallet SDK (`PaymentIntent` & `WalletExecutor`)** | **Implemented (reference host bridges)** | `prepare_payment_intent` → `PaymentIntent::approve(true)` → `execute_quote_handoff` enforces RFC 8785 JCS digest binding, witness/gossip/state-map evidence, and fee caps via `HostWalletSdkBridge` (`BdkOnchainBridge`, `LdkLightningBridge`, testnet-only `BoltzTestnetSwapBridge`). Rejects Silent Payments, Ark, BOLT12, and mainnet swaps ([`payment_intent.md`](payment_intent.md)) | [`wallet_executor_integration.rs`](../crates/satspath-router/tests/wallet_executor_integration.rs), `cargo test -p satspath-router --test wallet_executor_integration` |
| **Transparency, witnesses & S2S v2** | **Components implemented; daemon quorum pending** | Append-only RFC 6962 log, 256-bit Sparse Merkle state map, standalone `satspath-witness` cosigner and `satspath-gossip` binary. Daemon `/v2/resolve` currently serves empty `witness_cosignatures` and no envelope consistency proof ([#206](https://github.com/satspath/satspath/issues/206), [`s2s/server-v2.md`](s2s/server-v2.md)) | `cargo test -p satspath-witness`, `cargo test -p satspath-core --test transparency` |
| **Regtest Catena anchoring** | **Implemented (regtest operator RPC only)** | Opt-in `OP_RETURN` and continuation-UTXO chain anchoring against operator-controlled Bitcoin Core regtest; never user-payment execution and never for real funds ([`mainnet_safety.md`](mainnet_safety.md)) | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) (`bitcoin-regtest`), [`.github/workflows/daemon-e2e.yml`](../.github/workflows/daemon-e2e.yml) (`daemon-regtest-anchor`) |
| **Protocol conformance suite** | **Incremental** | Embedded `vectors/v1.json` covering canonicalization, expiry, BIP-21/BOLT12 handoff validation, capability descriptors, and `--observed` JSON comparison; `SKIP` never becomes `PASS`. Wallet execution, DNSSEC chain vectors, positive rotation, and `PaymentIntent` vectors remain tracked in [#196](https://github.com/satspath/satspath/issues/196) / [#204](https://github.com/satspath/satspath/issues/204) | [`crates/satspath-conformance/README.md`](../crates/satspath-conformance/README.md), `cargo test -p satspath-conformance` |
| **Swaps & Post-Quantum Cryptography** | **Experimental / Research** | Boltz v2 testnet/regtest scaffolding (`satspath-swaps`, mainnet execution closed) and hybrid `secp256k1` + ML-DSA-65 / ML-KEM research primitives (`satspath-pqc`); excluded from production safety claims | `cargo test -p satspath-swaps -p satspath-pqc` |

### H2 D1: positive daemon preview coverage

The active `onchain_owned_profile_handoffs_survive_restart_and_reject_replacement`
test in [`e2e_daemon_flow.rs`](../crates/satspathd/tests/e2e_daemon_flow.rs) covers
profile → genuine method-key ownership → transparency resolution → `quote/pay/send`
→ exact regtest BIP-21, including one-satoshi precision and same-home daemon restart.
Forged signatures, replay, unverified replacement destinations, and handoff
destination/amount/network changes are rejected. It runs in the existing
`daemon-flow` CI job and Husky daemon tests.

**Classification: hermetic preview evidence, not external interoperability.**
Alias authorization is explicitly dev-mocked (`identifier_verified: false`);
no wallet is opened, no spend approved, and no transaction signed or confirmed.
External-wallet settlement and no-mock alias acceptance remain pending under
[#202](https://github.com/satspath/satspath/issues/202); see the
[implementation plan](implementation-plan-202.md).

## Ignored-test inventory

Every `#[ignore]` test in the Rust workspace is inventoried below and checked
for 1-to-1 parity by [`docs/tests/openapi-and-docs.test.mjs`](tests/openapi-and-docs.test.mjs).
**Ignored regtest tests invoked automatically by CI workflows are active CI
coverage and do not count as missing coverage.**

| Test (`file :: function`) | Ignore reason | Covered capability | Executing command / CI job | Coverage classification |
| --- | --- | --- | --- | --- |
| `crates/satspath-core/tests/regtest_anchor.rs :: checkpoint_op_return_round_trip_on_bitcoin_core_regtest` | `requires an explicitly configured Bitcoin Core regtest node` | Single checkpoint `OP_RETURN` regtest anchor creation and RPC verification (`RegtestAnchorClient`) | `cargo test -p satspath-core --test regtest_anchor --all-features -- --ignored --test-threads=1` — [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) job `bitcoin-regtest` (push & PR) | **Active CI regtest coverage** |
| `crates/satspath-core/tests/regtest_anchor.rs :: catena_chain_anchoring_and_backward_verification_on_regtest` | `requires an explicitly configured Bitcoin Core regtest node` | Multi-step Catena genesis + continuation-UTXO chain anchoring and backward commitment verification | `cargo test -p satspath-core --test regtest_anchor --all-features -- --ignored --test-threads=1` — [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) job `bitcoin-regtest` (push & PR) | **Active CI regtest coverage** |
| `crates/satspath-core/tests/regtest_anchor.rs :: catena_double_spend_equivocation_rejected_by_bitcoin_core` | `requires an explicitly configured Bitcoin Core regtest node` | Bitcoin Core mempool/consensus double-spend rejection of conflicting Catena branches and equivocation proof detection | `cargo test -p satspath-core --test regtest_anchor --all-features -- --ignored --test-threads=1` — [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) job `bitcoin-regtest` (push & PR) | **Active CI regtest coverage** |
| `crates/satspathd/tests/e2e_daemon_flow.rs :: regtest_profile_checkpoint_is_anchored_on_chain` | `needs Bitcoin Core regtest: set SATSPATH_BITCOIN_RPC_URL/USER/PASSWORD` | Black-box daemon HTTP anchoring (`POST /v1/transparency/anchors`, `GET /v1/transparency/anchors/{txid}`, `GET /v1/transparency/catena/chain`) | `cargo test -p satspathd --test e2e_daemon_flow -- --ignored regtest_profile_checkpoint_is_anchored_on_chain` — [`.github/workflows/daemon-e2e.yml`](../.github/workflows/daemon-e2e.yml) job `daemon-regtest-anchor` (push & PR) | **Active CI regtest coverage** |
| `crates/satspathd/tests/e2e_daemon_flow.rs :: live_bip353_strict_dnssec_resolution_through_daemon` | `live DNSSEC lookup on the public internet` | Live public-internet BIP-353 strict DNSSEC lookup through `POST /v1/dns/resolve` (offline deterministic DNSSEC chains run in default CI) | `cargo test -p satspathd --test e2e_daemon_flow -- --ignored live_bip353_strict_dnssec_resolution_through_daemon` — [`.github/workflows/daemon-e2e.yml`](../.github/workflows/daemon-e2e.yml) job `daemon-live-dnssec` (`workflow_dispatch` with `run_live_dnssec=true`) | **Opt-in live external network smoke** |
| `crates/satspath-core/tests/dnssec_integration.rs :: test_live_dnssec_signed_domain` | `Live external network DNS test; run explicitly with -- --ignored` | Live `HickoryDnssecTxtResolver` validation of `cloudflare.com` against bundled ICANN KSKs (offline deterministic fixtures run in default CI) | `cargo test -p satspath-core --test dnssec_integration -- --ignored test_live_dnssec_signed_domain` (manual live smoke; offline suite runs in `.github/workflows/ci.yml` job `test`) | **Opt-in live external network smoke** |
| `crates/satspath-core/tests/dnssec_integration.rs :: test_live_dnssec_bogus_domain_fails_closed` | `Live external network DNS test; run explicitly with -- --ignored` | Live `HickoryDnssecTxtResolver` fail-closed rejection of `dnssec-failed.org` (offline bogus-signature tests run in default CI) | `cargo test -p satspath-core --test dnssec_integration -- --ignored test_live_dnssec_bogus_domain_fails_closed` (manual live smoke; offline suite runs in `.github/workflows/ci.yml` job `test`) | **Opt-in live external network smoke** |
| `crates/satspathd/tests/e2e_daemon_flow.rs :: acceptance_bolt12_offer_receive_method` | `acceptance: BOLT12 daemon receive method not implemented yet` | Executable acceptance spec for `POST /v1/profile/methods` (`bolt12_offer`) and `POST /v1/receive` (`bitcoin:?lno=...`) | `cargo test -p satspathd --test e2e_daemon_flow -- --ignored acceptance_bolt12_offer_receive_method` (not enabled in CI; reverted from #197 in [#198](https://github.com/satspath/satspath/pull/198), tracked in [#208](https://github.com/satspath/satspath/issues/208)) | **Pending unimplemented capability gate** |

## Reconciled implementation issues

To avoid duplicating downstream milestones, H0 ([#200](https://github.com/satspath/satspath/issues/200))
establishes the authoritative capability contract and reconciles existing
implementation issues as follows:

- **[#196 — Wallet integration guide, security checklist and conformance profile](https://github.com/satspath/satspath/issues/196):**
  H0 aligns [`docs/SDK_QUICKSTART.md`](SDK_QUICKSTART.md) and
  [`docs/payment_intent.md`](payment_intent.md) with the verified
  `prepare_payment_intent` → `PaymentIntent::approve` → `execute_quote_handoff`
  contract and real `satspath_router::wallet_executor` bridge names. Remaining
  #196 deliverables — `docs/integrations/README.md`, per-wallet pages
  (`arkade.md`, `sparrow.md`), integrator UX checklist, and the executable
  `satspath-conformance wallet --adapter ...` CLI profile — stay open and
  coordinated with H4 ([#204](https://github.com/satspath/satspath/issues/204))
  and H5 ([#205](https://github.com/satspath/satspath/issues/205)).
- **WASM and package parity ([#187](https://github.com/satspath/satspath/issues/187), [#188](https://github.com/satspath/satspath/issues/188), [#189](https://github.com/satspath/satspath/issues/189)):**
  Explicitly scoped as `Preview` above; tracked under H3 ([#203](https://github.com/satspath/satspath/issues/203))
  and H4 ([#204](https://github.com/satspath/satspath/issues/204)).
- **Experimental and external wallet promotion ([#171](https://github.com/satspath/satspath/issues/171), [#193](https://github.com/satspath/satspath/issues/193), [#195](https://github.com/satspath/satspath/issues/195), [#208](https://github.com/satspath/satspath/issues/208)):**
  Silent Payments ([#184](https://github.com/satspath/satspath/issues/184) / [#199](https://github.com/satspath/satspath/pull/199))
  and Ark ([#186](https://github.com/satspath/satspath/issues/186) / [#209](https://github.com/satspath/satspath/pull/209))
  now support daemon receive and URI formatting, while external host-wallet
  execution and BOLT12 daemon receive remain gated under H2/H5/H8.

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
node --test docs/tests/*.test.mjs crates/satspathd/tests/dashboard-auth.test.mjs
```

These checks cover local links, OpenAPI/auth parity, the four-surface lifecycle
matrix, 1-to-1 ignored-test inventory parity, workspace directory paths, and SDK
wrapper/approval examples. Mocked examples do **not** compile WASM or establish
wallet interoperability. Rust, regtest, and external wallet evidence must remain
separate.
