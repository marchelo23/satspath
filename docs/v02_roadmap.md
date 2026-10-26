# SatsPath v0.2 planning — current references

The maintained engineering roadmap is now [ROADMAP.md](../ROADMAP.md), with
prioritized milestones H0–H8, acceptance criteria, dependencies, and GitHub issues.
Use the [documentation index and capability matrix](README.md) for current behavior.

This page replaces an earlier component-completion checklist that incorrectly
implied full witness deployment, CLN/LDK interoperability, and finished wallet
integrations. Primitive implementations are not evidence of those complete flows.

## Existing foundations

- Signed profiles, key continuity, rotation, and guardian recovery primitives
  in `crates/satspath-core`; committing a guardian policy through the CLI is still
  unavailable. See [recovery limitations](key_recovery.md).
- Native BIP-353 DNSSEC validation and HTTPS/Nostr resolvers. The daemon's payable
  path uses local transactional state; WASM is a separate preview implementation.
- Transparency log, sparse state map, regtest Catena anchoring and gossip logic.
- Witness/cosigning library in `crates/satspath-witness`; the `satspath-gossip`
  monitor is a binary in that crate, not a separate crate or deployed federation.
- BOLT12 parsing, blinded paths and transport interfaces; BIP-352 public-vector
  checks; Ark ASP discovery, DAG checks and settlement handoff structures.
- `PaymentIntent` and reference `BdkOnchainBridge`, `LdkLightningBridge`,
  `BoltzTestnetSwapBridge`, and `HostWalletSdkBridge` in
  [wallet_executor.rs](../crates/satspath-router/src/wallet_executor.rs).
- Daemon routing/authentication, metrics, separate health contracts, and CI/fuzzing.

See [implementation mapping](implementations.md) for source paths and
[telemetry](telemetry.md) for what health responses actually check.

## Release work remains

1. Real alias attestation, method ownership integration, and a positive daemon
   on-chain journey: [H1](../ROADMAP.md#h1--p0--usable-onboarding-and-method-ownership-verification)
   and [H2](../ROADMAP.md#h2--p0--positive-end-to-end-on-chain-journey).
2. Packaging, SDK/WASM parity and real wallet adapters: H3–H5 in the project roadmap.
3. Integrated witness evidence, multi-operator operation and recoverable releases:
   H6–H7. A configured witness policy is not proof that cosignatures are collected.
4. Independent [external review](audit/EXTERNAL_CRYPTO_REVIEW_SPEC.md) before
   recommending real-fund use. No such completed review is claimed here.
5. Capability-specific external wallet evidence before removing BOLT12, Silent
   Payments, or Ark handoff gates: H8. Test-network evidence is not mainnet evidence.

## Architectural boundary

Host wallets retain spending keys, user approval, signing and payment execution.
The separate operator-only regtest anchor path is not user-payment execution.
See [mainnet safety](mainnet_safety.md).
