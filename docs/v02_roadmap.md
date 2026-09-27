# SatsPath: Current Architecture & Roadmap v0.2

This document summarizes the verified implementation status of SatsPath and outlines the engineering roadmap for the v0.2 milestone and future production readiness.

---

## 1. Verified Implemented Capabilities

The current codebase (`crates/`) implements and tests the following capabilities:

* **Core Protocol Specification & Cryptography:** Canonical JSON serialization (RFC 8785), domain-separated `secp256k1` Schnorr signatures (BIP-340), monotonic sequence tracking, and dual-signed key rotation.
* **Multi-Transport Resolver Chain:** Local registry, HTTPS `.well-known/satspath-authority`, BIP-353 DNS resolution (with DNSSEC fail-closed policy), and Nostr (NIP-05 and kind 30078).
* **BOLT12 Native Handling:** Bech32m TLV offer decoding, blinded path extraction, signed invoice requests, and invoice validation (`crates/satspath-router/src/bolt12.rs`).
* **Silent Payments (BIP-352):** Public key derivation, tagged hashing (`BIP0352/Inputs`, `BIP0352/SharedSecret`), multi-input aggregation, output computation, and BIP-21 URI formatting (`crates/satspath-router/src/silent_payments.rs`).
* **Multi-Source Fee Estimation:** Concurrent queries to Bitcoin Core RPC, Esplora, and Mempool.space with median consensus filtering and decaying cache fallback (`crates/satspath-router/src/fees.rs`).
* **S2S v2 Transparency & State Map:** Append-only RFC 6962 Merkle log, signed operator checkpoints, client pin store, and Sparse Merkle state map for non-inclusion proofs (`crates/satspath-core/src/state_map.rs`).
* **Witness Quorum Cosigning:** Standalone witness node daemon (`crates/satspath-witness`) performing $K$-of-$N$ Schnorr cosigning, consistency proof verification, and local rollback/equivocation detection.
* **Containerized Daemons & CLI:** Reference binaries for development and testing (`satspath-cli`, `satspathd`, `satspath-witness`).

---

## 2. Engineering Roadmap (v0.2 Milestone)

The v0.2 milestone focuses on external validation, production hardening, and wallet integration surfaces:

### A. Security Review & Cryptographic Auditing (P0 Release Gate)
* Independent third-party cryptographic review of canonical serialization, Merkle proof verifiers, key rotation, and domain-separated signing schemes.
* Independent threat modeling and penetration testing of `satspathd` reverse proxy and SSRF defenses.

### B. Decentralized Infrastructure & Witness Federation
* **Cross-Witness Gossip:** Implement public alert and gossip mechanisms between independent witness nodes to broadcast detected equivocation or split-view checkpoints in real-time.
* **Embedded DNSSEC Validator:** Integrate a lightweight local DNSSEC validator into `satspath-core` to enable `DnssecPolicy::Strict` without relying on external system resolvers.

### C. Wallet Integration & Mobile SDKs
* **TypeScript & WebAssembly SDK:** Production packaging of `@satspath/wasm` and `@satspath/router` for browser and React Native wallets.
* **Standardized Wallet Handoff Bridges:** Reference plugins for major open-source Bitcoin wallets to consume SatsPath BIP-21 and BOLT12 handoff payloads seamlessly.
* **Native Rust FFI:** C/Swift/Kotlin bindings for embedded mobile integration.

### D. Advanced Payment Rails
* **Live Ark ASP Settlement:** Integrate real Ark Service Provider VTXO round negotiation and DAG verification once Ark client implementations mature on testnet.
* **Multi-Recipient Batching:** Recursive resolution and route optimization for split or batched payments.
* **Encrypted Profile Metadata:** Optional ECDH-encrypted profile fields for recipients who wish to restrict address disclosure to authorized senders.

---

## 3. Architectural Boundary Reminder

SatsPath remains firmly committed to a **non-custodial, wallet-agnostic architecture**. SatsPath will not become a custodial wallet, will not store seed phrases, and will not take custody of funds. Payment execution and transaction signing remain sovereign responsibilities of the user's host wallet.
