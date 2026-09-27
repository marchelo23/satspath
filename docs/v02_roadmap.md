# SatsPath: Current Architecture & Roadmap v0.2

This document summarizes the verified implementation status of SatsPath and outlines the engineering roadmap for the v0.2 milestone and future production readiness.

---

## 1. Verified Capability Status

The current codebase (`crates/`) implements and tests the following capabilities:

* **Core Protocol Specification & Cryptography (IMPLEMENTED):** Canonical JSON serialization (RFC 8785), domain-separated `secp256k1` Schnorr signatures (BIP-340), monotonic sequence tracking, and dual-signed key rotation.
* **Multi-Transport Resolver Chain (IMPLEMENTED):** Local registry, HTTPS `.well-known/satspath-authority`, and Nostr (NIP-05 and kind 30078).
* **BIP-353 DNS Resolution (PREVIEW):** Record parsing and strict DNSSEC policy enforcement are implemented. The default DoH backend does not independently validate the DNSSEC chain; Strict mode therefore requires authenticated DNSSEC results and fails closed otherwise.
* **BOLT12 Native Handling (EXPERIMENTAL / PARTIAL):** Offer parsing, TLV stream decoding (`lno1...`), blinded path extraction, and experimental invoice request structures (`crates/satspath-router/src/bolt12.rs`). Full interoperability against official BOLT12 specifications (including all-TLV Merkle tree hashing and native bech32 encoding) and live CLN/LDK implementations is still being validated.
* **Silent Payments BIP-352 (EXPERIMENTAL):** Public scan/spend key derivation, tagged hashing (`BIP0352/Inputs`, `BIP0352/SharedSecret`), multi-input key aggregation, and ephemeral Taproot output derivation (`crates/satspath-router/src/silent_payments.rs`). Conformance testing against official BIP-352 test vectors is ongoing.
* **Multi-Source Fee Estimation (IMPLEMENTED):** Concurrent queries to Bitcoin Core RPC, Esplora, and Mempool.space with median consensus filtering and decaying cache fallback (`crates/satspath-router/src/fees.rs`).
* **S2S v2 Transparency & State Map (IMPLEMENTED):** Append-only RFC 6962 Merkle log, signed operator checkpoints, client pin store, and Sparse Merkle state map for non-inclusion proofs (`crates/satspath-core/src/state_map.rs`).
* **Witness Quorum Cosigning (IMPLEMENTED):** Standalone witness node daemon (`crates/satspath-witness`) performing $K$-of-$N$ Schnorr cosigning, consistency proof verification, and local rollback/equivocation detection.
* **Ark Payment Routing (PREVIEW):** Receive pointer parsing and route scoring exist; live Ark ASP VTXO round execution is simulated (`crates/satspath-router/src/ark.rs`).
* **Submarine / Reverse Swaps (EXPERIMENTAL):** Boltz Exchange v2 client, encrypted store (AES-256-GCM), and claim/refund tx builders for testnet/regtest only (`crates/satspath-swaps`).
* **Post-Quantum Cryptography (RESEARCH):** Hybrid signature research module (`secp256k1` + ML-DSA-65) in `crates/satspath-pqc`.
* **Containerized Daemons & CLI (IMPLEMENTED):** Reference binaries for development and testing (`satspath-cli`, `satspathd`, `satspath-witness`).

---

## 2. Engineering Roadmap (v0.2 Milestone)

The v0.2 milestone focuses on external validation, production hardening, and wallet integration surfaces:

### A. Security Review & Cryptographic Auditing (P0 Release Gate)
* Independent third-party cryptographic review of canonical serialization, Merkle proof verifiers, key rotation, and domain-separated signing schemes.
* Independent threat modeling and penetration testing of `satspathd` reverse proxy and SSRF defenses.

### B. Decentralized Infrastructure & Protocol Conformance
* **Official BOLT12 TLV Merkle Tree Alignment:** Implement the full all-TLV Merkle tree algorithm and execute conformance suites against Core Lightning and LDK test vectors.
* **Official BIP-352 Conformance:** Import and validate the standard BIP-352 test vectors into `satspath-router`.
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
