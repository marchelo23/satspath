# SatsPath

**Open-source Bitcoin payment discovery and routing infrastructure.**

> **One human-readable Bitcoin identity. Any compatible wallet. Multiple payment rails. No custody.**

[![CI](https://github.com/satspath/satspath/actions/workflows/ci.yml/badge.svg)](https://github.com/satspath/satspath/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 60-Second Executive Summary

### The Problem
Bitcoin users today navigate a fragmented landscape of payment identifiers:
* **Lightning Addresses** (`user@domain.com`)
* **LNURL-pay** links
* **BOLT12 Offers** (`lno1...`)
* **On-Chain Addresses** (SegWit, Taproot)
* **BIP-21 URIs**
* **BIP-353 DNS Names** (`₿user@domain.com`)
* **Silent Payments** (`sp1...`)
* **Ark Payment Pointers**
* **Nostr Pubkeys / NIP-05**

Different wallets support different subsets of these mechanisms. Today, paying someone in Bitcoin requires the sender to know in advance which rail the recipient supports, what channel liquidity is available, or what fee environment makes the transaction practical.

### The SatsPath Solution
SatsPath maps a single human-readable recipient identifier (e.g. `alice@example.com`) to a **cryptographically signed payment profile**, verifies its integrity and provenance, discovers the receiver's advertised payment capabilities, and generates a **wallet handoff payload** for the optimal rail.

```text
Human-readable identifier (alice@example.com)
       ↓
Multi-transport resolution (HTTPS / Nostr / BIP-353 / S2S)
       ↓
Cryptographic verification (BIP-340 Schnorr signature, expiry, Merkle inclusion)
       ↓
Capability discovery (Lightning, BOLT12, on-chain, Silent Payments, Ark)
       ↓
Reference route selection (amount, multi-source fee consensus, priority)
       ↓
Wallet handoff payload (BIP-21 URI, BOLT11 invoice, BOLT12 offer, Ark pointer)
       ↓
Host wallet signs and executes the payment
```

### Why SatsPath Exists
To receive Bitcoin across modern rails, a user should **not** need:
* A new custodial wallet or intermediary.
* A new seed phrase or backup ritual.
* A single centralized directory provider.
* To lock themselves into a single payment layer.
* To know which wallet implementation the sender is running.

SatsPath is public infrastructure that enables seamless interoperability between wallets without introducing a new custody layer, a new token, or a closed network.

> **Current Maturity & Safety Notice:** SatsPath is experimental, non-custodial open-source software. Mainnet payment discovery and wallet handoff are supported, but **mainnet payment execution and transaction signing by SatsPath are deliberately unsupported**. Real-funds execution remains strictly under the control of user wallets. An independent external cryptographic audit is required before production deployment.

Website: <https://satspath.com>

---

## Non-Custodial Architecture: A Security Invariant

**SatsPath does not have, and never requests, the user's private spending keys.**

This is not a missing feature—it is an intentional **security property**:

```mermaid
flowchart LR
    subgraph Discovery ["SatsPath (Discovery & Verification Layer)"]
        A[Recipient Identifier] --> B[Resolver Chain]
        B --> C[Profile Signature Verification]
        C --> D[Capability Discovery & Routing]
        D --> E[Wallet Handoff Payload]
    end

    subgraph Wallet ["User's Host Wallet (Sovereign Custody)"]
        E --> F[Display Payment Prompt]
        F --> G[Inspect Amounts & Dest]
        G --> H[Sign with Private Spending Key]
        H --> I[Broadcast to Bitcoin / Lightning]
    end

    classDef sats fill:#d4edda,stroke:#28a745,stroke-width:2px;
    classDef wallet fill:#cfe2ff,stroke:#0d6efd,stroke-width:2px;
    class A,B,C,D,E sats;
    class F,G,H,I wallet;
```

* **No Custody of Funds:** SatsPath cannot seize, freeze, or lose user funds.
* **No Seed Phrases:** SatsPath never handles BIP-39 seeds, xprv/tprv keys, or node credentials.
* **Identity Keys Carry No Funds:** The `secp256k1` identity keypair is used exclusively to sign public profiles, authorization statements, and key rotations.
* **Wallet Retains Final Authority:** The host wallet inspects the payment payload, presents it to the user, signs it using its internal spending keys, and broadcasts it directly to the network.

---

## Verified Capability Matrix

This table reflects the actual status of the codebase (`crates/`) verified by unit, integration, and security simulation tests.

| Capability | Current Codebase Status | Architectural Details & Limitations |
| :--- | :--- | :--- |
| **Signed Payment Profiles** | **Implemented** | Canonical JSON (RFC 8785), domain-separated `secp256k1` Schnorr signatures (`BIP-340`), monotonic sequence and expiry validation. |
| **Key Continuity & Rotation** | **Implemented** | Dual-signed rotation transitions (`AuthorizationV1` signed by old key, `AcceptanceV1` by new key) bound to canonical history. |
| **HTTPS S2S Resolver** | **Implemented** | Resolves signed profiles over HTTPS (`.well-known/satspath-authority`) with strict SSRF filtering, loopback/private IP blocking, and 50KB payload limits. |
| **Nostr Resolver** | **Implemented** | NIP-05 pubkey lookup and kind `30078` event fetching; verifies SatsPath profile signature independently of Nostr relay signatures. |
| **BIP-353 DNS Resolver** | **Implemented (Preview)** | Parses `₿user@domain` TXT records into `bitcoin:` URIs. Default `DnssecPolicy::Strict` fails closed without local DNSSEC validator. |
| **Lightning Address / LNURL** | **Implemented** | Resolves public metadata and requests concrete BOLT11 invoices for wallet handoff. |
| **BOLT12 Offers & Blinded Paths**| **Implemented** | TLV offer decoding (`lno1...`), blinded path extraction, signed invoice request generation (`lnr1...`), and invoice validation (`crates/satspath-router/src/bolt12.rs`). |
| **On-Chain / BIP-21** | **Implemented** | Network address validation (mainnet, testnet, regtest), dynamic fee estimation, and `bitcoin:` BIP-21 URI formatting. |
| **Silent Payments (BIP-352)** | **Implemented (Experimental)** | Public scan/spend key derivation, tagged hashing, multi-input key aggregation, and ephemeral Taproot output derivation (`crates/satspath-router/src/silent_payments.rs`). |
| **Multi-Source Fee Consensus** | **Implemented** | Concurrent queries across Bitcoin Core RPC, Esplora, and Mempool.space with median filtering and decaying cache fallback (`crates/satspath-router/src/fees.rs`). |
| **S2S v2 Transparency Log** | **Implemented** | Append-only Merkle event log, RFC 6962-style compact consistency proofs, and signed operator checkpoints (`crates/satspath-core/src/transparency.rs`). |
| **Authenticated State Map** | **Implemented** | Sparse Merkle tree generating cryptographic non-inclusion proofs, bound to checkpoint root (`crates/satspath-core/src/state_map.rs`). |
| **Witness Quorum Cosigning** | **Implemented** | Standalone witness node (`crates/satspath-witness`) performing $K$-of-$N$ Schnorr cosigning, consistency verification, and local rollback/equivocation detection. |
| **Ark Payment Routing** | **Preview (Simulated)** | Receive pointer parsing and route scoring exist; live Ark ASP VTXO round execution is simulated (`crates/satspath-router/src/ark.rs`). |
| **Submarine / Reverse Swaps** | **Experimental (Testnet)** | Boltz Exchange v2 client, AES-256-GCM encrypted store, and claim/refund tx builders for testnet/regtest only (`crates/satspath-swaps`). |
| **Post-Quantum Cryptography** | **Research (Experimental)** | Hybrid signature module (`secp256k1` + ML-DSA-65) in `crates/satspath-pqc`. Research primitive; not part of production safety claim. |
| **Mainnet Payment Execution** | **Deliberately Unsupported** | SatsPath does not execute mainnet payments, broadcast transactions, or sign with spending keys. Execution is delegated to wallets. |

---

## SatsPath in the Bitcoin Ecosystem

### Why Not Just Use a Lightning Address?
A Lightning Address (`user@domain.com`) is a useful protocol that maps an email-like alias to an HTTP LNURL-pay endpoint to fetch a BOLT11 invoice:
* **Scope:** A Lightning Address exclusively routes to a Lightning receiving node. If the receiver's node is offline, channel liquidity is depleted, or the transaction amount exceeds channel capacity, the payment fails.
* **SatsPath Complementarity:** SatsPath does not replace Lightning Addresses—it can consume them. A SatsPath profile can advertise a Lightning Address alongside on-chain addresses, BOLT12 offers, Silent Payments, and Ark pointers. The router dynamically selects the optimal rail based on live fees and transaction size.
* **Conceptually:**
  * *Lightning Address:* Identifier → Lightning Node
  * *SatsPath:* Identifier → Authenticated Identity Profile → Available Capabilities → Compatible Rail → Wallet Handoff

### How Does SatsPath Relate to BIP-353?
[BIP-353](https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki) establishes human-readable Bitcoin payment instructions via DNS TXT records (`₿user@domain.com`):
* **SatsPath Interoperability:** SatsPath natively supports BIP-353 as one of its core resolver backends. A SatsPath client can resolve BIP-353 TXT records directly, validate their DNSSEC signatures, and parse the resulting BIP-21 URI.
* **Beyond DNS:** BIP-353 requires the recipient to control their own DNS domain or rely on a managed DNS provider. Users with standard email addresses (e.g. `alice@gmail.com`) cannot publish arbitrary DNS records on their provider's zone. SatsPath provides alternative transports (Nostr NIP-05, S2S HTTP, invite flows) and adds key continuity tracking, transparency logs, and multi-rail negotiation.

### Why Isn't Nostr Alone Enough?
Nostr (NIP-05 and kind `30078`) provides an excellent censorship-resistant, decentralized distribution channel:
* **SatsPath Integration:** SatsPath uses Nostr relays as an active transport. A profile can be published to and resolved from Nostr relays without central servers.
* **Separation of Layers:** A Nostr event signature only proves which Nostr key published the event. SatsPath decouples the transport from identity: the profile itself is signed by an independent SatsPath protocol identity key. This prevents relay operators or Nostr key compromises from silently rewriting Bitcoin receiving capabilities.

---

## Zooko's Triangle: Separating Namespace Authority from Payment Identity

A frequent question from cryptographers and protocol engineers is whether SatsPath claims to "solve" Zooko's Triangle (the conjecture that a naming system can simultaneously possess at most two of: Human-Meaningful, Decentralized, and Secure).

> **SatsPath does NOT claim to solve Zooko's Triangle.**

Instead, SatsPath **separates human-readable namespace authority from cryptographic payment identity**:

```mermaid
flowchart TD
    subgraph HumanNamespace ["Human-Readable Namespace Layer"]
        A[DNS / DNSSEC / Domain Owner / Provider]
        A -->|Authority: Assigns or Censors| B[alice@example.com]
    end

    subgraph CryptoIdentity ["Cryptographic Payment Identity Layer"]
        C[secp256k1 Identity Keypair]
        C -->|Signs Canonical Profile| D[Signed Payment Profile]
        D -->|Append-Only History| E[RFC 6962 Merkle Log]
        E -->|Independent Attestation| F[Witness Quorum Cosigning]
    end

    B -.->|Resolves To| D

    classDef namespace fill:#ffeeba,stroke:#856404,stroke-width:2px;
    classDef crypto fill:#d4edda,stroke:#28a745,stroke-width:2px;
    class A,B namespace;
    class C,D,E,F crypto;
```

1. **Namespace Authority Acknowledged:** Human-readable names (`user@domain.com` or `₿user@domain.com`) ultimately rely on underlying namespace authorities (DNS registrars, DNSSEC zone owners, WebPKI, or platform providers). A domain owner retains the technical ability to censor, revoke, or cease publishing an identifier.
2. **Cryptographic Protection Against Impersonation:** While a provider can censor an account, cryptographic verification (BIP-340 Schnorr signatures, sequential hash chains, and witness quorums) is designed to **prevent the provider from silently substituting the user's payment methods or impersonating their identity**.
3. **Attributable Misbehavior:** If an adversarial server replaces Alice's key or serves an unauthorized profile, clients fail verification (`ERR_KEY_SUBSTITUTION` or `ERR_INCLUSION_MISMATCH`). The server cannot forge transitions without generating cryptographic proof of misbehavior.

---

## Security Model & Hostile Review FAQ

### 1. What happens if a resolver is malicious?
A resolver acts only as an untrusted transport. It returns signed profile payloads and Merkle proofs. If a malicious resolver alters a payment address or swaps a profile, the client's local verifier detects the signature mismatch against `identity_pubkey` and rejects the payload immediately. The resolver cannot forge a valid signature without the user's private key.

### 2. What happens if the namespace provider is malicious?
If the operator of `example.com` attempts to hijack `alice@example.com` by generating a new key and signing a fake profile:
* **Existing Contacts:** Any client that previously resolved Alice holds a local pin of her identity key or predecessor checkpoint. The client detects the un-authorized key swap (missing a dual-signed `KeyRotation`) and aborts with `ERR_KEY_SUBSTITUTION`.
* **New Contacts (First Contact):** S2S v2 requires checkpoints to be cosigned by an independent witness quorum ($K$-of-$N$). If the operator creates a split view for new contacts, witnesses refusing to cosign inconsistent roots prevent un-witnessed profiles from passing.

### 3. What are the limits of Trust-On-First-Use (TOFU)?
When a client contacts an identifier for the very first time without prior key pinning or out-of-band verification:
* **Protected:** Once pinned, all future updates require monotonic append-only continuity.
* **Unprotected:** If an active adversary controls resolution during the *very first lookup*, the client may pin the attacker's initial state unless validated against an independent witness quorum or out-of-band fingerprint. TOFU guarantees subsequent continuity, not absolute first-contact authentication.

### 4. Is hashing identifiers with SHA-256 private?
**No, not against an offline dictionary attacker.** SatsPath hashes aliases (`SHA256(canonical_alias)`) for transport indexing to prevent passive cleartext eavesdropping on network wires. However, because human-readable names (email addresses, usernames) have low entropy, an attacker can enumerate common names using offline dictionary attacks or rainbow tables. Deterministic hashing provides pseudonymity and transit obfuscation, **not absolute privacy**.

### 5. What happens if witnesses collude with the server?
The witness protocol requires a $K$-of-$N$ threshold (e.g. 2-of-3 or 3-of-5). If fewer than $K$ witnesses are compromised, the rogue operator cannot obtain the cosignatures needed to validate an equivocation. If $K$ or more witnesses collude with the operator to forge a split view, clients on disparate branches cannot detect the fork locally until checkpoints are audited or gossiped out-of-band.

### 6. Does SatsPath work on Bitcoin Mainnet today?
**For public discovery and wallet handoff: YES.** SatsPath can resolve mainnet Lightning Addresses, fetch mainnet BOLT11 invoices, parse mainnet BOLT12 offers, derive mainnet BIP-352 Silent Payment addresses, and generate mainnet BIP-21 URIs.  
**For transaction execution: NO.** SatsPath does not connect to the Bitcoin P2P network to broadcast transactions, does not manage UTXOs, and does not hold spending keys. Execution is delegated to the user's wallet.

### 7. Has SatsPath been externally audited?
**No.** SatsPath has completed internal conformance testing and automated adversarial simulation suites, but has **not yet undergone an independent third-party cryptographic or security audit**. Formal audit is a mandatory release gate before production real-funds recommendations.

---

## Workspace Structure

| Crate | Purpose | Status |
| :--- | :--- | :--- |
| **`crates/satspath-core`** | Canonical JSON, Schnorr crypto, Merkle log, Sparse Merkle state map, resolvers | **Implemented** |
| **`crates/satspath-router`** | Routing engine, fee consensus, BOLT12 handling, BIP-352 Silent Payments | **Implemented** |
| **`crates/satspath-cli`** | Reference command-line client for development and preview flows | **Implemented** |
| **`crates/satspathd`** | Server daemon, REST API, transparency endpoint, token-bucket rate limiting | **Implemented** |
| **`crates/satspath-witness`** | Independent witness node, $K$-of-$N$ checkpoint cosigning, split-view detector | **Implemented** |
| **`crates/satspath-wasm`** | WebAssembly bindings for web browsers and wallet integration | **Preview** |
| **`crates/satspath-swaps`** | Experimental Boltz v2 swap scaffolding (testnet/regtest only) | **Experimental** |
| **`crates/satspath-pqc`** | Hybrid classical + post-quantum signature research module (ML-DSA-65) | **Research** |

---

## Quickstart

### Build and Test

```bash
git clone https://github.com/satspath/satspath.git
cd satspath

# Build entire workspace
cargo build --workspace

# Run all test suites across all crates
cargo test --workspace --all-targets

# Check formatting and clippy
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

### CLI Preview Usage

```bash
# Register a local test profile
satspath register alice@example.com

# Query a payment quote with live multi-source fee evaluation
satspath quote alice@example.com 50000 --json

# Preview mainnet wallet handoff (touches public data only; returns BIP-21 / BOLT11 / BOLT12 payload)
satspath preview alice@example.com 21000 --mainnet
```

---

## CypherTank 2026 Non-Profit Positioning

SatsPath is developed as **free and open-source public infrastructure** for the global Bitcoin community:

* **Non-Profit & Open Source:** Licensed under MIT. No proprietary protocols, no closed APIs.
* **No Token, No Rent-Seeking:** SatsPath does not issue a token, take a fee cut, or impose transaction taxes.
* **Self-Custody Preserving:** Designed specifically to empower sovereign, non-custodial Bitcoin wallets.
* **Interoperability First:** Composable with existing standards (BIP-21, BIP-352, BIP-353, BOLT11, BOLT12, Nostr).
* **Hackathon Origins:** Originated at the **Plan ₿ Summer School 2026 in Lugano**, winning **2nd place in the hackathon**.

---

## Documentation Navigation

* **Architecture:** [`docs/architecture.md`](docs/architecture.md)
* **Threat Model & Security:** [`docs/threat_model.md`](docs/threat_model.md)
* **Key Transparency:** [`docs/key_transparency.md`](docs/key_transparency.md)
* **Mainnet Safety Boundaries:** [`docs/mainnet_safety.md`](docs/mainnet_safety.md)
* **Implementation Mapping:** [`docs/implementations.md`](docs/implementations.md)
* **Protocol v1 Specification:** [`docs/protocol.md`](docs/protocol.md)
* **Resolvers Specification:** [`docs/resolvers.md`](docs/resolvers.md)
* **BIP-353 DNS Resolution:** [`docs/bip353_dns_resolution.md`](docs/bip353_dns_resolution.md)
* **BOLT12 Handling:** [`docs/bolt12_handling.md`](docs/bolt12_handling.md)
* **Docker Deployment:** [`docs/docker.md`](docs/docker.md)
* **SDK Quickstart:** [`docs/SDK_QUICKSTART.md`](docs/SDK_QUICKSTART.md)
* **v0.2 Roadmap:** [`docs/v02_roadmap.md`](docs/v02_roadmap.md)
