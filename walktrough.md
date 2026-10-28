# SatsPath Engine — Walkthrough

SatsPath is a signed payment-profile discovery and routing toolkit, not a wallet.
It supplies payment previews/handoffs; the host wallet authorizes, signs and
executes user payments. Operator checkpoint anchoring is a separate, opt-in
regtest-only path using Bitcoin Core RPC.

## Read the current guides

1. [Documentation index and capability matrix](docs/README.md).
2. [Architecture and actual workspace layout](docs/architecture.md).
3. [CLI demonstration](examples/demo_flow.md).
4. [Wallet SDK quickstart](docs/SDK_QUICKSTART.md) and
   [PaymentIntent approval](docs/payment_intent.md).
5. [Docker development setup](docs/docker.md).
6. [Roadmap and tracked issues](ROADMAP.md).

## Important implementation distinctions

- Native BIP-353 includes a local DNSSEC validator. Browser WASM does not yet
  provide equivalent native resolver behavior.
- BOLT12 parsing/blinded-path/invoice-request primitives exist. They do not
  establish a live CLN/LDK wallet integration; the HTTP proxy is a dummy scaffold.
- Daemon BOLT12 receive was separated in `#198` and remains pending behind the
  ignored `acceptance_bolt12_offer_receive_method` spec; amount-bound BOLT12
  quotes and payments remain disabled.
- Silent Payments (`#199`) and wallet-supplied Bech32m Ark addresses (`#209`)
  support daemon `/v1/receive` and BIP-21/BIP-321 URI formatting (with independent
  ownership proofs required for daemon payable quotes), while `PaymentIntent`
  host-wallet execution remains gated to standard on-chain and payee-bound BOLT11.
- Witness cosigning is a library; `satspath-gossip` is a binary inside
  `satspath-witness`. The daemon does not yet collect/verify witness cosignatures.
- PQC is feature-gated research. It is not the default identity or production claim.
- A signed profile does not prove alias control or payment-method ownership.

This page is an entry point, not a second status checklist. The earlier walkthrough
contained obsolete rail, DNSSEC, and deployment claims; use the linked guides.
