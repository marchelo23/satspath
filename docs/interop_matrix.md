# Real-wallet interoperability matrix (#171)

No case is marked `PASS` until an actual host wallet executes a validated
SatsPath intent and an **independent receiving implementation** confirms the
payment. Existing mock receipts in #156 are unit tests, not real-wallet proof.

| Transport | Capability | Host wallet | Network | Status | Evidence required |
| --- | --- | --- | --- | --- | --- |
| HTTPS | Lightning BOLT11 | LDK | regtest | PENDING | recipient invoice + settlement preimage |
| BIP-353 | Lightning BOLT11 | LDK | signet | PENDING | local DNSSEC proof + receiver confirmation |
| HTTPS | On-chain | BDK | regtest | PENDING | txid + receiver UTXO confirmation |
| Nostr | On-chain | BDK | regtest | PENDING | signed event + receiver UTXO confirmation |
| BOLT12 | Offer/invoice | compatible node | regtest | PENDING | invoice settlement |
| HTTPS | Silent Payments | compatible BDK flow | signet | PENDING | derived output detected by receiver |
| HTTPS | Ark | live ASP | testnet/signet | PENDING | ASP receipt + receiver VTXO |
| Any eligible transport | production-ready rail | host wallet | mainnet | PENDING | capped approved amount + independent receipt |

The opt-in `real_wallet_interop` test provides a fail-closed driver contract
for on-chain HTTPS. It intentionally fails without a real profile, authenticated
transparency evidence, a host-wallet executable and an independent receiver
checker. It does **not** silently substitute in-memory mocks. No mainnet
transaction is initiated by CI.
