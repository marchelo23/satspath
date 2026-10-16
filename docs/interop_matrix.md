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

From the repository root, with an externally provisioned testnet/regtest wallet
and independently configured receiver, run:

```sh
SATSPATH_INTEROP_CONFIG=/absolute/path/to/interop.json \
  cargo test -p satspath-router --test real_wallet_interop \
  https_onchain_wallet_receiver_confirms_payment -- --ignored --nocapture
```

The private JSON config must contain `alias`, `amount_sats`, `max_fee_sats`,
`network` (`"Regtest"` or `"Testnet"`), `store_dir`, `pins_dir`, `wallet_driver`,
`receiving_wallet_checker`, `witness_quorum`, `witness_pubkeys`,
`observer_pubkeys`, and `transparency` (authenticated handoff evidence from
the independent witness/observer deployment). Do not commit credentials or
the JSON config. Both executables accept one JSON request on stdin and return
one JSON response on stdout. The host driver receives `action: send_onchain`,
`network`, `destination`, `amount_sats`, `max_fee_sats`; it must return an
`OnchainReceipt` with `txid`, `destination`, `amount_sats`, `fee_sats`,
`timestamp`. The independent checker receives `action: confirm_receive` plus
`network`, `txid`, `destination`, `amount_sats` and returns those fields with a
positive `confirmations` count. Each driver has a 30-second deadline and an
8 KiB output limit. The test cannot attest independence from executable output
alone: keep the receiver's transaction/UTXO evidence for manual verification.
