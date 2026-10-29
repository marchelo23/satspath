# Daemon end-to-end results (regtest)

> **Recorded local exercise, not a fresh test run.** Use
> [automated daemon E2E tests](../crates/satspathd/tests/e2e_daemon_flow.rs) and
> [their workflow](../.github/workflows/daemon-e2e.yml) for reproducible coverage.
> The observations below do not prove a positive quote→external-wallet payment.

These results come from a local end-to-end exercise against Bitcoin Core 29.4.
The external Core wallets signed every Bitcoin transaction; the daemon's
payment endpoints only produced handoff previews. The throwaway test harness,
node datadirs and credentials were **not committed**; this document records the
observed evidence.

## Regtest — passed

The disposable regtest lab used `miner` and `receiver` Core wallets, a loopback
RPC-only node, and a disposable daemon home.

| Check | Result |
| :--- | :--- |
| External miner → receiver | 0.01 regtest BTC; local txid `f62ca620203097db63917a73840184c916dd0b02642264431d023ff5b9493fd8`, at least 1 confirmation. Regtest transactions do not appear on public explorers. |
| Default alias gate and unknown invite | Challenge HTTP 400; invite preview returned; `is_claimable: false`; claim HTTP 400 and no transparency event. |
| Explicit devnet/regtest mock alias | Challenge/verify, local profile and proof-carrying SQLite resolution succeeded. Mock alias ownership is **not attested**. |
| Receive and routing | Valid regtest BIP-21 receive payload with exact amount. Send/quote/pay each returned `no_route` for the signed profile without a payment-method ownership proof; no user payment was executed. |
| Broadcast and restart | Repeated `/v1/broadcast` kept sequence and event count unchanged across daemon restart. |
| Catena genesis and continuation | Three confirmed anchors, linked predecessor outpoints and 1,000-sat continuation outputs. Transaction OP_RETURN commitments and structural/checkpoint checks passed: `90f0741f48a4d9e90eb45ff89110477030b5752d73015a957f5e7010af6df27e` (index 0), `df8466e02b90d39a742029aa1bbc17daa9054d2ee8b00506bd71dcf9652f3f94` (index 1), `8a455172ed75d3e7c2ed5167bfee98fba054037c2abd9f21309bee1427188a7d` (index 2). |
| Negative anchors | Duplicate anchor and wrong `SATSPATH_BITCOIN_NETWORK` returned HTTP 400. A daemon restarted with a non-regtest `--network` while Core RPC still selected regtest also returned HTTP 400, with no extra block or event. A mocked Core RPC reporting a non-regtest chain is rejected before signing or broadcast. |

## H2 D1 automated preview fixture

Unlike the historical exercise above, the committed D1 fixture attaches a real
method-key ownership signature through HTTP and obtains positive `quote/pay/send`
handoffs. Reproduce with:

```sh
cargo test -p satspathd --test e2e_daemon_flow onchain_owned_profile
```

It checks exact one-satoshi and 21,001-satoshi BIP-21 amounts on regtest, durable
profile/event/checkpoint continuity across process restart, invalid signature and
replay rejection without profile/event mutation, and ownership invalidation after
destination replacement. Destination/amount/network tampering is rejected by the
shared handoff validator. This is **hermetic preview coverage**: alias setup is
dev-mocked, `identifier_verified` remains false, and no external-wallet approval,
transaction signature, broadcast or confirmation is demonstrated. The historical
Core transfer above is not evidence of this positive daemon journey settling.

For standalone [#202](https://github.com/satspath/satspath/issues/202), remaining
evidence covers independent CLI/daemon validation of destination, amount, network
and approval policy, coordinated with real onboarding under #201. Named-wallet
adapters and external approval/signing/broadcast/confirmation evidence belong to
phase 2 (#216/#171), not standalone H2 acceptance. The lack of a settled payment
does not itself block #202; the daemon must report handoff versus payment truthfully.

## Remaining product blockers

- No production email/domain alias attestation; invitation claiming stays
  disabled by default.
- The `https://satspath.local/claim` URL is a placeholder, not a public claim
  service.
- Demo payment methods without an attached ownership proof still return
  `no_route`; the D1 fixture does not provide a production alias-control verifier.
- Regtest anchoring remains operator-only and must never use a wallet with real
  funds.
