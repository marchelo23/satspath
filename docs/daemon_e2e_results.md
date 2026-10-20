# Daemon end-to-end results (regtest and testnet4)

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
| Negative anchors | Duplicate anchor and wrong `SATSPATH_BITCOIN_NETWORK` returned HTTP 400. A daemon restarted as `--network testnet` while Core RPC still selected regtest also returned HTTP 400, with no extra block or event. A mocked Core RPC reporting a non-regtest chain is rejected before signing or broadcast. |

## Testnet4 — partial, no outgoing payment

The testnet4 run exercised the alias/invite gates on a disposable daemon:
default challenge/verify and claims returned HTTP 400, including a claim with
an external signed profile. Invite inspection reported `is_claimable: false`;
the invite and event log did not advance. It found two gaps now covered by
regression tests: the mock alias challenge/verify path could run on testnet4,
and `/v1/receive` rejected the `testnet4` network label even for a valid `tb1`
on-chain pointer. The mock is now limited to devnet/regtest; testnet4 and
signet on-chain receive handoffs use their expected address families without
accepting a testnet3 BOLT11 invoice as testnet4. A post-fix local HTTP check
restarted a disposable testnet-form profile as `--network testnet4`: its
amount-bound `tb1` BIP-21 receive payload succeeded, unproved send returned
`no_route`, and public challenge/claim remained HTTP 400. This **did not**
fund or spend testnet4 coins.

A public faucet broadcast tx
[`c66b413c95ff069ed16bab8ffe42fb903e4f35a01f5935e5de291397ba093dc0`](https://mempool.space/testnet4/tx/c66b413c95ff069ed16bab8ffe42fb903e4f35a01f5935e5de291397ba093dc0)
with 1,000,000 testnet4 sats to an **old disposable address**. A server restart
erased that wallet/key before it could synchronize; it was unconfirmed at the
last check. **Do not fund that address or describe this output as spendable.**
A replacement wallet was created in persistent local storage with zero UTXOs
and `connect=0` by default. Its node reached only 8,688 of 157,153 headers in a
bounded sync attempt, so no outgoing testnet4 transfer was possible or claimed.

## Remaining product blockers

- No production email/domain alias attestation; invitation claiming stays
  disabled by default.
- The `https://satspath.local/claim` URL is a placeholder, not a public claim
  service.
- Demo payment methods have no ownership proof, so routing them returns
  `no_route`.
- A public testnet4 payment still needs a fully synced node and externally
  funded wallet. Regtest anchoring remains operator-only and must never use a
  wallet with real funds.
