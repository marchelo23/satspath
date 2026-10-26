# BOLT12 handling: primitives, receive pointers, and remaining integration

## Current native implementation

[`satspath-router/src/bolt12.rs`](../crates/satspath-router/src/bolt12.rs) contains
checksumless Bech32 decoding with continuation handling, TLV parsing and Merkle
signature helpers, BOLT #4 blinded-path structures, invoice-request construction,
and invoice validation. These are component APIs, not evidence of a live wallet
payment or completed Core Lightning/LDK integration.

The native interfaces include:

- `Bolt12Signer`: host-provided signing; spending keys stay in the host boundary.
- `OnionMessageTransport`: host/gateway transport abstraction.
- `fetch_bolt12_invoice_via_transport`: constructs the request, dispatches through
  the supplied transport, and validates the returned invoice.
- `ReferenceNodeOnionTransport`: in-process reference responder for testing;
  its name does not mean it connects to an actual CLN/LDK node.

The offer→invoice-request→transport→invoice→wallet lifecycle is the intended
integration sequence. Route scoring or parsing an offer alone does not complete it.

## Receive is not payment execution

The daemon can persist a network-validated BOLT12 offer and return an **amountless**
`bitcoin:?lno=...` receive pointer. The active
[acceptance test](../crates/satspathd/tests/e2e_daemon_flow.rs) covers that behavior.
Do not describe BOLT12 receive support as wholly absent.

Daemon/router/WASM payable quote generation still rejects BOLT12 until
protocol-aware validation and wallet approval integration are complete. An offer
is not an amount-bound invoice. See [PaymentIntent gates](payment_intent.md).

## HTTP proxy is a scaffold, not a working backend

The native HTTP helper reads `SATSPATH_BOLT12_PROXY` and requests
`/invoice?offer=...&amount_msats=...`. The optional
[WASM helper](../crates/satspath-wasm/src/bolt12.rs) builds a similar URL.

The checked-in [worker](../proxy-workers/bolt12/src/index.ts), however, exposes
`/resolve/:offer?amount=...` and returns `lnbc1dummy_invoice_resolved_from_bolt12_offer`.
Its backend CLN/LDK communication is TODO. The client/worker contracts do not
currently match; setting a proxy URL does not create a usable invoice service.
Do not use that response as a payable invoice or claim deployment of an example
URL from source constants.

## Completion criteria

Tracked in [roadmap H8 / #208](https://github.com/satspath/satspath/issues/208):

1. Unify the client/proxy contract, including amount units and error responses.
2. Replace dummy responses with an explicitly configured real node transport.
3. Validate the invoice against offer, payee, amount, chain, expiry and signatures.
4. Integrate explicit host approval and retain wallet-controlled signing/execution.
5. Record versions and reproducible external wallet evidence before removing the
   corresponding handoff gate. Keep test-network evidence distinct from mainnet.
