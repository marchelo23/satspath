# SatsPath SDK Quickstart

This guide describes the APIs present in the checkout, not a promise of a
published package or a completed wallet integration. See the
[capability matrix](README.md) and [tracked SDK work](../ROADMAP.md).

## 1. Build from source

### Browser WASM — preview

From the repository root, install `wasm-pack` and the Rust wasm32 target, then:

```bash
rustup target add wasm32-unknown-unknown
wasm-pack build crates/satspath-wasm --target web --release --out-dir ../../pkg/satspath-wasm
```

Serve the generated JS and `.wasm` files through your application bundler or an
HTTP server; do not load them from `file://`. Examples below assume the app serves
the generated module at `/satspath-wasm/satspath_wasm.js`.

Registry publication is tracked in [#189](https://github.com/satspath/satspath/issues/189).
Do not assume `@satspath/wasm` is available from npm based on this checkout.
There are no source packages here for the previously documented
`@satspath/resolvers` or `@satspath/router` installs.

**Current limitations:** WASM is a separate implementation, not native core
compiled for the browser. `LocalRegistry.add_profile` returns an error, Nostr
relay querying is unimplemented, and the resolver chain has JSON serialization
and BIP-353 parity gaps. It does not provide native local DNSSEC guarantees.
High-level `quote` is an experimental preview that can reject before returning
a quote; it is not a production-ready resolve→pay integration.
See [resolver source](../crates/satspath-wasm/src/resolver.rs) and
[#187](https://github.com/satspath/satspath/issues/187)/
[#188](https://github.com/satspath/satspath/issues/188).

### Native Rust

Use workspace source dependencies, adjusting paths for your application's location:

```toml
[dependencies]
satspath-core = { path = "crates/satspath-core" }
satspath-router = { path = "crates/satspath-router" }
```

Reference adapters are `BdkOnchainBridge`, `LdkLightningBridge`,
`BoltzTestnetSwapBridge` and `HostWalletSdkBridge` in
[`satspath_router::wallet_executor`](../crates/satspath-router/src/wallet_executor.rs).
They require host callbacks; naming an adapter is not a completed BDK/LDK integration.

## 2. Browser identity example — disposable test vector only

Install `bip39` in the example application. This illustrates the exported
identity-derivation API inside a trusted host-wallet boundary. Never pass a real
wallet seed to a website, daemon, or remote service. The returned identity secret
is not a spending key, but must still be protected and must never be logged.

The implementation uses a dedicated HMAC domain label containing `m/9737'/0'`;
that string is **not** evidence of BIP-32 child-key derivation.

```typescript
import init, {
  derive_identity_keypair_from_seed,
} from "/satspath-wasm/satspath_wasm.js";
import * as bip39 from "bip39";

await init();

// TEST ONLY: public BIP-39 vector. Never register this identity or fund its wallet.
const mnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const seed = bip39.mnemonicToSeedSync(mnemonic);
const identity = derive_identity_keypair_from_seed(seed, 0);
if (!identity) {
  throw new Error("Failed to derive SatsPath identity keypair");
}
console.log("SatsPath Identity Pubkey:", identity.pubkey_hex);
```

## 3. Browser quote wrapper — preview, never payment approval

The JS export currently accepts **`number`, not `bigint`**: a positive whole
number of sats, no greater than Bitcoin's supply (`2_100_000_000_000_000`).
All such satoshi values fit within JavaScript's safe integer range.

The wrapper below handles the response contract and errors. Its checks are not
a replacement for authenticated identity continuity, ownership, transparency,
or host-wallet validation. A quote flag is not proof of alias control. Current
WASM payable payload construction supports on-chain only; other rails are gated.

```typescript
import { quote } from "/satspath-wasm/satspath_wasm.js";

export async function resolveAndQuote(recipientAlias: string, amountSats: number) {
  if (!Number.isSafeInteger(amountSats) || amountSats < 1 || amountSats > 2_100_000_000_000_000) {
    throw new Error("Amount must be a positive whole number of sats within Bitcoin supply");
  }
  const quoteResult = await quote(recipientAlias, amountSats);
  switch (quoteResult.status) {
    case "ok": {
      if (quoteResult.recipient.profile_signature_verified !== true) {
        throw new Error("Recipient profile signature failed verification");
      }
      if (quoteResult.selected_method.type !== "Onchain") {
        throw new Error("Unsupported preview rail");
      }
      console.log("Selected Method:", quoteResult.selected_method.type);
      console.log("Estimated Fee (sats):", quoteResult.fee_sats);
      console.log("Preview Payload:", quoteResult.qr);
      return quoteResult;
    }
    case "invalid_signature":
      throw new Error(`Invalid profile signature for ${quoteResult.recipient.alias}`);
    case "no_route":
      throw new Error(`No viable payment rail: ${quoteResult.reason}`);
    case "not_registered":
      console.log("Recipient not registered; invite token:", quoteResult.invite.invite_id);
      return null;
    default:
      throw new Error("Unknown quote status");
  }
}
```

`not_registered` is part of the shared response type, but resolution failures can
reject the promise instead of returning that status. An invite is not escrow or
a production claim service. Wrapper tests inject mock responses; they do not
prove that browser resolution currently completes successfully.

## 4. Native wallet approval and dispatch

Obtain the quote with `quote_with_resolver` or the appropriate verified-profile
API. Native `ChainResolver` policy and daemon local-state resolution are distinct;
do not assume every transport supplies the same evidence.

For execution, use this sequence from
[`wallet_executor.rs`](../crates/satspath-router/src/wallet_executor.rs):

1. Populate a `TransactionalTransparencyStore` and obtain verified `HandoffTrust`
   and `HandoffTransparencyEvidence` for the current profile/checkpoint.
2. Call `prepare_payment_intent` with that evidence, quote, wallet network, exact
   amount, positive maximum fee, and the actual `Vec<ResolverSource>` observed.
3. Show the returned `PaymentIntent` fields to the payer. Only after genuine UI
   confirmation call `intent.approve(user_confirmed)` to obtain a single-use token.
4. Pass the token, current store/trust/evidence, quote, `WalletExecutor` and
   `ExecutionGatePolicy` to `execute_quote_handoff`. It reconstructs the intent
   and rejects changed payment terms or identity state before invoking the host.

Do not synthesize witness evidence or provenance to make an example execute.
The current daemon does not supply a completed witness-quorum integration.
Missing evidence must fail, not be bypassed.

**Never dispatch SatsPath quotes directly through legacy `wallet.pay_bolt11` or
`send_onchain` calls.** Those bypass the approval contract. The host implements
fee-bound adapter methods, retains spending keys, and performs signing/broadcast.
For the exact contract and limitations, see [PaymentIntent](payment_intent.md)
and [native adapter/dispatch tests](../crates/satspath-router/tests/wallet_executor_integration.rs).

BOLT12, Ark, Silent Payments and swap approval paths remain capability-gated.
An amountless receive pointer is not an approved amount-bound payment.

## 5. API source references

| API | Actual surface | Notes |
| --- | --- | --- |
| `derive_identity_keypair_from_seed` | WASM `(Uint8Array, number)` | Returns identity keypair or `undefined`; host-local only |
| `verify_signed_profile` | WASM `(string) -> boolean` | Input is serialized signed-profile JSON; no alias attestation implied |
| `quote` | JS `(string, number) -> Promise` | Prototype high-level resolver; errors may reject |
| `quote_with_resolver` | Native router | Returns `QuoteResponse`; inspect status before preparing intent |
| `prepare_payment_intent` | Native router | Requires current evidence, source provenance and fee cap |
| `execute_quote_handoff` | Native router | Requires single-use host approval; revalidates before dispatch |

The generated `.d.ts` and actual Rust signatures are authoritative for the
checkout. Run `node --test docs/tests/*.test.mjs` for documentation checks; this
does not compile WASM or certify a TypeScript application against generated types.
