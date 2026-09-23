# ⚡ SatsPath SDK Quickstart Guide

Quickstart guide for wallet developers, PWAs, and web applications (React, Vite, React Native, Arkade).

---

## 📦 1. Installation (with `pnpm`)

Install official SatsPath packages using **`pnpm`**:

```bash
pnpm add @satspath/wasm bip39 react-qr-code
# or modular TypeScript packages:
pnpm add @satspath/resolvers @satspath/router
```

> **Tip:** If you are building the WebAssembly package directly from the local repository:
>
> ```bash
> cd crates/satspath-wasm
> wasm-pack build --target web --out-dir ../../pkg/satspath-wasm
> cd ../../your-app
> pnpm add ../satspath/pkg/satspath-wasm
> ```

---

## 🚀 2. Basic 3-Step Flow

```text
┌─────────────────────────┐     ┌─────────────────────────┐     ┌─────────────────────────┐
│ 1. DERIVE IDENTITY      │ ──> │ 2. RESOLVE & QUOTE      │ ──> │ 3. EXECUTE PAYMENT      │
│ Seed (12 words)         │     │ "user@domain" + sats    │     │ QR / BOLT11 / BIP-21    │
│ m/9737'/0'              │     │ Smart Route Selection   │     │ Host wallet pays        │
└─────────────────────────┘     └─────────────────────────┘     └─────────────────────────┘
```

---

## 💻 3. Code Example (TypeScript / React)

### Step 1: Initialize the SDK and Derive Identity

Deterministically derive a secure identity keypair inside the trusted wallet boundary without accessing or exposing Bitcoin spending keys:

```typescript
import init, { derive_identity_keypair_from_seed } from '@satspath/wasm';
import * as bip39 from 'bip39';

// 1. Initialize WASM module when mounting the app
await init();

// 2. Derive SatsPath identity inside the trusted wallet boundary (m/9737'/0')
// Seed/mnemonic remains strictly private inside the wallet context and is never transmitted.
const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const seed = bip39.mnemonicToSeedSync(mnemonic);

// Account 0 by default
const identity = derive_identity_keypair_from_seed(seed, 0);
if (!identity) {
  throw new Error("Failed to derive identity keypair");
}

console.log("Your SatsPath Public Key:", identity.pubkey_hex);
// => "03e0fa79bc28965724d3eee52d58cf0cd11f712462582f42e79a545d13d85aac0b"
```

---

### Step 2: Resolve an Alias and Quote Best Route (`quote`)

When a user inputs a recipient identifier (e.g. `chelo@satspath.dev`) and an amount in Satoshis:

```typescript
import { quote } from '@satspath/wasm';

async function handleSendPayment(recipientAlias: string, amountSats: bigint) {
  try {
    // Resolves alias and evaluates live mempool fees
    const quoteResult = await quote(recipientAlias, amountSats);

    if (quoteResult.status === "ok") {
      console.log("Selected Rail:", quoteResult.selected_method.type); // "Lightning" | "Ark" | "Onchain"
      console.log("Estimated Fee:", quoteResult.fee_sats, "sats");
      console.log("Payment Payload:", quoteResult.qr); 
      
      // quoteResult.qr contains the string ready for wallet payment:
      // - Lightning: "lnbc10u1p..." or BOLT12 offer
      // - Ark: "ark:<pubkey>?server=...&amount=10000"
      // - On-Chain: "bitcoin:bc1q...?amount=0.0001"
      
      return quoteResult.qr;
    } else if (quoteResult.status === "invalid_signature") {
      console.error("Invalid signature on recipient profile:", quoteResult.recipient.alias);
    } else if (quoteResult.status === "no_route") {
      console.error("No valid payment route found:", quoteResult.reason);
    } else if (quoteResult.status === "not_registered") {
      console.error("Recipient is not registered");
    }
  } catch (error) {
    console.error("Error resolving or quoting payment:", error);
  }
}
```

---

### Step 3: Render Payment QR Code in UI (React)

```tsx
import React from 'react';
import QRCode from 'react-qr-code';

export function PaymentScreen({ invoicePayload }: { invoicePayload: string }) {
  return (
    <div className="payment-card">
      <h3>Scan to Pay</h3>
      <div style={{ background: 'white', padding: '16px', borderRadius: '8px' }}>
        <QRCode value={invoicePayload} size={256} />
      </div>
      <p style={{ wordBreak: 'break-all', fontSize: '12px' }}>{invoicePayload}</p>
    </div>
  );
}
```

---

## 📖 4. Main Methods Reference

| Function | Parameters | Return Type | Description |
| :--- | :--- | :--- | :--- |
| `derive_identity_keypair_from_seed` | `seed: Uint8Array, index: number` | `{ pubkey_hex, secret_key_hex } \| undefined` | Deterministically derives identity keypair under the `m/9737'/0'` HMAC namespace. |
| `quote` | `recipient: string, amount_sats: bigint` | `QuoteResponse` | Resolves alias across S2S/DNSSEC chain and selects the optimal rail (Lightning, Ark, or On-chain). |
| `resolve_alias` | `alias: string` | `SignedPaymentProfile` | Resolves and retrieves the signed recipient profile (signature is verified with `verify_signed_profile`). |
| `verify_signed_profile` | `profile_json: string` | `boolean` | Verifies the `secp256k1` Schnorr signature of a received profile. |

---

## 🛡️ 5. Security Principles for Wallets

1. **Zero Custody:** The SDK never requests or stores private Bitcoin spending keys (`xprv`/`tprv`).
2. **Fail-Closed:** If a profile signature is invalid or DNSSEC fails, `quote` automatically rejects the payment.
3. **Mempool Smart Routing:** Evaluates Lightning first, selects On-chain when mempool fees are below threshold, and falls back to Ark as an off-chain alternative.
