# Invite and Claim Flow

Intended unknown-receiver flow (alias attestation **not yet implemented**):

```txt
identifier -> no signed profile -> create invite -> [future: receiver proves alias control to a trusted verifier] -> receiver publishes signed public profile -> sender re-resolves
```

## Security & Non-Custodial Invariants

- **Unknown receiver means invite only.** No payment route exists until the receiver publishes a valid, cryptographically signed profile.
- **No funds move on invite creation.** The daemon only returns an invitation preview and records a non-custodial invite record.
- **No spending keys or seeds:** SatsPath never generates seed phrases or Bitcoin spending keys for users, and never transmits or emails private material.
- **Identity-key boundary:** A future production receiver should hold its own identity key locally. In the current development-only mock claim, the daemon signs with its own local identity key, **not** a receiver-controlled key; its signature is not proof of email/domain ownership.
- **Authenticated sender attribution:** An invite may carry a Schnorr signature (`sender_signature`) bound to `sender_pubkey`. Unsigned invites are treated as unauthenticated.
- **Strict expiry:** Reject any invite whose `expires_at` has passed. Do not extend the expiry on claim.
- **Claim fails closed:** `POST /v1/claim` cannot establish control of an email address or domain. The public `/v1/send` response already contains the claim URL, and `/v1/invites` exposes invite IDs; neither an ID, matching alias hash, sender signature nor an independently signed profile proves receiver ownership of the alias. Without a production alias-control verifier/attestation, claims are disabled on mainnet, testnet and signet. They are also disabled by default on devnet/regtest.
- **Explicit insecure development mode only:** `--dev-mock-alias-verification` (or `SATSPATH_DEV_MOCK_ALIAS_VERIFICATION=1`) allows the daemon-identity claim path on **devnet/regtest only**. It does **not** verify alias control, and the resulting signed profile and transparency checkpoint do **not** constitute email/domain ownership proof. Never use it for real recipients or rely on it for payment trust. Externally supplied `signed_profile` is rejected even in mock mode: it supplies neither an alias attestation nor an independently signed `NameEvent` authorization. No Bitcoin spending key is generated or handled by claim.

---

## State Machine & Lifecycle

```txt
       [ Create Invite ]
               |
               v
           +-------+
            |Created| <------+ (waiting for claim; production stops here)
           +-------+        |
            /     \         | (delivery)
           /       \        |
(email sent)        \       v
    v                +-----------+
+---------+          | EmailSent |
 |Claimed  |<---------+-----------+ (explicit devnet/regtest mock only)
|(public  |
|profile) |
+---------+
    |
(expiry)
    +-------------------> [ Expired ]
(user cancel)
    +-------------------> [ Cancelled ]
```

- **`Created`:** The invite is generated and stored in `InviteStore`. Waiting for receiver to claim.
- **`EmailSent`:** Delivery occurred via email or messaging channel.
- **`ClaimedWithPublicProfile`:** Currently reachable via `POST /v1/claim` only in explicit insecure devnet/regtest mock mode; the daemon signs a public receive profile using its local identity key and publishes it to the Transparency Log. This status does not imply verified alias control or payment-method ownership.
- **`Expired`:** Current timestamp exceeds `expires_at`. The invite is locked and cannot be claimed.
- **`Cancelled`:** The sender explicitly cancelled the pending invite before claim.

---

## End-to-End Claim Protocol

1. **Sender initiates payment:** Sender calls `POST /v1/send` with recipient identifier and amount. If the identifier has no registered profile, the daemon may create an `InviteRecord` with a UUID `invite_id` in `InviteStore`. Sender signatures are optional; their presence does not authenticate the recipient.
2. **Receiver receives claim link:** The claim URL format is `https://satspath.local/claim?invite_id=<UUID>&alias_hash=<HASH>&amount=<SATS>`.
3. **Receiver inspects invite:** The wallet or web UI calls `GET /v1/claim?invite_id=<UUID>`. It returns amount, display hint, expiry and whether the optional sender signature verifies. `is_claimable` is `false` if this daemon's claim gate is disabled; `sender_verified` authenticates the sender's invite signature, **not** the recipient's alias.
4. **Production/testnet stops here:** No email/domain alias-control attestation is implemented for claim. A `POST /v1/claim` returns HTTP 400 without modifying wallet, invite status/notifications or the transparency log. A signed profile only proves control of its signing identity key, not the claimed email/domain alias.
5. **Development mock only:** With the flag on devnet/regtest, `POST /v1/claim` with `invite_id`, `alias` and public receive methods can publish a daemon-identity profile and transition the invite to `ClaimedWithPublicProfile`. The response explicitly warns that no alias-control attestation was performed. A `signed_profile` field is rejected (HTTP 400). This flow must not be used to assert verified identity or enable trusted settlement.

---

## API Specification

### 1. Inspect Invite
- **Endpoint:** `GET /v1/claim?invite_id=<UUID>`
- **Auth:** None (Public)
- **Response:**
  ```json
  {
    "invite_id": "c1f7b8a0-...",
    "identifier_hash": "a4b2c1...",
    "display_hint": "c***@example.com",
    "amount_sats": 25000,
    "memo": "Dinner",
    "status": "waiting_for_claim",
    "is_expired": false,
    "is_claimable": false,
    "created_at": 1727092800,
    "expires_at": 1727179200,
    "sender_verified": true,
    "sender_pubkey": "02..."
  }
  ```

### 2. Claim Invite (development mock only)
- **Endpoint:** `POST /v1/claim`
- **Auth:** None (Public mutation; the invite ID is public and is **not** an authorization token)
- **Availability:** Fail-closed HTTP 400 by default, even with a valid ID and `signed_profile`. On mainnet/testnet/signet it remains disabled with or without the mock flag. On devnet/regtest it works only with explicit `--dev-mock-alias-verification` (or `SATSPATH_DEV_MOCK_ALIAS_VERIFICATION=1`); the mock supplies **no** proof of email/domain ownership. A real verifier and alias attestation are still pending.
- **Request:**
  ```json
  {
    "invite_id": "c1f7b8a0-...",
    "alias": "carol@example.com",
    "lightning_address": "carol@getalby.com",
    "onchain_address": "<valid devnet/testnet receive address>"
  }
  ```
- **Response:**
  ```json
  {
    "status": "claimed",
    "invite_id": "c1f7b8a0-...",
    "alias": "carol@example.com",
    "amount_sats": 25000,
    "profile_pubkey": "03...",
    "claimed_at": 1727093400,
    "message": "DEVELOPMENT ONLY: insecure mock claim; receiver profile published without email/domain alias-control attestation. Do not treat its signature as proof of alias ownership"
  }
  ```

### 3. List Invites
- **Endpoint:** `GET /v1/invites`
- **Auth:** None (Public `GET`)
- **Response:** Array of `InviteRecord` objects.
- **Security:** IDs are visible here and in public send claim URLs; hiding this list cannot make claim safe without alias verification.

### 4. List Claim Notifications
- **Endpoint:** `GET /v1/invites/notifications`
- **Auth:** None (Public `GET`)
- **Response:** Array of `ClaimNotification` objects.

### 5. Mark Notification Read
- **Endpoint:** `POST /v1/invites/notifications/<ID>/read` (or `POST /v1/invites/notifications/read-all`)
- **Auth:** Bearer token (`admin.macaroon` / `SATSPATHD_AUTH_TOKEN`)
- **Response:** `{"status": "ok", "notification_id": "...", "read": true}` (or `{"status": "ok", "all_read": true}`)
