# Invite and Claim Flow

Unknown-receiver flow with HTTPS domain authorization (no mock flags required):

```txt
identifier -> no profile -> invite -> exact HTTPS domain challenge -> atomic registration + claim receipt -> method-key ownership proof -> sender re-resolves
```

## Security & Non-Custodial Invariants

- **Unknown receiver means invite only.** No payment route exists until the receiver publishes a valid, cryptographically signed profile.
- **No funds move on invite creation.** The daemon only returns an invitation preview and records a non-custodial invite record.
- **No spending keys or seeds:** SatsPath never generates seed phrases or Bitcoin spending keys for users, and never transmits or emails private material.
- **Identity-key boundary:** HTTPS claims create a separate local receiver identity key, never a Bitcoin spending key, in the administrator-controlled daemon home. They do not overwrite the operator wallet. This is a local administrative flow, not a public account service or a promise that a remote recipient exclusively controls that identity. The legacy mock claim still uses the daemon identity and does not prove alias control.
- **Authenticated sender attribution:** An invite may carry a Schnorr signature (`sender_signature`) bound to `sender_pubkey`. Unsigned invites are treated as unauthenticated.
- **Strict expiry:** Reject any invite whose `expires_at` has passed. Do not extend the expiry on claim.
- **Claim fails closed:** Neither an invite ID, alias hash, sender signature, profile signature nor administrator token proves alias control. `/v1/onboarding/verify` must fetch the exact, expiring authorization from the alias domain over valid HTTPS. It proves domain administrator authorization, not mailbox access. An invitation never bypasses that check. `POST /v1/claim` remains legacy/mock-only.
- **Explicit insecure development mode only:** `--dev-mock-alias-verification` (or `SATSPATH_DEV_MOCK_ALIAS_VERIFICATION=1`) allows the daemon-identity claim path on **devnet/regtest only**. It does **not** verify alias control, and the resulting signed profile and transparency checkpoint do **not** constitute email/domain ownership proof. Never use it for real recipients or rely on it for payment trust. Externally supplied `signed_profile` is rejected even in mock mode: it supplies neither an alias attestation nor an independently signed `NameEvent` authorization. No Bitcoin spending key is generated or handled by claim.

---

## State Machine & Lifecycle

```txt
       [ Create Invite ]
               |
               v
           +-------+
             |Created| <------+ (waiting for domain authorization)
           +-------+        |
            /     \         | (delivery)
           /       \        |
(email sent)        \       v
    v                +-----------+
+---------+          | EmailSent |
  |Claimed  |<---------+-----------+ (HTTPS authorization + atomic registration)
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
- **`ClaimedWithPublicProfile`:** HTTPS onboarding commits the receiver profile, owner-signed registration event, domain attestation, checkpoint and single-use invite receipt atomically in SQLite. The JSON invite/notification store is an idempotently recovered mirror. The legacy mock can also set this status, so inspect resolution evidence: the status alone does not imply domain authorization or method ownership.
- **`Expired`:** Current timestamp exceeds `expires_at`. The invite is locked and cannot be claimed.
- **`Cancelled`:** The sender explicitly cancelled the pending invite before claim.

---

## End-to-End Claim Protocol

1. **Sender initiates payment:** Sender calls `POST /v1/send` with recipient identifier and amount. If the identifier has no registered profile, the daemon may create an `InviteRecord` with a UUID `invite_id` in `InviteStore`. Sender signatures are optional; their presence does not authenticate the recipient.
2. **Claim link:** Configure `SATSPATH_CLAIM_BASE_URL=https://node.example.com/claim` for the dashboard's public HTTPS deployment; no credentials, query or fragment. Otherwise the link uses the actual loopback daemon `/claim?invite_id=<UUID>`, not a placeholder. Never share the administrator token with a remote recipient.
3. **Inspect:** `GET /v1/claim?invite_id=<UUID>` is public. `is_claimable` means an active invitation may start secure onboarding, not that any alias is already verified. `sender_verified` authenticates only the sender's optional signature.
4. **Prepare authorization:** The local administrator uses the dashboard or Bearer-protected `/v1/onboarding/challenge` with `alias`, `invite_id` and `methods`. Publish the response's exact `body` at its `url`, under `https://<alias-domain>/.well-known/satspath/authorization/<identifier-hash>`. The body displays and commits the candidate signed profile, identity, event/action/sequence/predecessor, network, random challenge, expiry and invite. Domain administration is required; mailbox access alone is insufficient.
5. **Verify and attach ownership:** Within 600 seconds call `/v1/onboarding/verify` with only `alias` and `challenge_id`. TLS/SSRF checks and exact content matching precede an atomic, single-use commit. Wrong alias, stale/expired/cancelled invite, replay, redirects and modified content fail closed. Then attach the method's independently signed proof through `/v1/profile/methods/proof` with optional receiver `alias`. The sender re-resolves before requesting a handoff. Neither claim nor handoff executes a payment.

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
    "status": "created",
    "is_expired": false,
    "is_claimable": true,
    "created_at": 1727092800,
    "expires_at": 1727179200,
    "sender_verified": true,
    "sender_pubkey": "02..."
  }
  ```

### 2. Claim Invite (development mock only)
- **Endpoint:** `POST /v1/claim`
- **Auth:** Bearer token (`admin.macaroon` / `SATSPATHD_AUTH_TOKEN`); the invite ID is **not** an authorization token.
- **Availability:** Legacy route, not HTTPS onboarding. Fail-closed HTTP 400 by default, even with a valid ID and `signed_profile`. On mainnet/testnet/signet it remains disabled with or without the mock flag. On devnet/regtest it works only with explicit `--dev-mock-alias-verification` (or `SATSPATH_DEV_MOCK_ALIAS_VERIFICATION=1`); the mock supplies **no** proof of email/domain ownership.
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
- **Auth:** Bearer token (`admin.macaroon` / `SATSPATHD_AUTH_TOKEN`)
- **Response:** Array of `InviteRecord` objects.
- **Security:** IDs are visible to the authenticated owner here and in authenticated send responses; possession of an ID cannot make claim safe without alias verification.

### 4. List Claim Notifications
- **Endpoint:** `GET /v1/invites/notifications`
- **Auth:** Bearer token (`admin.macaroon` / `SATSPATHD_AUTH_TOKEN`)
- **Response:** Array of `ClaimNotification` objects.

### 5. Mark Notification Read
- **Endpoint:** `POST /v1/invites/notifications/<ID>/read` (or `POST /v1/invites/notifications/read-all`)
- **Auth:** Bearer token (`admin.macaroon` / `SATSPATHD_AUTH_TOKEN`)
- **Response:** `{"status": "ok", "notification_id": "...", "read": true}` (or `{"status": "ok", "all_read": true}`)
