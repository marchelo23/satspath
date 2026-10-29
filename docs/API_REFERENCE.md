# satspathd HTTP API Reference

Human-readable companion to the machine-readable OpenAPI 3.0.3 specification in
[`openapi.yaml`](openapi.yaml). The spec is the source of truth for request and
response schemas; this page explains behavior that a schema cannot express
(authentication model, request pipeline, error conventions, and known quirks).

> **Payment boundary.** The send/quote/pay endpoints never execute user
> payments or hold user spending keys; `POST /v1/pay` returns a wallet handoff
> for the host wallet to authorize and execute. Separately, authenticated,
> opt-in **regtest checkpoint anchoring** can instruct an operator-controlled
> Bitcoin Core wallet, using loopback RPC credentials, to fund, sign, broadcast
> and mine its own anchor transactions. Do not use a wallet with real funds.

Maturity labels follow the [README taxonomy](../README.md#maturity-taxonomy):
BIP-353 and BOLT12 primitives are IMPLEMENTED; Ark payment routing is PREVIEW;
Silent Payments, P2P, and invites are EXPERIMENTAL; the post-quantum profile
fields are RESEARCH. Note that the daemon's quote, pay, send, and receive
handoff endpoints still enforce strict on-chain BIP-21 validation. SatsPath has
not had an independent third-party security audit.

---

## 1. Using the specification

The file is plain OpenAPI 3.0.3 YAML. Any compatible tool can render or consume it.

```bash
# Interactive Swagger UI on http://localhost:8081 (requires Docker)
docker run --rm -p 8081:8080 \
  -e SWAGGER_JSON=/spec/openapi.yaml \
  -v "$(pwd)/docs:/spec:ro" swaggerapi/swagger-ui

# Lint the spec (requires Node)
npx @redocly/cli lint docs/openapi.yaml
```

You can also paste the file into <https://editor.swagger.io>, or import it into
Postman or Insomnia to generate a request collection. Generated clients should be
treated as a convenience: review the "Errors returned with HTTP 200" section below
before relying on status codes.

Example values in the spec (hashes, signatures, fingerprints) are synthetic and
are **not** cryptographically valid.

---

## 2. Connection basics

| Item | Value |
| :--- | :--- |
| Default bind | `127.0.0.1:9737` (`--bind` or `SATSPATHD_BIND`) |
| Transport | HTTP; HTTPS via `--tls-cert`/`--tls-key` or a reverse proxy |
| Content type | `application/json` for all JSON bodies and responses |
| Default network | `devnet` (`--network` or `SATSPATH_NETWORK`) |
| Correlation id | Send `X-Request-Id`; the daemon echoes it or generates one |
| Max request body | 64 KiB (65,536 bytes) for declared `Content-Length` values and JSON request readers |

A production deployment must not expose cleartext HTTP. See
[`docker.md`](docker.md) and
[`security/REVERSE_PROXY_RATE_LIMITING.md`](security/REVERSE_PROXY_RATE_LIMITING.md).

### Host header allow-list

Requests normally require exactly one trusted `Host` header before routing.
Requests to `/metrics` are an exception when the parsed `Host` is `satspathd`:
the router may allow them even if the normal Host allow-list check fails. This
Host-based exception does not restrict `/metrics` to internal callers. Loopback
binds accept `localhost` and loopback IP literals. For a DNS name (proxy or
native TLS), set `SATSPATH_AUTHORITY_DOMAIN=node.example.com` or
`SATSPATH_AUTHORITY_URL=https://node.example.com/v2`. Missing, duplicate,
malformed, or untrusted hosts on other requests receive
`400 {"error":"untrusted HTTP Host"}`.
`X-Forwarded-Host` and `--behind-proxy` do not bypass this check. See
[`dashboard_authentication.md`](dashboard_authentication.md).

---

## 3. Authentication

Protected routes require a Bearer token:

```bash
TOKEN=$(cat ~/.satspath/admin.macaroon)   # 64 hex characters
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9737/v1/dashboard/auth
```

* The token is created on first start in `<home>/admin.macaroon` (mode 0600 on
  Unix) or supplied through `SATSPATHD_AUTH_TOKEN` (must be 64 hex characters).
* Comparison is constant-time and fail-closed: an unconfigured token rejects
  every protected request.
* The token grants full daemon administration. Never log it, put it in URLs, or
  share it. No endpoint returns it.

### Which routes are protected

Mutations require authentication except for an explicit public allow-list;
private invite listings require authentication even for reads:

1. Any request that is **not** `GET`, `HEAD`, or `OPTIONS` requires the Bearer
   token, **except** this public allow-list:
   `POST /v1/receive`, `POST /v1/dns/resolve`,
   `POST /v1/transparency/verify/inclusion`, `POST /v1/transparency/verify/catena`,
   `POST /v1/profile/recover`, and `POST /v2/resolve`.
2. `/v1/invites` and `/v1/invites/notifications` require the token, including
   `GET`/`HEAD`. Other `GET`, `HEAD`, and `OPTIONS` requests remain public.

Consequences worth knowing:

* `POST /v1/resolve`, `/v1/quote`, `/v1/preview`, `/v1/pay`, and `/v1/send`
  **require the token**. Send can persist invitations; an unauthenticated
  caller cannot trigger that mutation.
* `POST /v1/transparency/verify/consistency` requires the token, while the
  inclusion and Catena verifiers are public.
* Read-only `GET` endpoints such as `/v1/status`, `/v1/profile`, `/v1/node`,
  and `/v1/diagnostics/rate_limit` are open to anyone who can
  reach the port. `/v1/status` includes the daemon home path. Bind to loopback
  or restrict access at the proxy.

**Authentication compatibility:** `/v1/send` and the two invite-list endpoints
now require the owner Bearer token. Existing clients must attach it; the
dashboard's centralized client handles this after unlocking the tab. Public
inspection of a single invite via `/v1/claim?invite_id=...` remains unchanged.

---

### Payment-method ownership attachment

`POST /v1/profile/methods/proof` (Bearer required) attaches or renews an
externally produced `MethodVerification` on the daemon's current signed profile:

```bash
curl --fail-with-body -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' --data-binary @method-proof.json \
  http://127.0.0.1:9737/v1/profile/methods/proof
```

The file wraps the public proof as `{ "verification": { ... } }`, following the
OpenAPI `MethodVerification` schema. Sign the exact message generated by
`satspath_core::ownership_challenge_message` with the method's key **outside**
SatsPath; this API never accepts spending keys. Use the SatsPath Schnorr format,
not legacy Bitcoin `signmessage` or BIP-322. Initially only
`OnchainAddressSignature` (P2WPKH/key-path P2TR) and `ArkPubkeySignature` are
accepted; domain proofs, self-attestations and Silent Payments are not supported
by this endpoint.

An optional `alias` selects a receiver profile created by a locally authorized
invite claim. Its independent identity and exact receive methods are loaded from
the committed claim; attaching its proof never changes the operator's wallet.

`verified_at` must be within the last 600 seconds, not in the future. Explicit
`expires_at` must be after now and no more than 30 days after issuance. A renewal
must have a later issuance than the currently stored proof; repeated/stale
submissions return 400 without modifying the profile. The v1 method signature
binds identity, method descriptor and issuance, **not** expiry; the authenticated
profile owner selects expiry within the above bound. This reusable ownership
evidence is not a single-use alias-control challenge.

Success returns `ProfileResponse` with a new signed sequence and atomic
profile/event/checkpoint commit. Unrelated edits preserve proofs byte-for-byte;
changed/removed methods and identity rotation invalidate them. Expired evidence
is not silently renewed by an edit: resolvers re-check validity. This endpoint
does not itself prove alias control; real registration and claims use the
separate HTTPS onboarding workflow below.

## 4. Request pipeline and global errors

Checks run in this order; the first failure wins.

| Order | Check | Response |
| :--- | :--- | :--- |
| 1 | `Host` allow-list (except `/metrics` with parsed `Host: satspathd`) | `400` `{"error":"untrusted HTTP Host"}` |
| 2 | Declared `Content-Length` over limit | `413` `{"error":"...","max_bytes":65536}` |
| 3 | Per-IP token bucket (burst 60, refill 10/s) | `429` with `Retry-After` header and `{"error":"...","retry_after":N}` |
| 4 | Bearer token (protected routes) | `401` `{"error":"Unauthorized: ..."}` |
| 5 | Route dispatch | Handler response, or `404` `{"error":"endpoint not found"}` |

Rate limiting keys on the peer socket address. Behind a trusted proxy, start the
daemon with `--behind-proxy` (or `SATSPATHD_BEHIND_PROXY=1`) so
`X-Forwarded-For` and `X-Real-IP` are honored. Tune with `--rate-limit-burst` and
`--rate-limit-rate`.

### Error body

All failures include an `error` field. Some responses also include metadata
such as `max_bytes` or `retry_after`:

```json
{ "error": "human-readable message" }
```

### CORS

Responses built by the JSON, text, and empty-response helpers carry
`Access-Control-Allow-Origin` set to the **first** entry of
`SATSPATHD_CORS_ORIGIN` (default `http://localhost:5173`), plus
`Access-Control-Allow-Methods: GET, POST, OPTIONS` and
`Access-Control-Allow-Headers: Content-Type, Authorization, X-Request-Id`.
The HTML UI (`GET /` and `/claim`) sends only `Access-Control-Allow-Origin`;
`GET /dashboard-auth.mjs` sends none of these CORS headers.
After Host validation, the declared body-size check, and rate limiting pass,
`OPTIONS` on any path returns `204`. Because `PUT` is not in the allowed methods,
browsers cannot call `PUT /v1/profile` cross-origin; use `POST /v1/profile`
instead. For multiple origins, use a reverse proxy.

### Errors returned with HTTP 200

Handlers wired through the daemon's `json_result(StatusCode(200), ...)` helper
reuse the success status for failures. The body is still `{"error":"..."}`, but
the HTTP status is **200**. Always check for an `error` key before parsing a
success payload on these operations:

* `GET /v1/status`, `/v1/node`, `/v1/profile`
* `POST /v1/receive` after a successful body read and parse, `POST /v1/broadcast`
* `GET /v1/transparency/status`, `/checkpoints`, `/checkpoints/{hash}`,
  `/events`, `/events/{hash}`, `/identifiers/{id}`, `/inclusion/{hash}`,
  `/consistency`, `/anchors`, `/anchors/{txid}`, `/catena/chain`
* `GET /v1/claim?invite_id=...`, `GET /v1/claim/{id}`, `GET /v1/invites`,
  `GET /v1/invites/notifications`
* `POST /v1/invites/notifications/read-all` and `.../{id}/read`

The OpenAPI file models these as `oneOf [success schema, Error]`.
`GET /v1/claim` without an invite ID instead returns HTTP 400.

### Status-code conventions for the other operations

| Operation | Behavior |
| :--- | :--- |
| `POST /v1/quote`, `/v1/preview`, `/v1/pay`, `/v1/send`, `/v1/dns/resolve` | Protocol outcomes (`no_route`, `invalid_signature`, `not_registered`, `invite`, DNS `error`) are `status` values inside an HTTP 200 body. `400` is only an unparsable body. |
| `POST /v1/resolve` | Resolution errors and malformed bodies return `404`; an oversized body returns `413`. |
| `GET`/`POST /v2/resolve` | `404` when the error message contains "not found", otherwise `400`. |
| `POST /v1/claim` | `400` when claim is disabled or an external `signed_profile` is provided; in enabled dev mock mode, `404` unknown invite, `409` already claimed, `400` other validation failures. |
| `POST /v1/p2p/resolve` | Candidate-resolution failures return a generic `400`; body-read failures return `400`, or `413` for an oversized body. |
| `GET /v1/health` | `200` for `healthy`/`degraded`, `503` for `unhealthy`. |
| `GET /v2/health` | `200` for `healthy`, `503` for `degraded`. |

The daemon has no configured witness-quorum verifier or replication service:
`/v2/health` currently reports `witness_quorum_healthy: false` and
`replica_count: 0`, so it returns `503` even with a fresh checkpoint. With no
checkpoint it reports `checkpoint_age_secs: -1`. A readable empty log is **not**
evidence of V2 readiness. Oversized JSON bodies (including chunked uploads
without `Content-Length`) return `413` and increment the payload-size metrics;
the normal JSON limit is 65,536 bytes.

---

## 5. Endpoint index

Access is **Public** (no token) or **Bearer** (token required). 58 operations
across 53 paths.

### UI

| Method | Path | Access | Summary |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | Public | Dashboard (wallet UI) |
| `GET` | `/claim` | Public | Dashboard (claim view) |
| `GET` | `/dashboard-auth.mjs` | Public | Dashboard auth helper script |

### Health and diagnostics

| Method | Path | Access | Summary |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Public | Liveness probe |
| `GET` | `/v1/health` | Public | Deep health check (SQLite, fee API, log) |
| `GET` | `/v2/health` | Public | S2S v2 readiness |
| `GET` | `/metrics` | Public | Prometheus metrics |
| `GET` | `/v1/diagnostics/rate_limit` | Public | Rate-limiter statistics |

### Node

| Method | Path | Access | Summary |
| :--- | :--- | :--- | :--- |
| `GET` | `/v1/status` | Public | Daemon status |
| `GET` | `/v1/node` | Public | Status plus local profile |
| `GET` | `/v1/control` | Public | Node control summary (EXPERIMENTAL) |
| `POST` | `/v1/dashboard/auth` | Bearer | Validate Bearer token |

### Profile

| Method | Path | Access | Summary |
| :--- | :--- | :--- | :--- |
| `GET` | `/v1/profile` | Public | Get local profile |
| `PUT` | `/v1/profile` | Bearer | Create or update profile |
| `POST` | `/v1/profile` | Bearer | Same as `PUT` (CORS-friendly) |
| `POST` | `/v1/profile/methods` | Bearer | Update receive methods |
| `POST` | `/v1/profile/methods/proof` | Bearer | Attach or renew a public ownership proof |
| `POST` | `/v1/onboarding/challenge` | Bearer | Prepare an exact, expiring HTTPS domain authorization for registration or claim |
| `POST` | `/v1/onboarding/verify` | Bearer | Verify domain authorization and atomically publish the profile/event/receipt |
| `POST` | `/v1/profile/challenge` | Bearer | Start alias verification (DEV MOCK) |
| `POST` | `/v1/profile/verify` | Bearer | Complete alias verification (DEV MOCK) |
| `POST` | `/v1/profile/rotate-key` | Bearer | Rotate identity key |
| `POST` | `/v1/profile/recover` | Public | Recover key with guardian quorum |
| `POST` | `/v1/broadcast` | Bearer | Save profile for publication |

### Resolution and routing

| Method | Path | Access | Summary |
| :--- | :--- | :--- | :--- |
| `POST` | `/v1/resolve` | Bearer | Resolve with full transparency verification |
| `POST` | `/v1/quote` | Bearer | Quote the best rail |
| `POST` | `/v1/preview` | Bearer | Quote plus safety warnings |
| `POST` | `/v1/pay` | Bearer | Wallet handoff (never executes payment) |
| `POST` | `/v1/send` | Bearer | Preview send using the verified local SQLite profile; otherwise no route or experimental invite for a truly unknown alias |
| `POST` | `/v1/receive` | Public | Receive payload and QR for own profile |
| `POST` | `/v1/dns/resolve` | Public | Resolve a BIP-353 name (local DNSSEC) |
| `POST` | `/v1/p2p/resolve` | Bearer | Resolve a P2P candidate (EXPERIMENTAL) |

### S2S v2

| Method | Path | Access | Summary |
| :--- | :--- | :--- | :--- |
| `GET` | `/.well-known/satspath-authority` | Public | Namespace descriptor |
| `GET` | `/v2/namespace` | Public | Namespace descriptor (same handler) |
| `GET` | `/v2/resolve?identifier=` | Public | Proof-carrying resolution |
| `POST` | `/v2/resolve` | Public | Proof-carrying resolution (body) |

### Transparency

| Method | Path | Access | Summary |
| :--- | :--- | :--- | :--- |
| `GET` | `/v1/transparency/status` | Public | Log status |
| `GET` | `/v1/transparency/checkpoints` | Public | List checkpoints (paginated) |
| `GET` | `/v1/transparency/checkpoints/{hash}` | Public | Checkpoint by hash |
| `GET` | `/v1/transparency/events` | Public | List name events (paginated) |
| `GET` | `/v1/transparency/events/{hash}` | Public | Event by hash |
| `GET` | `/v1/transparency/identifiers/{id}` | Public | History of one identifier hash |
| `GET` | `/v1/transparency/inclusion/{hash}` | Public | Inclusion proof for an event |
| `GET` | `/v1/transparency/consistency?from=&to=` | Public | Consistency proof |
| `GET` | `/v1/transparency/anchors` | Public | List Bitcoin anchors (paginated) |
| `POST` | `/v1/transparency/anchors` | Bearer | Anchor latest checkpoint (regtest) |
| `GET` | `/v1/transparency/anchors/{txid}` | Public | Anchor by txid |
| `GET` | `/v1/transparency/catena/chain` | Public | Catena anchor chain |
| `POST` | `/v1/transparency/verify/inclusion` | Public | Verify an inclusion proof |
| `POST` | `/v1/transparency/verify/consistency` | Bearer | Verify a consistency proof |
| `POST` | `/v1/transparency/verify/catena` | Public | Verify anchor-chain structure |

List endpoints accept `offset` (default 0) and `limit` (default 50, clamped to
1-200) and return `{"items":[...],"offset":0,"limit":50,"total":N}`.

### Invites

| Method | Path | Access | Summary |
| :--- | :--- | :--- | :--- |
| `GET` | `/v1/claim?invite_id=` | Public | Inspect an invite |
| `GET` | `/v1/claim/{id}` | Public | Inspect an invite (path form) |
| `POST` | `/v1/claim` | Bearer | Disabled by default; insecure devnet/regtest mock claim only |
| `GET` | `/v1/invites` | Bearer | List invites |
| `GET` | `/v1/invites/notifications` | Bearer | List claim notifications |
| `POST` | `/v1/invites/notifications/read-all` | Bearer | Mark all read |
| `POST` | `/v1/invites/notifications/{id}/read` | Bearer | Mark one read |

`GET /v1/claim` remains public for inspection. `is_claimable` means the invitation
is active and can start **HTTPS domain onboarding**, not that alias control is
already verified. Use `/v1/onboarding/challenge` with `invite_id`, then
`/v1/onboarding/verify`. Neither possession of an invite ID, a matching alias hash,
admin authentication nor a profile signature replaces domain authorization.
The legacy `POST /v1/claim` remains mock-only and disabled by default; no gate on
that route is relaxed. See [`invite_flow.md`](invite_flow.md).

---

## 6. Worked examples

All examples assume a local daemon and `TOKEN` set as above. Output is abbreviated.

### Check the node

```bash
curl -s http://127.0.0.1:9737/v1/status
```

```json
{
  "daemon": "satspathd",
  "version": "0.1.0",
  "network": "devnet",
  "wallet_initialized": true,
  "alias": "alice@example.com",
  "identity_fingerprint": "a8fdac91",
  "methods": ["Lightning", "Onchain"],
  "safety": {
    "moves_funds": false,
    "signs_bitcoin_transactions": false,
    "broadcasts_transactions": false,
    "stores_wallet_seeds_or_spending_keys": false,
    "manages_signed_profiles": true
  }
}
```

### Publish a receiving profile

Start a clean daemon home **without** mock flags. Supply a valid receive address
for the configured network. The initial real mechanism is administrator control
of the alias domain through HTTPS, **not mailbox verification or DNSSEC**. Aliases
must follow the ASCII BIP-353 name syntax. Existing aliases/history cannot be
replaced through registration; use normal owner-authorized updates/rotation.

```bash
curl --fail-with-body -s -X POST http://127.0.0.1:9737/v1/onboarding/challenge \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"alias":"alice@example.com","methods":{"onchain_address":"<address-on-daemon-network>"}}' > challenge.json

# Publish these exact bytes at the response's .url on your alias domain.
jq -j .body challenge.json > domain-authorization.json

# After publishing over HTTPS, complete within the 600-second challenge window.
jq '{alias:"alice@example.com",challenge_id}' challenge.json > verify.json
curl --fail-with-body -s -X POST http://127.0.0.1:9737/v1/onboarding/verify \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data-binary @verify.json
```

The verifier requires valid TLS, public DNS addresses pinned to the connection,
HTTP 200 without redirects, and exact body bytes bounded to 16 KiB. Proxies are
disabled and requests time out after 10 seconds. It never accepts a proof body
or DNS answer from the verify request. The authorization commits identity,
profile, event/action/sequence/predecessor, network, expiry and optional invite.
Consumption, publication, attestation, checkpoint and optional claim receipt
commit atomically; replay/stale submissions fail closed. Wallet activation and
invite notifications recover from that authoritative transaction after restart.

The local operator signs a `Domain` identifier attestation valid no longer than
the candidate profile. By default the local resolver trusts its own operator for
that method; an explicit `SATSPATH_TRUSTED_VERIFIERS_JSON` policy replaces that
default, including an empty list. Remote consumers need their own trusted-verifier policy.
Owner updates rebind a current grant to the new profile without extending its
expiry; identity replacement does not inherit it. **Method ownership still
requires an independent method-key proof.** No payment is approved or executed.

For invite links, set `SATSPATH_CLAIM_BASE_URL=https://node.example.com/claim`
to the HTTPS origin/path serving this daemon's dashboard. Credentials, query and
fragment are forbidden. Without configuration the actual local `/claim` URL is
used (HTTP only on loopback); non-loopback binds require `SATSPATH_CLAIM_BASE_URL`
even when native TLS is enabled. There is no `satspath.local` placeholder.

Each save re-signs the profile (`SHA256("SatsPathProfileV1" || RFC8785(profile))`)
with the next `sequence` and a 30-day expiry, appends a `register` or
`update_profile` `NameEvent` to the transparency log, and signs a new operator
checkpoint.

### Rotate or recover an identity key

* **Key rotation (`POST /v1/profile/rotate-key`)**: requires Bearer auth and an
  empty request body. The daemon generates a new identity key and embeds a
  dual-signed `profile.rotation` object where the previous key signs under
  `SatsPathKeyRotationAuthorizationV1`, the new key signs under
  `SatsPathKeyRotationAcceptanceV1`, and the previous key signs the `rotate_key`
  `NameEvent`.
* **Guardian key recovery (`POST /v1/profile/recover`)**: public (no Bearer
  token). Accepts `alias`, `proof` (`KeyRecoveryProof`), and `signed_profile`
  (where `signed_profile.profile.recovery` must equal `proof`, retain a
  `recovery_policy`, and contain no `rotation`). Guardians sign under
  `SatsPathKeyRecoveryAuthorizationV1` and the new key signs acceptance under
  `SatsPathKeyRecoveryAcceptanceV1`. When the new key is not in the daemon's
  local keystore, also supply `event_signature` (over the `recover_key`
  `NameEvent`) and `event_created_at` (within ±300 seconds of server time). See
  [`key_recovery.md`](key_recovery.md).

### Resolve a BIP-353 DNS name

```bash
curl -s -X POST http://127.0.0.1:9737/v1/dns/resolve \
  -H 'Content-Type: application/json' \
  -d '{"name":"alice@example.com"}'
```

By default (`allow_insecure_dns_for_dev: false`), `/v1/dns/resolve` queries DNS
with `HickoryDnssecTxtResolver` under `DnssecPolicy::Strict`, validating the
RRSIG/DNSKEY/DS chain locally against the embedded ICANN root KSKs (`38696`,
`20326`, `19036`) and failing closed if DNSSEC validation fails. Passing
`"allow_insecure_dns_for_dev": true` switches to `DohTxtResolver` under
`DnssecPolicy::DevInsecure` for local testing.

### Quote and hand off to a wallet

```bash
curl -s -X POST http://127.0.0.1:9737/v1/quote \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"recipient":"alice@example.com","amount_sats":50000}'
```

After global checks and JSON parsing pass, `/v1/quote` returns HTTP 200 and is
tagged by `status`:

| `status` | Meaning |
| :--- | :--- |
| `ok` | Route selected; `qr` holds a validated, amount-bound on-chain BIP-21 URI for the configured network. |
| `no_route` | Profile resolution failed (including lookup or signature verification), no usable route was found, or the selected payload failed handoff validation. Resolution failures have a `reason` starting with `transparency verification failed:`. |

`/v1/quote`, `/v1/preview`, `/v1/pay`, and `/v1/send` route only through the mandatory
transparency composition (signature, identifier history, key continuity,
inclusion, checkpoint consistency, operator continuity). They then **keep only
payment methods that carry a valid ownership proof**; self-asserted methods are
dropped, so a profile with no proofs yields `no_route`. `/v1/send` no longer
treats legacy registry or external resolver results as payable. Only a locally
unknown alias may produce an experimental invite; it cannot be claimed in
production without a real alias-control verifier.

After the wallet-handoff gate in [#159](https://github.com/satspath/satspath/pull/159),
`/v1/quote`, `/v1/preview`, `/v1/pay`, and successful `/v1/send` responses emit
validated Bitcoin URIs whose on-chain address, Silent Payment key, or Ark address, network, and exact amount pass
final validation. A BOLT11 invoice can be validated against its payee, network,
amount, and expiry, but these quote paths do not generate one. Lightning
Addresses and LNURL links remain **amount-less receive pointers**. BOLT12 and
legacy server/key-only Ark pointers fail closed. Configure address-backed Ark
with `ark_server`, `ark_pubkey` (compressed contract output key), `ark_address`
(wallet-generated Bech32m), and `ark_asp_pubkey` (operator pin obtained from the
wallet/ASP). The output key, operator pin, and mainnet/test-network prefix must
match the address. Receives emit `bitcoin:?ark=<address>` with an optional
`&amount=<BTC>`; quote/pay/send still require independently verified ownership.
This is not a live ASP or VTXO check. See [Ark routes](ark_routes.md).
Configure Silent Payments with `silent_payment_address` (BIP-352,
validated against the daemon network); remove it independently with
`{"remove_methods":["silent_payment"]}`. On-chain receives emit
`bitcoin:?sp=<key>` or `bitcoin:<address>?sp=<key>`, appending `&amount=<BTC>`
when an amount is requested. Without a rail, receive
prefers on-chain when `amount_sats` is set and Lightning otherwise.

**Silent Payments compatibility note:** receive, quote, pay, and send responses
can now contain `sp` URIs, including SP-only methods without a static address.
This adds response variants; address-only BIP-21 payloads remain unchanged.
Strict generated clients that accept only `PayableBip21Payload` must be updated
to handle `PayableOnchainPayload` and `SilentPaymentReceivePointer` where applicable.
Clients and wallets without Silent Payment support must reject these payloads
explicitly rather than dropping the `sp` instruction.

`POST /v1/pay` wraps an `ok` quote as `status: wallet_handoff` with
`payment_payload`, `qr_svg`, and `handoff.daemon_executes_payment: false`.

### Verify a name with proofs (S2S v2)

```bash
curl -s -X POST http://127.0.0.1:9737/v2/resolve \
  -H 'Content-Type: application/json' -d '{"identifier":"alice@example.com"}'
```

Prefer `POST` so identifiers stay out of URLs and access logs. The
`ResolutionEnvelope` carries `signed_profile`, `name_events`, `inclusion_proof`,
and `checkpoint`. On this daemon `consistency_proof` is always `null` and
`witness_cosignatures` is always empty.

### Audit the transparency log

```bash
curl -s 'http://127.0.0.1:9737/v1/transparency/checkpoints?limit=10'
curl -s 'http://127.0.0.1:9737/v1/transparency/consistency?from=1&to=3'
```

---

## 7. Mapping from the original issue

Issue 104 listed eleven endpoints. The implemented surface is larger, and two
names differ:

| Issue listed | Reality |
| :--- | :--- |
| `GET /v1/status`, `/v1/node` | Implemented as listed. |
| `POST /v1/resolve`, `/quote`, `/preview`, `/pay`, `/send` | Implemented. All require the Bearer token. |
| `POST /v1/register` | **Does not exist.** Unauthenticated requests return `401`; authenticated requests reach the `404` fallback. Clean-daemon profiles are created through `/v1/onboarding/challenge` and `/v1/onboarding/verify`, without mock flags. `POST /v1/receive` builds a receive payload and does not register anything. |
| `GET /v1/transparency/events`, `/checkpoints` | Implemented, paginated. |
| `POST /v1/transparency/anchors` | Implemented, Bearer, regtest only. |

### Declared but not served

These appear in code or older docs but have no working handler. GET requests
return `404`; protected mutation requests pass through authentication first:

* `GET /v2/checkpoint/latest` is defined as a route constant, but the router does
  not dispatch it; [`s2s/server-v2.md`](s2s/server-v2.md) documents that gap. Use
  `GET /v1/transparency/checkpoints?limit=1` or the `checkpoint` field of
  `/v2/resolve`.
* `/v1/transparency/catena/anchor` is recognized for metrics labelling only.

---

## 8. Maintaining the spec

The spec is currently maintained by hand against
[`router.rs`](../crates/satspathd/src/router.rs),
[`types.rs`](../crates/satspathd/src/types.rs), and the handlers. When you add or
change a route:

1. Update `docs/openapi.yaml` (path, schemas, `security`, error responses).
2. Update the tables in this page.
3. Re-validate: `npx @redocly/cli lint docs/openapi.yaml`.

### Not yet implemented (needs Rust changes)

The remaining items from issue 104 require code in the daemon and are out of scope
for this documentation-only change:

* Serving Swagger UI and the spec from the daemon (for example `/docs` and
  `/openapi.json`). `tiny_http` has no built-in support; assets would be embedded
  with `include_str!`/`include_bytes!`, and the page CSP
  (`default-src 'self'`) must allow them. Unauthenticated `GET` routes mean the
  docs would be public unless gated.
* A CI test that boots a test daemon and validates real responses against the
  schemas in `openapi.yaml`. The HTTP test harness in `crates/satspathd/src/main.rs`
  already provides `start_test_daemon`.
* Deciding whether to fix the HTTP-200-on-error behavior described in section 4,
  which would change the contract documented here.
