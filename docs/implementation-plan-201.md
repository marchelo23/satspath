# Issue #201 — usable onboarding and method ownership

Status: implementation plan + D1 delivery. Tracks https://github.com/satspath/satspath/issues/201;
does **not** close H1 or certify external interoperability. Coordinate the capability
contract with #200 / #196. Baseline: `upstream/main` at `de96102`.

## Delivery order

1. **D1 — daemon ownership lifecycle (1 engineering day).** Add authenticated
   attachment/renewal of externally signed on-chain/Ark ownership proofs. Verify
   public material before writes, commit profile/event/checkpoint atomically,
   preserve proofs only for unchanged full payment methods and identity, invalidate
   changed/removed methods, reject expired/future/stale submissions. Add regression
   and HTTP authorization tests. No spending keys enter the daemon.
2. **D2 — real alias control (2 engineering days).** Initial mechanism: DNSSEC TXT
   challenge under the alias's exact user-specific DNS name. This proves domain
   administrator authorization for that alias, **not** mailbox access. Use local
   DNSSEC validation, not an upstream AD bit. Persist a random, expiring challenge
   binding canonical alias, identity key, intended action, profile hash, sequence,
   previous event hash and invitation ID (if applicable). Never return verification
   as successful from request-supplied DNS content. Commit the consumed challenge,
   attestation and authorized NameEvent together; bind the attestation hash into
   registration. Resolve the challenge/profile-hash dependency before coding:
   prepare the candidate profile and event first, then challenge their commitments.
3. **D3 — usable claims (1–2 engineering days).** Configure an HTTPS public claim
   base URL with validated origin/path, no credentials or fragments; connect it to
   the existing claim page. Prepare a receiver-authorized candidate profile/event,
   verify alias control, and atomically publish + consume invite/challenge. Keep
   sender/operator wallet state separate. An invitation never proves alias control.
   Retain development mock gates; production succeeds only through real evidence.
4. **D4 — acceptance evidence (1 engineering day).** Add no-mock onboarding/claim
   tests; wrong alias/key/event, expiry, replay, concurrent claims and restart
   persistence must fail without mutations. Prove attached methods resolve as
   verified, preserve unrelated methods and invalidate replaced ones. Exercise a
   controlled DNSSEC zone separately; record exact commands/results. Update the
   #200 capability matrix and ROADMAP only with observed evidence.

## D1 API and boundaries

`POST /v1/profile/methods/proof` accepts `{ "verification": MethodVerification }`
under the existing bearer authorization and mutation lock. The signer uses
`ownership_challenge_message(identity_pubkey, method.ownership_descriptor(), issued_at)`
from `satspath-core`. This is the existing SatsPath Schnorr challenge format, **not**
Bitcoin Core's legacy `signmessage` format or BIP-322. Only
`OnchainAddressSignature` and `ArkPubkeySignature` are initially accepted. P2WPKH
and key-path P2TR are supported by the existing verifier; Silent Payments and
legacy/multisig addresses are not certified by this delivery.

Require issuance within the last 600 seconds, no future issuance, and explicit
expiry after now and no later than 30 days after issuance. Renewal replaces the
same descriptor only with a later issuance timestamp; exact replay is rejected.
Proof timestamps/expiry follow existing v1 semantics: expiry is profile-owner
metadata, not signed by the method key. This is a reusable ownership attestation,
not the single-use alias authorization planned for D2. No domain-body upload,
network fetch, self-attestation or mock verification is promoted to verified.

Unchanged proofs are retained byte-for-byte (including expired evidence, which
resolvers still report expired). Full method equality is required because the
current ownership descriptor can omit fields such as an Ark contract address.
Changed identities and revoked/replaced/removed methods lose their proofs.

## Reproducible validation

```sh
npm ci                         # prepare installs Husky
cargo test -p satspathd
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
bash .agents/skills/satspath-crypto-audit/scripts/audit_crypto.sh
```

Husky checks formatting, daemon regressions and documentation tests on commit. Full workspace,
security-audit and interoperability results must be reported separately; ignored
or unexecuted external tests are not acceptance evidence. Request CodeRabbit with
the exact PR comment `@coderabbitai full review`. Do not merge or close #201 until
D2–D4 acceptance is met.
