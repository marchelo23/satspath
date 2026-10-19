# Incremental protocol conformance runner (#175)

From the repository root:

```sh
cargo run -p satspath-conformance -- test --format text
cargo run -p satspath-conformance -- test --format json
cargo run -p satspath-conformance -- test --resolver https://resolver.example.com/.well-known/satspath/alice --alias alice@example.com
cargo run -p satspath-conformance -- test --observed wallet-output.json --format json
```

`vectors/v1.json` is embedded by default (or supply `--vectors PATH`).
Missing/incorrect results fail; unknown features are SKIP, never PASS. A PASS
for a negative vector means the implementation **rejected** the unsafe input.
`--observed` first verifies each expectation against the local reference
evaluator; unsupported cases remain SKIP even if external JSON claims success.
`expiry` cases supply `{"as_of": UNIX_SECONDS, "profile": {...}}`; both
`expires_at + 59` (valid) and `expires_at + 60` (expired) are checked without
relying on the current clock. `bip21` cases supply a `uri`, `amount_sats`,
`network` and `as_of`; they validate every embedded payment instruction with
the wallet-handoff policy, not just URI syntax. Successful BIP-21 outputs
include every accepted instruction, its rail and the exact receiver (address,
invoice or offer), so an observed SDK cannot substitute or drop a receiver.
`capability` cases supply a `method`, `amount_sats`, `network` and `as_of`;
a descriptor is reported only after method validation. Unsupported opaque Ark
handoffs are rejected.
`bolt12` cases supply `offer`, `amount_sats`, `network` and `as_of`, and use
the same fixed-time handoff validation as the BIP-21 cases. BOLT12 results
additionally require the SatsPath offer HRP for the requested network, the
encoded offer amount (if present), and the profile method's minimum amount.
Unsupported network/encoding combinations are rejected, not inferred from
the shared validator's more permissive legacy behavior.
`--observed` compares a third-party wallet or
SDK's JSON object from vector ID to output; it does not execute that wallet or
attest a real payment. The live resolver probe uses production HTTPS, SSRF/DNS
pinning, response limits, signature and expiry verification, and checks the
requested alias. The resolver-disagreement vectors use a fixed `as_of` timestamp
and the protocol's 60-second expiry grace so their outcomes do not change as
wall-clock time advances. CI runs these vectors through `cargo test --workspace`.

**Not yet demonstrated:** wallet execution, BIP-353 DNSSEC chain validation,
positive rotation history, PaymentIntent approval (#173) and authenticated
resolver conflict policy (#174). These cannot be claimed PASS from this suite
until executable adapters and vectors are added.
The `rotation-invalid` vector checks malformed encoding only; it does not
exercise authorization, acceptance, replay or event-chain continuity.
The current negative resolver vectors exercise invalid signatures, not a
conflict between two independently valid signed profiles or a valid signed
revocation. Those cases remain pending until authenticated fixtures exist.
