# SatsPath CLI demonstration

Run from the repository root. This demonstrates local public-profile handling,
not a funded payment or production alias attestation. No fabricated success logs
are provided: inspect the actual output of your checkout.

## 1. Build and isolate local state

```bash
cargo build -p satspath-cli
export SATSPATH_DIR="$(mktemp -d)"
./target/debug/satspath init
```

`init` creates the local registry. The directory selected by `SATSPATH_DIR`
will also hold protocol identity keys as later commands create them. Those are
not spending keys; protect them and do not publish this directory.

## 2. Create and inspect a local identity profile

```bash
./target/debug/satspath register alice@example.com
./target/debug/satspath show alice@example.com
./target/debug/satspath export alice@example.com
```

`register` uses the alias as its default Lightning Address, creates a random
identity key, stores the signed profile and identity key locally, and attempts
publication to configured/default Nostr relays. **This step makes network calls**;
relay publication may fail while local registration succeeds. Use a disposable
alias and do not treat publication as proof of control of `example.com`.

The default profile has no method ownership proofs and no guardian recovery
policy. Its signature is not evidence that a payable method is available.

## 3. Encode a request

```bash
./target/debug/satspath encode alice@example.com 21000 --memo coffee
```

Copy the generated `satspath:v1:...` value and pass it to:

```text
./target/debug/satspath decode '<generated URI>'
```

Encoding a request does not reserve or transfer funds.

## 4. Inspect routing and ownership requirements

```bash
./target/debug/satspath quote alice@example.com 21000 --json
./target/debug/satspath prove alice@example.com --method-index 0
./target/debug/satspath attach-proof --help
```

The default Lightning pointer is not an amount-bound invoice, and the method is
not ownership-verified. Do not expect a payable QR or a successful payment from
this fixture. `prove` displays a challenge, not a completed proof. Use proof
material from the wallet or domain you actually control, following the command's
supported proof type; never attach synthetic signatures to bypass verification.

The CLI's explicit `--fetch-lnurl-invoice` preview option can fetch a BOLT11 only
when its payee, network, amount and expiry checks succeed. See
[mainnet preview limits](../docs/mainnet_safety.md) and the
[capability matrix](../docs/README.md). In `satspath preview`, BOLT12, Ark, and
Silent Payments payable handoffs remain gated, and human terminal output includes
static placeholder trust lines (`--json` reports actual verification fields).

## 5. Understand invite and daemon limits

Invites do not escrow money. The default claim URL is a placeholder, and daemon
claiming is disabled without real alias attestation; the mock is devnet/regtest
only. See [invite flow](../docs/invite_flow.md).

For actual recorded regtest observations, read
[daemon E2E results](../docs/daemon_e2e_results.md). For automated coverage, inspect
[the black-box tests](../crates/satspathd/tests/e2e_daemon_flow.rs).
A positive ownership-verified external-wallet journey is tracked in
[roadmap H2](../ROADMAP.md#h2--p0--positive-end-to-end-on-chain-journey).
