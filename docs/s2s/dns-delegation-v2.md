# SatsPath v2: DNSSEC Delegation

> **Namespace delegation specification.** This is distinct from native BIP-353
> payment-record resolution. The CLI `dns check` and `server init/check` commands
> are stubs, not provisioning/validation tools for this design. See
> [server status](server-v2.md) and [deployment limits](../../deploy/README.md).

## Overview

To provide strong, cryptographic binding between a domain-based identifier (e.g., `alice@example.com`) and its authoritative resolving server, SatsPath uses DNSSEC. This document specifies how a namespace owner configures their DNS to prove authority to SatsPath resolvers.

## The DNS Record

The descriptor is published as a `TXT` record at `_satspath.<domain>`.
For `example.com`, the record must be at `_satspath.example.com`.

### Format

The content is a string containing semicolon-separated key-value pairs.

```text
v=sp2; e=https://satspath.example.com; k=xpub...; l=log_id...; w=witness_policy;
```

#### Fields

- `v` (required): Protocol version. MUST be `sp2`.
- `e` (required): Authoritative S2S endpoint URL. MUST be HTTPS.
- `k` (required): Hex-encoded compressed secp256k1 public key of the namespace authority.
- `l` (required): The `log_id` (Merkle root hash or ID) of the transparency log.
- `w` (optional): Witness policy identifier.

## Validation Rules

1. **DNSSEC Required**: The resolver MUST validate the record using DNSSEC from a configured local trust anchor. Responses without the `AD` bit proven locally MUST NOT be treated as `domain_verified`.
2. **TTL Enforcement**: Resolvers MUST cache the record according to its TTL and MUST NOT use stale records.
3. **No Silently Falling Back**: If DNSSEC verification fails or the signature is bogus, the resolver MUST fail closed (error) rather than falling back to an unverified state.
