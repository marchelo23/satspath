# SatsPath v2 Server Migration & Identifier Portability

> **Target protocol design.** The CLI `migration export/verify` commands currently
> print “Feature coming soon!”; they do not produce or verify a server-state
> export. Profile-level `export/import` is a different feature. Do not use this
> document as an executable migration runbook. See [server status](server-v2.md)
> and [CLI dispatch](../../crates/satspath-cli/src/main.rs).

## Overview

A domain owner must be able to move from one SatsPath server to another while keeping `user@domain`, owner keys, histories, and verifier trust intact. Endpoint ownership and identity ownership are strictly decoupled.

## Identity Layers

SatsPath separates five distinct identity layers:

| Layer                       | Controls                          | Survives migration?                 |
| --------------------------- | --------------------------------- | ----------------------------------- |
| **Namespace authority key** | Domain policy, descriptor signing | Yes (held by domain owner)          |
| **Log identity (`log_id`)** | Append-only history continuity    | Yes (preferred: same log continues) |
| **Log operator key**        | Checkpoint signing                | Rotated via `OperatorKeyRotation`   |
| **Endpoint / TLS identity** | Network reachability              | Changed (new server URL)            |
| **Individual owner keys**   | User identity events              | Always preserved                    |

## Migration Cases

### 1. Planned Move (Old Server Cooperating)

The old server exports a signed `MigrationStatement` binding its latest checkpoint to the new endpoint. The new server imports the full event stream, verifies it, and begins serving.

### 2. Old Server Offline / Censoring

If the domain owner holds the namespace authority key, they can issue a new `NamespaceDescriptor` pointing to the new endpoint. Clients with pinned checkpoints verify continuation via consistency proofs from the new server.

### 3. Operator Key Compromise

The namespace authority issues an `OperatorKeyRotation` and a new descriptor epoch. The old operator key is revoked.

### 4. Witness Set Change

A new descriptor epoch lists updated witness pubkeys and quorum requirements.

### 5. Replica Promotion

A healthy replica is promoted by updating DNS and issuing a migration statement.

### 6. Hosted User Moving to New Domain

A provider-owned domain cannot be unilaterally redirected. Instead, a signed redirect links the old `alice@provider.example` to a new sovereign identifier `alice@sovereign.example`. Clients display this as a **new identifier**, not a transparent migration.

## Export / Import Format

A portable `MigrationExport` contains:

- Signed `NamespaceDescriptor` (current epoch)
- Full signed event stream (`Vec<NameEvent>`)
- All checkpoints with operator signatures
- Consistency proofs bridging checkpoints
- Current-state map reconstruction data
- Witness cosignature receipts
- Operator key transition history

Exports contain **no identity private keys** unless a separate local client backup action handles them explicitly.

## Security Properties

- A malicious old or new server cannot fabricate a migration.
- DNS rollback and endpoint rollback are detected and rejected.
- Clients with an old valid descriptor receive a precise `migration_required` or `policy_changed` result.
- The new server reconstructs and verifies the full state before advertising readiness.
