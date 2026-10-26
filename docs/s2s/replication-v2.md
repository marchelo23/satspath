# SatsPath v2 Verified Replication & Failover

> **Target protocol design, not a deployment guide.** The current daemon does not
> serve replicas or integrate witness cosignature verification; no runnable pull
> replication service is claimed here. See [server implementation status](server-v2.md).

## Overview

Cryptography prevents a server from forging identity state, but cannot prevent censorship or downtime. Server-to-server replication ensures availability, monitoring, and sovereign operation without reintroducing trust in whichever mirror responds fastest.

## Replication Model

SatsPath uses a **pull-based** replication model where replicas periodically fetch and verify updates from the primary authority.

### Roles

- **Primary**: The sole authority that accepts and commits signed name events. Only the primary appends to the log.
- **Replica**: Ingests, verifies, and durably stores the primary's data. A replica NEVER authors events; it only mirrors verified state.

### Ingestion Pipeline

A replica must ingest and verify, in order:

1. Namespace descriptor and policy epoch.
2. Signed name events (verified against `verify_event_transition`).
3. Append-only log entries and checkpoints (verified via `verify_checkpoint_transition`).
4. Compact consistency proofs (verified via `verify_consistency_proof`).
5. Current-state map snapshots or deterministic updates.
6. Witness cosignatures.
7. Operator and namespace-key transitions.

A replica serves data **only after full verification and durable commit**.

## Failover Rules

- Discovery may list multiple endpoints with explicit priority/role.
- Any endpoint may serve a proof envelope, but the client verifies the same namespace/log/witness policy.
- Prefer a newer policy-valid checkpoint; **never accept tree-size rollback** because the primary is unavailable.
- A stale replica may serve within a defined maximum staleness window and must disclose its checkpoint age.
- Two same-size/different-root views are a **critical equivocation**, not a normal conflict.

## Caching Rules

- Cache keys include: namespace, descriptor epoch, `log_id`, tree size/root, and identifier.
- Cached positive and negative answers cannot outlive descriptor/checkpoint freshness policy.
- Backfill can resume from a pinned checkpoint with a consistency proof; full trust reset is forbidden.

## Security Properties

- Replication transports **public identity data only**. No private keys cross any boundary.
- A corrupted or malicious replica cannot forge, roll back, or mix state.
- Conflicting authoritative views produce evidence and halt routing.
