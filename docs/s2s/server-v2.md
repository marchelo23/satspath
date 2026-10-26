# SatsPath v2 server: implementation status and target contract

This page separates the current `satspathd` routes from the broader
[S2S v2 specification](protocol-v2.md). It is not evidence of a deployed,
witnessed authority or complete replication/migration support.

## Implemented daemon routes

| Route | Current behavior |
| --- | --- |
| `GET /.well-known/satspath-authority` and `GET /v2/namespace` | Builds the local namespace descriptor, including configured witness policy |
| `GET /v2/resolve?identifier=...` and `POST /v2/resolve` | Builds an envelope from the local transactional store; POST avoids putting the identifier in the URL |
| `GET /v2/health` | Reports checkpoint age, quorum health and replica count; currently degraded/503 because quorum is false and replica count is zero |

The current envelope contains the stored signed profile, name-event history,
inclusion proof and checkpoint. It attempts a current-state proof and checks its
binding when the checkpoint contains `map_root`. However:

- `consistency_proof` is currently `None` in this envelope builder.
- `witness_cosignatures` is currently an empty list.
- A witness policy in the descriptor does not collect or verify cosignatures.
- Daemon quote/pay/send use the local verified-state path, not an integrated
  remote-authority discovery/replication pipeline.

Sources: [router](../../crates/satspathd/src/router.rs),
[resolve builder](../../crates/satspathd/src/handlers/resolve.rs),
[descriptor construction](../../crates/satspathd/src/handlers/transparency.rs),
[health response](../../crates/satspathd/src/v2_api.rs).

## Not implemented as a daemon route

`GET /v2/checkpoint/latest` is a constant in `v2_api.rs`, but has no router handler
and returns 404. Do not call it as an available API. Existing v1 checkpoint routes
are listed in the [HTTP API reference](../API_REFERENCE.md); they do not substitute
for a witness-cosigned v2 checkpoint service.

## Target verified resolution pipeline

The specification requires clients to compose namespace binding, owner/profile
validation, current-state evidence, append-only continuity, operator/witness
policy, and payment-method ownership before routing. Those requirements must
not be read as a claim that every step is integrated into the current server.

Quorum integration and independent operation are tracked in
[roadmap H6](../../ROADMAP.md#h6--p1--integrated-quorum-and-multi-operator-operations).
Replication and migration documents describe target contracts, not runnable
daemon provisioning instructions.

## Deployment boundary

Keep spending secrets out of the API. The local daemon may persist a separate
identity key and admin token; its storage is not exclusively public data.
Configure TLS/proxy, hostname allow-list, access controls, consistent backups and
resource limits explicitly. See [deployment limits](../../deploy/README.md),
[telemetry](../telemetry.md), and [mainnet safety](../mainnet_safety.md).
