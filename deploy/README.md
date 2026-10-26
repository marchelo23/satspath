# Authority deployment: current implementation and limits

`satspathd` can serve local profiles and transparency data, but this checkout is
not a turnkey production authority. Read the [capability matrix](../docs/README.md),
[HTTP API](../docs/API_REFERENCE.md), and [release roadmap](../ROADMAP.md) first.

## What is not implemented by the operator commands

`satspath server init <domain>` and `satspath server check <domain>` are
**output-only stubs** in
[server.rs](../crates/satspath-cli/src/commands/server.rs). They print example
records/status text and “Feature coming soon!”, then return success. They do not
generate an operator identity, provision DNS, validate DNSSEC, or check quorum.
Do not publish the placeholder key or treat exit code zero as validation.

## Use the source-built development setup

Follow the [Docker guide](../docs/docker.md), which uses the root
[`docker-compose.yml`](../docker-compose.yml) and local Dockerfile targets.

The adjacent [`deploy/docker-compose.yml`](docker-compose.yml) is an **incomplete
deployment sketch**, not the verified release path:

- It references `satspath/satspathd:0.1.0`; the repository Docker workflow publishes
  the CLI image, not that daemon image. Availability of that external tag is not
  established by the workflow.
- It publishes `9737` on all host interfaces without configuring native TLS or
  a reverse proxy. Do not expose it directly to the internet.
- Its `/health` probe checks liveness only, not dependencies or witness quorum.
- Setting `SATSPATH_WITNESS_QUORUM` advertises policy; it does not implement
  cosignature collection or make `/v2/health` ready.

## TLS and hostname configuration

For a native process behind a local TLS proxy, configure the actual authority
hostname and trust proxy headers only when clients cannot bypass that proxy:

```bash
SATSPATH_AUTHORITY_DOMAIN=node.example.com \
  cargo run -p satspathd -- --bind 127.0.0.1:9737 --network regtest \
  --behind-proxy --require-tls-or-proxy --no-open
```

Example host-installed Caddy configuration (replace the domain and arrange
certificate issuance/DNS yourself):

```caddyfile
node.example.com {
    @metrics path /metrics
    respond @metrics "Forbidden" 403
    reverse_proxy 127.0.0.1:9737
}
```

This is a transport example, not a production-readiness claim. The root Docker
Caddyfile instead uses an internal CA for development. Configure public TLS,
access controls, backups, independent witnesses, and the remaining release gates
before describing a service as production-ready.

## Identity keys, backups and upgrades

The daemon's local-wallet mode **does** generate and persist a protocol identity
key in its home. It is not a spending key. Backups may contain identity keys,
the admin token, databases and trust state; protect them as secrets. Do not claim
that all deployments keep user identity keys off-server.

For a consistent development backup, stop writers before copying the complete
state volume (including any SQLite sidecar files). Keep all writers stopped
until the copy completes, then restart. A live `tar` of a changing SQLite/WAL
directory is not a documented consistent snapshot procedure.

Restoration must be rehearsed on a fresh volume and checked for log identity,
profiles, sequences, checkpoints and pins. Updating an image tag alone does not
prove schema compatibility, witness continuity, or safe downgrade. Recovery and
upgrade acceptance criteria are tracked in roadmap H7.
