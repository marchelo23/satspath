# Docker development guide

**Status:** source-build development configuration, not a hardened production
deployment or a real-funds recommendation. See [current limits](README.md),
[authority deployment notes](../deploy/README.md), and [mainnet safety](mainnet_safety.md).

## What the repository actually provides

| Component | Source | Behavior |
| --- | --- | --- |
| CLI image | Dockerfile target `runtime` | `/usr/local/bin/satspath`, UID/GID 10001, `/data` working directory |
| Daemon image | Dockerfile target `runtime-daemon` | `/usr/local/bin/satspathd`, UID/GID 10002, `--home /data --no-open`, container bind `0.0.0.0:9737` |
| Root Compose | `docker-compose.yml` | Builds both targets; daemon host port bound to `127.0.0.1:9737`; optional Caddy, Prometheus and Grafana services |
| Caddy | `docker/Caddyfile` | HTTP redirect and TLS with **`tls internal`**, not default public ACME; blocks public `/metrics` |
| Docker CI | `.github/workflows/docker.yml` | Builds/scans/publishes CLI image; does not establish publication of a daemon image |

Both images run as non-root. The checked-in Compose files do **not** set
`read_only`, `cap_drop`, or `no-new-privileges`; those were previously documented
as existing guarantees, incorrectly. Image size and rebuild time depend on the
build and are not measured guarantees. Cargo-chef supplies dependency caching.

## 1. Build and inspect the CLI

Run from the repository root with Docker/BuildKit and Compose v2 installed:

```bash
docker build --target runtime -t satspath-cli:local .
docker run --rm satspath-cli:local --help
docker run --rm -v satspath_cli_demo:/data satspath-cli:local init
docker run --rm -v satspath_cli_demo:/data satspath-cli:local register alice@example.com
docker run --rm -v satspath_cli_demo:/data satspath-cli:local show alice@example.com
```

The registration command attempts Nostr publication and makes network calls.
Use disposable data. A default signed Lightning pointer has neither method
ownership proof nor a fetched, amount-bound invoice; a payable quote is not
promised by this example. See the [CLI demo](../examples/demo_flow.md).

The separate `satspath_cli_demo` volume avoids sharing ownership-sensitive state
with the daemon. The root Compose mounts `satspath_data` into **both** CLI and
daemon despite their different UIDs. Do not alternate recursive `chown` commands
between users: that can break the other process. Use separate state or explicitly
design permissions before sharing; never loosen private key/token permissions.

The CLI reads `SATSPATH_DIR` or defaults to `.satspath` relative to its working
directory (thus `/data/.satspath` in this image). The Dockerfile's
`SATSPATH_DATA_DIR` variable is not read by that native CLI path. The daemon is
different: its container command explicitly selects `--home /data`.

## 2. Start only the daemon

The root Compose defaults to `mainnet`, while the native daemon defaults to
`devnet`. Select the intended network explicitly; this example uses regtest:

```bash
SATSPATH_NETWORK=regtest docker compose up --build -d satspathd
docker compose logs -f satspathd
```

From another terminal:

```bash
curl --fail http://127.0.0.1:9737/health
curl --fail http://127.0.0.1:9737/v1/health
curl http://127.0.0.1:9737/v2/health
```

`/health` is liveness. `/v1/health` probes dependencies and can be degraded while
returning 200. `/v2/health` currently returns 503 because witness quorum is not
integrated; this is not fixed by starting more containers. See [telemetry](telemetry.md).

The default claim/challenge gates remain closed. The explicit development alias
mock is allowed only on devnet/regtest and is not real alias ownership.
Admin/mutating routes require the token in `/data/admin.macaroon`, unless supplied
through `SATSPATHD_AUTH_TOKEN`. Do not log or publish it. See [API auth](API_REFERENCE.md).

## 3. Optional proxy and monitoring

Start selected services rather than `docker compose up` without arguments:

```bash
docker compose up -d caddy prometheus
```

The default Caddy configuration uses an internal CA; clients must trust that CA
for local TLS. For a public hostname, replace the development site configuration
with an appropriate public-certificate setup and set `SATSPATH_AUTHORITY_DOMAIN`
to the same hostname in the daemon. The proxy preserves the Host header, and an
unconfigured hostname is rejected. `--behind-proxy` alone does not allow it.

Grafana requires `GRAFANA_PASSWORD` set to a secure non-default value. The checked-in
Prometheus rules are not a configured notification service: alert delivery must
be arranged and tested separately.

## TLS and exposure

Never expose public cleartext daemon HTTP. Native TLS is also available:

```bash
SATSPATH_AUTHORITY_DOMAIN=node.example.com satspathd --bind 0.0.0.0:9737 \
  --tls-cert /path/to/fullchain.pem --tls-key /path/to/privkey.pem \
  --require-tls-or-proxy --no-open
```

| Setting | Actual behavior |
| --- | --- |
| `--behind-proxy` / `SATSPATHD_BEHIND_PROXY=1` | Trusts forwarded client IP headers; only safe behind a proxy clients cannot bypass |
| `--require-tls-or-proxy` / `SATSPATHD_REQUIRE_TLS_OR_PROXY=1` | Refuses non-loopback cleartext startup without TLS/proxy; otherwise startup only warns |
| `SATSPATH_AUTHORITY_DOMAIN` / `SATSPATH_AUTHORITY_URL` | Configures trusted DNS Host names; see API Host rules |
| `SATSPATHD_AUTH_TOKEN` | Optional 64-hex-character admin token; otherwise created in the daemon home |
| `SATSPATH_LOG_FORMAT=json` | Structured logs; `RUST_LOG` controls verbosity |

Metrics have no Bearer authentication at the daemon; restrict network/proxy
access. Do not rely on a Host-header convention as an access-control boundary.

## State, backup and upgrade

`satspath_data` contains daemon state, including protocol identity material and
the admin token, not just public profiles. It contains no user spending seed by
design. Stop **all writers** before copying the complete state, or use a separately
validated consistent SQLite backup procedure. Protect the backup and rehearse
restore on a new volume; do not assume live `tar` provides a consistent WAL snapshot.

The `deploy/docker-compose.yml` file is an incomplete authority sketch with a
different image/exposure configuration; it is not interchangeable with the root
development Compose. See [its limitations](../deploy/README.md).

## Useful commands and limitations

```bash
make help
make build-cli     # CLI image only
make smoke         # CLI --help smoke test only
docker build --target runtime-daemon -t satspathd:latest .
make scan          # Requires Trivy and both expected :latest image tags
docker compose stop satspathd
```

`make up` starts all default services, including Grafana; it is not the minimal
daemon startup shown above. Some wallet-related Make targets refer to a `wallet/`
directory not shipped in this checkout and are not supported setup instructions.

Remaining packaging, deployment hardening, recovery and release verification are
tracked in [roadmap H3/H7](../ROADMAP.md), not claimed complete by this guide.
