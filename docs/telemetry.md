# SatsPath Daemon Telemetry & Observability

`satspathd` includes built-in observability across three pillars (`crates/satspathd/src/telemetry/`):

1. **Prometheus Metrics (`GET /metrics`)**
2. **Separate liveness, dependency health, and S2S readiness endpoints**
3. **Structured Request Tracing (`X-Request-ID`)**

---

## 1. Prometheus Metrics (`GET /metrics`)

`satspathd` exposes Prometheus text exposition format (`0.0.4`) at `GET /metrics`.

### Exported Metric Families

| Metric Name | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `satspathd_http_requests_total` | Counter | `method`, `endpoint`, `status` | Total number of HTTP requests processed by `satspathd`. |
| `satspathd_http_request_duration_seconds` | Histogram | `method`, `endpoint` | HTTP request latency in seconds (`0.005` to `10.0`s buckets). |
| `satspathd_profile_resolution_total` | Counter | `status`, `cache_hit` | Total count of receiver profile resolutions. |
| `satspathd_profile_resolution_duration_seconds` | Histogram | `status` | Duration of receiver profile resolution in seconds. |
| `satspathd_fee_api_requests_total` | Counter | `source`, `status` | Instrumented aggregate fee probes (`source="combined"`), not a complete per-provider request count. |
| `satspathd_fee_api_latency_seconds` | Histogram | `source`, `status` | Aggregate probe latency; do not infer individual provider latency from this series. |
| `satspathd_transparency_checkpoint_age_seconds` | Gauge | *(none)* | Age of the latest transparency log checkpoint in seconds. |
| `satspathd_rate_limit_dropped_total` | Counter | `reason` | Total requests dropped due to rate limiting (`rate_limited`) or payload cap (`payload_too_large`). |

---

## 2. Health endpoints have different contracts

| Endpoint | Current checks | HTTP status |
| --- | --- | --- |
| `GET /health` | Static liveness response `{"ok":true,"status":"healthy"}` | 200; not dependency health or quorum readiness |
| `GET /v1/health` | SQLite, fees and transparency dependency probes below | 200 for `healthy` **or `degraded`**, 503 for `unhealthy` |
| `GET /v2/health` | S2S readiness fields including checkpoint age and quorum status | Currently 503: the daemon passes quorum-not-satisfied and does not verify witness signatures or serve replicas |

Source: [router](../crates/satspathd/src/router.rs),
[dependency checks](../crates/satspathd/src/telemetry/health.rs).
Do not use `/health` to claim a ready authority or describe the three routes as aliases.

`/v1/health` evaluates:

- **`sqlite`**: Verifies that `satspath-transparency-v1.sqlite3` exists, opens cleanly, and is writable.
- **`fee_api`**: Checks freshness of the multi-source fee cache or executes a bounded `500ms` probe.
- **`transparency_log`**: Loads local transactional log state and checks checkpoint age. Older than 24 hours is degraded; an empty readable log has age zero and is not proof of a witnessed checkpoint.

Deep health responses are cached for five seconds per home/network. The daemon
also starts a background refresher every 30 seconds for checkpoint-age and fee
metrics; scraping `/metrics` itself does not perform the dependency probes.
Fee fallback can produce `degraded` while `ok` remains true. Check the JSON
dependency states, not only the HTTP status.

### Illustrative `/v1/health` response

```json
{
  "ok": true,
  "status": "healthy",
  "version": "0.1.0",
  "uptime_seconds": 3612,
  "timestamp": 1782810400,
  "dependencies": {
    "sqlite": {
      "status": "healthy",
      "latency_ms": 0.42,
      "writable": true,
      "log_id": "satspath-log-v1"
    },
    "fee_api": {
      "status": "healthy",
      "latency_ms": 0.05,
      "reachable": true,
      "cached": true,
      "fastest_sat_vb": 6
    },
    "transparency_log": {
      "status": "healthy",
      "latency_ms": 0.81,
      "checkpoint_count": 3,
      "latest_checkpoint_age_secs": 60,
      "is_stale": false
    }
  }
}
```

The example is not an observed current run; fields depend on cache/probe results.
Prometheus rules and Grafana assets in `monitoring/` are configuration examples,
not evidence of working alert delivery. Configure and test notification routing separately.

---

## 3. Structured Tracing & Request Correlation

Every incoming HTTP request is assigned a correlation ID (`X-Request-ID` header if valid ASCII `<= 128` chars, or a freshly generated UUIDv4) and echoed back in the response `X-Request-ID` header.

### Configuration Environment Variables

| Variable | Values | Default | Description |
| :--- | :--- | :--- | :--- |
| `RUST_LOG` | `info`, `debug`, `satspathd=debug` | `info` | Standard `tracing_subscriber::EnvFilter` directive. |
| `SATSPATH_LOG_FORMAT` | `text`, `pretty`, `json` | `text` | Set to `json` for structured JSON log lines in production containers (`--log-format` CLI flag). |
