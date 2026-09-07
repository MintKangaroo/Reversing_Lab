# Observability

How the API reports on itself: request correlation, structured logs, health probes,
and Prometheus metrics, plus a read-only load-testing harness for sizing.

## Request correlation

Every request is assigned a correlation id by the outermost middleware
([`api/observability.py`](../backend/reversing_lab/api/observability.py)):

- an inbound `X-Request-ID` header is reused when it is safe (`[A-Za-z0-9._~-]`, 1–128
  chars), so a proxy or upstream service can thread its own trace id through;
- otherwise the server mints one.

The id appears in three correlated places for the same request:

1. the `X-Request-ID` **response header** (on every response, not just mutations);
2. every **application log line** emitted while handling the request;
3. the **audit event** row for a mutation (`request_id`), see
   [AUDIT_LOGGING.md](AUDIT_LOGGING.md).

Given one id from any of those, the other two can be found.

## Logs

`configure_logging` installs a single stderr handler on the root logger. Two knobs:

| Setting | Default | Effect |
| --- | --- | --- |
| `RLAB_LOG_LEVEL` | `INFO` | Root log level. |
| `RLAB_LOG_FORMAT` | `text` | `text` for humans, `json` for log shippers. |
| `RLAB_ACCESS_LOG` | `true` | Emit one access line per request. |

Text format:

```
2026-09-07 05:40:00,123 | INFO     | 9f2c… | reversing_lab.access | POST /api/binaries -> 201 (12.4ms)
```

JSON format (one object per line; the correlation id is always `request_id`):

```json
{"timestamp":"2026-09-07T05:40:00+0000","level":"INFO","logger":"reversing_lab.access",
 "request_id":"9f2c...","message":"POST /api/binaries -> 201 (12.4ms)",
 "method":"POST","route":"/api/binaries","status_code":201,"duration_ms":12.4,
 "principal":"local"}
```

### Access log

The `reversing_lab.access` logger emits one line per request with `method`, the
**templated** `route` (`/api/binaries/{sha256}`, not the concrete path, so lines
aggregate per endpoint instead of exploding on ids), `status_code`, `duration_ms`, and
`principal`. Set `RLAB_ACCESS_LOG=false` to suppress it (for example if a reverse proxy
already produces access logs).

Logs may contain identifiers and state but never raw sample contents, decoder input, or
authorization headers (see [SECURITY.md](SECURITY.md)).

## Health probes

Two endpoints, for the two questions an orchestrator asks:

| Endpoint | Question | Behavior |
| --- | --- | --- |
| `GET /api/health` | Is the process alive? | Always `200` while serving; returns version and whether auth is required. |
| `GET /api/health/ready` | Can it serve traffic? | `200 {"status":"ready"}` when the database answers `SELECT 1`; `503 {"status":"not_ready"}` otherwise. |

Wire **liveness** to `/api/health` (restart the container if it fails) and **readiness**
to `/api/health/ready` (stop routing traffic here until dependencies recover). A
Kubernetes example:

```yaml
livenessProbe:
  httpGet: { path: /api/health, port: 8000 }
readinessProbe:
  httpGet: { path: /api/health/ready, port: 8000 }
```

`/api/health/ready` opens a short-lived connection on each call; it is cheap but not
free, so keep the probe period at the orchestrator default (10s+) rather than sub-second.

## Metrics

`GET /api/metrics` renders Prometheus text exposition (version 0.0.4), recorded by the
same middleware that emits the access log. Toggle with `RLAB_METRICS_ENABLED` (default
`true`); when disabled the endpoint returns `404` and nothing is recorded.

| Series | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `rlab_http_requests_total` | counter | `method`, `route`, `status` | Requests handled. |
| `rlab_http_request_duration_seconds` | histogram | `method`, `route` | Latency (default Prometheus buckets), with `_bucket`/`_sum`/`_count`. |
| `rlab_active_jobs` | gauge | — | In-process analysis jobs queued or running. |
| `rlab_max_concurrent_jobs` | gauge | — | Configured job concurrency limit. |

`route` is the **templated** path, so cardinality stays bounded. The registry is
**in-process** — like the rate limiter, it is a real single-worker guardrail, not a
shared store: scrape each worker separately, or aggregate at the proxy. Metrics carry no
sample content or identifiers, but they do reveal traffic shape, so keep the scrape
endpoint on a trusted network (it is unauthenticated, like the health probes).

A minimal scrape config:

```yaml
scrape_configs:
  - job_name: reversing-lab
    metrics_path: /api/metrics
    static_configs:
      - targets: ["reversing-lab.internal:8000"]
```

## Load testing

A bounded, **read-only** harness lives in [`backend/loadtest/`](../backend/loadtest).
It issues only GET requests to a single path at a fixed concurrency for a fixed
duration, then reports throughput, error rate, and latency percentiles. It is a sizing
tool, not a stress/DoS tool: point it only at a deployment you operate.

```bash
cd backend
python -m loadtest --url http://127.0.0.1:8000 --path /api/health \
    --concurrency 16 --duration 30
```

```
requests      : 2256
errors        : 0 (0.0)
wall seconds  : 8.033
throughput    : 280.85 req/s
latency (ms)  : p50=32.43 p90=128.33 p99=267.27 max=509.39 mean=55.79
```

The numbers above are one measured run — a single `uvicorn` worker on SQLite over
loopback, 16 concurrent clients against `/api/health` for 8s. Absolute throughput is
hardware- and configuration-dependent; treat this as a **method and a shape** (near-zero
errors, a bounded p99), not a guarantee. Re-measure on your own host to get a baseline.

### Reading the result against the deployment

- The harness's latency percentiles should track
  `rlab_http_request_duration_seconds` for the same route — cross-check the two.
- Watch `rlab_active_jobs` against `rlab_max_concurrent_jobs` while load runs: sustained
  saturation is the signal to raise `RLAB_MAX_CONCURRENT_JOBS` or add workers.
- A single `uvicorn` worker is one process; the metrics registry and rate limiter are
  per-worker (see above), so scale with `--workers` and re-measure, aggregating metrics
  across workers at the scrape layer.
- To exercise the rate limiter, enable it (`RLAB_RATE_LIMIT_ENABLED`) and confirm the
  harness starts reporting the throttled responses in its error count.
