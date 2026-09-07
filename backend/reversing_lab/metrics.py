"""In-process metrics registry rendered in Prometheus text exposition format.

Hand-rolled to avoid a client dependency, mirroring the in-process rate limiter: it
is a real single-process guardrail, not a distributed store. A multi-worker deployment
scrapes each worker separately (or aggregates at the proxy). Cardinality stays bounded
because requests are labelled by the *templated* route, not the concrete path.
"""

from __future__ import annotations

import threading
from collections import defaultdict

# Prometheus default latency buckets (seconds), ascending; "+Inf" is implicit.
_BUCKETS: tuple[float, ...] = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
)

_lock = threading.Lock()
_request_counts: dict[tuple[str, str, int], int] = defaultdict(int)
_bucket_counts: dict[tuple[str, str], list[int]] = {}
_latency_sum: dict[tuple[str, str], float] = defaultdict(float)
_latency_count: dict[tuple[str, str], int] = defaultdict(int)


def record_request(method: str, route: str, status: int, duration_seconds: float) -> None:
    """Record one completed request into the counter and latency histogram."""
    key = (method, route)
    with _lock:
        _request_counts[(method, route, status)] += 1
        buckets = _bucket_counts.get(key)
        if buckets is None:
            buckets = [0] * (len(_BUCKETS) + 1)
            _bucket_counts[key] = buckets
        index = len(_BUCKETS)
        for position, edge in enumerate(_BUCKETS):
            if duration_seconds <= edge:
                index = position
                break
        buckets[index] += 1
        _latency_sum[key] += duration_seconds
        _latency_count[key] += 1


def reset() -> None:
    """Clear all recorded metrics (used by tests)."""
    with _lock:
        _request_counts.clear()
        _bucket_counts.clear()
        _latency_sum.clear()
        _latency_count.clear()


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _labels(**pairs: str) -> str:
    body = ",".join(f'{key}="{_escape(value)}"' for key, value in pairs.items())
    return "{" + body + "}"


def render(active_jobs: int, max_jobs: int) -> str:
    """Render the current registry as Prometheus text (version 0.0.4)."""
    with _lock:
        request_counts = dict(_request_counts)
        bucket_counts = {key: list(value) for key, value in _bucket_counts.items()}
        latency_sum = dict(_latency_sum)
        latency_count = dict(_latency_count)

    lines: list[str] = []

    lines.append("# HELP rlab_http_requests_total Total HTTP requests handled.")
    lines.append("# TYPE rlab_http_requests_total counter")
    for (method, route, status), count in sorted(request_counts.items()):
        labels = _labels(method=method, route=route, status=str(status))
        lines.append(f"rlab_http_requests_total{labels} {count}")

    lines.append(
        "# HELP rlab_http_request_duration_seconds HTTP request latency in seconds."
    )
    lines.append("# TYPE rlab_http_request_duration_seconds histogram")
    for key in sorted(bucket_counts):
        method, route = key
        cumulative = 0
        for position, edge in enumerate(_BUCKETS):
            cumulative += bucket_counts[key][position]
            labels = _labels(method=method, route=route, le=str(edge))
            lines.append(f"rlab_http_request_duration_seconds_bucket{labels} {cumulative}")
        cumulative += bucket_counts[key][len(_BUCKETS)]
        inf_labels = _labels(method=method, route=route, le="+Inf")
        lines.append(f"rlab_http_request_duration_seconds_bucket{inf_labels} {cumulative}")
        pair = _labels(method=method, route=route)
        lines.append(
            f"rlab_http_request_duration_seconds_sum{pair} {latency_sum.get(key, 0.0)}"
        )
        lines.append(
            f"rlab_http_request_duration_seconds_count{pair} {latency_count.get(key, 0)}"
        )

    lines.append(
        "# HELP rlab_active_jobs In-process analysis jobs queued or running."
    )
    lines.append("# TYPE rlab_active_jobs gauge")
    lines.append(f"rlab_active_jobs {active_jobs}")
    lines.append(
        "# HELP rlab_max_concurrent_jobs Configured in-process job concurrency limit."
    )
    lines.append("# TYPE rlab_max_concurrent_jobs gauge")
    lines.append(f"rlab_max_concurrent_jobs {max_jobs}")

    return "\n".join(lines) + "\n"
