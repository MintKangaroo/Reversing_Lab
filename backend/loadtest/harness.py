"""Dependency-free statistics for the load-test harness.

Kept separate from the httpx-backed driver so the numbers are trivially testable and
carry no import cost.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RequestOutcome:
    """One completed request: whether it succeeded and how long it took."""

    ok: bool
    status: int
    latency_seconds: float


def percentile(sorted_values: list[float], q: float) -> float:
    """Linear-interpolated percentile of an ascending list. ``q`` is in [0, 100]."""
    if not sorted_values:
        return 0.0
    if q <= 0:
        return sorted_values[0]
    if q >= 100:
        return sorted_values[-1]
    rank = (q / 100) * (len(sorted_values) - 1)
    low = int(rank)
    high = min(low + 1, len(sorted_values) - 1)
    fraction = rank - low
    return sorted_values[low] + (sorted_values[high] - sorted_values[low]) * fraction


def summarize(outcomes: list[RequestOutcome], wall_seconds: float) -> dict[str, object]:
    """Aggregate outcomes into throughput, error rate, and latency percentiles (ms)."""
    total = len(outcomes)
    errors = sum(1 for outcome in outcomes if not outcome.ok)
    latencies = sorted(outcome.latency_seconds for outcome in outcomes)

    def ms(value: float) -> float:
        return round(value * 1000, 2)

    latency_ms = {
        "p50": ms(percentile(latencies, 50)),
        "p90": ms(percentile(latencies, 90)),
        "p99": ms(percentile(latencies, 99)),
        "max": ms(latencies[-1]) if latencies else 0.0,
        "mean": ms(sum(latencies) / total) if total else 0.0,
    }
    throughput = round(total / wall_seconds, 2) if wall_seconds > 0 else 0.0

    return {
        "requests": total,
        "errors": errors,
        "error_rate": round(errors / total, 4) if total else 0.0,
        "wall_seconds": round(wall_seconds, 3),
        "throughput_rps": throughput,
        "latency_ms": latency_ms,
    }


def format_summary(summary: dict[str, object]) -> str:
    """Render a summary dict as a short human-readable block."""
    latency = summary["latency_ms"]
    assert isinstance(latency, dict)
    return (
        f"requests      : {summary['requests']}\n"
        f"errors        : {summary['errors']} ({summary['error_rate']})\n"
        f"wall seconds  : {summary['wall_seconds']}\n"
        f"throughput    : {summary['throughput_rps']} req/s\n"
        f"latency (ms)  : p50={latency['p50']} p90={latency['p90']} "
        f"p99={latency['p99']} max={latency['max']} mean={latency['mean']}"
    )
