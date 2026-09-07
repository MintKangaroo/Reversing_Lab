"""Load-test harness statistics and the read-only driver (over ASGI transport)."""

from __future__ import annotations

import asyncio

from loadtest.driver import run_load
from loadtest.harness import RequestOutcome, percentile, summarize


def test_percentile_interpolates_and_clamps() -> None:
    values = [1.0, 2.0, 3.0, 4.0]
    assert percentile([], 50) == 0.0
    assert percentile(values, 0) == 1.0
    assert percentile(values, 100) == 4.0
    assert percentile(values, 50) == 2.5  # midpoint of a 4-element list


def test_summarize_reports_throughput_error_rate_and_percentiles() -> None:
    outcomes = [
        RequestOutcome(ok=True, status=200, latency_seconds=0.010),
        RequestOutcome(ok=True, status=200, latency_seconds=0.020),
        RequestOutcome(ok=True, status=200, latency_seconds=0.030),
        RequestOutcome(ok=False, status=500, latency_seconds=0.040),
    ]
    summary = summarize(outcomes, wall_seconds=2.0)

    assert summary["requests"] == 4
    assert summary["errors"] == 1
    assert summary["error_rate"] == 0.25
    assert summary["throughput_rps"] == 2.0  # 4 requests / 2s
    latency = summary["latency_ms"]
    assert latency["max"] == 40.0
    assert latency["mean"] == 25.0
    assert latency["p50"] == 25.0


def test_summarize_handles_no_outcomes() -> None:
    summary = summarize([], wall_seconds=1.0)
    assert summary["requests"] == 0
    assert summary["error_rate"] == 0.0
    assert summary["throughput_rps"] == 0.0
    assert summary["latency_ms"]["p99"] == 0.0


def test_driver_generates_read_only_load_against_the_app(api_client) -> None:
    import httpx

    # Reuse the TestClient's ASGI app so the driver hits the real handlers, no socket.
    transport = httpx.ASGITransport(app=api_client.app)

    async def drive():
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return await run_load(
                base_url="http://testserver",
                path="/api/health",
                concurrency=4,
                duration_seconds=0.3,
                client=client,
            )

    outcomes, wall = asyncio.run(drive())
    assert outcomes, "expected the driver to collect responses"
    assert all(outcome.status == 200 for outcome in outcomes)
    summary = summarize(outcomes, wall)
    assert summary["errors"] == 0
    assert summary["throughput_rps"] > 0
