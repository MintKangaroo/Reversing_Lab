"""Async request driver for the load-test harness.

Read-only by construction: it issues GET requests to a single path with a fixed
concurrency for a bounded duration, then hands the outcomes to :mod:`.harness`.
httpx is imported lazily so importing this module (and the package) stays cheap.
"""

from __future__ import annotations

import asyncio
import time

from .harness import RequestOutcome


async def _worker(
    client, url: str, deadline: float, outcomes: list[RequestOutcome]
) -> None:
    while time.monotonic() < deadline:
        started = time.perf_counter()
        try:
            response = await client.get(url)
            latency = time.perf_counter() - started
            outcomes.append(
                RequestOutcome(
                    ok=response.status_code < 500,
                    status=response.status_code,
                    latency_seconds=latency,
                )
            )
        except Exception:
            latency = time.perf_counter() - started
            outcomes.append(RequestOutcome(ok=False, status=0, latency_seconds=latency))


async def run_load(
    base_url: str,
    path: str,
    concurrency: int,
    duration_seconds: float,
    timeout_seconds: float = 10.0,
    client=None,
) -> tuple[list[RequestOutcome], float]:
    """Drive ``concurrency`` GET loops against ``base_url + path`` for the duration.

    Returns the collected outcomes and the actual wall-clock seconds elapsed. Pass an
    existing httpx client (e.g. an ASGI-transport one) to drive without a socket; its
    lifecycle is then the caller's responsibility.
    """
    url = path if path.startswith("http") else base_url.rstrip("/") + path
    outcomes: list[RequestOutcome] = []
    started = time.monotonic()
    deadline = started + duration_seconds

    async def drive(active_client) -> None:
        await asyncio.gather(
            *(_worker(active_client, url, deadline, outcomes) for _ in range(concurrency))
        )

    if client is not None:
        await drive(client)
    else:
        import httpx  # lazy: only needed when actually opening a network client

        async with httpx.AsyncClient(timeout=timeout_seconds) as owned:
            await drive(owned)
    return outcomes, time.monotonic() - started
