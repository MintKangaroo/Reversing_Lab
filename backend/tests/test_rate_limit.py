"""Opt-in server-side rate limiting: window logic and HTTP enforcement."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from reversing_lab.api.rate_limit import FixedWindowRateLimiter, get_rate_limiter


def test_fixed_window_allows_then_blocks(monkeypatch) -> None:
    clock = {"now": 1000.0}
    monkeypatch.setattr(
        "reversing_lab.api.rate_limit.time.monotonic", lambda: clock["now"]
    )
    limiter = FixedWindowRateLimiter()
    assert limiter.check("k", limit=2, window_seconds=60) is None
    assert limiter.check("k", limit=2, window_seconds=60) is None
    retry = limiter.check("k", limit=2, window_seconds=60)
    assert retry is not None and 0 < retry <= 60
    # A different key has its own budget.
    assert limiter.check("other", limit=2, window_seconds=60) is None
    # After the window elapses the budget resets.
    clock["now"] += 61
    assert limiter.check("k", limit=2, window_seconds=60) is None


@pytest.fixture()
def rate_limited_client(tmp_path: Path, monkeypatch) -> Iterator[object]:
    monkeypatch.setenv("RLAB_DATABASE_URL", f"sqlite:///{tmp_path / 'rl.db'}")
    monkeypatch.setenv("RLAB_STORAGE_DIR", str(tmp_path / "storage"))
    monkeypatch.setenv("RLAB_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RLAB_RATE_LIMIT_REQUESTS", "3")
    monkeypatch.setenv("RLAB_RATE_LIMIT_WINDOW_SECONDS", "60")

    from reversing_lab import config
    from reversing_lab.api import services
    from reversing_lab.database import session as db_session

    config.get_settings.cache_clear()
    db_session._engine = None
    db_session._SessionFactory = None
    services.clear_cache()
    get_rate_limiter().reset()

    from fastapi.testclient import TestClient
    from reversing_lab.api.app import create_app

    with TestClient(create_app()) as client:
        yield client

    config.get_settings.cache_clear()
    db_session._engine = None
    db_session._SessionFactory = None
    get_rate_limiter().reset()


def test_requests_are_limited_after_the_window_budget(rate_limited_client) -> None:
    # The health probe is exempt, so it never contributes to or trips the limit.
    for _ in range(10):
        assert rate_limited_client.get("/api/health").status_code == 200

    # A limited endpoint: 3 allowed, the 4th is 429 with a Retry-After header.
    codes = [rate_limited_client.get("/api/tooling").status_code for _ in range(4)]
    assert codes[:3] == [200, 200, 200]
    assert codes[3] == 429
    blocked = rate_limited_client.get("/api/tooling")
    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) >= 1


def test_rate_limiting_is_off_by_default(api_client) -> None:
    # The default api_client fixture does not enable limiting; many requests pass.
    for _ in range(20):
        assert api_client.get("/api/tooling").status_code == 200
