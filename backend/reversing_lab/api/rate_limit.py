"""Opt-in server-side rate limiting.

A per-principal fixed-window counter enforced as a global dependency, so it runs
after :func:`authorize_request` has resolved ``request.state.principal``. Keys on the
authenticated principal id, falling back to the client host for unauthenticated or
public requests.

Scope: the counter lives in process memory. It is correct for a single worker and is a
meaningful guardrail for a single-process deployment; a multi-worker or multi-host
deployment needs a shared store (e.g. Redis) to enforce a global limit. This is called
out in SECURITY.md rather than pretending the in-process limiter is distributed.
"""

from __future__ import annotations

import threading
import time

from fastapi import HTTPException, Request

from ..config import get_settings
from .auth import Principal

# Never rate-limit the unauthenticated liveness probe.
_EXEMPT_PATHS = {"/api/health"}


class FixedWindowRateLimiter:
    """Thread-safe per-key fixed-window request counter."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # key -> (window_start_monotonic, count)
        self._windows: dict[str, tuple[float, int]] = {}

    def check(self, key: str, *, limit: int, window_seconds: float) -> float | None:
        """Register a hit for ``key``. Return ``None`` if allowed, else the number of
        seconds until the window resets (``Retry-After``)."""
        now = time.monotonic()
        with self._lock:
            start, count = self._windows.get(key, (now, 0))
            if now - start >= window_seconds:
                start, count = now, 0
            if count >= limit:
                self._windows[key] = (start, count)
                return max(0.0, window_seconds - (now - start))
            self._windows[key] = (start, count + 1)
            return None

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()


_limiter = FixedWindowRateLimiter()


def get_rate_limiter() -> FixedWindowRateLimiter:
    return _limiter


def _principal_key(request: Request) -> str:
    principal = getattr(request.state, "principal", None)
    if isinstance(principal, Principal) and principal.authentication_enabled:
        return f"principal:{principal.id}"
    client = request.client
    return f"host:{client.host}" if client else "host:unknown"


def enforce_rate_limit(request: Request) -> None:
    """Global dependency: reject a request that exceeds the configured window."""
    settings = get_settings()
    if not settings.rate_limit_enabled or request.url.path in _EXEMPT_PATHS:
        return
    retry_after = _limiter.check(
        _principal_key(request),
        limit=settings.rate_limit_requests,
        window_seconds=settings.rate_limit_window_seconds,
    )
    if retry_after is not None:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded; slow down and retry.",
            headers={"Retry-After": str(int(retry_after) + 1)},
        )
