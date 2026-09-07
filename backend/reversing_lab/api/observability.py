"""Request correlation and structured access logging.

The outermost HTTP middleware. It assigns each request a correlation id — reusing a
safe inbound ``X-Request-ID`` or minting one — exposes it on ``request.state`` and the
response header, and emits one access-log line with the request's timing and outcome.
The id is also placed in a context variable so every application log line for the
request carries it (see :mod:`reversing_lab.logging_config`).
"""

from __future__ import annotations

import logging
import re
import time
from uuid import uuid4

from fastapi import Request

from ..config import get_settings
from ..logging_config import request_id_var

logger = logging.getLogger(__name__)
access_logger = logging.getLogger("reversing_lab.access")

# Bound and sanitize any inbound id so it cannot inject into logs or grow unbounded.
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")


def _incoming_request_id(request: Request) -> str:
    candidate = request.headers.get("x-request-id")
    if candidate and _SAFE_REQUEST_ID.match(candidate):
        return candidate
    return uuid4().hex


def _route_template(request: Request) -> str:
    """The matched route template, normalized to the ``/api`` prefix like audit rows.

    Templated (``/binaries/{sha256}``) rather than the concrete path, so access logs
    aggregate by endpoint instead of exploding on per-request ids.
    """
    route = request.scope.get("route")
    template = getattr(route, "path", None)
    if not isinstance(template, str):
        return "unmatched"
    return template if template.startswith("/api/") else f"/api{template}"


async def correlation_middleware(request: Request, call_next):
    """Correlate the request, time it, and emit one access-log line."""
    request_id = _incoming_request_id(request)
    request.state.request_id = request_id
    token = request_id_var.set(request_id)
    start = time.perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        response.headers["X-Request-ID"] = request_id
        return response
    finally:
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        if get_settings().access_log:
            principal = getattr(request.state, "principal", None)
            access_logger.info(
                "%s %s -> %s (%sms)",
                request.method,
                _route_template(request),
                status_code,
                duration_ms,
                extra={
                    "method": request.method,
                    "route": _route_template(request),
                    "status_code": status_code,
                    "duration_ms": duration_ms,
                    "principal": getattr(principal, "id", "anonymous"),
                },
            )
        request_id_var.reset(token)
