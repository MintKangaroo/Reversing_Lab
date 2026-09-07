"""Health / metadata endpoints."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import text

from ... import __version__, metrics
from ...config import get_settings
from ...database.session import get_engine
from ...jobs import active_job_count

logger = logging.getLogger(__name__)
router = APIRouter(tags=["meta"])


@router.get("/health")
def health() -> dict[str, str | bool]:
    """Liveness probe: the process is up and serving."""
    return {
        "status": "ok",
        "version": __version__,
        "authentication_required": get_settings().auth_mode != "disabled",
    }


@router.get("/health/ready")
def readiness() -> JSONResponse:
    """Readiness probe: dependencies (the database) are reachable.

    Returns 200 with ``{"status": "ready"}`` when the database answers, otherwise
    503 so an orchestrator stops routing traffic here until it recovers.
    """
    try:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception:
        logger.exception("Readiness check failed: database unreachable.")
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "database": "unreachable"},
        )
    return JSONResponse(content={"status": "ready", "database": "ok"})


@router.get("/metrics")
def prometheus_metrics() -> PlainTextResponse:
    """Prometheus exposition of request counts, latency, and job gauges.

    In-process (per worker); restrict scrape access at the network layer. Returns 404
    when metrics are disabled (``RLAB_METRICS_ENABLED=false``).
    """
    settings = get_settings()
    if not settings.metrics_enabled:
        raise HTTPException(status_code=404, detail="Metrics are disabled.")
    body = metrics.render(
        active_jobs=active_job_count(),
        max_jobs=settings.max_concurrent_jobs,
    )
    return PlainTextResponse(
        content=body,
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
