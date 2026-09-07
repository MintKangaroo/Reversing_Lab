"""Health / metadata endpoints."""

from __future__ import annotations

import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from ... import __version__
from ...config import get_settings
from ...database.session import get_engine

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
