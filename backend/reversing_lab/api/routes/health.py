"""Health / metadata endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from ... import __version__
from ...config import get_settings

router = APIRouter(tags=["meta"])


@router.get("/health")
def health() -> dict[str, str | bool]:
    """Liveness probe."""
    return {
        "status": "ok",
        "version": __version__,
        "authentication_required": get_settings().auth_mode != "disabled",
    }
