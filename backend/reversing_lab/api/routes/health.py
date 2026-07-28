"""Health / metadata endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from ... import __version__

router = APIRouter(tags=["meta"])


@router.get("/health")
def health() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok", "version": __version__}
