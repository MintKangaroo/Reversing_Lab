"""Translate domain exceptions into HTTP responses in one place."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ..errors import (
    BinaryNotFoundError,
    ChallengeError,
    DisassemblyError,
    IntegrationUnavailableError,
    ParseError,
    ReversingLabError,
    UnsupportedFormatError,
)

logger = logging.getLogger(__name__)

# Domain exception -> HTTP status code.
_STATUS_MAP: list[tuple[type[ReversingLabError], int]] = [
    (UnsupportedFormatError, 415),  # Unsupported Media Type
    (BinaryNotFoundError, 404),
    (ChallengeError, 404),
    (IntegrationUnavailableError, 503),  # Service Unavailable
    (ParseError, 422),  # Unprocessable Entity
    (DisassemblyError, 422),
]


def _status_for(exc: ReversingLabError) -> int:
    for exc_type, status in _STATUS_MAP:
        if isinstance(exc, exc_type):
            return status
    return 400


def register_exception_handlers(app: FastAPI) -> None:
    """Attach a single handler that maps every domain error to a JSON response."""

    @app.exception_handler(ReversingLabError)
    async def _handle_domain_error(_: Request, exc: ReversingLabError) -> JSONResponse:
        status = _status_for(exc)
        if status >= 500:
            # 5xx from a mapped domain error is an expected condition (e.g. an optional
            # tool is absent), not a crash — log it without a stack trace.
            logger.warning("Domain error surfaced as %d: %s", status, exc)
        else:
            logger.info("Domain error surfaced as %d: %s", status, exc)
        return JSONResponse(
            status_code=status,
            content={"error": exc.__class__.__name__, "detail": str(exc)},
        )
