"""Body-free append-only audit capture for mutation requests."""

from __future__ import annotations

import logging
from uuid import uuid4

from fastapi import Request

from ..database import AuditRepository
from ..database.session import get_session_factory
from .auth import Principal

logger = logging.getLogger(__name__)
_MUTATION_METHODS = {"POST", "PATCH", "PUT", "DELETE"}
_RESOURCE_KEYS = (
    "sha256",
    "project_id",
    "dump_id",
    "run_id",
    "job_id",
    "workspace_id",
    "slug",
)


def _route_template(request: Request) -> str:
    route = request.scope.get("route")
    template = getattr(route, "path", None)
    if not isinstance(template, str):
        return "unmatched"
    return template if template.startswith("/api/") else f"/api{template}"


def _resource_type(route: str) -> str:
    parts = [part for part in route.split("/") if part]
    if len(parts) >= 2 and parts[0] == "api":
        return parts[1][:64]
    return "unknown"


def _resource_id(request: Request) -> str | None:
    for key in _RESOURCE_KEYS:
        value = request.path_params.get(key)
        if isinstance(value, str) and value:
            return value[:128]
    return None


def _persist_event(
    request: Request,
    *,
    request_id: str,
    status_code: int,
) -> None:
    principal = getattr(request.state, "principal", None)
    if not isinstance(principal, Principal):
        principal = Principal("anonymous", "none", True)
    route = _route_template(request)
    outcome = (
        "succeeded"
        if status_code < 400
        else "denied"
        if status_code in {401, 403}
        else "failed"
    )
    session = get_session_factory()()
    try:
        AuditRepository(session).record(
            request_id=request_id,
            principal_id=principal.id,
            role=principal.role,
            action=f"{request.method} {route}",
            resource_type=_resource_type(route),
            resource_id=_resource_id(request),
            method=request.method,
            route=route,
            status_code=status_code,
            outcome=outcome,
        )
    except Exception:
        session.rollback()
        logger.exception("Failed to persist audit event %s", request_id)
    finally:
        session.close()


async def audit_mutations(request: Request, call_next):
    """Attach a server request ID and persist mutation metadata after handling."""
    request_id = str(uuid4())
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        response.headers["X-Request-ID"] = request_id
        return response
    finally:
        if request.method in _MUTATION_METHODS:
            _persist_event(request, request_id=request_id, status_code=status_code)
