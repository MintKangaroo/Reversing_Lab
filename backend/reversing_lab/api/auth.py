"""Digest-backed bearer authentication and coarse HTTP role enforcement."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..config import get_settings

_bearer = HTTPBearer(auto_error=False, scheme_name="ReversingLabApiKey")
_PUBLIC_PATHS = {"/api/health"}
_READ_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass(frozen=True, slots=True)
class Principal:
    id: str
    role: str
    authentication_enabled: bool


def _match_principal(raw_key: str) -> Principal | None:
    candidate = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    matched: Principal | None = None
    for expected, descriptor in get_settings().auth_api_key_hashes.items():
        if hmac.compare_digest(candidate, expected):
            principal_id, role = descriptor.rsplit(":", 1)
            matched = Principal(principal_id, role, True)
    return matched


async def authorize_request(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> Principal:
    """Authenticate globally and prevent viewer-role mutations."""
    settings = get_settings()
    if settings.auth_mode == "disabled":
        principal = Principal("local", "admin", False)
        request.state.principal = principal
        return principal
    if request.url.path in _PUBLIC_PATHS:
        principal = Principal("public", "viewer", True)
        request.state.principal = principal
        return principal
    if (
        credentials is None
        or credentials.scheme.lower() != "bearer"
        or len(credentials.credentials) > 4096
    ):
        raise HTTPException(
            status_code=401,
            detail="A valid bearer API key is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    principal = _match_principal(credentials.credentials)
    if principal is None:
        raise HTTPException(
            status_code=401,
            detail="Bearer API key is invalid.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if principal.role == "viewer" and request.method not in _READ_METHODS:
        raise HTTPException(
            status_code=403,
            detail="The viewer role cannot modify analysis state.",
        )
    request.state.principal = principal
    return principal


def get_current_principal(request: Request) -> Principal:
    principal = getattr(request.state, "principal", None)
    if not isinstance(principal, Principal):
        raise HTTPException(status_code=500, detail="Authentication context is missing.")
    return principal
