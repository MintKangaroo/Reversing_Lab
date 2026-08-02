"""Authenticated principal metadata."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ..auth import Principal, get_current_principal
from ..schemas import PrincipalSchema

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.get("/me", response_model=PrincipalSchema)
def current_principal(
    principal: Principal = Depends(get_current_principal),
) -> PrincipalSchema:
    return PrincipalSchema(
        id=principal.id,
        role=principal.role,
        authentication_enabled=principal.authentication_enabled,
    )
