"""Integration availability listing."""

from __future__ import annotations

from fastapi import APIRouter

from ...integrations import list_integrations
from ..schemas import IntegrationInfoSchema

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("", response_model=list[IntegrationInfoSchema])
def list_available() -> list[IntegrationInfoSchema]:
    """Report which external RE tools (radare2/Ghidra/Binary Ninja) are available."""
    return [IntegrationInfoSchema.model_validate(i) for i in list_integrations()]
