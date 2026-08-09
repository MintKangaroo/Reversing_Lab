"""Dry-run-first retention and principal-owned data purge API."""

from __future__ import annotations

import hmac

from fastapi import APIRouter, Depends, HTTPException, Query

from ...database import RetentionRepository
from ..auth import Principal, get_current_principal, resource_scope
from ..dependencies import get_retention_repository
from ..schemas import (
    RetentionPreviewSchema,
    RetentionPurgeRequestSchema,
    RetentionPurgeResultSchema,
)

router = APIRouter(prefix="/retention", tags=["retention"])


@router.get("/preview", response_model=RetentionPreviewSchema)
def preview_owned_data_purge(
    include_binary_access: bool = Query(default=False),
    repository: RetentionRepository = Depends(get_retention_repository),
) -> RetentionPreviewSchema:
    return RetentionPreviewSchema.model_validate(
        repository.preview(include_binary_access)
    )


@router.post("/purge", response_model=RetentionPurgeResultSchema)
def purge_owned_data(
    payload: RetentionPurgeRequestSchema,
    repository: RetentionRepository = Depends(get_retention_repository),
    principal: Principal = Depends(get_current_principal),
) -> RetentionPurgeResultSchema:
    owner_id, _ = resource_scope(principal)
    expected = f"PURGE:{owner_id}"
    if not hmac.compare_digest(
        payload.confirmation.encode("utf-8"), expected.encode("utf-8")
    ):
        raise HTTPException(
            status_code=422,
            detail="Retention confirmation does not match the current principal.",
        )
    return RetentionPurgeResultSchema.model_validate(
        repository.purge(payload.include_binary_access)
    )
