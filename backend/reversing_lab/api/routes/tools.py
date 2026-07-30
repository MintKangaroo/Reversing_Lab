"""Data-only analyst tools; request inputs are never persisted."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ...analyzer import transform_data
from ..schemas import TransformRequestSchema, TransformResultSchema

router = APIRouter(prefix="/tools", tags=["analyst-tools"])


@router.post("/decode", response_model=TransformResultSchema)
def decode_data(payload: TransformRequestSchema) -> TransformResultSchema:
    try:
        result = transform_data(payload.operation, payload.input, payload.parameters)
    except (ValueError, OverflowError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return TransformResultSchema.model_validate(result)
