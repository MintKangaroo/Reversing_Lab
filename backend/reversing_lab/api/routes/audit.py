"""Principal-scoped, read-only audit event API."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query

from ...database import AuditRepository
from ..dependencies import get_audit_repository
from ..schemas import AuditEventPageSchema, AuditEventSchema

router = APIRouter(prefix="/audit-events", tags=["audit"])


@router.get("", response_model=AuditEventPageSchema)
def list_audit_events(
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    action: str | None = Query(default=None, max_length=192),
    resource_type: str | None = Query(default=None, max_length=64),
    outcome: str | None = Query(
        default=None, pattern="^(succeeded|denied|failed)$"
    ),
    repository: AuditRepository = Depends(get_audit_repository),
) -> AuditEventPageSchema:
    records, total = repository.list(
        offset=offset,
        limit=limit,
        action=action,
        resource_type=resource_type,
        outcome=outcome,
    )
    return AuditEventPageSchema(
        items=[
            AuditEventSchema(
                id=record.id,
                request_id=record.request_id,
                principal_id=record.principal_id,
                role=record.role,
                action=record.action,
                resource_type=record.resource_type,
                resource_id=record.resource_id,
                method=record.method,
                route=record.route,
                status_code=record.status_code,
                outcome=record.outcome,
                details=json.loads(record.details_json),
                created_at=record.created_at,
            )
            for record in records
        ],
        total=total,
        offset=offset,
        limit=limit,
    )
