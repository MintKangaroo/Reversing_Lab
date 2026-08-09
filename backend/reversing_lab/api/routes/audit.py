"""Principal-scoped, read-only audit event API."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from ...audit import stream_hash_chained_jsonl
from ...config import get_settings
from ...database import AuditRepository
from ...database.session import get_session_factory
from ..auth import Principal, get_current_principal, resource_scope
from ..dependencies import get_audit_repository
from ..schemas import AuditEventPageSchema, AuditEventSchema

router = APIRouter(prefix="/audit-events", tags=["audit"])


def _utc_filter(value: datetime | None, name: str) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise HTTPException(
            status_code=422,
            detail=f"{name} must include a UTC offset, for example 2026-08-09T00:00:00Z.",
        )
    return value.astimezone(timezone.utc)


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


@router.get("/export")
def export_audit_events(
    action: str | None = Query(default=None, max_length=192),
    resource_type: str | None = Query(default=None, max_length=64),
    outcome: str | None = Query(
        default=None, pattern="^(succeeded|denied|failed)$"
    ),
    created_after: datetime | None = Query(default=None),
    created_before: datetime | None = Query(default=None),
    repository: AuditRepository = Depends(get_audit_repository),
    principal: Principal = Depends(get_current_principal),
) -> StreamingResponse:
    """Stream a bounded JSONL export suitable for external archive ingestion."""
    after = _utc_filter(created_after, "created_after")
    before = _utc_filter(created_before, "created_before")
    if after is not None and before is not None and after >= before:
        raise HTTPException(
            status_code=422,
            detail="created_after must be earlier than created_before.",
        )
    export_arguments = {
        "action": action,
        "resource_type": resource_type,
        "outcome": outcome,
        "created_after": after,
        "created_before": before,
    }
    total = repository.export_count(**export_arguments)
    maximum = get_settings().max_audit_export_records
    if total > maximum:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Audit export contains {total} events, above the configured limit "
                f"of {maximum}; narrow the UTC time range or filters."
            ),
        )

    generated_at = datetime.now(timezone.utc)
    owner_id, unrestricted = resource_scope(principal)
    export_filters = {
        key: (
            value.isoformat().replace("+00:00", "Z")
            if isinstance(value, datetime)
            else value
        )
        for key, value in export_arguments.items()
        if value is not None
    }

    def stream():
        # A dedicated session must outlive response creation on every supported
        # FastAPI version; request-scoped dependency cleanup timing has changed.
        session = get_session_factory()()
        try:
            records = AuditRepository(session, owner_id, unrestricted).iter_export(
                limit=total,
                **export_arguments,
            )
            yield from stream_hash_chained_jsonl(
                records,
                generated_at=generated_at,
                scope="all-principals" if unrestricted else f"principal:{owner_id}",
                filters=export_filters,
            )
        finally:
            session.close()

    timestamp = generated_at.strftime("%Y%m%dT%H%M%SZ")
    return StreamingResponse(
        stream(),
        media_type="application/x-ndjson; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="audit-{timestamp}.jsonl"',
            "X-Audit-Export-Records": str(total),
            "X-Content-Type-Options": "nosniff",
        },
    )
