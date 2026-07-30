"""Background job status, cancellation, and SSE progress."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from ...database import JobRepository
from ...database.session import get_session_factory
from ...jobs import cancel_job
from ..dependencies import get_job_repository
from ..schemas import JobSchema

router = APIRouter(prefix="/jobs", tags=["jobs"])
_TERMINAL = {"completed", "failed", "cancelled"}


@router.get("", response_model=list[JobSchema])
def list_jobs(
    limit: int = Query(100, ge=1, le=500),
    repository: JobRepository = Depends(get_job_repository),
) -> list[JobSchema]:
    return [JobSchema.model_validate(record) for record in repository.list(limit)]


@router.get("/{job_id}", response_model=JobSchema)
def get_job(
    job_id: str,
    repository: JobRepository = Depends(get_job_repository),
) -> JobSchema:
    return JobSchema.model_validate(repository.get(job_id))


@router.post("/{job_id}/cancel", response_model=JobSchema)
def request_job_cancel(
    job_id: str,
    repository: JobRepository = Depends(get_job_repository),
) -> JobSchema:
    repository.get(job_id)
    cancel_job(job_id)
    return JobSchema.model_validate(repository.get(job_id))


@router.get("/{job_id}/stream")
def stream_job(job_id: str) -> StreamingResponse:
    async def events():
        last = None
        while True:
            session = get_session_factory()()
            try:
                record = JobRepository(session).get(job_id)
                payload = JobSchema.model_validate(record).model_dump(mode="json")
            finally:
                session.close()
            serialized = json.dumps(payload, separators=(",", ":"))
            if serialized != last:
                yield f"event: progress\ndata: {serialized}\n\n"
                last = serialized
            if payload["state"] in _TERMINAL:
                break
            await asyncio.sleep(0.35)

    return StreamingResponse(events(), media_type="text/event-stream")
