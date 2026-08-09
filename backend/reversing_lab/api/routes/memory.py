"""Memory dump upload, background analysis, and paginated result views."""

from __future__ import annotations

import gzip
import json
from dataclasses import asdict
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile

from ...config import get_settings
from ...database import JobRepository, MemoryDumpRepository
from ...database.session import get_session_factory
from ...jobs import submit_job
from ...memory import analyze_memory, detect_dump_format
from ..dependencies import get_job_repository, get_memory_dump_repository
from ..schemas import (
    JobSchema,
    MemoryAnalysisRequestSchema,
    MemoryAnalysisSummarySchema,
    MemoryDumpSchema,
    MemoryFindingSchema,
    MemoryModulePageSchema,
    MemoryModuleSchema,
    MemoryProcessPageSchema,
    MemoryProcessSchema,
    MemoryRegionPageSchema,
    MemoryRegionSchema,
)
from ..uploads import read_upload_limited, safe_display_filename

router = APIRouter(prefix="/memory-dumps", tags=["memory-analysis"])


def _dump_schema(record) -> MemoryDumpSchema:
    return MemoryDumpSchema(
        id=record.id,
        sha256=record.sha256,
        filename=record.filename,
        size=record.size,
        dump_format=record.dump_format,
        analysis_provider=record.analysis_provider,
        analysis_available=record.analysis_path is not None,
        created_at=record.created_at,
    )


def _result(record) -> dict:
    if not record.analysis_path:
        raise HTTPException(status_code=409, detail="Memory analysis has not completed.")
    path = Path(record.analysis_path)
    if not path.is_file():
        raise HTTPException(status_code=409, detail="Memory analysis artifact is missing.")
    try:
        return json.loads(gzip.decompress(path.read_bytes()).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail="Memory result artifact is corrupt.") from exc


@router.post("", response_model=MemoryDumpSchema, status_code=201)
async def upload_memory_dump(
    file: UploadFile = File(...),
    repository: MemoryDumpRepository = Depends(get_memory_dump_repository),
) -> MemoryDumpSchema:
    limit = get_settings().max_memory_dump_bytes
    data = await read_upload_limited(file, limit, "Memory dump")
    if not data:
        raise HTTPException(status_code=422, detail="Memory dump is empty.")
    dump_format, _, _ = detect_dump_format(data)
    record = repository.save(
        data,
        safe_display_filename(file.filename, "memory.dump"),
        dump_format,
    )
    return _dump_schema(record)


@router.get("/{dump_id}", response_model=MemoryDumpSchema)
def get_memory_dump(
    dump_id: str,
    repository: MemoryDumpRepository = Depends(get_memory_dump_repository),
) -> MemoryDumpSchema:
    return _dump_schema(repository.get(dump_id))


@router.post("/{dump_id}/analysis", response_model=JobSchema, status_code=202)
def start_memory_analysis(
    dump_id: str,
    payload: MemoryAnalysisRequestSchema,
    dumps: MemoryDumpRepository = Depends(get_memory_dump_repository),
    jobs: JobRepository = Depends(get_job_repository),
) -> JobSchema:
    dump = dumps.get(dump_id)
    job = jobs.create("memory-analysis", dump_id)
    dump_path = Path(dump.storage_path)

    def task(context) -> str:
        result = analyze_memory(
            dump_path,
            use_volatility=payload.use_volatility,
            context=context,
        )
        compressed = gzip.compress(
            json.dumps(asdict(result), sort_keys=True).encode("utf-8"),
            compresslevel=6,
        )
        session = get_session_factory()()
        try:
            updated = MemoryDumpRepository(session).set_analysis(
                dump_id, compressed, result.provider
            )
            return str(updated.analysis_path)
        finally:
            session.close()

    submit_job(job.id, task)
    return JobSchema.model_validate(job)


@router.get("/{dump_id}/analysis", response_model=MemoryAnalysisSummarySchema)
def memory_analysis_summary(
    dump_id: str,
    repository: MemoryDumpRepository = Depends(get_memory_dump_repository),
) -> MemoryAnalysisSummarySchema:
    payload = _result(repository.get(dump_id))
    return MemoryAnalysisSummarySchema(
        metadata=payload["metadata"],
        provider=payload["provider"],
        process_count=len(payload.get("processes", [])),
        module_count=len(payload.get("modules", [])),
        region_count=len(payload.get("regions", [])),
        string_count=len(payload.get("strings", [])),
        urls=payload.get("urls", []),
        ip_addresses=payload.get("ip_addresses", []),
        domains=payload.get("domains", []),
        finding_count=len(payload.get("findings", [])),
        unavailable=payload.get("unavailable", []),
        warnings=payload.get("warnings", []),
    )


@router.get("/{dump_id}/processes", response_model=MemoryProcessPageSchema)
def memory_processes(
    dump_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=1_000),
    repository: MemoryDumpRepository = Depends(get_memory_dump_repository),
) -> MemoryProcessPageSchema:
    items = _result(repository.get(dump_id)).get("processes", [])
    return MemoryProcessPageSchema(
        items=[MemoryProcessSchema.model_validate(item) for item in items[offset : offset + limit]],
        total=len(items),
        offset=offset,
        limit=limit,
    )


@router.get("/{dump_id}/modules", response_model=MemoryModulePageSchema)
def memory_modules(
    dump_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=1_000),
    repository: MemoryDumpRepository = Depends(get_memory_dump_repository),
) -> MemoryModulePageSchema:
    items = _result(repository.get(dump_id)).get("modules", [])
    return MemoryModulePageSchema(
        items=[
            MemoryModuleSchema.model_validate(item)
            for item in items[offset : offset + limit]
        ],
        total=len(items),
        offset=offset,
        limit=limit,
    )


@router.get("/{dump_id}/regions", response_model=MemoryRegionPageSchema)
def memory_regions(
    dump_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=1_000),
    repository: MemoryDumpRepository = Depends(get_memory_dump_repository),
) -> MemoryRegionPageSchema:
    items = _result(repository.get(dump_id)).get("regions", [])
    return MemoryRegionPageSchema(
        items=[MemoryRegionSchema.model_validate(item) for item in items[offset : offset + limit]],
        total=len(items),
        offset=offset,
        limit=limit,
    )


@router.get("/{dump_id}/findings", response_model=list[MemoryFindingSchema])
def memory_findings(
    dump_id: str,
    repository: MemoryDumpRepository = Depends(get_memory_dump_repository),
) -> list[MemoryFindingSchema]:
    return [
        MemoryFindingSchema.model_validate(item)
        for item in _result(repository.get(dump_id)).get("findings", [])
    ]
