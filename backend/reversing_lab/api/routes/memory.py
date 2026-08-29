"""Memory dump upload, background analysis, and paginated result views."""

from __future__ import annotations

import gzip
import json
from dataclasses import asdict
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, Response, UploadFile

from ...analyzer import hex_page
from ...config import get_settings
from ...database import JobRepository, MemoryDumpRepository
from ...database.session import get_session_factory
from ...jobs import submit_job
from ...memory import (
    VolatilityAdapter,
    analyze_memory,
    detect_dump_format,
    disassemble_region,
)
from ...reporting import (
    build_memory_report,
    render_memory_html,
    render_memory_markdown,
)
from ..dependencies import get_job_repository, get_memory_dump_repository
from ..schemas import (
    JobSchema,
    MemoryAnalysisRequestSchema,
    MemoryAnalysisSummarySchema,
    MemoryDumpSchema,
    MemoryFindingSchema,
    MemoryHandlePageSchema,
    MemoryHandleSchema,
    MemoryModulePageSchema,
    MemoryModuleSchema,
    MemoryNetworkArtifactPageSchema,
    MemoryNetworkArtifactSchema,
    MemoryProcessPageSchema,
    MemoryProcessSchema,
    MemoryRegionArtifactPageSchema,
    MemoryRegionArtifactSchema,
    MemoryRegionDisassemblySchema,
    MemoryRegionHexPageSchema,
    MemoryRegionHexRowSchema,
    MemoryRegionInspectionRequestSchema,
    MemoryRegionInstructionSchema,
    MemoryRegionPageSchema,
    MemoryRegionSchema,
    MemoryThreadPageSchema,
    MemoryThreadSchema,
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
        network_count=len(payload.get("network", [])),
        handle_count=len(payload.get("handles", [])),
        thread_count=len(payload.get("threads", [])),
        string_count=len(payload.get("strings", [])),
        urls=payload.get("urls", []),
        ip_addresses=payload.get("ip_addresses", []),
        domains=payload.get("domains", []),
        finding_count=len(payload.get("findings", [])),
        unavailable=payload.get("unavailable", []),
        warnings=payload.get("warnings", []),
    )


@router.get("/{dump_id}/report")
def export_memory_report(
    dump_id: str,
    format: str = Query(default="json", pattern="^(json|markdown|html)$"),
    repository: MemoryDumpRepository = Depends(get_memory_dump_repository),
) -> Response:
    """Export one bounded report for a completed memory analysis."""
    dump = repository.get(dump_id)
    report = build_memory_report(
        dump_id=dump.id,
        filename=dump.filename,
        created_at=dump.created_at,
        result=_result(dump),
    )
    if format == "markdown":
        content = render_memory_markdown(report)
        media_type = "text/markdown; charset=utf-8"
        suffix = "md"
    elif format == "html":
        content = render_memory_html(report)
        media_type = "text/html; charset=utf-8"
        suffix = "html"
    else:
        content = json.dumps(report, indent=2, ensure_ascii=False)
        media_type = "application/json"
        suffix = "json"
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="memory-{dump.id[:12]}.{suffix}"'
        },
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


@router.get("/{dump_id}/handles", response_model=MemoryHandlePageSchema)
def memory_handles(
    dump_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=1_000),
    pid: int | None = Query(default=None, ge=0, le=2**32 - 1),
    object_type: str | None = Query(default=None, max_length=128),
    keyword: str | None = Query(default=None, max_length=256),
    repository: MemoryDumpRepository = Depends(get_memory_dump_repository),
) -> MemoryHandlePageSchema:
    items = _result(repository.get(dump_id)).get("handles", [])
    if pid is not None:
        items = [item for item in items if item.get("pid") == pid]
    if object_type:
        expected = object_type.casefold()
        items = [
            item
            for item in items
            if str(item.get("object_type", "")).casefold() == expected
        ]
    if keyword:
        expected = keyword.casefold()

        def search_text(item: dict[str, object]) -> str:
            values = [
                str(item.get("process_name", "")),
                str(item.get("object_type", "")),
                str(item.get("name", "")),
            ]
            for field in ("object_offset", "handle_value", "granted_access"):
                value = item.get(field)
                if isinstance(value, int) and value >= 0:
                    values.append(f"0x{value:x}")
            return " ".join(values).casefold()

        items = [item for item in items if expected in search_text(item)]
    return MemoryHandlePageSchema(
        items=[
            MemoryHandleSchema.model_validate(item)
            for item in items[offset : offset + limit]
        ],
        total=len(items),
        offset=offset,
        limit=limit,
    )


@router.get("/{dump_id}/threads", response_model=MemoryThreadPageSchema)
def memory_threads(
    dump_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=1_000),
    pid: int | None = Query(default=None, ge=0, le=2**32 - 1),
    tid: int | None = Query(default=None, ge=0, le=2**32 - 1),
    keyword: str | None = Query(default=None, max_length=256),
    repository: MemoryDumpRepository = Depends(get_memory_dump_repository),
) -> MemoryThreadPageSchema:
    items = _result(repository.get(dump_id)).get("threads", [])
    if pid is not None:
        items = [item for item in items if item.get("pid") == pid]
    if tid is not None:
        items = [item for item in items if item.get("tid") == tid]
    if keyword:
        expected = keyword.casefold()

        def search_text(item: dict[str, object]) -> str:
            values = [
                str(item.get("process_name", "")),
                str(item.get("start_path", "")),
                str(item.get("win32_start_path", "")),
                str(item.get("create_time", "")),
                str(item.get("exit_time", "")),
            ]
            for field in ("object_offset", "start_address", "win32_start_address"):
                value = item.get(field)
                if isinstance(value, int) and value >= 0:
                    values.append(f"0x{value:x}")
            return " ".join(values).casefold()

        items = [item for item in items if expected in search_text(item)]
    return MemoryThreadPageSchema(
        items=[
            MemoryThreadSchema.model_validate(item)
            for item in items[offset : offset + limit]
        ],
        total=len(items),
        offset=offset,
        limit=limit,
    )


def _validated_dump_path(record) -> Path | None:
    path = Path(record.storage_path).resolve()
    expected_parent = (get_settings().storage_dir.parent / "memory").resolve()
    if path.parent != expected_parent or path.name != record.sha256 or not path.is_file():
        return None
    return path


@router.post(
    "/{dump_id}/regions/inspect", response_model=JobSchema, status_code=202
)
def inspect_memory_region(
    dump_id: str,
    payload: MemoryRegionInspectionRequestSchema,
    dumps: MemoryDumpRepository = Depends(get_memory_dump_repository),
    jobs: JobRepository = Depends(get_job_repository),
) -> JobSchema:
    dump = dumps.get(dump_id)
    if dump.dump_format != "windows-memory-dump":
        raise HTTPException(
            status_code=409,
            detail="Region extraction currently requires a Windows full memory dump.",
        )
    dump_path = _validated_dump_path(dump)
    if dump_path is None:
        raise HTTPException(status_code=409, detail="Memory dump path failed validation.")
    analysis = _result(dump)
    region = next(
        (
            item
            for item in analysis.get("regions", [])
            if item.get("pid") == payload.pid
            and item.get("start") == payload.start_address
        ),
        None,
    )
    if region is None:
        raise HTTPException(
            status_code=422,
            detail="The requested PID and address do not identify a normalized VAD.",
        )
    if region.get("source_provider") != VolatilityAdapter.name:
        raise HTTPException(
            status_code=409,
            detail="The selected region was not reported by the Volatility provider.",
        )
    end = region.get("end")
    if not isinstance(end, int) or end < payload.start_address:
        raise HTTPException(status_code=500, detail="Stored VAD range is invalid.")
    size = end - payload.start_address + 1
    limit = get_settings().max_memory_region_extract_bytes
    if size > limit:
        raise HTTPException(
            status_code=422,
            detail=f"The selected VAD exceeds the {limit}-byte extraction limit.",
        )
    adapter = VolatilityAdapter()
    if not adapter.is_available():
        raise HTTPException(
            status_code=409,
            detail="Volatility 3 is unavailable; region extraction is disabled.",
        )
    job = jobs.create(
        "memory-region-inspection",
        f"{dump_id}:{payload.pid}:{payload.start_address:x}",
    )

    def task(context) -> str:
        context.update(15, "Extracting the allowlisted VAD")
        extracted = VolatilityAdapter().extract_region(
            dump_path,
            pid=payload.pid,
            address=payload.start_address,
            max_bytes=limit,
        )
        if extracted.start != payload.start_address or extracted.end != end:
            raise ValueError("Volatility returned a different VAD than requested.")
        context.update(72, "Validating and storing the region artifact")
        session = get_session_factory()()
        try:
            artifact = MemoryDumpRepository(session).save_region_artifact(
                dump_id,
                pid=payload.pid,
                start_address=extracted.start,
                end_address=extracted.end,
                architecture=payload.architecture,
                provider=extracted.provider,
                data=extracted.data,
            )
            return artifact.id
        finally:
            session.close()

    submit_job(job.id, task)
    return JobSchema.model_validate(job)


@router.get(
    "/{dump_id}/region-artifacts", response_model=MemoryRegionArtifactPageSchema
)
def memory_region_artifacts(
    dump_id: str,
    limit: int = Query(200, ge=1, le=1_000),
    offset: int = Query(0, ge=0),
    repository: MemoryDumpRepository = Depends(get_memory_dump_repository),
) -> MemoryRegionArtifactPageSchema:
    items, total = repository.list_region_artifacts(dump_id, limit, offset)
    return MemoryRegionArtifactPageSchema(
        items=[MemoryRegionArtifactSchema.model_validate(item) for item in items],
        total=total,
        offset=offset,
        limit=limit,
    )


def _artifact_bytes(repository: MemoryDumpRepository, dump_id: str, artifact_id: str):
    record = repository.get_region_artifact(dump_id, artifact_id)
    try:
        data = repository.read_region_artifact(record)
    except ValueError as exc:
        raise HTTPException(
            status_code=500, detail="Memory region artifact failed integrity validation."
        ) from exc
    return record, data


@router.get(
    "/{dump_id}/region-artifacts/{artifact_id}",
    response_model=MemoryRegionArtifactSchema,
)
def memory_region_artifact(
    dump_id: str,
    artifact_id: str,
    repository: MemoryDumpRepository = Depends(get_memory_dump_repository),
) -> MemoryRegionArtifactSchema:
    return MemoryRegionArtifactSchema.model_validate(
        repository.get_region_artifact(dump_id, artifact_id)
    )


@router.get(
    "/{dump_id}/region-artifacts/{artifact_id}/hex",
    response_model=MemoryRegionHexPageSchema,
)
def memory_region_hex(
    dump_id: str,
    artifact_id: str,
    offset: int = Query(0, ge=0),
    length: int = Query(256, ge=1, le=4_096),
    repository: MemoryDumpRepository = Depends(get_memory_dump_repository),
) -> MemoryRegionHexPageSchema:
    record, data = _artifact_bytes(repository, dump_id, artifact_id)
    page = hex_page(data, offset=offset, length=length)
    return MemoryRegionHexPageSchema(
        offset=page.offset,
        length=page.length,
        total_size=page.total_size,
        base_address=record.start_address,
        base_address_hex=f"0x{record.start_address:x}",
        rows=[
            MemoryRegionHexRowSchema(
                offset=row.offset,
                address=record.start_address + row.offset,
                address_hex=f"0x{record.start_address + row.offset:x}",
                hex_bytes=list(row.hex_bytes),
                ascii=row.ascii,
            )
            for row in page.rows
        ],
    )


@router.get(
    "/{dump_id}/region-artifacts/{artifact_id}/disassembly",
    response_model=MemoryRegionDisassemblySchema,
)
def memory_region_disassembly(
    dump_id: str,
    artifact_id: str,
    offset: int = Query(0, ge=0),
    count: int = Query(200, ge=1, le=2_000),
    repository: MemoryDumpRepository = Depends(get_memory_dump_repository),
) -> MemoryRegionDisassemblySchema:
    record, data = _artifact_bytes(repository, dump_id, artifact_id)
    result = disassemble_region(
        data,
        base_address=record.start_address,
        architecture=record.architecture,
        offset=offset,
        count=count,
    )
    return MemoryRegionDisassemblySchema(
        start_address=result.start_address,
        start_address_hex=f"0x{result.start_address:x}",
        architecture=record.architecture,
        instruction_count=result.instruction_count,
        truncated=result.truncated,
        instructions=[
            MemoryRegionInstructionSchema.model_validate(item)
            for item in result.instructions
        ],
    )


@router.get("/{dump_id}/region-artifacts/{artifact_id}/download")
def download_memory_region_artifact(
    dump_id: str,
    artifact_id: str,
    repository: MemoryDumpRepository = Depends(get_memory_dump_repository),
) -> Response:
    record, data = _artifact_bytes(repository, dump_id, artifact_id)
    filename = f"memory-region-{record.content_sha256[:12]}.bin"
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-SHA256": record.content_sha256,
        },
    )


@router.get("/{dump_id}/network", response_model=MemoryNetworkArtifactPageSchema)
def memory_network(
    dump_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=1_000),
    pid: int | None = Query(default=None, ge=0, le=2**32 - 1),
    protocol: str | None = Query(default=None, max_length=16),
    state: str | None = Query(default=None, max_length=64),
    keyword: str | None = Query(default=None, max_length=256),
    repository: MemoryDumpRepository = Depends(get_memory_dump_repository),
) -> MemoryNetworkArtifactPageSchema:
    items = _result(repository.get(dump_id)).get("network", [])
    if pid is not None:
        items = [item for item in items if item.get("pid") == pid]
    if protocol:
        expected = protocol.casefold()
        items = [item for item in items if str(item.get("protocol", "")).casefold() == expected]
    if state:
        expected = state.casefold()
        items = [item for item in items if str(item.get("state", "")).casefold() == expected]
    if keyword:
        expected = keyword.casefold()
        items = [
            item
            for item in items
            if expected
            in " ".join(
                str(item.get(field, ""))
                for field in (
                    "process_name",
                    "local_address",
                    "remote_address",
                    "local_port",
                    "remote_port",
                )
            ).casefold()
        ]
    return MemoryNetworkArtifactPageSchema(
        items=[
            MemoryNetworkArtifactSchema.model_validate(item)
            for item in items[offset : offset + limit]
        ],
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
