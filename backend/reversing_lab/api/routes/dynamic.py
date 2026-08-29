"""Guarded dynamic-analysis orchestration; never executes a sample in the API."""

from __future__ import annotations

import gzip
import json
from dataclasses import asdict
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

from ...config import get_settings
from ...database import BinaryRepository, DynamicRunRepository, JobRepository
from ...database.session import get_session_factory
from ...dynamic import SandboxPolicy, get_sandbox_provider
from ...jobs import cancel_job, submit_job
from ...reporting import (
    build_dynamic_report,
    render_dynamic_html,
    render_dynamic_markdown,
)
from ..dependencies import (
    get_binary_repository,
    get_dynamic_run_repository,
    get_job_repository,
)
from ..schemas import (
    DynamicAnalysisRequestSchema,
    DynamicArtifactSchema,
    DynamicEventPageSchema,
    DynamicEventSchema,
    DynamicRunSchema,
    JobSchema,
    SandboxReadinessSchema,
)

router = APIRouter(prefix="/dynamic-analysis", tags=["dynamic-analysis"])


def _validated_sample(repo: BinaryRepository, sha256: str | None) -> Path | None:
    if sha256 is None:
        return None
    record = repo.get(sha256)
    path = Path(record.storage_path).resolve()
    storage = get_settings().storage_dir.resolve()
    if (
        not path.is_file()
        or path.name != sha256
        or path.parent != storage
    ):
        return None
    return path


def _run_schema(record, job) -> DynamicRunSchema:
    return DynamicRunSchema(
        id=record.id,
        job_id=record.job_id,
        binary_sha256=record.binary_sha256,
        provider=record.provider,
        policy=json.loads(record.policy_json),
        result_available=record.result_path is not None,
        created_at=record.created_at,
        job=JobSchema.model_validate(job),
    )


def _result(record) -> dict:
    if not record.result_path:
        raise HTTPException(status_code=409, detail="Dynamic analysis has not completed.")
    path = Path(record.result_path)
    try:
        return json.loads(gzip.decompress(path.read_bytes()).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail="Dynamic result artifact is corrupt.") from exc


@router.get("/readiness", response_model=SandboxReadinessSchema)
def dynamic_readiness(
    binary_sha256: str | None = Query(default=None, pattern="^[0-9a-f]{64}$"),
    acknowledged: bool = Query(default=False),
    binaries: BinaryRepository = Depends(get_binary_repository),
) -> SandboxReadinessSchema:
    path = _validated_sample(binaries, binary_sha256) if binary_sha256 else None
    return SandboxReadinessSchema.model_validate(
        get_sandbox_provider().readiness(
            sample_path_validated=path is not None,
            user_acknowledged=acknowledged,
        )
    )


@router.post("", response_model=DynamicRunSchema, status_code=202)
def start_dynamic_analysis(
    payload: DynamicAnalysisRequestSchema,
    binaries: BinaryRepository = Depends(get_binary_repository),
    runs: DynamicRunRepository = Depends(get_dynamic_run_repository),
    jobs: JobRepository = Depends(get_job_repository),
) -> DynamicRunSchema:
    sample_path = _validated_sample(binaries, payload.binary_sha256)
    provider = get_sandbox_provider()
    readiness = provider.readiness(
        sample_path_validated=sample_path is not None,
        user_acknowledged=payload.acknowledged,
    )
    if not readiness.ready or sample_path is None:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Dynamic analysis guardrails are not satisfied.",
                "reasons": list(readiness.reasons),
                "warning": readiness.warning,
            },
        )

    settings = get_settings()
    policy = SandboxPolicy(
        network=settings.sandbox_network_policy,
        cpu_count=settings.sandbox_cpu_count,
        memory_mb=settings.sandbox_memory_mb,
        timeout_seconds=settings.sandbox_timeout_seconds,
        process_limit=settings.sandbox_process_limit,
    )
    job = jobs.create("dynamic-analysis", payload.binary_sha256)
    run = runs.create(
        job.id,
        job.id,
        payload.binary_sha256,
        provider.name,
        asdict(policy),
    )

    def task(context) -> str:
        # This call crosses the provider interface. A real implementation must send
        # the request to the configured isolated worker; the API never subprocesses
        # or imports the uploaded sample.
        result = provider.analyze(sample_path, policy, context)
        if len(result.events) > settings.max_dynamic_events:
            raise ValueError("Sandbox returned more events than the configured limit.")
        compressed = gzip.compress(
            json.dumps(asdict(result), sort_keys=True).encode("utf-8"),
            compresslevel=6,
        )
        session = get_session_factory()()
        try:
            updated = DynamicRunRepository(session).set_result(run.id, compressed)
            return str(updated.result_path)
        finally:
            session.close()

    submit_job(job.id, task)
    return _run_schema(run, job)


@router.get("/{run_id}", response_model=DynamicRunSchema)
def get_dynamic_analysis(
    run_id: str,
    runs: DynamicRunRepository = Depends(get_dynamic_run_repository),
    jobs: JobRepository = Depends(get_job_repository),
) -> DynamicRunSchema:
    run = runs.get(run_id)
    return _run_schema(run, jobs.get(run.job_id))


@router.post("/{run_id}/cancel", response_model=DynamicRunSchema)
def cancel_dynamic_analysis(
    run_id: str,
    runs: DynamicRunRepository = Depends(get_dynamic_run_repository),
    jobs: JobRepository = Depends(get_job_repository),
) -> DynamicRunSchema:
    run = runs.get(run_id)
    cancel_job(run.job_id)
    return _run_schema(run, jobs.get(run.job_id))


@router.get("/{run_id}/events", response_model=DynamicEventPageSchema)
def dynamic_events(
    run_id: str,
    process: str | None = None,
    event_type: str | None = None,
    severity: str | None = None,
    keyword: str | None = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(500, ge=1, le=5_000),
    runs: DynamicRunRepository = Depends(get_dynamic_run_repository),
) -> DynamicEventPageSchema:
    payload = _result(runs.get(run_id))
    items = payload["events"]
    if process:
        items = [item for item in items if process.lower() in str(item.get("process", "")).lower()]
    if event_type:
        items = [item for item in items if item.get("category") == event_type]
    if severity:
        items = [item for item in items if item.get("severity") == severity]
    if keyword:
        lowered = keyword.lower()
        items = [item for item in items if lowered in json.dumps(item).lower()]
    return DynamicEventPageSchema(
        items=[
            DynamicEventSchema.model_validate(item)
            for item in items[offset : offset + limit]
        ],
        total=len(items),
        offset=offset,
        limit=limit,
        unavailable_events=payload["unavailable_events"],
        warnings=payload["warnings"],
    )


@router.get("/{run_id}/report")
def export_dynamic_report(
    run_id: str,
    format: str = Query(default="json", pattern="^(json|markdown|html)$"),
    runs: DynamicRunRepository = Depends(get_dynamic_run_repository),
) -> Response:
    """Export one bounded behavioral report for a completed dynamic run."""
    run = runs.get(run_id)
    report = build_dynamic_report(
        run_id=run.id,
        job_id=run.job_id,
        binary_sha256=run.binary_sha256,
        created_at=run.created_at,
        result=_result(run),
    )
    if format == "markdown":
        content = render_dynamic_markdown(report)
        media_type = "text/markdown; charset=utf-8"
        suffix = "md"
    elif format == "html":
        content = render_dynamic_html(report)
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
            "Content-Disposition": f'attachment; filename="dynamic-{run.id[:12]}.{suffix}"'
        },
    )


@router.get("/{run_id}/artifacts", response_model=list[DynamicArtifactSchema])
def dynamic_artifacts(
    run_id: str,
    runs: DynamicRunRepository = Depends(get_dynamic_run_repository),
) -> list[DynamicArtifactSchema]:
    return [
        DynamicArtifactSchema.model_validate(item)
        for item in _result(runs.get(run_id))["artifacts"]
    ]
