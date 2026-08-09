"""Unified optional-tool capability inventory."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ...analyzer import upx_executable
from ...config import get_settings
from ...decompiler import list_decompilers
from ...dynamic import get_sandbox_provider
from ...integrations import list_integrations
from ...memory import ALLOWED_PLUGINS, VolatilityAdapter
from ..schemas import (
    AnalysisLimitsSchema,
    AuthenticationConfigSchema,
    RuntimeConfigurationSchema,
    SandboxPolicyConfigSchema,
    ToolingStatusSchema,
)

router = APIRouter(prefix="/tooling", tags=["tooling"])


def _inventory() -> list[ToolingStatusSchema]:
    items = [
        ToolingStatusSchema(
            name=item.name,
            category="integration",
            available=item.available,
            detail=item.detail,
            capabilities=["whole-binary analysis"],
        )
        for item in list_integrations()
    ]
    items.extend(
        ToolingStatusSchema(
            name=item.name,
            category="decompiler",
            available=item.available,
            detail=item.detail,
            capabilities=["function decompilation", "estimated C-like output"],
        )
        for item in list_decompilers()
    )
    upx = upx_executable()
    items.append(
        ToolingStatusSchema(
            name="upx",
            category="unpacker",
            available=upx is not None,
            detail=(
                f"Resolved executable: {upx}"
                if upx is not None
                else "UPX is not installed or configured."
            ),
            capabilities=["explicit unpack to separate artifact"],
        )
    )
    volatility = VolatilityAdapter()
    items.append(
        ToolingStatusSchema(
            name="volatility3",
            category="memory",
            available=volatility.is_available(),
            detail=(
                "Volatility 3 is available; only the server allowlist can run."
                if volatility.is_available()
                else "Volatility 3 is unavailable; basic dump triage remains available."
            ),
            capabilities=[f"allowlisted plugin: {plugin}" for plugin in ALLOWED_PLUGINS],
        )
    )
    sandbox = get_sandbox_provider()
    sandbox_status = sandbox.readiness(
        sample_path_validated=False, user_acknowledged=False
    )
    items.append(
        ToolingStatusSchema(
            name="sandbox",
            category="dynamic-analysis",
            available=sandbox_status.provider_configured
            and sandbox_status.isolated_worker_available,
            detail=sandbox_status.warning,
            capabilities=[
                "out-of-process provider interface",
                "blocked-by-default network policy",
                "resource/timeout/process limits",
            ],
        )
    )
    return items


@router.get("", response_model=list[ToolingStatusSchema])
def list_tooling() -> list[ToolingStatusSchema]:
    return _inventory()


@router.get("/configuration", response_model=RuntimeConfigurationSchema)
def runtime_configuration() -> RuntimeConfigurationSchema:
    """Expose non-secret resource and isolation policy values."""
    settings = get_settings()
    return RuntimeConfigurationSchema(
        limits=AnalysisLimitsSchema(
            max_upload_bytes=settings.max_upload_bytes,
            max_memory_dump_bytes=settings.max_memory_dump_bytes,
            max_memory_region_extract_bytes=settings.max_memory_region_extract_bytes,
            max_disassembly_instructions=settings.max_disassembly_instructions,
            max_functions=settings.max_functions,
            max_cfg_nodes=settings.max_cfg_nodes,
            max_call_graph_nodes=settings.max_call_graph_nodes,
            max_strings=settings.max_strings,
            max_yara_matches=settings.max_yara_matches,
            max_dynamic_events=settings.max_dynamic_events,
            max_audit_export_records=settings.max_audit_export_records,
            max_analysis_seconds=settings.max_analysis_seconds,
            max_decompiler_seconds=settings.max_decompiler_seconds,
            max_external_output_bytes=settings.max_external_output_bytes,
            max_concurrent_jobs=settings.max_concurrent_jobs,
        ),
        sandbox_policy=SandboxPolicyConfigSchema(
            provider=settings.sandbox_provider,
            network=settings.sandbox_network_policy,
            cpu_count=settings.sandbox_cpu_count,
            memory_mb=settings.sandbox_memory_mb,
            timeout_seconds=settings.sandbox_timeout_seconds,
            process_limit=settings.sandbox_process_limit,
        ),
        authentication=AuthenticationConfigSchema(
            mode=settings.auth_mode,
            required=settings.auth_mode == "api_key",
            project_ownership_enforced=settings.auth_mode == "api_key",
        ),
    )


@router.get("/{tool_name}", response_model=ToolingStatusSchema)
def tooling_detail(tool_name: str) -> ToolingStatusSchema:
    item = next((candidate for candidate in _inventory() if candidate.name == tool_name), None)
    if item is None:
        raise HTTPException(status_code=404, detail=f"Unknown tool: {tool_name!r}.")
    return item
