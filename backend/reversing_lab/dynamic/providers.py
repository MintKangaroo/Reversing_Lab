"""Disabled-by-default and no-execution mock sandbox providers."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from ..config import get_settings
from ..errors import IntegrationUnavailableError
from ..jobs import JobContext
from .base import DynamicEvent, DynamicResult, SandboxPolicy, SandboxReadiness


_EVENT_TYPES = (
    "process creation",
    "process termination",
    "thread creation",
    "module load",
    "file operations",
    "registry access",
    "network attempts",
    "DNS queries",
    "memory allocation/protection",
    "API calls",
    "syscalls",
    "exceptions",
    "debugger detection",
    "stdout/stderr",
)


def _readiness(
    provider: str,
    *,
    configured: bool,
    worker: bool,
    workspace: bool,
    sample_path_validated: bool,
    user_acknowledged: bool,
    warning: str,
) -> SandboxReadiness:
    settings = get_settings()
    limits = (
        settings.sandbox_cpu_count > 0
        and settings.sandbox_memory_mb > 0
        and settings.sandbox_process_limit > 0
    )
    timeout = settings.sandbox_timeout_seconds > 0
    network = settings.sandbox_network_policy in {"blocked", "simulated", "allowlisted"}
    checks = {
        "Sandbox provider is not configured.": configured,
        "An isolated worker is not available.": worker,
        "CPU, memory, or process limits are missing.": limits,
        "Sandbox timeout is not configured.": timeout,
        "Network policy is not configured.": network,
        "A private writable workspace is not configured.": workspace,
        "The sample path has not been validated.": sample_path_validated,
        "User acknowledgement is required.": user_acknowledged,
    }
    reasons = tuple(message for message, passed in checks.items() if not passed)
    return SandboxReadiness(
        provider=provider,
        provider_configured=configured,
        isolated_worker_available=worker,
        resource_limits_configured=limits,
        timeout_configured=timeout,
        network_policy_configured=network,
        writable_workspace_configured=workspace,
        sample_path_validated=sample_path_validated,
        user_acknowledged=user_acknowledged,
        ready=not reasons,
        reasons=reasons,
        warning=warning,
    )


class DisabledSandboxProvider:
    name = "disabled"

    def readiness(
        self, *, sample_path_validated: bool, user_acknowledged: bool
    ) -> SandboxReadiness:
        return _readiness(
            self.name,
            configured=False,
            worker=False,
            workspace=False,
            sample_path_validated=sample_path_validated,
            user_acknowledged=user_acknowledged,
            warning=(
                "Dynamic analysis is disabled. Real malware requires a separately "
                "managed VM sandbox; Docker alone is not a strong isolation boundary."
            ),
        )

    def analyze(
        self, sample_path: Path, policy: SandboxPolicy, context: JobContext
    ) -> DynamicResult:
        raise IntegrationUnavailableError("Dynamic analysis provider is disabled.")


class MockSandboxProvider:
    """Test/control-plane provider. It deliberately does not execute the sample."""

    name = "mock"

    def readiness(
        self, *, sample_path_validated: bool, user_acknowledged: bool
    ) -> SandboxReadiness:
        settings = get_settings()
        workspace = (
            settings.sandbox_workspace_dir is not None
            and settings.sandbox_workspace_dir.is_dir()
        )
        return _readiness(
            self.name,
            configured=True,
            worker=True,
            workspace=workspace,
            sample_path_validated=sample_path_validated,
            user_acknowledged=user_acknowledged,
            warning="Mock provider validates orchestration only and never executes samples.",
        )

    def analyze(
        self, sample_path: Path, policy: SandboxPolicy, context: JobContext
    ) -> DynamicResult:
        context.update(20, "Mock worker validating policy")
        context.check_cancelled()
        data = sample_path.read_bytes()
        context.update(70, "Mock worker creating control event")
        event = DynamicEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            process=None,
            process_id=None,
            thread_id=None,
            category="analysis_control",
            operation="mock_no_execution",
            target=hashlib.sha256(data).hexdigest(),
            result="not_executed",
            arguments_summary=(
                f"network={policy.network}; cpu={policy.cpu_count}; "
                f"memory={policy.memory_mb}MB; timeout={policy.timeout_seconds}s"
            ),
            call_stack=(),
            severity="info",
            source_provider=self.name,
        )
        return DynamicResult(
            provider=self.name,
            events=(event,),
            artifacts=(),
            unavailable_events=_EVENT_TYPES,
            warnings=(
                "Mock provider did not execute the sample and emitted no behavioral observations.",
            ),
        )


def get_sandbox_provider():
    configured = get_settings().sandbox_provider
    if configured == "mock":
        return MockSandboxProvider()
    return DisabledSandboxProvider()
