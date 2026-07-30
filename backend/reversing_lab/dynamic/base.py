"""Normalized dynamic-analysis provider interface."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..jobs import JobContext


@dataclass(frozen=True, slots=True)
class SandboxReadiness:
    provider: str
    provider_configured: bool
    isolated_worker_available: bool
    resource_limits_configured: bool
    timeout_configured: bool
    network_policy_configured: bool
    writable_workspace_configured: bool
    sample_path_validated: bool
    user_acknowledged: bool
    ready: bool
    reasons: tuple[str, ...]
    warning: str


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    network: str
    cpu_count: float
    memory_mb: int
    timeout_seconds: int
    process_limit: int
    read_only_base: bool = True
    temporary_overlay: bool = True
    host_mounts: bool = False
    docker_socket: bool = False
    privileged: bool = False
    host_pid: bool = False
    host_network: bool = False
    destroy_after_analysis: bool = True


@dataclass(frozen=True, slots=True)
class DynamicEvent:
    timestamp: str
    process: str | None
    process_id: int | None
    thread_id: int | None
    category: str
    operation: str
    target: str | None
    result: str
    arguments_summary: str | None
    call_stack: tuple[str, ...]
    severity: str
    source_provider: str


@dataclass(frozen=True, slots=True)
class DynamicArtifact:
    name: str
    kind: str
    content_sha256: str | None
    size: int | None


@dataclass(frozen=True, slots=True)
class DynamicResult:
    provider: str
    events: tuple[DynamicEvent, ...]
    artifacts: tuple[DynamicArtifact, ...]
    unavailable_events: tuple[str, ...]
    warnings: tuple[str, ...]


@runtime_checkable
class SandboxProvider(Protocol):
    name: str

    def readiness(
        self, *, sample_path_validated: bool, user_acknowledged: bool
    ) -> SandboxReadiness:
        ...

    def analyze(
        self, sample_path: Path, policy: SandboxPolicy, context: JobContext
    ) -> DynamicResult:
        ...
