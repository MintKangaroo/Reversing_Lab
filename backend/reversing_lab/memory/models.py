"""Normalized, artifact-friendly memory analysis records."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MemoryMetadata:
    sha256: str
    size: int
    dump_format: str
    os_guess: str | None
    architecture: str | None
    confidence: float


@dataclass(frozen=True, slots=True)
class MemoryProcess:
    pid: int
    ppid: int | None
    name: str
    command_line: str | None
    thread_count: int | None
    module_count: int | None
    source_provider: str


@dataclass(frozen=True, slots=True)
class MemoryRegion:
    start: int
    end: int
    protection: str
    mapped_file: str | None
    suspicious: bool
    reason: str | None
    source_provider: str


@dataclass(frozen=True, slots=True)
class MemoryFinding:
    id: str
    title: str
    severity: str
    confidence: float
    summary: str
    evidence: tuple[str, ...]
    false_positive_note: str


@dataclass(frozen=True, slots=True)
class MemoryAnalysisResult:
    metadata: MemoryMetadata
    processes: tuple[MemoryProcess, ...]
    regions: tuple[MemoryRegion, ...]
    strings: tuple[str, ...]
    urls: tuple[str, ...]
    ip_addresses: tuple[str, ...]
    domains: tuple[str, ...]
    findings: tuple[MemoryFinding, ...]
    provider: str
    unavailable: tuple[str, ...]
    warnings: tuple[str, ...]
