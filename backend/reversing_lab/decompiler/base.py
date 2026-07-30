"""Common decompiler adapter contract and normalized results."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..analysis.models import ProvenanceKind


@dataclass(frozen=True, slots=True)
class DecompileOptions:
    timeout_seconds: float = 30.0
    max_output_bytes: int = 2 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class DecompiledVariable:
    name: str
    type_name: str | None
    storage: str | None
    confidence: float
    provenance: ProvenanceKind


@dataclass(frozen=True, slots=True)
class DecompiledParameter:
    name: str
    type_name: str | None
    storage: str | None
    confidence: float
    provenance: ProvenanceKind


@dataclass(frozen=True, slots=True)
class SourceMapEntry:
    line: int
    address_start: int
    address_end: int
    confidence: float
    provenance: ProvenanceKind


@dataclass(frozen=True, slots=True)
class DecompiledFunction:
    function_address: int
    function_name: str
    language: str
    code: str
    warnings: tuple[str, ...]
    confidence: float
    variables: tuple[DecompiledVariable, ...]
    parameters: tuple[DecompiledParameter, ...]
    return_type: str | None
    source_map: tuple[SourceMapEntry, ...]
    provider: str
    elapsed_ms: int
    provenance: ProvenanceKind = ProvenanceKind.INFERRED


@dataclass(frozen=True, slots=True)
class DecompilerInfo:
    name: str
    available: bool
    detail: str
    priority: int


@runtime_checkable
class DecompilerAdapter(Protocol):
    name: str

    def is_available(self) -> bool:
        ...

    def decompile_function(
        self,
        binary_path: Path,
        address: int,
        options: DecompileOptions,
    ) -> DecompiledFunction:
        ...
