"""Normalized models for derived analysis and its provenance."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ProvenanceKind(str, Enum):
    """How an analysis statement was produced."""

    VERIFIED = "verified"
    HEURISTIC = "heuristic"
    INFERRED = "inferred"
    DYNAMIC = "dynamic"
    USER = "user"


@dataclass(frozen=True, slots=True)
class Evidence:
    """A concrete reason supporting a derived fact."""

    source: str
    message: str
    provenance: ProvenanceKind = ProvenanceKind.HEURISTIC
    address: int | None = None
    file_offset: int | None = None
    function_address: int | None = None
    raw_value: str | None = None


@dataclass(frozen=True, slots=True)
class FunctionAnalysis:
    """A bounded static approximation of one function."""

    address: int
    name: str
    demangled_name: str | None
    size: int
    call_count: int
    callers: tuple[int, ...]
    callees: tuple[int, ...]
    cyclomatic_complexity: int
    basic_block_count: int
    instruction_count: int
    api_references: tuple[str, ...] = ()
    string_references: tuple[str, ...] = ()
    stack_frame_size: int | None = None
    arguments: tuple[str, ...] = ()
    return_type: str | None = None
    is_thunk: bool = False
    is_library: bool = False
    suspicious_score: int = 0
    user_name: str | None = None
    user_comment: str | None = None
    confidence: float = 0.0
    provenance: ProvenanceKind = ProvenanceKind.HEURISTIC
    evidence: tuple[Evidence, ...] = field(default_factory=tuple)
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class CallGraphNode:
    address: int
    name: str
    is_library: bool
    is_entry: bool
    suspicious_score: int
    provenance: ProvenanceKind


@dataclass(frozen=True, slots=True)
class CallGraphEdge:
    source: int
    target: int
    kind: str = "static"
    call_sites: tuple[int, ...] = ()
    recursive: bool = False


@dataclass(frozen=True, slots=True)
class CallGraph:
    nodes: tuple[CallGraphNode, ...]
    edges: tuple[CallGraphEdge, ...]
    root_address: int | None
    truncated: bool
