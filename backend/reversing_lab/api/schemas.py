"""Pydantic response/request schemas for the HTTP API.

These mirror the analysis-core dataclasses field-for-field and are built from them with
``model_validate(obj, from_attributes=True)``. Keeping them separate from the core
models means the wire format is an explicit, versionable contract rather than an
accidental reflection of internal types.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

_FROM_ATTRS = ConfigDict(from_attributes=True)


# --- Parser -----------------------------------------------------------------------
class SectionSchema(BaseModel):
    model_config = _FROM_ATTRS
    name: str
    virtual_address: int
    size: int
    offset: int
    entropy: float
    flags: list[str]
    contains_code: bool


class SymbolSchema(BaseModel):
    model_config = _FROM_ATTRS
    name: str
    value: int
    size: int
    kind: str
    binding: str
    is_exported: bool
    is_imported: bool


class ImportSchema(BaseModel):
    model_config = _FROM_ATTRS
    name: str
    library: str | None = None
    address: int | None = None


class ExportSchema(BaseModel):
    model_config = _FROM_ATTRS
    name: str
    address: int
    ordinal: int | None = None


class BinaryInfoSchema(BaseModel):
    model_config = _FROM_ATTRS
    binary_format: str
    architecture: str
    bits: int
    endianness: str
    entry_point: int
    is_pie: bool
    has_nx: bool
    has_relro: bool
    file_size: int
    sha256: str
    sections: list[SectionSchema]
    symbols: list[SymbolSchema]
    imports: list[ImportSchema]
    exports: list[ExportSchema]
    extra: dict[str, str]


class BinarySummarySchema(BaseModel):
    """Compact record returned on upload and in listings."""

    model_config = _FROM_ATTRS
    sha256: str
    filename: str
    binary_format: str
    size: int


# --- Analyzer ---------------------------------------------------------------------
class StringSchema(BaseModel):
    model_config = _FROM_ATTRS
    value: str
    offset: int
    encoding: str
    length: int


class StringsResponse(BaseModel):
    count: int
    strings: list[StringSchema]


class HexRowSchema(BaseModel):
    model_config = _FROM_ATTRS
    offset: int
    hex_bytes: list[str]
    ascii: str


class HexPageSchema(BaseModel):
    model_config = _FROM_ATTRS
    offset: int
    length: int
    total_size: int
    rows: list[HexRowSchema]


class EntropyWindowSchema(BaseModel):
    model_config = _FROM_ATTRS
    offset: int
    size: int
    entropy: float


class EntropyReportSchema(BaseModel):
    model_config = _FROM_ATTRS
    overall: float
    windows: list[EntropyWindowSchema]


class PackingIndicatorSchema(BaseModel):
    model_config = _FROM_ATTRS
    name: str
    detail: str
    weight: int


class PackingEvidenceSchema(BaseModel):
    model_config = _FROM_ATTRS
    source: str
    message: str
    provenance: str
    address: int | None = None
    file_offset: int | None = None
    function_address: int | None = None
    raw_value: str | None = None


class DetectedPackerSchema(BaseModel):
    model_config = _FROM_ATTRS
    name: str
    confidence: float
    evidence: list[PackingEvidenceSchema]


class PackingReportSchema(BaseModel):
    model_config = _FROM_ATTRS
    likely_packed: bool
    score: int
    detected_packer: str | None
    overall_entropy: float
    indicators: list[PackingIndicatorSchema]
    confidence: float
    detected_packers: list[DetectedPackerSchema]
    evidence: list[PackingEvidenceSchema]
    recommended_next_steps: list[str]


# --- Disassembler -----------------------------------------------------------------
class InstructionSchema(BaseModel):
    model_config = _FROM_ATTRS
    address: int
    mnemonic: str
    op_str: str
    bytes_hex: str
    size: int
    groups: list[str]
    text: str


class DisassemblySchema(BaseModel):
    model_config = _FROM_ATTRS
    start_address: int
    instruction_count: int
    truncated: bool
    instructions: list[InstructionSchema]


class BasicBlockSchema(BaseModel):
    model_config = _FROM_ATTRS
    id: int
    start_address: int
    end_address: int
    instructions: list[InstructionSchema]
    successors: list[int]
    is_loop_header: bool = False
    is_unreachable: bool = False
    immediate_dominator: int | None = None


class CfgEdgeSchema(BaseModel):
    model_config = _FROM_ATTRS
    source: int
    target: int | None
    kind: str
    instruction_address: int
    target_address: int | None = None


class CfgSchema(BaseModel):
    model_config = _FROM_ATTRS
    entry_address: int
    blocks: list[BasicBlockSchema]
    edges: list[tuple[int, int]]
    truncated: bool
    typed_edges: list[CfgEdgeSchema] = Field(default_factory=list)
    loop_headers: list[int] = Field(default_factory=list)
    unreachable_blocks: list[int] = Field(default_factory=list)


# --- Higher-level analysis --------------------------------------------------------
class EvidenceSchema(BaseModel):
    model_config = _FROM_ATTRS
    source: str
    message: str
    provenance: str
    address: int | None = None
    file_offset: int | None = None
    function_address: int | None = None
    raw_value: str | None = None


class FindingSchema(BaseModel):
    model_config = _FROM_ATTRS
    id: str
    category: str
    title: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: float
    summary: str
    evidence: list[EvidenceSchema]
    recommendations: list[str]
    false_positive_notes: list[str]
    technique: str | None = None
    address_start: int | None = None
    address_end: int | None = None
    related_function: int | None = None
    mitre_id: str | None = None


class FlowStageSchema(BaseModel):
    model_config = _FROM_ATTRS
    id: str
    title: str
    summary: str
    function_addresses: list[int]
    evidence: list[EvidenceSchema]
    confidence: float
    provenance: str


class ProgramFlowSummarySchema(BaseModel):
    model_config = _FROM_ATTRS
    entry_point: int
    stages: list[FlowStageSchema]
    major_branches: list[EvidenceSchema]
    failure_paths: list[EvidenceSchema]
    anti_analysis: list[EvidenceSchema]
    limitations: list[str]


class FunctionSchema(BaseModel):
    model_config = _FROM_ATTRS
    address: int
    name: str
    demangled_name: str | None
    size: int
    call_count: int
    callers: list[int]
    callees: list[int]
    cyclomatic_complexity: int
    basic_block_count: int
    instruction_count: int
    api_references: list[str]
    string_references: list[str]
    stack_frame_size: int | None
    arguments: list[str]
    return_type: str | None
    is_thunk: bool
    is_library: bool
    suspicious_score: int
    user_name: str | None
    user_comment: str | None
    confidence: float
    provenance: str
    evidence: list[EvidenceSchema]
    truncated: bool


class FunctionListSchema(BaseModel):
    items: list[FunctionSchema]
    total: int
    offset: int
    limit: int


class CallGraphNodeSchema(BaseModel):
    model_config = _FROM_ATTRS
    address: int
    name: str
    is_library: bool
    is_entry: bool
    suspicious_score: int
    provenance: str


class CallGraphEdgeSchema(BaseModel):
    model_config = _FROM_ATTRS
    source: int
    target: int
    kind: str
    call_sites: list[int]
    recursive: bool


class CallGraphSchema(BaseModel):
    model_config = _FROM_ATTRS
    nodes: list[CallGraphNodeSchema]
    edges: list[CallGraphEdgeSchema]
    root_address: int | None
    truncated: bool


class DecompiledVariableSchema(BaseModel):
    model_config = _FROM_ATTRS
    name: str
    type_name: str | None
    storage: str | None
    confidence: float
    provenance: str


class DecompiledParameterSchema(DecompiledVariableSchema):
    pass


class SourceMapEntrySchema(BaseModel):
    model_config = _FROM_ATTRS
    line: int
    address_start: int
    address_end: int
    confidence: float
    provenance: str


class DecompiledFunctionSchema(BaseModel):
    model_config = _FROM_ATTRS
    function_address: int
    function_name: str
    language: str
    code: str
    warnings: list[str]
    confidence: float
    variables: list[DecompiledVariableSchema]
    parameters: list[DecompiledParameterSchema]
    return_type: str | None
    source_map: list[SourceMapEntrySchema]
    provider: str
    elapsed_ms: int
    provenance: str


# --- Analyst overlays and projects -----------------------------------------------
class AnnotationWriteSchema(BaseModel):
    address: int = Field(ge=0)
    kind: Literal["function_name", "comment"]
    value: str = Field(min_length=1, max_length=8_192)


class AnnotationSchema(BaseModel):
    model_config = _FROM_ATTRS
    id: int
    binary_sha256: str
    address: int
    kind: str
    value: str
    created_at: datetime
    updated_at: datetime
    provenance: Literal["user"] = "user"


class BookmarkWriteSchema(BaseModel):
    address: int = Field(ge=0)
    label: str = Field(default="", max_length=160)
    note: str = Field(default="", max_length=8_192)


class BookmarkSchema(BaseModel):
    model_config = _FROM_ATTRS
    id: int
    binary_sha256: str
    address: int
    label: str
    note: str
    created_at: datetime


class ProjectCreateSchema(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=16_384)


class ProjectPatchSchema(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=16_384)


class ProjectSchema(BaseModel):
    model_config = _FROM_ATTRS
    id: str
    name: str
    description: str
    created_at: datetime
    updated_at: datetime
    sample_sha256: list[str] = Field(default_factory=list)


class TransformRequestSchema(BaseModel):
    operation: Literal[
        "hex_decode",
        "hex_encode",
        "base64_decode",
        "base64_encode",
        "url_decode",
        "url_encode",
        "xor_single",
        "xor_repeating",
        "add",
        "sub",
        "rol",
        "ror",
        "utf16_decode",
        "escaped_bytes",
        "stack_string",
    ]
    input: str = Field(max_length=1_048_576)
    parameters: dict[str, str | int | bool] = Field(default_factory=dict)


class TransformResultSchema(BaseModel):
    model_config = _FROM_ATTRS
    operation: str
    text: str
    bytes_hex: str
    warnings: list[str]
    python_snippet: str


class UnpackRequestSchema(BaseModel):
    acknowledged: Literal[True]


class SectionChangeSchema(BaseModel):
    model_config = _FROM_ATTRS
    name: str
    original_size: int | None
    unpacked_size: int | None


class UnpackResultSchema(BaseModel):
    provider: str
    artifact_id: str
    original_sha256: str
    unpacked_sha256: str
    original_size: int
    unpacked_size: int
    section_changes: list[SectionChangeSchema]
    warnings: list[str]


class ArtifactSchema(BaseModel):
    id: str
    binary_sha256: str
    kind: str
    content_sha256: str
    size: int
    metadata: dict[str, object]
    created_at: datetime


class ToolingStatusSchema(BaseModel):
    name: str
    category: str
    available: bool
    detail: str
    capabilities: list[str] = Field(default_factory=list)


# --- Challenges -------------------------------------------------------------------
class ChallengeSchema(BaseModel):
    model_config = _FROM_ATTRS
    slug: str
    title: str
    category: str
    difficulty: str
    description: str
    hint: str
    artifact_filename: str
    artifact_size: int


class ChallengeSubmission(BaseModel):
    answer: str = Field(min_length=1, max_length=512)


class ChallengeResultSchema(BaseModel):
    model_config = _FROM_ATTRS
    slug: str
    correct: bool
    message: str


# --- Integrations -----------------------------------------------------------------
class IntegrationInfoSchema(BaseModel):
    model_config = _FROM_ATTRS
    name: str
    available: bool
    version: str | None = None
    detail: str


class IntegrationResultSchema(BaseModel):
    model_config = _FROM_ATTRS
    name: str
    summary: str
    functions: list[str]
    data: dict[str, str]
