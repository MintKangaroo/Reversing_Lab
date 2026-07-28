"""Pydantic response/request schemas for the HTTP API.

These mirror the analysis-core dataclasses field-for-field and are built from them with
``model_validate(obj, from_attributes=True)``. Keeping them separate from the core
models means the wire format is an explicit, versionable contract rather than an
accidental reflection of internal types.
"""

from __future__ import annotations

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


class PackingReportSchema(BaseModel):
    model_config = _FROM_ATTRS
    likely_packed: bool
    score: int
    detected_packer: str | None
    overall_entropy: float
    indicators: list[PackingIndicatorSchema]


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


class CfgSchema(BaseModel):
    model_config = _FROM_ATTRS
    entry_address: int
    blocks: list[BasicBlockSchema]
    edges: list[tuple[int, int]]
    truncated: bool


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
