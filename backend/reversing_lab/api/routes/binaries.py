"""Binary upload and per-view analysis endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Query, UploadFile

from ...analyzer import detect_packing, entropy_profile, extract_strings, hex_page
from ...config import get_settings
from ...database import BinaryRepository
from ...disassembler import build_cfg, disassemble
from ...errors import UnsupportedFormatError
from ...integrations import get_adapter
from ...parser import detect_format
from ..dependencies import get_binary_repository
from ..schemas import (
    BinaryInfoSchema,
    BinarySummarySchema,
    CfgSchema,
    DisassemblySchema,
    EntropyReportSchema,
    HexPageSchema,
    IntegrationResultSchema,
    PackingReportSchema,
    StringSchema,
    StringsResponse,
)
from ..services import parse_cached

router = APIRouter(prefix="/binaries", tags=["binaries"])


def _load(repo: BinaryRepository, sha256: str):
    """Load stored bytes + cached parse for ``sha256`` (raises if unknown)."""
    data = repo.load_bytes(sha256)
    return data, parse_cached(sha256, data)


@router.post("", response_model=BinarySummarySchema, status_code=201)
async def upload_binary(
    file: UploadFile = File(...),
    repo: BinaryRepository = Depends(get_binary_repository),
) -> BinarySummarySchema:
    """Upload a binary. Validates size and format before persisting."""
    settings = get_settings()
    data = await file.read()

    if len(data) > settings.max_upload_bytes:
        raise UnsupportedFormatError(
            f"File exceeds the {settings.max_upload_bytes}-byte upload limit."
        )
    # Reject unsupported formats up front (raises UnsupportedFormatError -> HTTP 415).
    fmt = detect_format(data)

    record = repo.save(data, filename=file.filename or "upload.bin", binary_format=fmt.value)
    return BinarySummarySchema.model_validate(record)


@router.get("", response_model=list[BinarySummarySchema])
def list_binaries(
    repo: BinaryRepository = Depends(get_binary_repository),
) -> list[BinarySummarySchema]:
    """List recently uploaded binaries, newest first."""
    return [BinarySummarySchema.model_validate(r) for r in repo.list()]


@router.get("/{sha256}/info", response_model=BinaryInfoSchema)
def binary_info(
    sha256: str, repo: BinaryRepository = Depends(get_binary_repository)
) -> BinaryInfoSchema:
    """Full normalized metadata: header, sections, symbols, imports, exports."""
    _, info = _load(repo, sha256)
    return BinaryInfoSchema.model_validate(info)


@router.get("/{sha256}/strings", response_model=StringsResponse)
def binary_strings(
    sha256: str,
    min_length: int = Query(4, ge=1, le=64),
    limit: int = Query(2000, ge=1, le=10000),
    repo: BinaryRepository = Depends(get_binary_repository),
) -> StringsResponse:
    """Extract ASCII/UTF-16LE strings."""
    data, _ = _load(repo, sha256)
    found = extract_strings(data, min_length=min_length, max_results=limit)
    return StringsResponse(
        count=len(found),
        strings=[StringSchema.model_validate(s) for s in found],
    )


@router.get("/{sha256}/hex", response_model=HexPageSchema)
def binary_hex(
    sha256: str,
    offset: int = Query(0, ge=0),
    length: int = Query(1024, ge=1, le=65536),
    repo: BinaryRepository = Depends(get_binary_repository),
) -> HexPageSchema:
    """Paged hex dump."""
    data, _ = _load(repo, sha256)
    return HexPageSchema.model_validate(hex_page(data, offset=offset, length=length))


@router.get("/{sha256}/entropy", response_model=EntropyReportSchema)
def binary_entropy(
    sha256: str,
    window: int = Query(4096, ge=64, le=65536),
    repo: BinaryRepository = Depends(get_binary_repository),
) -> EntropyReportSchema:
    """Whole-file and windowed entropy profile."""
    data, _ = _load(repo, sha256)
    return EntropyReportSchema.model_validate(entropy_profile(data, window_size=window))


@router.get("/{sha256}/packing", response_model=PackingReportSchema)
def binary_packing(
    sha256: str, repo: BinaryRepository = Depends(get_binary_repository)
) -> PackingReportSchema:
    """Packer/obfuscation detection with rationale."""
    data, info = _load(repo, sha256)
    return PackingReportSchema.model_validate(detect_packing(info, data))


@router.get("/{sha256}/disassembly", response_model=DisassemblySchema)
def binary_disassembly(
    sha256: str,
    address: int | None = Query(None, ge=0),
    count: int = Query(200, ge=1, le=20000),
    repo: BinaryRepository = Depends(get_binary_repository),
) -> DisassemblySchema:
    """Linear disassembly starting at ``address`` (defaults to the entry point)."""
    data, info = _load(repo, sha256)
    return DisassemblySchema.model_validate(
        disassemble(info, data, address=address, count=count)
    )


@router.get("/{sha256}/cfg", response_model=CfgSchema)
def binary_cfg(
    sha256: str,
    address: int | None = Query(None, ge=0),
    repo: BinaryRepository = Depends(get_binary_repository),
) -> CfgSchema:
    """Control-flow graph for the function at ``address`` (defaults to the entry point)."""
    data, info = _load(repo, sha256)
    return CfgSchema.model_validate(build_cfg(info, data, address=address))


@router.post("/{sha256}/integrations/{name}", response_model=IntegrationResultSchema)
def run_integration(
    sha256: str, name: str, repo: BinaryRepository = Depends(get_binary_repository)
) -> IntegrationResultSchema:
    """Run an external-tool integration (radare2/ghidra/binary_ninja) on the binary."""
    record = repo.get(sha256)
    adapter = get_adapter(name)  # raises IntegrationUnavailableError (503) if unknown
    result = adapter.analyze(record.storage_path)
    return IntegrationResultSchema.model_validate(result)
