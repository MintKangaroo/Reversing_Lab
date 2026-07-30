"""Function analysis, call graph, annotations, and bookmarks."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from ...analysis import build_call_graph, get_function
from ...database import AnnotationRepository, BinaryRepository, BookmarkRepository
from ...config import get_settings
from ...decompiler import DecompileOptions, decompile_function
from ...disassembler import disassemble
from ..dependencies import (
    get_annotation_repository,
    get_binary_repository,
    get_bookmark_repository,
)
from ..schemas import (
    AnnotationSchema,
    AnnotationWriteSchema,
    BookmarkSchema,
    BookmarkWriteSchema,
    CallGraphSchema,
    DisassemblySchema,
    DecompiledFunctionSchema,
    FunctionListSchema,
    FunctionSchema,
)
from ..services import functions_cached, parse_cached

router = APIRouter(prefix="/binaries", tags=["function-analysis"])


def parse_address(value: str) -> int:
    """Parse a decimal or `0x` address without accepting signs or loose syntax."""
    candidate = value.strip().lower()
    base = 16 if candidate.startswith("0x") else 10
    digits = candidate[2:] if base == 16 else candidate
    if not digits or any(character not in ("0123456789abcdef" if base == 16 else "0123456789") for character in digits):
        raise HTTPException(status_code=422, detail=f"Malformed address: {value!r}.")
    try:
        address = int(digits, base)
    except ValueError as exc:  # defensive; character validation should catch this
        raise HTTPException(status_code=422, detail=f"Malformed address: {value!r}.") from exc
    if address < 0 or address > (2**64 - 1):
        raise HTTPException(status_code=422, detail="Address is outside the unsigned 64-bit range.")
    return address


def _load(repo: BinaryRepository, sha256: str):
    data = repo.load_bytes(sha256)
    info = parse_cached(sha256, data)
    return data, info, functions_cached(sha256, info, data)


def _with_annotations(functions, records):
    by_target = {(record.address, record.kind): record.value for record in records}
    return tuple(
        replace(
            function,
            user_name=by_target.get((function.address, "function_name")),
            user_comment=by_target.get((function.address, "comment")),
        )
        for function in functions
    )


@router.get("/{sha256}/functions", response_model=FunctionListSchema)
def list_functions(
    sha256: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=1_000),
    repo: BinaryRepository = Depends(get_binary_repository),
    annotations: AnnotationRepository = Depends(get_annotation_repository),
) -> FunctionListSchema:
    _, _, functions = _load(repo, sha256)
    overlaid = _with_annotations(functions, annotations.list(sha256))
    page = overlaid[offset : offset + limit]
    return FunctionListSchema(
        items=[FunctionSchema.model_validate(function) for function in page],
        total=len(overlaid),
        offset=offset,
        limit=limit,
    )


@router.get("/{sha256}/callgraph", response_model=CallGraphSchema)
def call_graph(
    sha256: str,
    root: str | None = Query(default=None),
    depth: int = Query(default=3, ge=0, le=12),
    repo: BinaryRepository = Depends(get_binary_repository),
    annotations: AnnotationRepository = Depends(get_annotation_repository),
) -> CallGraphSchema:
    _, _, functions = _load(repo, sha256)
    functions = _with_annotations(functions, annotations.list(sha256))
    root_address = parse_address(root) if root is not None else None
    return CallGraphSchema.model_validate(
        build_call_graph(functions, root_address=root_address, depth=depth)
    )


@router.get("/{sha256}/functions/{address}/disassembly", response_model=DisassemblySchema)
def function_disassembly(
    sha256: str,
    address: str,
    repo: BinaryRepository = Depends(get_binary_repository),
) -> DisassemblySchema:
    data, info, functions = _load(repo, sha256)
    function = get_function(functions, parse_address(address))
    return DisassemblySchema.model_validate(
        disassemble(
            info,
            data,
            address=function.address,
            count=max(function.instruction_count, 1),
        )
    )


@router.get(
    "/{sha256}/functions/{address}/decompile",
    response_model=DecompiledFunctionSchema,
)
def function_decompile(
    sha256: str,
    address: str,
    provider: str = Query(
        default="auto", pattern="^(auto|ghidra|pseudo_c)$"
    ),
    repo: BinaryRepository = Depends(get_binary_repository),
) -> DecompiledFunctionSchema:
    _, _, functions = _load(repo, sha256)
    function = get_function(functions, parse_address(address))
    settings = get_settings()
    record = repo.get(sha256)
    result = decompile_function(
        binary_path=Path(record.storage_path),
        address=function.address,
        provider=provider,
        options=DecompileOptions(
            timeout_seconds=settings.max_decompiler_seconds,
            max_output_bytes=settings.max_external_output_bytes,
        ),
    )
    return DecompiledFunctionSchema.model_validate(result)


@router.get("/{sha256}/functions/{address}", response_model=FunctionSchema)
def function_detail(
    sha256: str,
    address: str,
    repo: BinaryRepository = Depends(get_binary_repository),
    annotations: AnnotationRepository = Depends(get_annotation_repository),
) -> FunctionSchema:
    _, _, functions = _load(repo, sha256)
    function = get_function(functions, parse_address(address))
    overlaid = _with_annotations((function,), annotations.list(sha256, function.address))[0]
    return FunctionSchema.model_validate(overlaid)


@router.get("/{sha256}/annotations", response_model=list[AnnotationSchema])
def list_annotations(
    sha256: str,
    repo: BinaryRepository = Depends(get_binary_repository),
    annotations: AnnotationRepository = Depends(get_annotation_repository),
) -> list[AnnotationSchema]:
    repo.get(sha256)
    return [AnnotationSchema.model_validate(item) for item in annotations.list(sha256)]


@router.post("/{sha256}/annotations", response_model=AnnotationSchema)
def save_annotation(
    sha256: str,
    payload: AnnotationWriteSchema,
    repo: BinaryRepository = Depends(get_binary_repository),
    annotations: AnnotationRepository = Depends(get_annotation_repository),
) -> AnnotationSchema:
    repo.get(sha256)
    record = annotations.upsert(sha256, payload.address, payload.kind, payload.value)
    return AnnotationSchema.model_validate(record)


@router.get("/{sha256}/bookmarks", response_model=list[BookmarkSchema])
def list_bookmarks(
    sha256: str,
    repo: BinaryRepository = Depends(get_binary_repository),
    bookmarks: BookmarkRepository = Depends(get_bookmark_repository),
) -> list[BookmarkSchema]:
    repo.get(sha256)
    return [BookmarkSchema.model_validate(item) for item in bookmarks.list(sha256)]


@router.post("/{sha256}/bookmarks", response_model=BookmarkSchema)
def save_bookmark(
    sha256: str,
    payload: BookmarkWriteSchema,
    repo: BinaryRepository = Depends(get_binary_repository),
    bookmarks: BookmarkRepository = Depends(get_bookmark_repository),
) -> BookmarkSchema:
    repo.get(sha256)
    record = bookmarks.upsert(
        sha256, payload.address, payload.label, payload.note
    )
    return BookmarkSchema.model_validate(record)


@router.delete("/{sha256}/bookmarks/{address}", status_code=204)
def delete_bookmark(
    sha256: str,
    address: str,
    repo: BinaryRepository = Depends(get_binary_repository),
    bookmarks: BookmarkRepository = Depends(get_bookmark_repository),
) -> Response:
    repo.get(sha256)
    bookmarks.delete(sha256, parse_address(address))
    return Response(status_code=204)
