"""Bounded multipart helpers.

Uploaded filenames are display metadata only. Storage repositories derive every
filesystem path from a server-computed content hash.
"""

from __future__ import annotations

import re
from pathlib import PurePath

from fastapi import HTTPException, UploadFile

_CHUNK_SIZE = 1024 * 1024
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


async def read_upload_limited(file: UploadFile, limit: int, label: str) -> bytes:
    """Read at most ``limit`` bytes without buffering an unbounded request body."""
    if limit < 1:
        raise RuntimeError("Upload limit must be positive.")
    chunks: list[bytes] = []
    received = 0
    while True:
        chunk = await file.read(min(_CHUNK_SIZE, limit - received + 1))
        if not chunk:
            break
        received += len(chunk)
        if received > limit:
            raise HTTPException(
                status_code=413,
                detail=f"{label} exceeds the configured {limit}-byte limit.",
            )
        chunks.append(chunk)
    return b"".join(chunks)


def safe_display_filename(filename: str | None, fallback: str) -> str:
    """Return a bounded basename for UI display; never use it as a disk path."""
    candidate = (filename or "").replace("\\", "/")
    candidate = PurePath(candidate).name
    candidate = _CONTROL_CHARACTERS.sub("", candidate).strip()
    return candidate[:255] or fallback
