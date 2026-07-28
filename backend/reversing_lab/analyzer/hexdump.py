"""Paged hex viewer.

Produces the canonical ``offset | hex bytes | ascii`` rows, one page at a time, so the
front-end can lazily scroll a large file without ever transferring the whole thing.
"""

from __future__ import annotations

from dataclasses import dataclass

_BYTES_PER_ROW = 16


@dataclass(frozen=True, slots=True)
class HexRow:
    """One 16-byte row of the hex dump."""

    offset: int
    hex_bytes: tuple[str, ...]  # up to 16 two-char hex strings
    ascii: str  # printable rendering, '.' for non-printable


@dataclass(frozen=True, slots=True)
class HexPage:
    """A page of hex rows plus pagination metadata."""

    offset: int
    length: int
    total_size: int
    rows: tuple[HexRow, ...]


def _ascii_render(chunk: bytes) -> str:
    return "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)


def hex_page(data: bytes, offset: int = 0, length: int = 1024) -> HexPage:
    """Return the hex dump of ``data[offset : offset + length]`` as rows.

    ``offset`` is clamped to the file bounds and ``length`` must be positive. Rows are
    16 bytes wide; the final row of the page may be shorter.
    """
    if offset < 0:
        raise ValueError("offset must be non-negative.")
    if length <= 0:
        raise ValueError("length must be a positive integer.")

    total = len(data)
    start = min(offset, total)
    end = min(start + length, total)
    window = data[start:end]

    rows: list[HexRow] = []
    for row_start in range(0, len(window), _BYTES_PER_ROW):
        chunk = window[row_start : row_start + _BYTES_PER_ROW]
        rows.append(
            HexRow(
                offset=start + row_start,
                hex_bytes=tuple(f"{b:02x}" for b in chunk),
                ascii=_ascii_render(chunk),
            )
        )

    return HexPage(
        offset=start,
        length=len(window),
        total_size=total,
        rows=tuple(rows),
    )
