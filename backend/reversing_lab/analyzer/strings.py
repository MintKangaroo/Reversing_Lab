"""String extraction (ASCII and UTF-16LE).

Mirrors the classic ``strings(1)`` utility but also recovers wide (UTF-16LE) strings,
which are pervasive in PE binaries, and records each hit's file offset and encoding so
the UI can cross-reference them with the hex view.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Printable ASCII run of at least ``min_length`` characters.
_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}")
# UTF-16LE: printable ASCII byte followed by a NUL, repeated.
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}")


@dataclass(frozen=True, slots=True)
class ExtractedString:
    """A recovered string with its location and encoding."""

    value: str
    offset: int
    encoding: str  # "ascii" | "utf-16le"
    length: int


def extract_strings(
    data: bytes,
    min_length: int = 4,
    max_results: int = 10_000,
) -> list[ExtractedString]:
    """Extract printable ASCII and UTF-16LE strings from ``data``.

    Results are sorted by file offset. At most ``max_results`` strings are returned
    (a bound that protects the API from pathological inputs); ``min_length`` is the
    minimum run length, in characters, for a match.
    """
    if min_length < 1:
        raise ValueError("min_length must be at least 1.")

    results: list[ExtractedString] = []

    ascii_re = re.compile(_ASCII_RE.pattern % min_length)
    for match in ascii_re.finditer(data):
        results.append(
            ExtractedString(
                value=match.group().decode("ascii"),
                offset=match.start(),
                encoding="ascii",
                length=len(match.group()),
            )
        )

    utf16_re = re.compile(_UTF16_RE.pattern % min_length)
    for match in utf16_re.finditer(data):
        raw = match.group()
        results.append(
            ExtractedString(
                value=raw.decode("utf-16-le"),
                offset=match.start(),
                encoding="utf-16le",
                length=len(raw) // 2,
            )
        )

    results.sort(key=lambda item: (item.offset, item.encoding))
    return results[:max_results]
