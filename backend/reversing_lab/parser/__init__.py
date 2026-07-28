"""Binary parsing: format detection and normalization into :mod:`.models`."""

from __future__ import annotations

from .detect import detect_format
from .factory import get_parser, parse_binary
from .models import (
    Architecture,
    BinaryFormat,
    BinaryInfo,
    Export,
    Import,
    Section,
    Symbol,
)

__all__ = [
    "Architecture",
    "BinaryFormat",
    "BinaryInfo",
    "Export",
    "Import",
    "Section",
    "Symbol",
    "detect_format",
    "get_parser",
    "parse_binary",
]
