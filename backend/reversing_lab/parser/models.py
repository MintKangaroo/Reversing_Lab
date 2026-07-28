"""Normalized, backend-agnostic representation of a parsed binary.

These frozen dataclasses are the shared vocabulary of the whole platform. Parsers
translate LIEF/pefile/pyelftools objects *into* these types; every other module
(analyzer, disassembler, api schemas) depends only on these — never on a parsing
library's own classes. This is the seam that keeps the core decoupled from its
backends (Dependency Inversion Principle).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class BinaryFormat(str, Enum):
    """Supported executable container formats."""

    ELF = "ELF"
    PE = "PE"
    MACHO = "Mach-O"


class Architecture(str, Enum):
    """CPU architecture, normalized across formats."""

    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    PPC = "ppc"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Section:
    """A section/segment of the binary image."""

    name: str
    virtual_address: int
    size: int
    offset: int
    entropy: float
    flags: tuple[str, ...] = ()
    contains_code: bool = False


@dataclass(frozen=True, slots=True)
class Symbol:
    """A symbol from the symbol/dynamic-symbol table."""

    name: str
    value: int
    size: int
    kind: str  # e.g. "function", "object", "section", "notype"
    binding: str  # e.g. "global", "local", "weak"
    is_exported: bool = False
    is_imported: bool = False


@dataclass(frozen=True, slots=True)
class Import:
    """An imported symbol, optionally attributed to a library."""

    name: str
    library: str | None = None
    address: int | None = None


@dataclass(frozen=True, slots=True)
class Export:
    """An exported symbol."""

    name: str
    address: int
    ordinal: int | None = None


@dataclass(frozen=True, slots=True)
class BinaryInfo:
    """Everything the parser extracts about a binary, in normalized form."""

    binary_format: BinaryFormat
    architecture: Architecture
    bits: int  # 32 or 64
    endianness: str  # "little" | "big"
    entry_point: int
    is_pie: bool
    has_nx: bool
    has_relro: bool
    file_size: int
    sha256: str
    sections: tuple[Section, ...] = ()
    symbols: tuple[Symbol, ...] = ()
    imports: tuple[Import, ...] = ()
    exports: tuple[Export, ...] = ()
    # Format-specific extras that don't fit the common model (e.g. PE subsystem).
    extra: dict[str, str] = field(default_factory=dict)
