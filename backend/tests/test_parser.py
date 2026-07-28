"""Parser tests across all three formats."""

from __future__ import annotations

import pytest

from reversing_lab.errors import ParseError, UnsupportedFormatError
from reversing_lab.parser import Architecture, BinaryFormat, parse_binary
from reversing_lab.parser.base import normalize_arch


def test_parse_elf(elf_bytes: bytes) -> None:
    info = parse_binary(elf_bytes)
    assert info.binary_format is BinaryFormat.ELF
    assert info.architecture is Architecture.X86_64
    assert info.bits == 64
    assert info.endianness == "little"
    assert info.entry_point == 0x401000
    assert info.file_size == len(elf_bytes)
    assert len(info.sha256) == 64
    names = {section.name for section in info.sections}
    assert ".text" in names
    text = next(s for s in info.sections if s.name == ".text")
    assert text.contains_code is True


def test_parse_pe(pe_bytes: bytes) -> None:
    info = parse_binary(pe_bytes)
    assert info.binary_format is BinaryFormat.PE
    assert info.architecture is Architecture.X86_64
    assert info.bits == 64
    assert info.has_nx is True  # NX_COMPAT set in the fixture.
    assert info.entry_point == 0x140001000
    assert info.extra["subsystem"] == "WINDOWS_CUI"


def test_parse_macho(macho_bytes: bytes) -> None:
    info = parse_binary(macho_bytes)
    assert info.binary_format is BinaryFormat.MACHO
    assert info.architecture is Architecture.X86_64
    assert info.is_pie is True  # MH_PIE flag set in the fixture.
    assert any(section.contains_code for section in info.sections)


def test_arch_x86_64_not_shadowed_by_x86() -> None:
    # Regression: "X86" is a substring of "X86_64"; the specific token must win.
    assert normalize_arch("ARCH.X86_64") == (Architecture.X86_64, 64)
    assert normalize_arch("ARCH.I386") == (Architecture.X86, 32)


def test_unknown_arch_degrades() -> None:
    assert normalize_arch("ARCH.SPARC") == (Architecture.UNKNOWN, 0)


def test_parse_unsupported_raises() -> None:
    with pytest.raises(UnsupportedFormatError):
        parse_binary(b"not an executable, just text bytes here")


def test_parse_truncated_elf_degrades_gracefully(elf_bytes: bytes) -> None:
    # LIEF is intentionally tolerant of malformed inputs (useful for RE), so a
    # corrupt header must not crash: either it raises a typed ParseError or it returns
    # a degraded BinaryInfo with an UNKNOWN architecture — never an unhandled exception.
    truncated = elf_bytes[:8] + b"\x00" * 8
    try:
        info = parse_binary(truncated)
    except (ParseError, UnsupportedFormatError):
        return
    assert info.architecture is Architecture.UNKNOWN


def test_parse_bare_magic_never_crashes() -> None:
    # A bare ELF magic with no header body must be handled cleanly: a typed error or a
    # degraded, UNKNOWN-architecture result — but never an unhandled native exception.
    try:
        info = parse_binary(b"\x7fELF")
    except (ParseError, UnsupportedFormatError):
        return
    assert info.architecture is Architecture.UNKNOWN
