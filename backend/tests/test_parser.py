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


# --- mitigation / provenance metadata --------------------------------------------
def test_elf_mitigations_negative_and_undetermined(elf_bytes: bytes) -> None:
    m = parse_binary(elf_bytes).mitigations
    assert m.stack_canary is False  # no __stack_chk_* in the minimal fixture.
    assert m.control_flow_guard is None  # no GNU property note -> undetermined, not False.
    assert m.signed is None  # ELF has no code-signing scheme.
    assert m.has_debug_info is False
    assert m.build_id is None
    assert m.tls is False
    assert m.overlay_size == 0


def test_pe_mitigations_from_dll_characteristics(pe_bytes: bytes) -> None:
    m = parse_binary(pe_bytes).mitigations
    # The fixture's DllCharacteristics (0x8160) set NX/DYNAMIC_BASE but not GUARD_CF,
    # so CFG is a confirmed False (checked, absent) rather than undetermined.
    assert m.control_flow_guard is False
    assert m.signed is False
    assert m.stack_canary is False
    assert m.overlay_size == 0


def test_macho_mitigations_parity(macho_bytes: bytes) -> None:
    m = parse_binary(macho_bytes).mitigations
    # Populated for Mach-O: signing, canary (via symbols), UUID build id, overlay.
    assert m.signed is False  # no LC_CODE_SIGNATURE in the fixture.
    assert m.stack_canary is False  # no __stack_chk_* symbol.
    assert m.build_id is None  # no LC_UUID in the fixture.
    assert m.has_debug_info is False  # no __DWARF segment.
    # The fixture appends 0x100 trailing bytes past the mapped segments.
    assert m.overlay_size == 0x100
    # Control Flow Guard / TLS have no reliable Mach-O signal -> not applicable.
    assert m.control_flow_guard is None
    assert m.tls is None


def test_macho_uuid_and_canary_helpers() -> None:
    from reversing_lab.parser.macho_parser import _macho_mitigations, _macho_uuid

    class _UuidBinary:
        has_uuid = True
        uuid = [0xDE, 0xAD, 0xBE, 0xEF]
        has_code_signature = True
        sections = []

        @property
        def overlay(self):
            return b""

    binary = _UuidBinary()
    assert _macho_uuid(binary) == "deadbeef"
    m = _macho_mitigations(binary, {"_main", "__stack_chk_fail"})
    assert m.stack_canary is True
    assert m.signed is True
    assert m.build_id == "deadbeef"


def test_elf_build_id_and_canary_helpers() -> None:
    # Positive coverage without a hand-crafted note-bearing ELF: drive the helpers with
    # duck-typed stubs mirroring the LIEF surface they read.
    from reversing_lab.parser.elf_parser import _elf_build_id, _elf_has_stack_canary

    class _Note:
        type = "TYPE.GNU_BUILD_ID"
        description = b"\xde\xad\xbe\xef"

    class _Sym:
        def __init__(self, name):
            self.name = name

    build_binary = type("B", (), {"notes": [_Note()]})()
    assert _elf_build_id(build_binary) == "deadbeef"

    canary_binary = type(
        "B", (), {"symbols": [_Sym("__stack_chk_fail")], "dynamic_symbols": []}
    )()
    assert _elf_has_stack_canary(canary_binary) is True


def test_mitigation_helpers_never_raise_on_hostile_binary() -> None:
    # Every attribute access on a binary whose LIEF surface misbehaves must degrade to a
    # safe default, never propagate out of the parse.
    from reversing_lab.parser.elf_parser import _elf_mitigations
    from reversing_lab.parser.pe_parser import _pe_mitigations

    class _Hostile:
        def __getattr__(self, name):
            raise RuntimeError("boom")

    elf_m = _elf_mitigations(_Hostile())
    assert elf_m.overlay_size == 0 and elf_m.build_id is None
    pe_m = _pe_mitigations(_Hostile(), set(), (), [])
    assert pe_m.overlay_size == 0 and pe_m.signed is False


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
