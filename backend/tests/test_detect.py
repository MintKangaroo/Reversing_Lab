"""Format-detection tests."""

from __future__ import annotations

import pytest

from reversing_lab.errors import UnsupportedFormatError
from reversing_lab.parser import BinaryFormat, detect_format


def test_detect_elf(elf_bytes: bytes) -> None:
    assert detect_format(elf_bytes) is BinaryFormat.ELF


def test_detect_pe(pe_bytes: bytes) -> None:
    assert detect_format(pe_bytes) is BinaryFormat.PE


def test_detect_macho(macho_bytes: bytes) -> None:
    assert detect_format(macho_bytes) is BinaryFormat.MACHO


def test_reject_short_input() -> None:
    with pytest.raises(UnsupportedFormatError):
        detect_format(b"MZ")


def test_reject_plain_text() -> None:
    with pytest.raises(UnsupportedFormatError):
        detect_format(b"this is just some text, not an executable at all")


def test_reject_mz_without_pe_signature() -> None:
    # DOS "MZ" header but no valid PE signature at e_lfanew.
    blob = b"MZ" + b"\x00" * 0x3A + b"\x80\x00\x00\x00" + b"\x00" * 0x40
    with pytest.raises(UnsupportedFormatError):
        detect_format(blob)
