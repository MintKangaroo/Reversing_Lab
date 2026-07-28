"""Analyzer tests: strings, hex, entropy, packing."""

from __future__ import annotations

import pytest

from reversing_lab.analyzer import (
    detect_packing,
    entropy_profile,
    extract_strings,
    hex_page,
    shannon_entropy,
)
from reversing_lab.parser import parse_binary


def test_extract_ascii_string(elf_bytes: bytes) -> None:
    values = [s.value for s in extract_strings(elf_bytes, min_length=5)]
    assert "hello reversing lab" in values


def test_extract_utf16_string() -> None:
    data = b"\x00\x01" + "WIDE".encode("utf-16-le") + b"\xff\xfe"
    results = extract_strings(data, min_length=4)
    assert any(s.encoding == "utf-16le" and s.value == "WIDE" for s in results)


def test_strings_respect_min_length() -> None:
    data = b"ab\x00abcdef\x00"
    assert [s.value for s in extract_strings(data, min_length=4)] == ["abcdef"]


def test_strings_are_bounded() -> None:
    data = (b"AAAA\x00") * 100
    assert len(extract_strings(data, min_length=4, max_results=10)) == 10


def test_shannon_entropy_bounds() -> None:
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 256) == 0.0
    assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)


def test_entropy_profile_windows() -> None:
    report = entropy_profile(b"\x00" * 10000, window_size=4096)
    assert report.overall == 0.0
    assert len(report.windows) == 3  # 4096 + 4096 + 1808


def test_hex_page_layout(elf_bytes: bytes) -> None:
    page = hex_page(elf_bytes, offset=0, length=16)
    assert page.total_size == len(elf_bytes)
    assert page.rows[0].offset == 0
    assert page.rows[0].hex_bytes[0] == "7f"  # ELF magic
    assert page.rows[0].ascii[1:4] == "ELF"


def test_hex_page_clamps_offset(elf_bytes: bytes) -> None:
    page = hex_page(elf_bytes, offset=10**9, length=16)
    assert page.length == 0
    assert page.rows == ()


def test_hex_page_rejects_bad_length(elf_bytes: bytes) -> None:
    with pytest.raises(ValueError):
        hex_page(elf_bytes, offset=0, length=0)


def test_packing_flags_high_entropy_upx_section() -> None:
    from reversing_lab.challenge import get_registry

    _, artifact = get_registry().artifact("packing-detection")
    info = parse_binary(artifact)
    report = detect_packing(info, artifact)
    assert report.likely_packed is True
    assert report.detected_packer == "UPX"


def test_packing_clean_binary(elf_bytes: bytes) -> None:
    info = parse_binary(elf_bytes)
    report = detect_packing(info, elf_bytes)
    assert report.likely_packed is False
