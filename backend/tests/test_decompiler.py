"""Decompiler protocol, fallback pseudo-C, and graceful degradation."""

from __future__ import annotations

from pathlib import Path

from reversing_lab.challenge.elfbuilder import build_elf64
from reversing_lab.decompiler import DecompileOptions, decompile_function
from reversing_lab.decompiler.ghidra import GhidraDecompilerAdapter


def _conditional_fixture() -> bytes:
    # cmp edi, 0xa; je target; mov eax, 0; ret; mov eax, 1; ret
    return build_elf64(code=bytes.fromhex("83ff0a7406b800000000c3b801000000c3"))


def test_fallback_pseudo_c_has_warning_and_source_map(tmp_path: Path) -> None:
    sample = tmp_path / "sample"
    sample.write_bytes(_conditional_fixture())
    result = decompile_function(
        sample, 0x401000, DecompileOptions(), provider="pseudo_c"
    )
    assert result.provider == "pseudo_c"
    assert "not the original source code" in result.code
    assert "if (arg0 ==" in result.code
    assert "return result" in result.code
    assert result.confidence < 0.5
    assert result.source_map
    assert all(item.address_start >= 0x401000 for item in result.source_map)


def test_auto_falls_back_when_ghidra_is_unavailable(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    sample = tmp_path / "sample"
    sample.write_bytes(_conditional_fixture())
    result = decompile_function(sample, 0x401000)
    assert result.provider == "pseudo_c"
    assert any("ghidra is unavailable" in warning for warning in result.warnings)
    assert GhidraDecompilerAdapter().is_available() is False


def test_decompile_api_returns_estimated_code(api_client) -> None:
    data = _conditional_fixture()
    uploaded = api_client.post(
        "/api/binaries", files={"file": ("conditional.elf", data)}
    )
    sha256 = uploaded.json()["sha256"]
    response = api_client.get(
        f"/api/binaries/{sha256}/functions/0x401000/decompile?provider=pseudo_c"
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["provider"] == "pseudo_c"
    assert body["language"] == "C-like"
    assert body["provenance"] == "inferred"
    assert body["source_map"]
