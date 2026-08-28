"""Decompiler protocol, fallback pseudo-C, and graceful degradation."""

from __future__ import annotations

from pathlib import Path

import pytest

from reversing_lab.challenge.elfbuilder import build_elf64
from reversing_lab.decompiler import DecompileOptions, decompile_function, list_decompilers
from reversing_lab.decompiler import r2ghidra as r2ghidra_mod
from reversing_lab.decompiler import retdec as retdec_mod
from reversing_lab.decompiler.ghidra import GhidraDecompilerAdapter
from reversing_lab.decompiler.r2ghidra import R2GhidraDecompilerAdapter
from reversing_lab.decompiler.retdec import RetDecDecompilerAdapter
from reversing_lab.errors import IntegrationUnavailableError


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


# --- external decompiler adapters (r2ghidra, RetDec) ------------------------------
def test_new_providers_are_registered() -> None:
    names = {info.name for info in list_decompilers()}
    assert {"r2ghidra", "retdec", "ghidra", "pseudo_c"} <= names


def test_external_adapters_unavailable_without_tools(monkeypatch) -> None:
    monkeypatch.setattr(r2ghidra_mod.shutil, "which", lambda _name: None)
    monkeypatch.setattr(retdec_mod.shutil, "which", lambda _name: None)
    assert R2GhidraDecompilerAdapter().is_available() is False
    assert RetDecDecompilerAdapter().is_available() is False


def test_auto_degrades_through_external_providers(tmp_path: Path, monkeypatch) -> None:
    # No external tool present: auto must traverse the chain and land on pseudo-C,
    # recording that each external provider was unavailable.
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.setattr(r2ghidra_mod.shutil, "which", lambda _name: None)
    monkeypatch.setattr(retdec_mod.shutil, "which", lambda _name: None)
    sample = tmp_path / "sample"
    sample.write_bytes(_conditional_fixture())
    result = decompile_function(sample, 0x401000)
    assert result.provider == "pseudo_c"
    assert any("r2ghidra is unavailable" in w for w in result.warnings)
    assert any("retdec is unavailable" in w for w in result.warnings)


def test_r2ghidra_parses_pdgj_output(tmp_path: Path, monkeypatch) -> None:
    sample = tmp_path / "sample"
    sample.write_bytes(_conditional_fixture())
    monkeypatch.setattr(r2ghidra_mod.shutil, "which", lambda _name: "/usr/bin/r2")

    class _Completed:
        returncode = 0
        stdout = b'{"code": "int sub_401000(void) { return 0; }"}'
        stderr = b""

    monkeypatch.setattr(r2ghidra_mod.subprocess, "run", lambda *a, **k: _Completed())
    result = R2GhidraDecompilerAdapter().decompile_function(
        sample, 0x401000, DecompileOptions()
    )
    assert result.provider == "r2ghidra"
    assert "int sub_401000" in result.code


def test_r2ghidra_missing_plugin_raises_typed_error(tmp_path: Path, monkeypatch) -> None:
    sample = tmp_path / "sample"
    sample.write_bytes(_conditional_fixture())
    monkeypatch.setattr(r2ghidra_mod.shutil, "which", lambda _name: "/usr/bin/r2")

    class _Completed:
        returncode = 0
        stdout = b"Cannot find plugin\n"  # non-JSON: plugin absent
        stderr = b""

    monkeypatch.setattr(r2ghidra_mod.subprocess, "run", lambda *a, **k: _Completed())
    with pytest.raises(IntegrationUnavailableError):
        R2GhidraDecompilerAdapter().decompile_function(sample, 0x401000, DecompileOptions())


def test_retdec_reads_output_and_names_function(tmp_path: Path, monkeypatch) -> None:
    sample = tmp_path / "sample"
    sample.write_bytes(_conditional_fixture())
    monkeypatch.setattr(retdec_mod.shutil, "which", lambda _name: "/usr/bin/retdec-decompiler")

    def _fake_run(command, **_kwargs):
        out = Path(command[command.index("-o") + 1])
        out.write_text("int entry(void) { return 1; }\n", encoding="utf-8")
        out.with_suffix(".config.json").write_text(
            '{"functions": [{"startAddr": "0x401000", "name": "entry"}]}', encoding="utf-8"
        )
        return type("C", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

    monkeypatch.setattr(retdec_mod.subprocess, "run", _fake_run)
    result = RetDecDecompilerAdapter().decompile_function(sample, 0x401000, DecompileOptions())
    assert result.provider == "retdec"
    assert result.function_name == "entry"
    assert "int entry" in result.code


def test_r2ghidra_live_decompiles_when_installed(tmp_path: Path) -> None:
    # Opt-in live integration: runs only where radare2 + the r2ghidra plugin are
    # actually installed (skipped in CI and dev boxes without them). Guards against
    # regressions in the real pdgj invocation and JSON parsing — e.g. the subprocess
    # environment must forward HOME so r2 finds a user-installed plugin.
    adapter = R2GhidraDecompilerAdapter()
    if not adapter.is_available():
        pytest.skip("radare2 is not on PATH")
    sample = tmp_path / "sample"
    sample.write_bytes(_conditional_fixture())
    try:
        result = adapter.decompile_function(sample, 0x401000, DecompileOptions(timeout_seconds=60))
    except IntegrationUnavailableError as exc:
        pytest.skip(f"r2ghidra plugin not usable: {exc}")
    assert result.provider == "r2ghidra"
    assert result.code.strip()


def test_retdec_timeout_raises_typed_error(tmp_path: Path, monkeypatch) -> None:
    import subprocess as _subprocess

    sample = tmp_path / "sample"
    sample.write_bytes(_conditional_fixture())
    monkeypatch.setattr(retdec_mod.shutil, "which", lambda _name: "/usr/bin/retdec-decompiler")

    def _timeout(*_a, **_k):
        raise _subprocess.TimeoutExpired(cmd="retdec", timeout=1.0)

    monkeypatch.setattr(retdec_mod.subprocess, "run", _timeout)
    with pytest.raises(IntegrationUnavailableError):
        RetDecDecompilerAdapter().decompile_function(sample, 0x401000, DecompileOptions())


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
