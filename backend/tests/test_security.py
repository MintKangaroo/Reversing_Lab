"""Security regression tests for untrusted input and external-tool boundaries."""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

from reversing_lab.analyzer import unpacking
from reversing_lab.analyzer.unpacking import unpack_upx
from reversing_lab.config import get_settings

from .fixtures import sample_elf


def test_binary_upload_limit_is_enforced_before_persistence(api_client) -> None:
    settings = get_settings()
    previous = settings.max_upload_bytes
    data = sample_elf()
    settings.max_upload_bytes = len(data) - 1
    try:
        response = api_client.post(
            "/api/binaries", files={"file": ("large.elf", data)}
        )
    finally:
        settings.max_upload_bytes = previous
    assert response.status_code == 413
    assert api_client.get("/api/binaries").json() == []


def test_upload_filename_is_display_only_and_sanitized(api_client, tmp_path: Path) -> None:
    response = api_client.post(
        "/api/binaries",
        files={"file": ("../../outside/fixture.elf", sample_elf())},
    )
    assert response.status_code == 201
    record = response.json()
    assert record["filename"] == "fixture.elf"
    assert not (tmp_path / "outside" / "fixture.elf").exists()
    storage_file = tmp_path / "storage" / record["sha256"]
    assert storage_file.is_file()


def test_malformed_hash_and_path_traversal_are_not_resolved(api_client) -> None:
    for value in ("deadbeef", "..%2F..%2Fetc%2Fpasswd", "A" * 64):
        response = api_client.get(f"/api/binaries/{value}/info")
        assert response.status_code == 404


def test_upx_uses_fixed_non_shell_vector(
    tmp_path: Path, monkeypatch
) -> None:
    executable = tmp_path / "upx"
    executable.write_text("# placeholder", encoding="utf-8")
    executable.chmod(0o700)
    original = sample_elf()
    digest = hashlib.sha256(original).hexdigest()
    sample = tmp_path / digest
    sample.write_bytes(original)
    observed: dict[str, object] = {}

    monkeypatch.setattr(unpacking, "upx_executable", lambda: executable)
    monkeypatch.setattr(unpacking, "parse_binary", lambda _: SimpleNamespace(sections=()))

    def fake_run(command, **kwargs):
        observed["command"] = command
        observed["shell"] = kwargs["shell"]
        observed["timeout"] = kwargs["timeout"]
        output = Path(command[command.index("-o") + 1])
        output.write_bytes(original)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(unpacking.subprocess, "run", fake_run)
    result, derived = unpack_upx(sample, digest)
    assert derived == original
    assert result.original_sha256 == digest
    assert observed["command"][-1] == str(sample)
    assert observed["shell"] is False
    assert isinstance(observed["timeout"], float)
