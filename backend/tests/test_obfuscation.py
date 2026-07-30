"""Obfuscation findings and safe data-transform contracts."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from reversing_lab.analyzer import analyze_obfuscation, transform_data
from reversing_lab.analyzer.unpacking import UnpackResult, unpack_upx
from reversing_lab.challenge.elfbuilder import build_elf64
from reversing_lab.parser import parse_binary


def _xor_loop_fixture() -> bytes:
    code = bytes.fromhex("345a48ffc74883ff0475f5c3")
    encoded = base64.b64encode(b"authorized-ctf-fixture-data")
    return build_elf64(code=code, rodata=encoded + b"\x00")


def test_xor_loop_and_base64_findings_have_evidence() -> None:
    data = _xor_loop_fixture()
    findings = analyze_obfuscation(parse_binary(data), data)
    by_technique = {finding.technique: finding for finding in findings}
    assert "xor_loop" in by_technique
    assert "base64_data" in by_technique
    xor = by_technique["xor_loop"]
    assert xor.related_function == 0x401000
    assert xor.evidence
    assert xor.false_positive_notes
    assert xor.mitre_id == "T1027"


def test_safe_xor_and_base64_transforms() -> None:
    xored = transform_data(
        "xor_single",
        "121f161615",
        {"input_format": "hex", "key": "5a", "key_format": "hex"},
    )
    assert xored.text == "HELLO"
    decoded = transform_data("base64_decode", "Ukw=")
    assert decoded.text == "RL"


def test_transform_rejects_malformed_data() -> None:
    with pytest.raises(ValueError):
        transform_data("base64_decode", "%%%")
    with pytest.raises(ValueError):
        transform_data("xor_single", "00", {"input_format": "hex", "key": "ffff"})


def test_obfuscation_and_decode_api(api_client) -> None:
    data = _xor_loop_fixture()
    upload = api_client.post(
        "/api/binaries", files={"file": ("xor-loop.elf", data)}
    )
    sha256 = upload.json()["sha256"]
    response = api_client.get(f"/api/binaries/{sha256}/obfuscation")
    assert response.status_code == 200, response.text
    assert any(item["technique"] == "xor_loop" for item in response.json())
    assert all(item["evidence"] for item in response.json())

    decoded = api_client.post(
        "/api/tools/decode",
        json={
            "operation": "xor_single",
            "input": "121f",
            "parameters": {
                "input_format": "hex",
                "key": "5a",
                "key_format": "hex",
            },
        },
    )
    assert decoded.status_code == 200
    assert decoded.json()["text"] == "HE"


def test_packing_report_has_normalized_evidence(api_client) -> None:
    from reversing_lab.challenge import get_registry

    _, data = get_registry().artifact("packing-detection")
    upload = api_client.post("/api/binaries", files={"file": ("packed.elf", data)})
    sha256 = upload.json()["sha256"]
    report = api_client.get(f"/api/binaries/{sha256}/packing")
    assert report.status_code == 200, report.text
    body = report.json()
    assert body["likely_packed"] is True
    assert body["confidence"] > 0.8
    assert body["detected_packers"][0]["name"] == "UPX"
    assert body["evidence"]
    assert body["recommended_next_steps"]


def test_upx_uses_fixed_arguments_and_content_hash_path(
    tmp_path: Path, monkeypatch
) -> None:
    from reversing_lab.analyzer import unpacking

    data = _xor_loop_fixture()
    sha256 = hashlib.sha256(data).hexdigest()
    sample = tmp_path / sha256
    sample.write_bytes(data)
    executable = tmp_path / "upx"
    executable.write_text("# test placeholder", encoding="utf-8")
    executable.chmod(0o700)
    observed = {}

    monkeypatch.setattr(unpacking, "upx_executable", lambda: executable)
    monkeypatch.setattr(
        unpacking,
        "get_settings",
        lambda: SimpleNamespace(
            integration_timeout_seconds=2,
            max_upload_bytes=2 * 1024 * 1024,
            max_decompiler_seconds=2,
        ),
    )

    def fake_run(command, **kwargs):
        observed["command"] = command
        observed["kwargs"] = kwargs
        Path(command[3]).write_bytes(Path(command[4]).read_bytes())
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(unpacking.subprocess, "run", fake_run)
    result, output = unpack_upx(sample, sha256)
    assert output == data
    assert result.original_sha256 == sha256
    assert observed["command"] == [
        str(executable),
        "-d",
        "-o",
        observed["command"][3],
        str(sample),
    ]
    assert observed["kwargs"]["shell"] is False


def test_unpack_api_requires_ack_and_indexes_artifact(api_client, monkeypatch) -> None:
    from reversing_lab.api.routes import binaries

    data = _xor_loop_fixture()
    upload = api_client.post(
        "/api/binaries", files={"file": ('";touch-pwned;.elf', data)}
    )
    sha256 = upload.json()["sha256"]
    assert api_client.post(
        f"/api/binaries/{sha256}/unpack", json={"acknowledged": False}
    ).status_code == 422

    fake = UnpackResult(
        provider="upx",
        original_sha256=sha256,
        unpacked_sha256=sha256,
        original_size=len(data),
        unpacked_size=len(data),
        section_changes=(),
        warnings=("fixture",),
    )
    monkeypatch.setattr(binaries, "unpack_upx", lambda path, digest: (fake, data))
    response = api_client.post(
        f"/api/binaries/{sha256}/unpack", json={"acknowledged": True}
    )
    assert response.status_code == 200, response.text
    artifacts = api_client.get(f"/api/binaries/{sha256}/artifacts").json()
    assert artifacts[0]["kind"] == "unpacked-upx"
    assert artifacts[0]["content_sha256"] == sha256


def test_tooling_reports_graceful_capabilities(api_client) -> None:
    items = api_client.get("/api/tooling")
    assert items.status_code == 200
    by_name = {item["name"]: item for item in items.json()}
    assert by_name["pseudo_c"]["available"] is True
    assert isinstance(by_name["upx"]["available"], bool)
    assert api_client.get("/api/tooling/upx").status_code == 200
    assert api_client.get("/api/tooling/not-allowlisted").status_code == 404
