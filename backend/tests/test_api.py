"""API contract tests via FastAPI's TestClient."""

from __future__ import annotations

from . import fixtures


def _upload(client, data: bytes, name: str = "sample.bin") -> str:
    response = client.post("/api/binaries", files={"file": (name, data)})
    assert response.status_code == 201, response.text
    return response.json()["sha256"]


def test_health(api_client) -> None:
    body = api_client.get("/api/health").json()
    assert body["status"] == "ok"


def test_upload_and_info(api_client) -> None:
    sha = _upload(api_client, fixtures.sample_elf(), "prog.elf")
    info = api_client.get(f"/api/binaries/{sha}/info").json()
    assert info["binary_format"] == "ELF"
    assert info["architecture"] == "x86_64"
    assert any(section["name"] == ".text" for section in info["sections"])


def test_upload_deduplicates(api_client) -> None:
    data = fixtures.sample_elf()
    first = _upload(api_client, data)
    second = _upload(api_client, data)
    assert first == second
    listing = api_client.get("/api/binaries").json()
    assert len([b for b in listing if b["sha256"] == first]) == 1


def test_reject_unsupported_upload(api_client) -> None:
    response = api_client.post("/api/binaries", files={"file": ("x.txt", b"plain text not a binary")})
    assert response.status_code == 415


def test_all_views(api_client) -> None:
    sha = _upload(api_client, fixtures.sample_elf())
    assert api_client.get(f"/api/binaries/{sha}/strings?min_length=5").json()["count"] >= 1
    assert api_client.get(f"/api/binaries/{sha}/hex?length=16").json()["rows"][0]["hex_bytes"][0] == "7f"
    assert "overall" in api_client.get(f"/api/binaries/{sha}/entropy").json()
    assert "likely_packed" in api_client.get(f"/api/binaries/{sha}/packing").json()
    disasm = api_client.get(f"/api/binaries/{sha}/disassembly?count=4").json()
    assert disasm["instruction_count"] >= 1
    cfg = api_client.get(f"/api/binaries/{sha}/cfg").json()
    assert len(cfg["blocks"]) >= 1


def test_missing_binary_returns_404(api_client) -> None:
    assert api_client.get("/api/binaries/deadbeef/info").status_code == 404


def test_pe_and_macho_roundtrip(api_client) -> None:
    pe_sha = _upload(api_client, fixtures.sample_pe(), "a.exe")
    assert api_client.get(f"/api/binaries/{pe_sha}/info").json()["binary_format"] == "PE"
    macho_sha = _upload(api_client, fixtures.sample_macho(), "a.macho")
    assert api_client.get(f"/api/binaries/{macho_sha}/info").json()["binary_format"] == "Mach-O"


def test_challenges_listing_and_submit(api_client) -> None:
    challenges = api_client.get("/api/challenges").json()
    assert len(challenges) == 6
    for challenge in challenges:
        assert "answer" not in challenge  # answer must never be serialized

    result = api_client.post(
        "/api/challenges/hidden-string/submit",
        json={"answer": "RLAB{str1ngs_r3v34l_s3cr3ts}"},
    ).json()
    assert result["correct"] is True

    wrong = api_client.post(
        "/api/challenges/hidden-string/submit", json={"answer": "RLAB{nope}"}
    ).json()
    assert wrong["correct"] is False


def test_challenge_artifact_download(api_client) -> None:
    response = api_client.get("/api/challenges/crackme-disasm/artifact")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.content[:4] == b"\x7fELF"


def test_integrations_listing(api_client) -> None:
    integrations = {i["name"]: i for i in api_client.get("/api/integrations").json()}
    assert {"radare2", "ghidra", "binary_ninja"} <= set(integrations)
    for info in integrations.values():
        assert isinstance(info["available"], bool)


def test_unavailable_integration_returns_503(api_client) -> None:
    sha = _upload(api_client, fixtures.sample_elf())
    # radare2 is not installed in the test environment.
    response = api_client.post(f"/api/binaries/{sha}/integrations/radare2")
    assert response.status_code == 503


def test_tooling_configuration_exposes_limits_without_paths(api_client) -> None:
    response = api_client.get("/api/tooling/configuration")
    assert response.status_code == 200
    body = response.json()
    assert body["limits"]["max_upload_bytes"] > 0
    assert body["limits"]["max_audit_export_records"] > 0
    assert body["sandbox_policy"]["network"] == "blocked"
    assert body["sandbox_policy"]["privileged"] is False
    assert body["authentication"] == {
        "mode": "disabled",
        "required": False,
        "project_ownership_enforced": False,
        "binary_catalog_scope": "shared",
    }
    assert body["content_addressed_storage"] is True
    assert "storage_dir" not in response.text
    assert "api_key_hashes" not in response.text
