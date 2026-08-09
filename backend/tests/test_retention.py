"""Dry-run-first owned-data retention and deletion safety contracts."""

from __future__ import annotations

from pathlib import Path

from reversing_lab.database import JobRepository
from reversing_lab.database.models import MemoryDumpRecord
from reversing_lab.database.session import get_session_factory

from .fixtures import sample_elf


def _upload_binary(client) -> str:
    response = client.post(
        "/api/binaries", files={"file": ("retention.elf", sample_elf())}
    )
    assert response.status_code == 201, response.text
    return response.json()["sha256"]


def test_preview_confirmation_and_mutable_state_purge(api_client) -> None:
    sha256 = _upload_binary(api_client)
    api_client.post(
        f"/api/binaries/{sha256}/annotations",
        json={"address": 0x401000, "kind": "comment", "value": "remove me"},
    )
    api_client.post(
        f"/api/binaries/{sha256}/bookmarks",
        json={"address": 0x401000, "label": "remove me"},
    )
    project_id = api_client.post(
        "/api/projects", json={"name": "Retention project"}
    ).json()["id"]
    api_client.post(f"/api/projects/{project_id}/samples/{sha256}")
    workspace_id = api_client.post(
        "/api/ctf-workspaces",
        json={"title": "Retention CTF", "binary_sha256": sha256},
    ).json()["id"]
    memory_id = api_client.post(
        "/api/memory-dumps",
        files={"file": ("retention.raw", b"retention-memory-buffer")},
    ).json()["id"]

    preview = api_client.get("/api/retention/preview").json()
    assert preview["required_confirmation"] == "PURGE:local"
    assert preview["counts"]["binary_access"] == 1
    assert preview["counts"]["annotations"] == 1
    assert preview["counts"]["bookmarks"] == 1
    assert preview["counts"]["projects"] == 1
    assert preview["counts"]["project_samples"] == 1
    assert preview["counts"]["ctf_workspaces"] == 1
    assert preview["counts"]["memory_dumps"] == 1
    assert preview["audit_events_retained"] is True

    denied = api_client.post(
        "/api/retention/purge",
        json={"confirmation": "PURGE:분석가"},
    )
    assert denied.status_code == 422
    assert api_client.get(f"/api/projects/{project_id}").status_code == 200

    purged = api_client.post(
        "/api/retention/purge",
        json={"confirmation": "PURGE:local", "include_binary_access": False},
    )
    assert purged.status_code == 200, purged.text
    result = purged.json()
    assert result["deleted_counts"]["binary_access"] == 0
    assert result["deleted_counts"]["annotations"] == 1
    assert result["deleted_counts"]["memory_dumps"] == 1
    assert result["files_removed"] == 1
    assert result["audit_events_retained"] is True
    assert api_client.get(f"/api/binaries/{sha256}/info").status_code == 200
    assert api_client.get(f"/api/projects/{project_id}").status_code == 404
    assert api_client.get(f"/api/ctf-workspaces/{workspace_id}").status_code == 404
    assert api_client.get(f"/api/memory-dumps/{memory_id}").status_code == 404
    assert api_client.get(f"/api/binaries/{sha256}/annotations").json() == []
    assert api_client.get("/api/audit-events").json()["total"] >= 1


def test_active_job_blocks_purge(api_client) -> None:
    session = get_session_factory()()
    try:
        job = JobRepository(session).create("retention-test", "local-target")
        job_id = job.id
    finally:
        session.close()

    preview = api_client.get("/api/retention/preview").json()
    assert preview["active_jobs"] == 1
    response = api_client.post(
        "/api/retention/purge", json={"confirmation": "PURGE:local"}
    )
    assert response.status_code == 409
    assert api_client.get(f"/api/jobs/{job_id}").status_code == 200


def test_purge_never_unlinks_a_tampered_path_outside_storage(
    api_client, tmp_path: Path
) -> None:
    upload = api_client.post(
        "/api/memory-dumps",
        files={"file": ("tampered.raw", b"authorized-memory")},
    )
    dump_id = upload.json()["id"]
    outside = tmp_path / "outside-retention-target"
    outside.write_bytes(b"must survive")
    session = get_session_factory()()
    try:
        record = session.get(MemoryDumpRecord, dump_id)
        assert record is not None
        record.storage_path = str(outside)
        session.commit()
    finally:
        session.close()

    result = api_client.post(
        "/api/retention/purge", json={"confirmation": "PURGE:local"}
    ).json()
    assert outside.read_bytes() == b"must survive"
    assert result["files_removed"] == 0
    assert result["warnings"] == [
        "Skipped a file outside configured storage roots."
    ]
