"""Optional bearer authentication and coarse role authorization."""

from __future__ import annotations

import hashlib
import importlib
import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import ValidationError

from reversing_lab.config import Settings
from .fixtures import sample_elf


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@pytest.fixture()
def authenticated_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[object, dict[str, str]]]:
    tokens = {
        "viewer": "viewer-local-test-token",
        "analyst": "analyst-local-test-token",
        "analyst_two": "analyst-two-local-test-token",
        "admin": "admin-local-test-token",
    }
    principals = {
        _digest(tokens["viewer"]): "viewer-one:viewer",
        _digest(tokens["analyst"]): "analyst-one:analyst",
        _digest(tokens["analyst_two"]): "analyst-two:analyst",
        _digest(tokens["admin"]): "admin-one:admin",
    }
    monkeypatch.setenv("RLAB_DATABASE_URL", f"sqlite:///{tmp_path / 'auth.db'}")
    monkeypatch.setenv("RLAB_STORAGE_DIR", str(tmp_path / "storage"))
    monkeypatch.setenv("RLAB_AUTH_MODE", "api_key")
    monkeypatch.setenv("RLAB_AUTH_API_KEY_HASHES", json.dumps(principals))

    from reversing_lab import config
    from reversing_lab.api import services
    from reversing_lab.database import session as db_session

    config.get_settings.cache_clear()
    db_session._engine = None
    db_session._SessionFactory = None
    services.clear_cache()

    from fastapi.testclient import TestClient
    from reversing_lab.api.app import create_app

    with TestClient(create_app()) as client:
        yield client, tokens

    config.get_settings.cache_clear()
    db_session._engine = None
    db_session._SessionFactory = None
    importlib.invalidate_caches()


def _authorization(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_api_key_configuration_fails_closed_without_valid_digests() -> None:
    with pytest.raises(ValidationError, match="requires at least one digest"):
        Settings(
            _env_file=None,
            auth_mode="api_key",
            auth_api_key_hashes={},
        )
    with pytest.raises(ValidationError, match="lowercase SHA-256"):
        Settings(
            _env_file=None,
            auth_mode="api_key",
            auth_api_key_hashes={"NOT-A-DIGEST": "analyst-one:analyst"},
        )


def test_health_is_public_but_api_requires_a_valid_key(authenticated_client) -> None:
    client, tokens = authenticated_client
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["authentication_required"] is True

    missing = client.get("/api/binaries")
    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert client.get(
        "/api/binaries", headers=_authorization("not-a-key")
    ).status_code == 401

    me = client.get("/api/auth/me", headers=_authorization(tokens["viewer"]))
    assert me.status_code == 200
    assert me.json() == {
        "id": "viewer-one",
        "role": "viewer",
        "authentication_enabled": True,
    }


def test_viewer_is_read_only_and_analyst_can_upload(authenticated_client) -> None:
    client, tokens = authenticated_client
    viewer = _authorization(tokens["viewer"])
    analyst = _authorization(tokens["analyst"])
    admin = _authorization(tokens["admin"])

    denied = client.post(
        "/api/binaries",
        headers=viewer,
        files={"file": ("fixture.elf", sample_elf())},
    )
    assert denied.status_code == 403

    uploaded = client.post(
        "/api/binaries",
        headers=analyst,
        files={"file": ("fixture.elf", sample_elf())},
    )
    assert uploaded.status_code == 201, uploaded.text
    assert client.get("/api/binaries", headers=viewer).json() == []
    assert client.get("/api/binaries", headers=analyst).json()[0][
        "sha256"
    ] == uploaded.json()["sha256"]
    assert client.get("/api/binaries", headers=admin).json()[0][
        "sha256"
    ] == uploaded.json()["sha256"]


def test_binary_grants_and_analyst_overlays_are_owner_scoped(
    authenticated_client,
) -> None:
    client, tokens = authenticated_client
    analyst_one = _authorization(tokens["analyst"])
    analyst_two = _authorization(tokens["analyst_two"])
    data = sample_elf()

    first = client.post(
        "/api/binaries",
        headers=analyst_one,
        files={"file": ("first.elf", data)},
    )
    sha256 = first.json()["sha256"]
    assert client.get(
        f"/api/binaries/{sha256}/info", headers=analyst_two
    ).status_code == 404

    second = client.post(
        "/api/binaries",
        headers=analyst_two,
        files={"file": ("same-content.elf", data)},
    )
    assert second.json()["sha256"] == sha256
    assert first.json()["filename"] == "first.elf"
    assert second.json()["filename"] == "same-content.elf"
    assert client.get("/api/binaries", headers=analyst_one).json()[0][
        "filename"
    ] == "first.elf"
    assert client.get("/api/binaries", headers=analyst_two).json()[0][
        "filename"
    ] == "same-content.elf"
    assert client.get(
        f"/api/binaries/{sha256}/info", headers=analyst_two
    ).status_code == 200

    second_report = client.get(
        f"/api/binaries/{sha256}/report?format=json", headers=analyst_two
    )
    assert second_report.json()["sample_metadata"]["filename"] == "same-content.elf"

    renamed = client.post(
        f"/api/binaries/{sha256}/annotations",
        headers=analyst_one,
        json={
            "address": 0x401000,
            "kind": "function_name",
            "value": "analyst_one_entry",
        },
    )
    assert renamed.status_code == 200
    client.post(
        f"/api/binaries/{sha256}/bookmarks",
        headers=analyst_one,
        json={"address": 0x401000, "label": "private lead"},
    )
    assert client.get(
        f"/api/binaries/{sha256}/annotations", headers=analyst_two
    ).json() == []
    assert client.get(
        f"/api/binaries/{sha256}/bookmarks", headers=analyst_two
    ).json() == []

    second_name = client.post(
        f"/api/binaries/{sha256}/annotations",
        headers=analyst_two,
        json={
            "address": 0x401000,
            "kind": "function_name",
            "value": "analyst_two_entry",
        },
    )
    assert second_name.status_code == 200
    assert client.get(
        f"/api/binaries/{sha256}/annotations", headers=analyst_one
    ).json()[0]["value"] == "analyst_one_entry"
    assert client.get(
        f"/api/binaries/{sha256}/annotations", headers=analyst_two
    ).json()[0]["value"] == "analyst_two_entry"


def test_ctf_memory_and_jobs_are_owner_scoped(authenticated_client) -> None:
    client, tokens = authenticated_client
    analyst_one = _authorization(tokens["analyst"])
    analyst_two = _authorization(tokens["analyst_two"])
    admin = _authorization(tokens["admin"])

    uploaded = client.post(
        "/api/binaries",
        headers=analyst_one,
        files={"file": ("owned.elf", sample_elf())},
    )
    workspace = client.post(
        "/api/ctf-workspaces",
        headers=analyst_one,
        json={
            "title": "Private investigation",
            "binary_sha256": uploaded.json()["sha256"],
        },
    )
    assert workspace.status_code == 201, workspace.text
    workspace_id = workspace.json()["id"]
    assert client.get(
        f"/api/ctf-workspaces/{workspace_id}", headers=analyst_two
    ).status_code == 404
    assert client.get(
        f"/api/ctf-workspaces/{workspace_id}", headers=admin
    ).status_code == 200

    memory = client.post(
        "/api/memory-dumps",
        headers=analyst_one,
        files={"file": ("private.raw", b"authorized-memory-buffer")},
    )
    assert memory.status_code == 201, memory.text
    dump_id = memory.json()["id"]
    assert client.get(
        f"/api/memory-dumps/{dump_id}", headers=analyst_two
    ).status_code == 404
    started = client.post(
        f"/api/memory-dumps/{dump_id}/analysis",
        headers=analyst_one,
        json={"use_volatility": False},
    )
    assert started.status_code == 202, started.text
    job_id = started.json()["id"]
    assert client.get(f"/api/jobs/{job_id}", headers=analyst_two).status_code == 404
    assert client.get(
        f"/api/jobs/{job_id}/stream", headers=analyst_two
    ).status_code == 404
    assert client.get(f"/api/jobs/{job_id}", headers=admin).status_code == 200


def test_project_cannot_link_an_ungranted_sample(authenticated_client) -> None:
    client, tokens = authenticated_client
    analyst_one = _authorization(tokens["analyst"])
    analyst_two = _authorization(tokens["analyst_two"])
    data = sample_elf()
    sha256 = client.post(
        "/api/binaries",
        headers=analyst_one,
        files={"file": ("owner-one.elf", data)},
    ).json()["sha256"]
    project_id = client.post(
        "/api/projects",
        headers=analyst_two,
        json={"name": "Second analyst project"},
    ).json()["id"]

    denied = client.post(
        f"/api/projects/{project_id}/samples/{sha256}", headers=analyst_two
    )
    assert denied.status_code == 404

    client.post(
        "/api/binaries",
        headers=analyst_two,
        files={"file": ("authorized-copy.elf", data)},
    )
    granted = client.post(
        f"/api/projects/{project_id}/samples/{sha256}", headers=analyst_two
    )
    assert granted.status_code == 200
    assert granted.json()["sample_sha256"] == [sha256]


def test_audit_events_are_principal_scoped_and_admin_auditable(
    authenticated_client,
) -> None:
    client, tokens = authenticated_client
    analyst_one = _authorization(tokens["analyst"])
    analyst_two = _authorization(tokens["analyst_two"])
    admin = _authorization(tokens["admin"])

    first = client.post(
        "/api/projects",
        headers=analyst_one,
        json={"name": "private analyst one name"},
    )
    second = client.post(
        "/api/projects",
        headers=analyst_two,
        json={"name": "private analyst two name"},
    )
    denied = client.post("/api/projects", json={"name": "unauthenticated"})
    assert first.status_code == 201
    assert second.status_code == 201
    assert denied.status_code == 401

    first_events = client.get("/api/audit-events", headers=analyst_one).json()
    assert first_events["total"] == 1
    assert {item["principal_id"] for item in first_events["items"]} == {
        "analyst-one"
    }
    assert "private analyst one name" not in json.dumps(first_events)

    admin_events = client.get("/api/audit-events", headers=admin).json()
    assert admin_events["total"] == 3
    assert {item["principal_id"] for item in admin_events["items"]} == {
        "analyst-one",
        "analyst-two",
        "anonymous",
    }


def test_shared_binary_is_reclaimed_only_after_last_owner_purges(
    authenticated_client,
) -> None:
    client, tokens = authenticated_client
    analyst_one = _authorization(tokens["analyst"])
    analyst_two = _authorization(tokens["analyst_two"])
    admin = _authorization(tokens["admin"])
    data = sample_elf()
    sha256 = client.post(
        "/api/binaries",
        headers=analyst_one,
        files={"file": ("one.elf", data)},
    ).json()["sha256"]
    client.post(
        "/api/binaries",
        headers=analyst_two,
        files={"file": ("two.elf", data)},
    )

    first_preview = client.get(
        "/api/retention/preview?include_binary_access=true",
        headers=analyst_one,
    ).json()
    assert first_preview["orphanable_binary_count"] == 0
    first_purge = client.post(
        "/api/retention/purge",
        headers=analyst_one,
        json={
            "confirmation": "PURGE:analyst-one",
            "include_binary_access": True,
        },
    )
    assert first_purge.status_code == 200, first_purge.text
    assert first_purge.json()["binary_records_deleted"] == 0
    assert client.get(
        f"/api/binaries/{sha256}/info", headers=analyst_one
    ).status_code == 404
    assert client.get(
        f"/api/binaries/{sha256}/info", headers=analyst_two
    ).status_code == 200

    second_preview = client.get(
        "/api/retention/preview?include_binary_access=true",
        headers=analyst_two,
    ).json()
    assert second_preview["orphanable_binary_count"] == 1
    second_purge = client.post(
        "/api/retention/purge",
        headers=analyst_two,
        json={
            "confirmation": "PURGE:analyst-two",
            "include_binary_access": True,
        },
    )
    assert second_purge.status_code == 200, second_purge.text
    assert second_purge.json()["binary_records_deleted"] == 1
    assert second_purge.json()["files_removed"] == 1
    assert client.get(
        f"/api/binaries/{sha256}/info", headers=admin
    ).status_code == 404


def test_viewer_cannot_purge_and_denial_is_audited(authenticated_client) -> None:
    client, tokens = authenticated_client
    viewer = _authorization(tokens["viewer"])
    denied = client.post(
        "/api/retention/purge",
        headers=viewer,
        json={"confirmation": "PURGE:viewer-one"},
    )
    assert denied.status_code == 403
    events = client.get(
        "/api/audit-events?outcome=denied", headers=viewer
    ).json()
    assert events["total"] == 1
    assert events["items"][0]["principal_id"] == "viewer-one"


def test_disabled_auth_remains_backward_compatible(api_client) -> None:
    response = api_client.get("/api/auth/me")
    assert response.status_code == 200
    assert response.json() == {
        "id": "local",
        "role": "admin",
        "authentication_enabled": False,
    }


def test_project_ownership_is_scoped_and_admin_can_audit(
    authenticated_client,
) -> None:
    client, tokens = authenticated_client
    analyst = _authorization(tokens["analyst"])
    viewer = _authorization(tokens["viewer"])
    admin = _authorization(tokens["admin"])

    created = client.post(
        "/api/projects",
        headers=analyst,
        json={"name": "Analyst-owned investigation", "description": "Authorized"},
    )
    assert created.status_code == 201, created.text
    project_id = created.json()["id"]
    assert created.json()["owner_id"] == "analyst-one"

    assert client.get("/api/projects", headers=viewer).json() == []
    assert client.get(
        f"/api/projects/{project_id}", headers=viewer
    ).status_code == 404
    audited = client.get("/api/projects", headers=admin)
    assert audited.status_code == 200
    assert audited.json()[0]["id"] == project_id
