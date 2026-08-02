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
        "admin": "admin-local-test-token",
    }
    principals = {
        _digest(tokens["viewer"]): "viewer-one:viewer",
        _digest(tokens["analyst"]): "analyst-one:analyst",
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
    listing = client.get("/api/binaries", headers=viewer)
    assert listing.status_code == 200
    assert listing.json()[0]["sha256"] == uploaded.json()["sha256"]


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
