"""Append-only, body-free audit event contracts."""

from __future__ import annotations

import json
from uuid import UUID

from .fixtures import sample_elf


def test_mutation_audit_is_body_free_and_request_correlated(api_client) -> None:
    uploaded = api_client.post(
        "/api/binaries",
        files={"file": ("sensitive-display-name.elf", sample_elf())},
    )
    assert uploaded.status_code == 201
    UUID(uploaded.headers["x-request-id"])

    response = api_client.get("/api/audit-events?resource_type=binaries")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    event = body["items"][0]
    assert event["request_id"] == uploaded.headers["x-request-id"]
    assert event["principal_id"] == "local"
    assert event["role"] == "admin"
    assert event["action"] == "POST /api/binaries"
    assert event["resource_type"] == "binaries"
    assert event["resource_id"] is None
    assert event["status_code"] == 201
    assert event["outcome"] == "succeeded"
    assert event["details"] == {}
    serialized = json.dumps(event)
    assert "sensitive-display-name" not in serialized
    assert "authorization" not in serialized.lower()


def test_failed_mutation_is_audited_without_recording_payload(api_client) -> None:
    response = api_client.post(
        "/api/binaries", files={"file": ("invalid.bin", b"not executable")}
    )
    assert response.status_code == 415
    event = api_client.get("/api/audit-events?outcome=failed").json()["items"][0]
    assert event["status_code"] == 415
    assert event["route"] == "/api/binaries"
    assert "not executable" not in json.dumps(event)
