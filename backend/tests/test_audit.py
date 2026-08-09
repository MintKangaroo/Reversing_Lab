"""Append-only, body-free audit event contracts."""

from __future__ import annotations

import hashlib
import json
from uuid import UUID

from reversing_lab.config import get_settings

from .fixtures import sample_elf


def _canonical(payload: dict) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


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


def test_audit_jsonl_export_is_bounded_complete_and_hash_chained(api_client) -> None:
    first = api_client.post(
        "/api/projects", json={"name": "secret project body must not export"}
    )
    second = api_client.post(
        "/api/binaries", files={"file": ("private-name.bin", b"invalid")}
    )
    assert first.status_code == 201
    assert second.status_code == 415

    response = api_client.get("/api/audit-events/export")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/x-ndjson")
    assert response.headers["x-audit-export-records"] == "2"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "secret project body" not in response.text
    assert "private-name.bin" not in response.text

    lines = [json.loads(line) for line in response.text.splitlines()]
    manifest, first_event, second_event, footer = lines
    unsigned_manifest = {
        key: value for key, value in manifest.items() if key != "manifest_hash"
    }
    manifest_hash = hashlib.sha256(
        _canonical(unsigned_manifest).encode("utf-8")
    ).hexdigest()
    assert manifest["manifest_hash"] == manifest_hash
    assert manifest["scope"] == "all-principals"

    previous_hash = manifest_hash
    for event in (first_event, second_event):
        unsigned_event = {
            key: value
            for key, value in event.items()
            if key not in {"previous_hash", "record_hash"}
        }
        expected = hashlib.sha256(
            f"{previous_hash}\n{_canonical(unsigned_event)}".encode()
        ).hexdigest()
        assert event["previous_hash"] == previous_hash
        assert event["record_hash"] == expected
        previous_hash = expected
    assert footer == {
        "type": "footer",
        "record_count": 2,
        "manifest_hash": manifest_hash,
        "chain_head": previous_hash,
        "complete": True,
    }

    empty = api_client.get(
        "/api/audit-events/export",
        params={"created_after": "2100-01-01T00:00:00Z"},
    )
    assert empty.status_code == 200
    assert json.loads(empty.text.splitlines()[-1])["record_count"] == 0
    assert api_client.get(
        "/api/audit-events/export",
        params={"created_after": "2100-01-01T00:00:00"},
    ).status_code == 422

    settings = get_settings()
    previous_limit = settings.max_audit_export_records
    settings.max_audit_export_records = 1
    try:
        limited = api_client.get("/api/audit-events/export")
    finally:
        settings.max_audit_export_records = previous_limit
    assert limited.status_code == 413
    assert "narrow the UTC time range" in limited.json()["detail"]
