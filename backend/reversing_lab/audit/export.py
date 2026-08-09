"""Canonical JSONL audit export with an export-time SHA-256 hash chain."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator, Mapping
from datetime import datetime, timezone
from typing import Protocol


class AuditExportRecord(Protocol):
    id: str
    request_id: str
    principal_id: str
    role: str
    action: str
    resource_type: str
    resource_id: str | None
    method: str
    route: str
    status_code: int
    outcome: str
    created_at: datetime


def _canonical(payload: Mapping[str, object]) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def stream_hash_chained_jsonl(
    records: Iterable[AuditExportRecord],
    *,
    generated_at: datetime,
    scope: str,
    filters: Mapping[str, object],
) -> Iterator[bytes]:
    """Yield manifest, chained events, and a completeness footer as JSON Lines.

    The chain detects modification or omission within the exported file. Because it is
    computed during export and has no external trust anchor, it does not prove the
    source database itself was complete or untampered.
    """
    manifest_payload: dict[str, object] = {
        "type": "manifest",
        "schema": "reversing-lab.audit.v1",
        "generated_at": _utc_iso(generated_at),
        "scope": scope,
        "filters": dict(filters),
        "hash_algorithm": "sha256",
        "chain_scheme": "sha256(previous_hash + LF + canonical_event)",
    }
    manifest_hash = hashlib.sha256(
        _canonical(manifest_payload).encode("utf-8")
    ).hexdigest()
    yield (
        _canonical({**manifest_payload, "manifest_hash": manifest_hash}) + "\n"
    ).encode("utf-8")

    previous_hash = manifest_hash
    record_count = 0
    for record in records:
        event: dict[str, object] = {
            "type": "event",
            "event_id": record.id,
            "request_id": record.request_id,
            "principal_id": record.principal_id,
            "role": record.role,
            "action": record.action,
            "resource_type": record.resource_type,
            "resource_id": record.resource_id,
            "method": record.method,
            "route": record.route,
            "status_code": record.status_code,
            "outcome": record.outcome,
            "created_at": _utc_iso(record.created_at),
        }
        canonical_event = _canonical(event)
        record_hash = hashlib.sha256(
            f"{previous_hash}\n{canonical_event}".encode()
        ).hexdigest()
        yield (
            _canonical(
                {
                    **event,
                    "previous_hash": previous_hash,
                    "record_hash": record_hash,
                }
            )
            + "\n"
        ).encode("utf-8")
        previous_hash = record_hash
        record_count += 1

    footer = {
        "type": "footer",
        "record_count": record_count,
        "manifest_hash": manifest_hash,
        "chain_head": previous_hash,
        "complete": True,
    }
    yield (_canonical(footer) + "\n").encode("utf-8")
