"""Request correlation, access logging, and health/readiness probes."""

from __future__ import annotations

import logging

import pytest

from reversing_lab.logging_config import (
    _JsonFormatter,
    _RequestIdFilter,
    request_id_var,
)

from .fixtures import sample_elf


def test_every_response_carries_a_correlation_id(api_client) -> None:
    response = api_client.get("/api/health")
    assert response.status_code == 200
    assert response.headers["x-request-id"]


def test_inbound_request_id_is_propagated_to_response_and_audit(api_client) -> None:
    supplied = "trace-abc.123_ID~1"
    uploaded = api_client.post(
        "/api/binaries",
        files={"file": ("named.elf", sample_elf())},
        headers={"X-Request-ID": supplied},
    )
    assert uploaded.status_code == 201
    assert uploaded.headers["x-request-id"] == supplied

    events = api_client.get("/api/audit-events?resource_type=binaries").json()
    assert events["items"][0]["request_id"] == supplied


def test_unsafe_inbound_request_id_is_replaced(api_client) -> None:
    response = api_client.get(
        "/api/health", headers={"X-Request-ID": "bad id with spaces\nand newline"}
    )
    assert response.status_code == 200
    assert response.headers["x-request-id"] != "bad id with spaces\nand newline"
    assert " " not in response.headers["x-request-id"]


def test_readiness_reports_database_ok(api_client) -> None:
    response = api_client.get("/api/health/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "database": "ok"}


def test_readiness_returns_503_when_database_unreachable(
    api_client, monkeypatch
) -> None:
    from reversing_lab.api.routes import health

    def boom():
        raise RuntimeError("connection refused")

    monkeypatch.setattr(health, "get_engine", boom)
    response = api_client.get("/api/health/ready")
    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"


def test_access_log_line_is_emitted_with_request_fields(api_client) -> None:
    # Capture directly on the access logger: configure_logging clears root handlers,
    # so relying on caplog's root propagation is order-dependent under the full suite.
    captured: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record)

    access_logger = logging.getLogger("reversing_lab.access")
    handler = _Collector(level=logging.INFO)
    previous_level = access_logger.level
    access_logger.addHandler(handler)
    access_logger.setLevel(logging.INFO)
    try:
        api_client.get("/api/health")
    finally:
        access_logger.removeHandler(handler)
        access_logger.setLevel(previous_level)

    assert captured, "expected an access-log record"
    record = captured[-1]
    assert record.method == "GET"
    assert record.route == "/api/health"
    assert record.status_code == 200
    assert isinstance(record.duration_ms, float)


def test_json_formatter_includes_request_id_and_extras() -> None:
    token = request_id_var.set("req-42")
    try:
        record = logging.LogRecord(
            "reversing_lab.test", logging.INFO, __file__, 1, "hello", None, None
        )
        _RequestIdFilter().filter(record)
        record.route = "/api/health"
        import json

        payload = json.loads(_JsonFormatter().format(record))
    finally:
        request_id_var.reset(token)

    assert payload["request_id"] == "req-42"
    assert payload["message"] == "hello"
    assert payload["level"] == "INFO"
    assert payload["route"] == "/api/health"


def test_request_id_filter_defaults_outside_a_request() -> None:
    record = logging.LogRecord(
        "reversing_lab.test", logging.INFO, __file__, 1, "x", None, None
    )
    _RequestIdFilter().filter(record)
    assert record.request_id == "-"
