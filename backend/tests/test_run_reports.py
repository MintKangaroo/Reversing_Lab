"""Dynamic-run and memory-dump report builders and export endpoints."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from reversing_lab.dynamic import MockSandboxProvider, SandboxReadiness
from reversing_lab.reporting import build_dynamic_report, build_memory_report

from .fixtures import sample_elf


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Builder unit tests (pure, no database)
# --------------------------------------------------------------------------- #


def test_dynamic_builder_orders_by_severity_and_flags_execution() -> None:
    result = {
        "provider": "mock",
        "events": [
            {"category": "api", "operation": "b", "severity": "info", "result": "ok",
             "timestamp": "2026-01-01T00:00:01", "target": "x"},
            {"category": "network", "operation": "a", "severity": "critical", "result": "ok",
             "timestamp": "2026-01-01T00:00:00", "target": "evil.example"},
        ],
        "artifacts": [{"name": "drop.exe", "kind": "file", "content_sha256": "ab", "size": 10}],
        "unavailable_events": ["syscalls"],
        "warnings": ["partial coverage"],
    }
    report = build_dynamic_report(
        run_id="run-1", job_id="job-1", binary_sha256="a" * 64,
        created_at=_now(), result=result,
    )
    assert report["report_type"] == "dynamic"
    assert report["executive_summary"]["sample_executed"] is True
    assert report["executive_summary"]["highest_severity"] == "critical"
    # Critical event sorts ahead of the info event.
    assert report["behavioral_timeline"]["events"][0]["severity"] == "critical"
    assert report["event_summary"]["by_severity"] == {"critical": 1, "info": 1}
    assert report["dropped_artifacts"]["artifacts"][0]["name"] == "drop.exe"


def test_dynamic_builder_marks_not_executed_when_provider_skips() -> None:
    result = {
        "provider": "mock",
        "events": [{"category": "analysis_control", "operation": "mock_no_execution",
                    "severity": "info", "result": "not_executed", "target": None}],
        "artifacts": [],
        "unavailable_events": [],
        "warnings": [],
    }
    report = build_dynamic_report(
        run_id="r", job_id="j", binary_sha256="b" * 64, created_at=_now(), result=result,
    )
    assert report["executive_summary"]["sample_executed"] is False
    assert report["event_summary"]["provenance"] == "not_observed"
    assert any("did not execute" in step for step in report["recommended_next_steps"])


def test_memory_builder_filters_suspicious_regions_and_sorts_findings() -> None:
    result = {
        "metadata": {"sha256": "c" * 64, "size": 4096, "dump_format": "raw-memory-region",
                     "os_guess": "windows", "architecture": "x64", "confidence": 0.7},
        "provider": "basic",
        "processes": [{"pid": 4, "ppid": 0, "name": "System", "command_line": None}],
        "regions": [
            {"start": 0x1000, "end": 0x2000, "protection": "rwx", "suspicious": True,
             "reason": "rwx private", "pid": 10},
            {"start": 0x3000, "end": 0x4000, "protection": "r--", "suspicious": False,
             "reason": None, "pid": 10},
        ],
        "findings": [
            {"id": "f-low", "title": "low one", "severity": "low", "confidence": 0.2,
             "summary": "s", "evidence": [], "false_positive_note": ""},
            {"id": "f-high", "title": "high one", "severity": "high", "confidence": 0.9,
             "summary": "s", "evidence": [], "false_positive_note": ""},
        ],
        "strings": ["a", "b", "c"],
        "urls": ["https://evil.example/x"],
        "ip_addresses": ["192.0.2.10"],
        "domains": ["evil.example"],
        "unavailable": [],
        "warnings": [],
        "modules": [], "network": [], "handles": [], "threads": [],
    }
    report = build_memory_report(
        dump_id="dump-1", filename="mem.raw", created_at=_now(), result=result,
    )
    assert report["report_type"] == "memory"
    assert report["executive_summary"]["suspicious_region_count"] == 1
    assert report["executive_summary"]["region_count"] == 2
    assert report["suspicious_regions"]["items"][0]["protection"] == "rwx"
    # High-severity finding sorts first.
    assert report["findings"][0]["id"] == "f-high"
    assert report["executive_summary"]["highest_severity"] == "high"
    assert report["strings_and_iocs"]["urls"] == ["https://evil.example/x"]


def test_memory_html_escapes_untrusted_finding_text() -> None:
    from reversing_lab.reporting import render_memory_html

    result = {
        "metadata": {"sha256": "d" * 64, "size": 1, "dump_format": "raw-memory-region",
                     "os_guess": None, "architecture": None, "confidence": 0.0},
        "provider": "basic",
        "processes": [], "regions": [],
        "findings": [{"id": "x", "title": "<script>alert(1)</script>", "severity": "high",
                      "confidence": 0.5, "summary": "s", "evidence": [], "false_positive_note": ""}],
        "strings": [], "urls": [], "ip_addresses": [], "domains": [],
        "unavailable": [], "warnings": [], "modules": [], "network": [],
        "handles": [], "threads": [],
    }
    report = build_memory_report(
        dump_id="d", filename="x.raw", created_at=_now(), result=result,
    )
    html = render_memory_html(report)
    assert "<script>alert" not in html
    assert "&lt;script&gt;alert" in html


# --------------------------------------------------------------------------- #
# Endpoint integration tests
# --------------------------------------------------------------------------- #


def _ready_mock():
    class ReadyMock(MockSandboxProvider):
        def readiness(self, *, sample_path_validated, user_acknowledged):
            reasons = () if sample_path_validated and user_acknowledged else ("not ready",)
            return SandboxReadiness(
                provider="mock", provider_configured=True, isolated_worker_available=True,
                resource_limits_configured=True, timeout_configured=True,
                network_policy_configured=True, writable_workspace_configured=True,
                sample_path_validated=sample_path_validated,
                user_acknowledged=user_acknowledged, ready=not reasons,
                reasons=reasons, warning="mock",
            )

    return ReadyMock()


def _wait_run(client, run_id: str, timeout: float = 4.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if client.get(f"/api/dynamic-analysis/{run_id}").json()["job"]["state"] in {
            "completed", "failed", "cancelled"
        }:
            return
        time.sleep(0.03)
    raise AssertionError("dynamic job did not finish")


def _wait_job(client, job_id: str, timeout: float = 4.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if client.get(f"/api/jobs/{job_id}").json()["state"] in {
            "completed", "failed", "cancelled"
        }:
            return
        time.sleep(0.03)
    raise AssertionError("memory job did not finish")


def test_dynamic_report_export_all_formats(api_client, monkeypatch) -> None:
    from reversing_lab.api.routes import dynamic

    monkeypatch.setattr(dynamic, "get_sandbox_provider", _ready_mock)
    sha256 = api_client.post(
        "/api/binaries", files={"file": ("run.elf", sample_elf())}
    ).json()["sha256"]
    run_id = api_client.post(
        "/api/dynamic-analysis", json={"binary_sha256": sha256, "acknowledged": True}
    ).json()["id"]
    _wait_run(api_client, run_id)

    body = api_client.get(f"/api/dynamic-analysis/{run_id}/report?format=json")
    assert body.status_code == 200, body.text
    report = body.json()
    assert report["report_type"] == "dynamic"
    assert report["executive_summary"]["sample_executed"] is False
    assert report["run_metadata"]["binary_sha256"] == sha256

    markdown = api_client.get(f"/api/dynamic-analysis/{run_id}/report?format=markdown")
    assert markdown.status_code == 200
    assert "## 9. Recommended Next Steps" in markdown.text
    assert 'filename="dynamic-' in markdown.headers["content-disposition"]

    html = api_client.get(f"/api/dynamic-analysis/{run_id}/report?format=html")
    assert html.status_code == 200
    assert "<!doctype html>" in html.text


def test_dynamic_report_rejects_bad_format(api_client, monkeypatch) -> None:
    from reversing_lab.api.routes import dynamic

    monkeypatch.setattr(dynamic, "get_sandbox_provider", _ready_mock)
    sha256 = api_client.post(
        "/api/binaries", files={"file": ("run.elf", sample_elf())}
    ).json()["sha256"]
    run_id = api_client.post(
        "/api/dynamic-analysis", json={"binary_sha256": sha256, "acknowledged": True}
    ).json()["id"]
    _wait_run(api_client, run_id)
    bad = api_client.get(f"/api/dynamic-analysis/{run_id}/report?format=../etc")
    assert bad.status_code == 422


def test_memory_report_export_all_formats(api_client) -> None:
    data = (
        b"RAW-MEMORY\x00https://triage.example.test/path\x00"
        b"connection=192.0.2.44\x00-----BEGIN PRIVATE KEY-----\x00"
    )
    dump_id = api_client.post(
        "/api/memory-dumps", files={"file": ("report.raw", data)}
    ).json()["id"]
    job_id = api_client.post(
        f"/api/memory-dumps/{dump_id}/analysis", json={"use_volatility": False}
    ).json()["id"]
    _wait_job(api_client, job_id)

    body = api_client.get(f"/api/memory-dumps/{dump_id}/report?format=json")
    assert body.status_code == 200, body.text
    report = body.json()
    assert report["report_type"] == "memory"
    assert report["dump_metadata"]["dump_id"] == dump_id
    assert "https://triage.example.test/path" in report["strings_and_iocs"]["urls"]
    assert report["executive_summary"]["finding_count"] >= 1

    markdown = api_client.get(f"/api/memory-dumps/{dump_id}/report?format=markdown")
    assert markdown.status_code == 200
    assert "## 11. Recommended Next Steps" in markdown.text
    assert 'filename="memory-' in markdown.headers["content-disposition"]

    html = api_client.get(f"/api/memory-dumps/{dump_id}/report?format=html")
    assert html.status_code == 200
    assert "<!doctype html>" in html.text


def test_memory_report_conflicts_before_analysis(api_client) -> None:
    dump_id = api_client.post(
        "/api/memory-dumps", files={"file": ("pending.raw", b"0123456789abcdef")}
    ).json()["id"]
    pending = api_client.get(f"/api/memory-dumps/{dump_id}/report?format=json")
    assert pending.status_code == 409
