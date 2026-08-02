"""Memory analysis, Volatility allowlist, background jobs, and cancellation."""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from reversing_lab.memory.volatility import VolatilityAdapter


def _wait_for_job(client, job_id: str, terminal=None, timeout: float = 4.0) -> dict:
    terminal = terminal or {"completed", "failed", "cancelled"}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = client.get(f"/api/jobs/{job_id}").json()
        if body["state"] in terminal:
            return body
        time.sleep(0.03)
    raise AssertionError(f"job {job_id} did not reach {terminal}")


def test_basic_memory_analysis_job_and_iocs(api_client) -> None:
    data = (
        b"RAW-MEMORY\x00https://triage.example.test/path\x00"
        b"connection=192.0.2.44\x00-----BEGIN PRIVATE KEY-----\x00"
    )
    upload = api_client.post(
        "/api/memory-dumps", files={"file": ("authorized.raw", data)}
    )
    assert upload.status_code == 201, upload.text
    dump_id = upload.json()["id"]
    assert upload.json()["dump_format"] == "raw-memory-region"
    assert upload.json()["analysis_available"] is False

    started = api_client.post(
        f"/api/memory-dumps/{dump_id}/analysis",
        json={"use_volatility": False},
    )
    assert started.status_code == 202, started.text
    job = _wait_for_job(api_client, started.json()["id"])
    assert job["state"] == "completed", job
    assert job["progress"] == 100

    summary = api_client.get(f"/api/memory-dumps/{dump_id}/analysis")
    assert summary.status_code == 200, summary.text
    body = summary.json()
    assert body["provider"] == "basic"
    assert "https://triage.example.test/path" in body["urls"]
    assert "192.0.2.44" in body["ip_addresses"]
    findings = api_client.get(f"/api/memory-dumps/{dump_id}/findings").json()
    assert findings[0]["title"] == "Possible secret material"
    assert api_client.get(f"/api/memory-dumps/{dump_id}/processes").json()["items"] == []


def test_memory_result_is_unavailable_before_analysis(api_client) -> None:
    upload = api_client.post(
        "/api/memory-dumps", files={"file": ("small.raw", b"0123456789abcdef")}
    )
    dump_id = upload.json()["id"]
    assert api_client.get(f"/api/memory-dumps/{dump_id}/analysis").status_code == 409


def test_running_job_can_be_cancelled(api_client, monkeypatch) -> None:
    from reversing_lab.api.routes import memory
    from reversing_lab.jobs import JobCancelled

    upload = api_client.post(
        "/api/memory-dumps", files={"file": ("cancel.raw", b"A" * 128)}
    )
    dump_id = upload.json()["id"]

    def slow_analysis(path, *, use_volatility, context):
        context.update(10, "waiting for cancellation")
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if context.cancelled():
                raise JobCancelled
            time.sleep(0.01)
        raise AssertionError("cancellation was not delivered")

    monkeypatch.setattr(memory, "analyze_memory", slow_analysis)
    started = api_client.post(
        f"/api/memory-dumps/{dump_id}/analysis",
        json={"use_volatility": False},
    ).json()
    _wait_for_job(api_client, started["id"], terminal={"running"})
    cancelled = api_client.post(f"/api/jobs/{started['id']}/cancel")
    assert cancelled.status_code == 200
    terminal = _wait_for_job(api_client, started["id"])
    assert terminal["state"] == "cancelled"
    assert terminal["cancel_requested"] is True


def test_volatility_adapter_uses_allowlisted_fixed_plugin(
    tmp_path: Path, monkeypatch
) -> None:
    from reversing_lab.memory import volatility

    executable = tmp_path / "vol"
    executable.write_text("# placeholder", encoding="utf-8")
    executable.chmod(0o700)
    dump = tmp_path / "dump"
    dump.write_bytes(b"PAGEDUMP" + b"\x00" * 128)
    monkeypatch.setattr(VolatilityAdapter, "executable", lambda self: executable)
    monkeypatch.setattr(
        volatility,
        "get_settings",
        lambda: SimpleNamespace(
            max_analysis_seconds=2,
            max_external_output_bytes=1024 * 1024,
        ),
    )
    observed = {}

    def fake_run(command, **kwargs):
        observed["command"] = command
        observed["shell"] = kwargs["shell"]
        kwargs["stdout"].write(
            json.dumps(
                [{"PID": 4, "PPID": 0, "ImageFileName": "System", "Threads": 10}]
            ).encode()
        )
        kwargs["stdout"].flush()
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(volatility.subprocess, "run", fake_run)
    processes, _, warnings = VolatilityAdapter().analyze(dump)
    assert processes[0].pid == 4
    assert warnings == ()
    assert observed["command"][-1] == "windows.pslist.PsList"
    assert observed["shell"] is False
    with pytest.raises(ValueError):
        VolatilityAdapter()._run(dump, "windows.evil.Arbitrary")
