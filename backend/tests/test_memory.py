"""Memory analysis, Volatility allowlist, background jobs, and cancellation."""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from reversing_lab.errors import IntegrationUnavailableError
from reversing_lab.memory.models import (
    MemoryAnalysisResult,
    MemoryMetadata,
    MemoryModule,
    MemoryProcess,
    MemoryRegion,
)
from reversing_lab.memory.volatility import VolatilityAdapter, VolatilityResult


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
    assert (
        api_client.get(f"/api/memory-dumps/{dump_id}/processes").json()["items"] == []
    )


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
            max_memory_processes=100,
            max_memory_modules=100,
            max_memory_regions=100,
        ),
    )
    observed = {"commands": []}

    def fake_run(command, **kwargs):
        observed["commands"].append(command)
        observed["shell"] = kwargs["shell"]
        payloads = {
            "windows.pslist.PsList": [
                {"PID": 4, "PPID": 0, "ImageFileName": "System", "Threads": 10}
            ],
            "windows.dlllist.DllList": [
                {
                    "PID": 4,
                    "Process": "System",
                    "Base": "0x180000000",
                    "Size": 4096,
                    "Name": "ntoskrnl.exe",
                    "Path": r"C:\\Windows\\System32\\ntoskrnl.exe",
                }
            ],
            "windows.vadinfo.VadInfo": [
                {
                    "PID": 4,
                    "Process": "System",
                    "Start VPN": "0x400000",
                    "End VPN": "0x401fff",
                    "Protection": "PAGE_EXECUTE_READWRITE",
                    "PrivateMemory": True,
                    "File": "N/A",
                    "Tag": "VadS",
                }
            ],
        }
        kwargs["stdout"].write(json.dumps(payloads[command[-1]]).encode())
        kwargs["stdout"].flush()
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(volatility.subprocess, "run", fake_run)
    result = VolatilityAdapter().analyze(dump)
    assert result.processes[0].pid == 4
    assert result.processes[0].module_count == 1
    assert result.modules[0].base_address == 0x180000000
    assert result.regions[0].suspicious is True
    assert result.regions[0].private_memory is True
    assert result.warnings == ()
    assert [command[-1] for command in observed["commands"]] == [
        "windows.pslist.PsList",
        "windows.dlllist.DllList",
        "windows.vadinfo.VadInfo",
    ]
    assert observed["shell"] is False
    with pytest.raises(ValueError):
        VolatilityAdapter()._run(dump, "windows.evil.Arbitrary")


def test_volatility_plugin_failures_are_isolated(tmp_path: Path, monkeypatch) -> None:
    dump = tmp_path / "dump"
    dump.write_bytes(b"PAGEDUMP")

    def fake_run(self, dump_path, plugin):
        del self, dump_path
        if plugin == "windows.dlllist.DllList":
            raise IntegrationUnavailableError("dlllist symbols unavailable")
        if plugin == "windows.pslist.PsList":
            return [{"PID": "8", "PPID": "4", "ImageFileName": "worker.exe"}]
        return {
            "columns": [
                "PID",
                "Process",
                "Start",
                "End",
                "Protection",
                "PrivateMemory",
                "File",
            ],
            "rows": [[8, "worker.exe", 4096, 8191, "PAGE_EXECUTE_READ", True, None]],
        }

    monkeypatch.setattr(VolatilityAdapter, "_run", fake_run)
    result = VolatilityAdapter().analyze(dump)

    assert result.processes[0].name == "worker.exe"
    assert result.processes[0].module_count is None
    assert result.modules == ()
    assert result.regions[0].reason == (
        "Private executable memory without a mapped file (heuristic)."
    )
    assert result.completed_plugins == (
        "windows.pslist.PsList",
        "windows.vadinfo.VadInfo",
    )
    assert result.warnings == ("dlllist symbols unavailable",)


def test_volatility_normalized_records_are_bounded(tmp_path: Path, monkeypatch) -> None:
    from reversing_lab.memory import volatility

    dump = tmp_path / "dump"
    dump.write_bytes(b"PAGEDUMP")
    monkeypatch.setattr(
        volatility,
        "get_settings",
        lambda: SimpleNamespace(
            max_memory_processes=1,
            max_memory_modules=1,
            max_memory_regions=1,
        ),
    )

    def fake_run(self, dump_path, plugin):
        del self, dump_path
        if plugin == "windows.pslist.PsList":
            return [
                {"PID": 1, "ImageFileName": "first.exe"},
                {"PID": 2, "ImageFileName": "second.exe"},
            ]
        return []

    monkeypatch.setattr(VolatilityAdapter, "_run", fake_run)
    result = VolatilityAdapter().analyze(dump)

    assert [process.pid for process in result.processes] == [1]
    assert "returned 2 records" in result.warnings[0]
    assert "configured maximum of 1" in result.warnings[0]


def test_volatility_rejects_unsupported_json_structure(
    tmp_path: Path, monkeypatch
) -> None:
    dump = tmp_path / "dump"
    dump.write_bytes(b"PAGEDUMP")

    def fake_run(self, dump_path, plugin):
        del self, dump_path
        return {} if plugin == "windows.dlllist.DllList" else []

    monkeypatch.setattr(VolatilityAdapter, "_run", fake_run)
    result = VolatilityAdapter().analyze(dump)

    assert "windows.dlllist.DllList" not in result.completed_plugins
    assert result.warnings == (
        "Volatility plugin windows.dlllist.DllList returned an unsupported JSON structure.",
    )


def test_memory_analyzer_emits_evidenced_region_finding(
    tmp_path: Path, monkeypatch
) -> None:
    from reversing_lab.memory.analyzer import analyze_memory

    dump = tmp_path / "authorized.dmp"
    dump.write_bytes(b"PAGEDUMP" + b"\x00" * 248)
    provider_result = VolatilityResult(
        processes=(),
        modules=(),
        regions=(
            MemoryRegion(
                start=0x700000,
                end=0x700FFF,
                protection="PAGE_EXECUTE_READWRITE",
                mapped_file=None,
                suspicious=True,
                reason="Writable and executable memory region (heuristic).",
                source_provider="volatility3",
                pid=77,
                process_name="jit-fixture.exe",
                private_memory=True,
                tag="VadS",
            ),
        ),
        completed_plugins=("windows.vadinfo.VadInfo",),
        warnings=(),
    )
    monkeypatch.setattr(VolatilityAdapter, "is_available", lambda self: True)
    monkeypatch.setattr(
        VolatilityAdapter, "analyze", lambda self, dump_path: provider_result
    )

    result = analyze_memory(dump)

    assert result.findings[0].title == "Writable and executable memory region"
    assert result.findings[0].severity == "high"
    assert "PID 77" in result.findings[0].evidence[0]
    assert "memory protection map" not in result.unavailable
    assert "loaded modules" in result.unavailable


def test_memory_module_api_and_region_metadata(api_client, monkeypatch) -> None:
    from reversing_lab.api.routes import memory

    result = MemoryAnalysisResult(
        metadata=MemoryMetadata(
            sha256="a" * 64,
            size=256,
            dump_format="windows-memory-dump",
            os_guess="Windows",
            architecture="x86_64",
            confidence=0.9,
        ),
        processes=(
            MemoryProcess(
                pid=44,
                ppid=4,
                name="fixture.exe",
                command_line=None,
                thread_count=2,
                module_count=1,
                source_provider="volatility3",
            ),
        ),
        regions=(
            MemoryRegion(
                start=0xFFFF800000001000,
                end=0xFFFF800000001FFF,
                protection="PAGE_EXECUTE_READWRITE",
                mapped_file=None,
                suspicious=True,
                reason="Writable and executable memory region (heuristic).",
                source_provider="volatility3",
                pid=44,
                process_name="fixture.exe",
                private_memory=True,
                tag="VadS",
            ),
        ),
        strings=(),
        urls=(),
        ip_addresses=(),
        domains=(),
        findings=(),
        provider="volatility3",
        unavailable=(),
        warnings=(),
        modules=(
            MemoryModule(
                pid=44,
                process_name="fixture.exe",
                base_address=0x140000000,
                size=8192,
                name="fixture.exe",
                path=r"C:\\fixture.exe",
                load_time=None,
                source_provider="volatility3",
            ),
        ),
    )
    monkeypatch.setattr(memory, "analyze_memory", lambda *args, **kwargs: result)
    upload = api_client.post(
        "/api/memory-dumps",
        files={"file": ("fixture.dmp", b"PAGEDUMP" + b"\x00" * 248)},
    )
    dump_id = upload.json()["id"]
    started = api_client.post(
        f"/api/memory-dumps/{dump_id}/analysis", json={"use_volatility": True}
    )
    assert _wait_for_job(api_client, started.json()["id"])["state"] == "completed"

    summary = api_client.get(f"/api/memory-dumps/{dump_id}/analysis").json()
    modules = api_client.get(f"/api/memory-dumps/{dump_id}/modules").json()
    regions = api_client.get(f"/api/memory-dumps/{dump_id}/regions").json()
    assert summary["module_count"] == 1
    assert modules["total"] == 1
    assert modules["items"][0]["base_address"] == 0x140000000
    assert modules["items"][0]["base_address_hex"] == "0x140000000"
    assert regions["items"][0]["pid"] == 44
    assert regions["items"][0]["start_hex"] == "0xffff800000001000"
    assert regions["items"][0]["end_hex"] == "0xffff800000001fff"
