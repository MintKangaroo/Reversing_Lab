"""Memory analysis, Volatility allowlist, background jobs, and cancellation."""

from __future__ import annotations

import gzip
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from reversing_lab.errors import IntegrationUnavailableError
from reversing_lab.memory.models import (
    MemoryAnalysisResult,
    MemoryHandle,
    MemoryMetadata,
    MemoryModule,
    MemoryNetworkArtifact,
    MemoryProcess,
    MemoryRegion,
    MemoryThread,
)
from reversing_lab.memory.volatility import (
    RegionExtraction,
    VolatilityAdapter,
    VolatilityResult,
)


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
            max_memory_network_records=100,
            max_memory_handles=100,
            max_memory_threads=100,
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
            "windows.pstree.PsTree": [
                {
                    "PID": 4,
                    "PPID": 0,
                    "ImageFileName": "System",
                    "__children": [
                        {
                            "PID": 120,
                            "PPID": 4,
                            "ImageFileName": "smss.exe",
                            "Cmd": r"\\SystemRoot\\System32\\smss.exe",
                        }
                    ],
                }
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
            "windows.cmdline.CmdLine": [
                {
                    "PID": 120,
                    "Process": "smss.exe",
                    "Args": r"\\SystemRoot\\System32\\smss.exe --fixture",
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
            "windows.netscan.NetScan": [
                {
                    "Offset": "0xffff800000001000",
                    "Proto": "TCPv4",
                    "LocalAddr": "10.0.0.5",
                    "LocalPort": 51514,
                    "ForeignAddr": "1.1.1.1",
                    "ForeignPort": 443,
                    "State": "ESTABLISHED",
                    "PID": 120,
                    "Owner": "smss.exe",
                    "Created": "2026-08-09 03:00:00",
                }
            ],
            "windows.handles.Handles": [
                {
                    "PID": 120,
                    "Process": "smss.exe",
                    "Offset": "0xffff800000003000",
                    "HandleValue": "0x44",
                    "Type": "File",
                    "GrantedAccess": "0x12019f",
                    "Name": r"\\Device\\HarddiskVolume3\\Windows\\fixture.bin",
                }
            ],
            "windows.threads.Threads": [
                {
                    "Offset": "0xffff800000004000",
                    "PID": 120,
                    "TID": 124,
                    "StartAddress": "0xfffff80000100000",
                    "StartPath": "ntoskrnl.exe",
                    "Win32StartAddress": "0x400100",
                    "Win32StartPath": "smss.exe",
                    "CreateTime": "2026-08-12 09:00:00",
                    "ExitTime": "N/A",
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
    assert result.processes[1].pid == 120
    assert result.processes[1].tree_depth == 1
    assert result.processes[1].command_line.endswith("smss.exe --fixture")
    assert result.modules[0].base_address == 0x180000000
    assert result.regions[0].suspicious is True
    assert result.regions[0].private_memory is True
    assert result.network[0].remote_address == "1.1.1.1"
    assert result.network[0].offset == 0xFFFF800000001000
    assert result.handles[0].pid == 120
    assert result.handles[0].handle_value == 0x44
    assert result.handles[0].granted_access == 0x12019F
    assert result.threads[0].process_name == "smss.exe"
    assert result.threads[0].tid == 124
    assert result.threads[0].object_offset == 0xFFFF800000004000
    assert result.threads[0].win32_start_address == 0x400100
    assert result.warnings == ()
    assert [command[-1] for command in observed["commands"]] == [
        "windows.pslist.PsList",
        "windows.pstree.PsTree",
        "windows.cmdline.CmdLine",
        "windows.dlllist.DllList",
        "windows.vadinfo.VadInfo",
        "windows.netscan.NetScan",
        "windows.handles.Handles",
        "windows.threads.Threads",
    ]
    assert observed["shell"] is False
    with pytest.raises(ValueError):
        VolatilityAdapter()._run(dump, "windows.evil.Arbitrary")


def test_volatility_region_extraction_uses_fixed_bounded_arguments(
    tmp_path: Path, monkeypatch
) -> None:
    from reversing_lab.memory import volatility

    executable = tmp_path / "vol"
    executable.write_text("# placeholder", encoding="utf-8")
    executable.chmod(0o700)
    dump = tmp_path / "authorized.dmp"
    dump.write_bytes(b"PAGEDUMP" + b"\x00" * 64)
    monkeypatch.setattr(VolatilityAdapter, "executable", lambda self: executable)
    monkeypatch.setattr(
        volatility,
        "get_settings",
        lambda: SimpleNamespace(
            max_analysis_seconds=2,
            max_external_output_bytes=1024 * 1024,
            max_memory_region_extract_bytes=4096,
        ),
    )
    observed = {}

    def fake_run(command, **kwargs):
        observed["command"] = command
        observed["shell"] = kwargs["shell"]
        output_dir = Path(command[command.index("-o") + 1])
        filename = "pid.44.vad.0x1000-0x1fff.dmp"
        (output_dir / filename).write_bytes(b"\x90" * 4095 + b"\xc3")
        kwargs["stdout"].write(
            json.dumps(
                [
                    {
                        "PID": 44,
                        "Process": "fixture.exe",
                        "Start VPN": "0x1000",
                        "End VPN": "0x1fff",
                        "File output": filename,
                    }
                ]
            ).encode()
        )
        kwargs["stdout"].flush()
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(volatility.subprocess, "run", fake_run)
    extracted = VolatilityAdapter().extract_region(
        dump, pid=44, address=0x1000, max_bytes=4096
    )

    assert extracted.data[-1] == 0xC3
    assert extracted.start == 0x1000
    assert extracted.end == 0x1FFF
    assert observed["shell"] is False
    assert observed["command"][-8:] == [
        "windows.vadinfo.VadInfo",
        "--pid",
        "44",
        "--address",
        "4096",
        "--dump",
        "--maxsize",
        "4096",
    ]


def test_volatility_region_extraction_rejects_provider_path_traversal(
    tmp_path: Path, monkeypatch
) -> None:
    from reversing_lab.memory import volatility

    executable = tmp_path / "vol"
    executable.write_text("# placeholder", encoding="utf-8")
    executable.chmod(0o700)
    dump = tmp_path / "authorized.dmp"
    dump.write_bytes(b"PAGEDUMP")
    monkeypatch.setattr(VolatilityAdapter, "executable", lambda self: executable)
    monkeypatch.setattr(
        volatility,
        "get_settings",
        lambda: SimpleNamespace(
            max_analysis_seconds=2,
            max_external_output_bytes=1024 * 1024,
            max_memory_region_extract_bytes=4096,
        ),
    )

    def fake_run(command, **kwargs):
        output_dir = Path(command[command.index("-o") + 1])
        (output_dir.parent / "escaped.bin").write_bytes(b"A" * 4096)
        kwargs["stdout"].write(
            json.dumps(
                [
                    {
                        "PID": 44,
                        "Start VPN": 0x1000,
                        "End VPN": 0x1FFF,
                        "File output": "../escaped.bin",
                    }
                ]
            ).encode()
        )
        kwargs["stdout"].flush()
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(volatility.subprocess, "run", fake_run)
    with pytest.raises(IntegrationUnavailableError, match="invalid region artifact path"):
        VolatilityAdapter().extract_region(
            dump, pid=44, address=0x1000, max_bytes=4096
        )


def test_volatility_plugin_failures_are_isolated(tmp_path: Path, monkeypatch) -> None:
    dump = tmp_path / "dump"
    dump.write_bytes(b"PAGEDUMP")

    def fake_run(self, dump_path, plugin):
        del self, dump_path
        if plugin == "windows.dlllist.DllList":
            raise IntegrationUnavailableError("dlllist symbols unavailable")
        if plugin == "windows.pslist.PsList":
            return [{"PID": "8", "PPID": "4", "ImageFileName": "worker.exe"}]
        if plugin == "windows.vadinfo.VadInfo":
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
                "rows": [
                    [8, "worker.exe", 4096, 8191, "PAGE_EXECUTE_READ", True, None]
                ],
            }
        return []

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
        "windows.pstree.PsTree",
        "windows.cmdline.CmdLine",
        "windows.vadinfo.VadInfo",
        "windows.netscan.NetScan",
        "windows.handles.Handles",
        "windows.threads.Threads",
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
            max_memory_network_records=1,
            max_memory_handles=1,
            max_memory_threads=1,
        ),
    )

    def fake_run(self, dump_path, plugin):
        del self, dump_path
        if plugin == "windows.pslist.PsList":
            return [
                {"PID": 1, "ImageFileName": "first.exe"},
                {"PID": 2, "ImageFileName": "second.exe"},
            ]
        if plugin == "windows.netscan.NetScan":
            return [
                {"Proto": "TCPv4", "LocalAddr": "127.0.0.1", "LocalPort": 80},
                {"Proto": "UDPv4", "LocalAddr": "0.0.0.0", "LocalPort": 53},
            ]
        if plugin == "windows.handles.Handles":
            return [
                {"PID": 1, "Type": "File", "HandleValue": "0x10"},
                {"PID": 2, "Type": "Key", "HandleValue": "0x20"},
            ]
        if plugin == "windows.threads.Threads":
            return [
                {"PID": 1, "TID": 10, "Offset": "0x1000"},
                {"PID": 2, "TID": 20, "Offset": "0x2000"},
            ]
        return []

    monkeypatch.setattr(VolatilityAdapter, "_run", fake_run)
    result = VolatilityAdapter().analyze(dump)

    assert [process.pid for process in result.processes] == [1]
    assert len(result.network) == 1
    assert len(result.handles) == 1
    assert len(result.threads) == 1
    assert "returned 2 records" in result.warnings[0]
    assert "configured maximum of 1" in result.warnings[0]
    assert any(
        "windows.netscan.NetScan returned 2 records" in warning
        for warning in result.warnings
    )
    assert any(
        "windows.handles.Handles returned 2 records" in warning
        for warning in result.warnings
    )
    assert any(
        "windows.threads.Threads returned 2 records" in warning
        for warning in result.warnings
    )


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


def test_memory_thread_routes_read_persisted_artifact_directly(tmp_path: Path) -> None:
    from reversing_lab.api.routes.memory import (
        memory_analysis_summary,
        memory_threads,
    )

    artifact = tmp_path / "analysis.json.gz"
    artifact.write_bytes(
        gzip.compress(
            json.dumps(
                {
                    "metadata": {
                        "sha256": "a" * 64,
                        "size": 256,
                        "dump_format": "windows-memory-dump",
                        "os_guess": "Windows",
                        "architecture": "x86_64",
                        "confidence": 0.9,
                    },
                    "provider": "volatility3",
                    "threads": [
                        {
                            "pid": 44,
                            "tid": 88,
                            "process_name": "fixture.exe",
                            "object_offset": 0xFFFF800000004000,
                            "start_address": 0xFFFFF80000100000,
                            "start_path": "ntoskrnl.exe",
                            "win32_start_address": 0x140001000,
                            "win32_start_path": "fixture.exe",
                            "create_time": "2026-08-12 09:00:00",
                            "exit_time": None,
                            "source_provider": "volatility3",
                        }
                    ],
                }
            ).encode()
        )
    )

    class Repository:
        def get(self, dump_id):
            assert dump_id == "dump-1"
            return SimpleNamespace(analysis_path=str(artifact))

    repository = Repository()
    page = memory_threads(
        "dump-1",
        offset=0,
        limit=20,
        pid=44,
        tid=88,
        keyword="0x140001000",
        repository=repository,
    )
    item = page.items[0].model_dump()
    assert page.total == 1
    assert item["object_offset_hex"] == "0xffff800000004000"
    assert item["win32_start_address_hex"] == "0x140001000"
    assert memory_analysis_summary("dump-1", repository).thread_count == 1


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
        completed_plugins=(
            "windows.cmdline.CmdLine",
            "windows.vadinfo.VadInfo",
            "windows.threads.Threads",
        ),
        warnings=(),
        threads=(
            MemoryThread(
                pid=77,
                tid=88,
                process_name="jit-fixture.exe",
                object_offset=0xFFFF800000004000,
                start_address=0xFFFFF80000100000,
                start_path="ntoskrnl.exe",
                win32_start_address=0x700100,
                win32_start_path=None,
                create_time="2026-08-12 09:00:00",
                exit_time=None,
                source_provider="volatility3",
            ),
        ),
    )
    monkeypatch.setattr(VolatilityAdapter, "is_available", lambda self: True)
    monkeypatch.setattr(
        VolatilityAdapter, "analyze", lambda self, dump_path: provider_result
    )

    result = analyze_memory(dump)

    assert result.findings[0].title == "Writable and executable memory region"
    assert result.findings[0].severity == "high"
    assert "PID 77" in result.findings[0].evidence[0]
    assert result.findings[1].title == "Thread starts in a suspicious memory region"
    assert "TID 88" in result.findings[1].evidence[0]
    assert "memory protection map" not in result.unavailable
    assert "thread details" not in result.unavailable
    assert "command lines" not in result.unavailable
    assert "loaded modules" in result.unavailable


def test_memory_analyzer_emits_conservative_network_findings(
    tmp_path: Path, monkeypatch
) -> None:
    from reversing_lab.memory.analyzer import analyze_memory

    dump = tmp_path / "authorized.dmp"
    dump.write_bytes(b"PAGEDUMP" + b"\x00" * 248)
    provider_result = VolatilityResult(
        processes=(),
        modules=(),
        regions=(),
        completed_plugins=(
            "windows.netscan.NetScan",
            "windows.handles.Handles",
        ),
        warnings=(),
        network=(
            MemoryNetworkArtifact(
                protocol="TCPV4",
                local_address="10.0.0.5",
                local_port=51514,
                remote_address="1.1.1.1",
                remote_port=443,
                state="ESTABLISHED",
                pid=77,
                process_name="browser-fixture.exe",
                created_at=None,
                source_provider="volatility3",
                offset=0x1000,
            ),
            MemoryNetworkArtifact(
                protocol="TCPV6",
                local_address="::",
                local_port=4444,
                remote_address="::",
                remote_port=0,
                state="LISTENING",
                pid=None,
                process_name=None,
                created_at=None,
                source_provider="volatility3",
                offset=0x2000,
            ),
        ),
        handles=(
            MemoryHandle(
                pid=77,
                process_name="browser-fixture.exe",
                object_offset=0x3000,
                handle_value=0x40,
                object_type="File",
                granted_access=0x12019F,
                name=r"\\Device\\HarddiskVolume3\\cache.bin",
                source_provider="volatility3",
            ),
        ),
    )
    monkeypatch.setattr(VolatilityAdapter, "is_available", lambda self: True)
    monkeypatch.setattr(
        VolatilityAdapter, "analyze", lambda self, dump_path: provider_result
    )

    result = analyze_memory(dump)

    assert [finding.title for finding in result.findings] == [
        "Public remote network endpoint observed",
        "Unattributed wildcard listener",
    ]
    assert [finding.severity for finding in result.findings] == ["info", "low"]
    assert "network connections" not in result.unavailable
    assert "handles" not in result.unavailable
    assert result.handles[0].object_type == "File"


def test_memory_process_thread_module_region_handle_and_network_api(
    api_client, monkeypatch
) -> None:
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
                command_line=r"C:\fixture.exe --authorized-test",
                thread_count=2,
                module_count=1,
                source_provider="volatility3",
                tree_depth=2,
                orphaned=False,
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
        network=(
            MemoryNetworkArtifact(
                protocol="TCPV4",
                local_address="10.0.0.5",
                local_port=51514,
                remote_address="1.1.1.1",
                remote_port=443,
                state="ESTABLISHED",
                pid=44,
                process_name="fixture.exe",
                created_at="2026-08-09 03:00:00",
                source_provider="volatility3",
                offset=0xFFFF800000002000,
            ),
        ),
        handles=(
            MemoryHandle(
                pid=44,
                process_name="fixture.exe",
                object_offset=0xFFFF800000003000,
                handle_value=0x88,
                object_type="File",
                granted_access=0x12019F,
                name=r"\\Device\\HarddiskVolume3\\fixture.bin",
                source_provider="volatility3",
            ),
        ),
        threads=(
            MemoryThread(
                pid=44,
                tid=88,
                process_name="fixture.exe",
                object_offset=0xFFFF800000004000,
                start_address=0xFFFFF80000100000,
                start_path="ntoskrnl.exe",
                win32_start_address=0x140001000,
                win32_start_path="fixture.exe",
                create_time="2026-08-12 09:00:00",
                exit_time=None,
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
    processes = api_client.get(f"/api/memory-dumps/{dump_id}/processes").json()
    modules = api_client.get(f"/api/memory-dumps/{dump_id}/modules").json()
    regions = api_client.get(f"/api/memory-dumps/{dump_id}/regions").json()
    handles = api_client.get(
        f"/api/memory-dumps/{dump_id}/handles",
        params={"pid": 44, "object_type": "file", "keyword": "0x12019f"},
    ).json()
    threads = api_client.get(
        f"/api/memory-dumps/{dump_id}/threads",
        params={"pid": 44, "tid": 88, "keyword": "0x140001000"},
    ).json()
    network = api_client.get(
        f"/api/memory-dumps/{dump_id}/network",
        params={
            "pid": 44,
            "protocol": "tcpv4",
            "state": "established",
            "keyword": "1.1.1.1",
        },
    ).json()
    assert summary["module_count"] == 1
    assert summary["network_count"] == 1
    assert summary["handle_count"] == 1
    assert summary["thread_count"] == 1
    assert processes["items"][0]["tree_depth"] == 2
    assert processes["items"][0]["orphaned"] is False
    assert processes["items"][0]["command_line"].endswith("--authorized-test")
    assert modules["total"] == 1
    assert modules["items"][0]["base_address"] == 0x140000000
    assert modules["items"][0]["base_address_hex"] == "0x140000000"
    assert regions["items"][0]["pid"] == 44
    assert regions["items"][0]["start_hex"] == "0xffff800000001000"
    assert regions["items"][0]["end_hex"] == "0xffff800000001fff"
    assert handles["total"] == 1
    assert handles["items"][0]["object_offset_hex"] == "0xffff800000003000"
    assert handles["items"][0]["handle_value_hex"] == "0x88"
    assert handles["items"][0]["granted_access_hex"] == "0x12019f"
    assert threads["total"] == 1
    assert threads["items"][0]["object_offset_hex"] == "0xffff800000004000"
    assert threads["items"][0]["start_address_hex"] == "0xfffff80000100000"
    assert threads["items"][0]["win32_start_address_hex"] == "0x140001000"
    assert network["total"] == 1
    assert network["items"][0]["offset_hex"] == "0xffff800000002000"
    assert (
        api_client.get(
            f"/api/memory-dumps/{dump_id}/network", params={"keyword": "x" * 257}
        ).status_code
        == 422
    )
    assert (
        api_client.get(
            f"/api/memory-dumps/{dump_id}/handles", params={"keyword": "x" * 257}
        ).status_code
        == 422
    )
    assert (
        api_client.get(
            f"/api/memory-dumps/{dump_id}/threads", params={"keyword": "x" * 257}
        ).status_code
        == 422
    )


def test_memory_region_inspection_artifact_hex_disassembly_and_download(
    api_client, monkeypatch
) -> None:
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
        processes=(),
        regions=(
            MemoryRegion(
                start=0x1000,
                end=0x1FFF,
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
    )
    code = b"\x48\x31\xc0\x48\x83\xc0\x01\xc3" + b"\x00" * (4096 - 8)
    monkeypatch.setattr(memory, "analyze_memory", lambda *args, **kwargs: result)
    monkeypatch.setattr(VolatilityAdapter, "is_available", lambda self: True)
    monkeypatch.setattr(
        VolatilityAdapter,
        "extract_region",
        lambda self, dump_path, *, pid, address, max_bytes: RegionExtraction(
            data=code,
            pid=pid,
            start=address,
            end=address + len(code) - 1,
            process_name="fixture.exe",
            provider="volatility3",
        ),
    )
    upload = api_client.post(
        "/api/memory-dumps",
        files={"file": ("fixture.dmp", b"PAGEDUMP" + b"\x00" * 248)},
    )
    dump_id = upload.json()["id"]
    started = api_client.post(
        f"/api/memory-dumps/{dump_id}/analysis", json={"use_volatility": True}
    )
    assert _wait_for_job(api_client, started.json()["id"])["state"] == "completed"

    inspect = api_client.post(
        f"/api/memory-dumps/{dump_id}/regions/inspect",
        json={
            "pid": 44,
            "start_address": 0x1000,
            "architecture": "x86_64",
            "acknowledged": True,
        },
    )
    assert inspect.status_code == 202, inspect.text
    job = _wait_for_job(api_client, inspect.json()["id"])
    assert job["state"] == "completed", job
    artifact_id = job["result_ref"]

    artifacts = api_client.get(
        f"/api/memory-dumps/{dump_id}/region-artifacts"
    ).json()
    assert artifacts["total"] == 1
    assert artifacts["offset"] == 0
    assert len(artifacts["items"]) == 1
    assert artifacts["items"][0]["id"] == artifact_id
    assert artifacts["items"][0]["start_hex"] == "0x1000"
    assert artifacts["items"][0]["size"] == 4096

    # Pagination: total stays accurate while an out-of-range offset returns no items.
    paged = api_client.get(
        f"/api/memory-dumps/{dump_id}/region-artifacts",
        params={"offset": 1, "limit": 10},
    ).json()
    assert paged["total"] == 1
    assert paged["offset"] == 1
    assert paged["items"] == []

    page = api_client.get(
        f"/api/memory-dumps/{dump_id}/region-artifacts/{artifact_id}/hex",
        params={"offset": 0, "length": 16},
    ).json()
    assert page["base_address_hex"] == "0x1000"
    assert page["rows"][0]["address_hex"] == "0x1000"
    assert page["rows"][0]["hex_bytes"][:3] == ["48", "31", "c0"]

    disassembly = api_client.get(
        f"/api/memory-dumps/{dump_id}/region-artifacts/{artifact_id}/disassembly",
        params={"count": 4},
    ).json()
    assert disassembly["architecture"] == "x86_64"
    assert disassembly["instructions"][0]["address_hex"] == "0x1000"
    assert disassembly["instructions"][0]["mnemonic"] == "xor"
    assert disassembly["instructions"][2]["mnemonic"] == "ret"

    download = api_client.get(
        f"/api/memory-dumps/{dump_id}/region-artifacts/{artifact_id}/download"
    )
    assert download.status_code == 200
    assert download.content == code
    assert download.headers["x-content-sha256"] == artifacts["items"][0]["content_sha256"]

    invalid = api_client.post(
        f"/api/memory-dumps/{dump_id}/regions/inspect",
        json={
            "pid": 99,
            "start_address": 0x1000,
            "architecture": "x86_64",
            "acknowledged": True,
        },
    )
    assert invalid.status_code == 422
    injection = api_client.post(
        f"/api/memory-dumps/{dump_id}/regions/inspect",
        json={
            "pid": "44;touch /tmp/owned",
            "start_address": "0x1000;id",
            "architecture": "x86_64;id",
            "acknowledged": True,
        },
    )
    assert injection.status_code == 422


def test_memory_region_inspection_is_disabled_without_volatility(
    api_client, monkeypatch
) -> None:
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
        processes=(),
        regions=(
            MemoryRegion(
                start=0x1000,
                end=0x1FFF,
                protection="PAGE_READWRITE",
                mapped_file=None,
                suspicious=False,
                reason=None,
                source_provider="volatility3",
                pid=44,
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
    monkeypatch.setattr(VolatilityAdapter, "is_available", lambda self: False)

    response = api_client.post(
        f"/api/memory-dumps/{dump_id}/regions/inspect",
        json={
            "pid": 44,
            "start_address": 0x1000,
            "architecture": "x86_64",
            "acknowledged": True,
        },
    )
    assert response.status_code == 409
    assert "unavailable" in response.json()["detail"]
