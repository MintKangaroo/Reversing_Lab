"""Volatility 3 adapter with fixed plugins and bounded normalization."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path

from ..config import get_settings
from ..errors import IntegrationUnavailableError
from .models import (
    MemoryHandle,
    MemoryModule,
    MemoryNetworkArtifact,
    MemoryProcess,
    MemoryRegion,
)

ALLOWED_PLUGINS: tuple[str, ...] = (
    "windows.info.Info",
    "windows.pslist.PsList",
    "windows.pstree.PsTree",
    "windows.dlllist.DllList",
    "windows.vadinfo.VadInfo",
    "windows.netscan.NetScan",
    "windows.handles.Handles",
)

_UNAVAILABLE_TEXT = {
    "",
    "-",
    "n/a",
    "na",
    "none",
    "not applicable",
    "not available",
    "unreadable",
}


@dataclass(frozen=True, slots=True)
class VolatilityResult:
    processes: tuple[MemoryProcess, ...]
    modules: tuple[MemoryModule, ...]
    regions: tuple[MemoryRegion, ...]
    completed_plugins: tuple[str, ...]
    warnings: tuple[str, ...]
    network: tuple[MemoryNetworkArtifact, ...] = ()
    handles: tuple[MemoryHandle, ...] = ()


@dataclass(frozen=True, slots=True)
class RegionExtraction:
    data: bytes
    pid: int
    start: int
    end: int
    process_name: str | None
    provider: str


def _column_key(value: object) -> str:
    return "".join(character for character in str(value).lower() if character.isalnum())


def _value(row: dict[str, object], *names: str) -> object | None:
    normalized = {_column_key(key): value for key, value in row.items()}
    for name in names:
        key = _column_key(name)
        if key in normalized:
            return normalized[key]
    return None


def _text(value: object | None) -> str | None:
    if value is None or isinstance(value, (dict, list, tuple)):
        return None
    rendered = str(value).strip()
    return None if rendered.lower() in _UNAVAILABLE_TEXT else rendered


def _integer(value: object | None) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else None
    rendered = _text(value)
    if rendered is None:
        return None
    rendered = rendered.replace(",", "")
    try:
        return int(
            rendered, 0 if rendered.lower().startswith(("0x", "+0x", "-0x")) else 10
        )
    except ValueError:
        return None


def _boolean(value: object | None) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    rendered = _text(value)
    if rendered is None:
        return None
    normalized = rendered.lower()
    if normalized in {"true", "yes", "1"}:
        return True
    if normalized in {"false", "no", "0"}:
        return False
    return None


def _rows(payload: object) -> list[dict[str, object]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("data", "results"):
        nested = payload.get(key)
        if isinstance(nested, list):
            return [row for row in nested if isinstance(row, dict)]
    columns = payload.get("columns")
    rows = payload.get("rows")
    if isinstance(rows, list) and all(isinstance(row, dict) for row in rows):
        return list(rows)
    if isinstance(columns, list) and isinstance(rows, list):
        names = [str(column) for column in columns]
        return [
            dict(zip(names, row, strict=False))
            for row in rows
            if isinstance(row, (list, tuple))
        ]
    return []


def _supported_payload(payload: object) -> bool:
    if isinstance(payload, list):
        return True
    if not isinstance(payload, dict):
        return False
    return any(
        isinstance(payload.get(key), list) for key in ("data", "results", "rows")
    )


def _tree_rows(payload: object) -> list[tuple[dict[str, object], int]]:
    flattened: list[tuple[dict[str, object], int]] = []

    def visit(row: dict[str, object], depth: int) -> None:
        reported_depth = _integer(_value(row, "Depth", "TreeDepth"))
        actual_depth = max(reported_depth if reported_depth is not None else depth, 0)
        flattened.append((row, actual_depth))
        children = row.get("__children")
        if isinstance(children, list):
            for child in children:
                if isinstance(child, dict):
                    visit(child, actual_depth + 1)

    for row in _rows(payload):
        visit(row, 0)
    return flattened


def _region_assessment(
    protection: str, private_memory: bool | None, mapped_file: str | None
) -> tuple[bool, str | None]:
    normalized = protection.upper().replace("-", "_")
    executable = "EXECUTE" in normalized or (
        "PAGE_" not in normalized and "X" in normalized
    )
    writable = "READWRITE" in normalized or (
        "PAGE_" not in normalized and "W" in normalized
    )
    if executable and writable:
        return True, "Writable and executable memory region (heuristic)."
    if executable and private_memory is True and mapped_file is None:
        return True, "Private executable memory without a mapped file (heuristic)."
    return False, None


def _normalize_processes(payload: object, provider: str) -> list[MemoryProcess]:
    normalized: list[MemoryProcess] = []
    for row in _rows(payload):
        pid = _integer(_value(row, "PID", "Pid"))
        if pid is None or pid < 0:
            continue
        ppid = _integer(_value(row, "PPID", "PPid", "Parent PID"))
        normalized.append(
            MemoryProcess(
                pid=pid,
                ppid=ppid if ppid is None or ppid >= 0 else None,
                name=_text(_value(row, "ImageFileName", "Name", "Process"))
                or "unknown",
                command_line=None,
                thread_count=_integer(_value(row, "Threads", "ThreadCount")),
                module_count=None,
                source_provider=provider,
            )
        )
    return normalized


def _normalize_process_tree(payload: object, provider: str) -> list[MemoryProcess]:
    normalized: list[MemoryProcess] = []
    for row, depth in _tree_rows(payload):
        pid = _integer(_value(row, "PID", "Pid"))
        if pid is None or pid < 0:
            continue
        ppid = _integer(_value(row, "PPID", "PPid", "Parent PID"))
        normalized.append(
            MemoryProcess(
                pid=pid,
                ppid=ppid if ppid is None or ppid >= 0 else None,
                name=_text(_value(row, "ImageFileName", "Name", "Process"))
                or "unknown",
                command_line=_text(_value(row, "CommandLine", "Command Line", "Cmd")),
                thread_count=_integer(_value(row, "Threads", "ThreadCount")),
                module_count=None,
                source_provider=provider,
                tree_depth=depth,
            )
        )
    return normalized


def _normalize_modules(payload: object, provider: str) -> list[MemoryModule]:
    normalized: list[MemoryModule] = []
    for row in _rows(payload):
        pid = _integer(_value(row, "PID", "Pid"))
        base = _integer(_value(row, "Base", "BaseAddress", "DllBase"))
        if pid is None or pid < 0 or base is None or base < 0:
            continue
        path = _text(_value(row, "Path", "FullPath"))
        name = _text(_value(row, "Name", "Module", "BaseDllName"))
        if name is None and path:
            name = Path(path.replace("\\", "/")).name
        normalized.append(
            MemoryModule(
                pid=pid,
                process_name=_text(_value(row, "Process", "ImageFileName")),
                base_address=base,
                size=max(_integer(_value(row, "Size", "ImageSize")) or 0, 0),
                name=name or "unknown",
                path=path,
                load_time=_text(_value(row, "LoadTime", "Load Time")),
                source_provider=provider,
            )
        )
    return normalized


def _normalize_regions(payload: object, provider: str) -> list[MemoryRegion]:
    normalized: list[MemoryRegion] = []
    for row in _rows(payload):
        start = _integer(_value(row, "Start VPN", "Start", "StartAddress"))
        end = _integer(_value(row, "End VPN", "End", "EndAddress"))
        if start is None or end is None or start < 0 or end < start:
            continue
        protection = _text(_value(row, "Protection", "Protect")) or "unknown"
        private_memory = _boolean(
            _value(row, "PrivateMemory", "Private Memory", "Private")
        )
        mapped_file = _text(_value(row, "File", "FileName", "MappedFile"))
        suspicious, reason = _region_assessment(protection, private_memory, mapped_file)
        pid = _integer(_value(row, "PID", "Pid"))
        normalized.append(
            MemoryRegion(
                start=start,
                end=end,
                protection=protection,
                mapped_file=mapped_file,
                suspicious=suspicious,
                reason=reason,
                source_provider=provider,
                pid=pid if pid is None or pid >= 0 else None,
                process_name=_text(_value(row, "Process", "ImageFileName")),
                private_memory=private_memory,
                tag=_text(_value(row, "Tag")),
            )
        )
    return normalized


def _normalize_network(payload: object, provider: str) -> list[MemoryNetworkArtifact]:
    normalized: list[MemoryNetworkArtifact] = []
    for row in _rows(payload):
        protocol = _text(_value(row, "Proto", "Protocol"))
        local_address = _text(_value(row, "LocalAddr", "Local Address", "LocalAddress"))
        if protocol is None or local_address is None:
            continue
        pid = _integer(_value(row, "PID", "Pid"))
        local_port = _integer(_value(row, "LocalPort", "Local Port"))
        remote_port = _integer(
            _value(row, "ForeignPort", "RemotePort", "Foreign Port", "Remote Port")
        )
        offset = _integer(_value(row, "Offset"))
        if offset is not None and offset < 0:
            offset = None
        normalized.append(
            MemoryNetworkArtifact(
                protocol=protocol.upper(),
                local_address=local_address,
                local_port=(
                    local_port
                    if local_port is None or 0 <= local_port <= 65_535
                    else None
                ),
                remote_address=_text(
                    _value(
                        row,
                        "ForeignAddr",
                        "RemoteAddr",
                        "Foreign Address",
                        "Remote Address",
                    )
                ),
                remote_port=(
                    remote_port
                    if remote_port is None or 0 <= remote_port <= 65_535
                    else None
                ),
                state=_text(_value(row, "State")),
                pid=pid if pid is None or pid >= 0 else None,
                process_name=_text(_value(row, "Owner", "Process", "ImageFileName")),
                created_at=_text(_value(row, "Created", "CreateTime", "Create Time")),
                source_provider=provider,
                offset=offset,
            )
        )
    return normalized


def _normalize_handles(payload: object, provider: str) -> list[MemoryHandle]:
    normalized: list[MemoryHandle] = []
    for row in _rows(payload):
        pid = _integer(_value(row, "PID", "Pid"))
        if pid is None or pid < 0:
            continue
        object_offset = _integer(
            _value(row, "Offset", "Object", "ObjectOffset", "Object Address")
        )
        handle_value = _integer(_value(row, "HandleValue", "Handle Value", "Handle"))
        granted_access = _integer(
            _value(row, "GrantedAccess", "Granted Access", "Access")
        )
        if object_offset is not None and object_offset < 0:
            object_offset = None
        if handle_value is not None and handle_value < 0:
            handle_value = None
        if granted_access is not None and granted_access < 0:
            granted_access = None
        process_name = _text(_value(row, "Process", "ImageFileName"))
        object_type = _text(_value(row, "Type", "ObjectType", "Object Type"))
        name = _text(_value(row, "Name", "Details", "ObjectName", "Object Name"))
        normalized.append(
            MemoryHandle(
                pid=pid,
                process_name=process_name[:512] if process_name else None,
                object_offset=object_offset,
                handle_value=handle_value,
                object_type=(object_type[:128] if object_type else "unknown"),
                granted_access=granted_access,
                name=name[:4096] if name else None,
                source_provider=provider,
            )
        )
    return normalized


def _merge_processes(
    listed: list[MemoryProcess], tree: list[MemoryProcess], tree_available: bool
) -> list[MemoryProcess]:
    by_pid = {process.pid: process for process in listed}
    for tree_process in tree:
        listed_process = by_pid.get(tree_process.pid)
        if listed_process is None:
            by_pid[tree_process.pid] = tree_process
            continue
        by_pid[tree_process.pid] = replace(
            listed_process,
            ppid=tree_process.ppid
            if tree_process.ppid is not None
            else listed_process.ppid,
            name=(
                tree_process.name
                if listed_process.name == "unknown" and tree_process.name != "unknown"
                else listed_process.name
            ),
            command_line=tree_process.command_line or listed_process.command_line,
            tree_depth=tree_process.tree_depth,
        )
    processes = list(by_pid.values())
    if tree_available:
        known_pids = set(by_pid)
        processes = [
            replace(
                process,
                orphaned=(
                    process.ppid not in {None, 0} and process.ppid not in known_pids
                ),
            )
            for process in processes
        ]
    return processes


class VolatilityAdapter:
    name = "volatility3"

    def executable(self) -> Path | None:
        found = shutil.which(get_settings().volatility_path)
        if found is None:
            return None
        resolved = Path(found).resolve()
        return resolved if resolved.is_file() and os.access(resolved, os.X_OK) else None

    def is_available(self) -> bool:
        return self.executable() is not None

    def _run(self, dump_path: Path, plugin: str) -> object:
        if plugin not in ALLOWED_PLUGINS:
            raise ValueError(f"Volatility plugin is not allowlisted: {plugin!r}.")
        executable = self.executable()
        if executable is None:
            raise IntegrationUnavailableError(
                "Volatility 3 is not installed or configured."
            )
        settings = get_settings()
        with tempfile.TemporaryDirectory(prefix="rlab-volatility-") as temporary:
            stdout_path = Path(temporary) / "stdout.json"
            stderr_path = Path(temporary) / "stderr.log"
            command = [
                str(executable),
                "-f",
                str(dump_path.resolve()),
                "-r",
                "json",
                plugin,
            ]
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                try:
                    completed = subprocess.run(
                        command,
                        stdin=subprocess.DEVNULL,
                        stdout=stdout,
                        stderr=stderr,
                        timeout=settings.max_analysis_seconds,
                        check=False,
                        shell=False,
                        env={"PATH": str(executable.parent), "LANG": "C.UTF-8"},
                    )
                except subprocess.TimeoutExpired as exc:
                    raise IntegrationUnavailableError(
                        f"Volatility plugin {plugin} timed out."
                    ) from exc
            if completed.returncode != 0:
                detail = stderr_path.read_bytes()[-2_000:].decode(
                    "utf-8", errors="replace"
                )
                raise IntegrationUnavailableError(
                    f"Volatility plugin {plugin} failed: {detail or 'no output'}."
                )
            if stdout_path.stat().st_size > settings.max_external_output_bytes:
                raise IntegrationUnavailableError(
                    f"Volatility plugin {plugin} exceeded the output limit."
                )
            try:
                return json.loads(stdout_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise IntegrationUnavailableError(
                    f"Volatility plugin {plugin} returned malformed JSON."
                ) from exc

    def extract_region(
        self,
        dump_path: Path,
        *,
        pid: int,
        address: int,
        max_bytes: int,
    ) -> RegionExtraction:
        """Extract one exact VAD through fixed VadInfo arguments and a private output dir."""
        if pid < 0 or pid > 2**32 - 1:
            raise ValueError("PID is outside the supported range.")
        if address < 0 or address > 2**63 - 1:
            raise ValueError("Region address is outside the supported range.")
        configured_limit = get_settings().max_memory_region_extract_bytes
        if max_bytes < 1 or max_bytes > configured_limit:
            raise ValueError("Region extraction size exceeds the configured bound.")
        executable = self.executable()
        if executable is None:
            raise IntegrationUnavailableError(
                "Volatility 3 is not installed or configured."
            )
        settings = get_settings()
        plugin = "windows.vadinfo.VadInfo"
        with tempfile.TemporaryDirectory(prefix="rlab-volatility-region-") as temporary:
            temporary_path = Path(temporary)
            output_dir = temporary_path / "output"
            output_dir.mkdir(mode=0o700)
            stdout_path = temporary_path / "stdout.json"
            stderr_path = temporary_path / "stderr.log"
            command = [
                str(executable),
                "-f",
                str(dump_path.resolve()),
                "-o",
                str(output_dir),
                "-r",
                "json",
                plugin,
                "--pid",
                str(pid),
                "--address",
                str(address),
                "--dump",
                "--maxsize",
                str(max_bytes),
            ]
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                try:
                    completed = subprocess.run(
                        command,
                        stdin=subprocess.DEVNULL,
                        stdout=stdout,
                        stderr=stderr,
                        timeout=settings.max_analysis_seconds,
                        check=False,
                        shell=False,
                        env={"PATH": str(executable.parent), "LANG": "C.UTF-8"},
                    )
                except subprocess.TimeoutExpired as exc:
                    raise IntegrationUnavailableError(
                        "Volatility memory-region extraction timed out."
                    ) from exc
            if completed.returncode != 0:
                detail = stderr_path.read_bytes()[-2_000:].decode(
                    "utf-8", errors="replace"
                )
                raise IntegrationUnavailableError(
                    "Volatility memory-region extraction failed: "
                    f"{detail or 'no output'}."
                )
            if stdout_path.stat().st_size > settings.max_external_output_bytes:
                raise IntegrationUnavailableError(
                    "Volatility memory-region metadata exceeded the output limit."
                )
            try:
                payload = json.loads(stdout_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise IntegrationUnavailableError(
                    "Volatility memory-region extraction returned malformed JSON."
                ) from exc

            matches: list[tuple[dict[str, object], int, int, str]] = []
            for row in _rows(payload):
                row_pid = _integer(_value(row, "PID", "Pid"))
                start = _integer(_value(row, "Start VPN", "Start", "StartAddress"))
                end = _integer(_value(row, "End VPN", "End", "EndAddress"))
                file_output = _text(_value(row, "File output", "FileOutput"))
                if (
                    row_pid == pid
                    and start == address
                    and end is not None
                    and end >= start
                    and file_output is not None
                ):
                    matches.append((row, start, end, file_output))
            if len(matches) != 1:
                raise IntegrationUnavailableError(
                    "Volatility did not return exactly one requested VAD artifact."
                )
            row, start, end, file_output = matches[0]
            expected_size = end - start + 1
            if expected_size > max_bytes:
                raise IntegrationUnavailableError(
                    "The requested VAD exceeds the configured extraction limit."
                )
            filename = Path(file_output.replace("\\", "/")).name
            candidate = output_dir / filename
            if (
                not filename
                or candidate.is_symlink()
                or candidate.resolve().parent != output_dir.resolve()
                or not candidate.is_file()
            ):
                raise IntegrationUnavailableError(
                    "Volatility returned an invalid region artifact path."
                )
            size = candidate.stat().st_size
            if size < 1 or size > max_bytes or size != expected_size:
                raise IntegrationUnavailableError(
                    "Volatility region artifact violated the expected size bound."
                )
            data = candidate.read_bytes()
            if len(data) != size:
                raise IntegrationUnavailableError(
                    "Volatility region artifact changed while it was being read."
                )
            return RegionExtraction(
                data=data,
                pid=pid,
                start=start,
                end=end,
                process_name=_text(_value(row, "Process", "ImageFileName")),
                provider=self.name,
            )

    def analyze(self, dump_path: Path) -> VolatilityResult:
        """Run only server-selected plugins; callers cannot supply plugin names."""
        settings = get_settings()
        processes: list[MemoryProcess] = []
        tree_processes: list[MemoryProcess] = []
        modules: list[MemoryModule] = []
        regions: list[MemoryRegion] = []
        network: list[MemoryNetworkArtifact] = []
        handles: list[MemoryHandle] = []
        completed_plugins: list[str] = []
        warnings: list[str] = []
        specifications = (
            (
                "windows.pslist.PsList",
                _normalize_processes,
                processes,
                settings.max_memory_processes,
            ),
            (
                "windows.pstree.PsTree",
                _normalize_process_tree,
                tree_processes,
                settings.max_memory_processes,
            ),
            (
                "windows.dlllist.DllList",
                _normalize_modules,
                modules,
                settings.max_memory_modules,
            ),
            (
                "windows.vadinfo.VadInfo",
                _normalize_regions,
                regions,
                settings.max_memory_regions,
            ),
            (
                "windows.netscan.NetScan",
                _normalize_network,
                network,
                settings.max_memory_network_records,
            ),
            (
                "windows.handles.Handles",
                _normalize_handles,
                handles,
                settings.max_memory_handles,
            ),
        )
        for plugin, normalizer, destination, limit in specifications:
            try:
                payload = self._run(dump_path, plugin)
            except IntegrationUnavailableError as exc:
                warnings.append(str(exc))
                continue
            if not _supported_payload(payload):
                warnings.append(
                    f"Volatility plugin {plugin} returned an unsupported JSON structure."
                )
                continue
            normalized = normalizer(payload, self.name)
            destination.extend(normalized[:limit])
            completed_plugins.append(plugin)
            if len(normalized) > limit:
                warnings.append(
                    f"Volatility plugin {plugin} returned {len(normalized)} records; "
                    f"retained the configured maximum of {limit}."
                )

        processes = _merge_processes(
            processes,
            tree_processes,
            "windows.pstree.PsTree" in completed_plugins,
        )
        if len(processes) > settings.max_memory_processes:
            warnings.append(
                f"Merged process records exceeded the configured maximum of "
                f"{settings.max_memory_processes}."
            )
            processes = processes[: settings.max_memory_processes]

        modules.sort(key=lambda item: (item.pid, item.base_address, item.name.lower()))
        regions.sort(
            key=lambda item: (item.pid if item.pid is not None else -1, item.start)
        )
        network.sort(
            key=lambda item: (
                item.pid if item.pid is not None else -1,
                item.protocol,
                item.local_address,
                item.local_port if item.local_port is not None else -1,
            )
        )
        handles.sort(
            key=lambda item: (
                item.pid,
                item.object_type.casefold(),
                item.handle_value if item.handle_value is not None else -1,
                item.object_offset if item.object_offset is not None else -1,
            )
        )
        processes.sort(key=lambda item: item.pid)
        if "windows.dlllist.DllList" in completed_plugins:
            counts: dict[int, int] = {}
            for module in modules:
                counts[module.pid] = counts.get(module.pid, 0) + 1
            processes = [
                replace(process, module_count=counts.get(process.pid, 0))
                for process in processes
            ]

        return VolatilityResult(
            processes=tuple(processes),
            modules=tuple(modules),
            regions=tuple(regions),
            completed_plugins=tuple(completed_plugins),
            warnings=tuple(warnings),
            network=tuple(network),
            handles=tuple(handles),
        )
