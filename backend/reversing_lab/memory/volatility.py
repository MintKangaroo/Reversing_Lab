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
from .models import MemoryModule, MemoryProcess, MemoryRegion

ALLOWED_PLUGINS: tuple[str, ...] = (
    "windows.info.Info",
    "windows.pslist.PsList",
    "windows.pstree.PsTree",
    "windows.dlllist.DllList",
    "windows.vadinfo.VadInfo",
    "windows.netscan.NetScan",
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

    def analyze(self, dump_path: Path) -> VolatilityResult:
        """Run only server-selected plugins; callers cannot supply plugin names."""
        settings = get_settings()
        processes: list[MemoryProcess] = []
        modules: list[MemoryModule] = []
        regions: list[MemoryRegion] = []
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

        modules.sort(key=lambda item: (item.pid, item.base_address, item.name.lower()))
        regions.sort(
            key=lambda item: (item.pid if item.pid is not None else -1, item.start)
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
        )
