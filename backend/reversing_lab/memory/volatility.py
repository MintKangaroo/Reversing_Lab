"""Volatility 3 adapter with a fixed plugin allowlist."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..config import get_settings
from ..errors import IntegrationUnavailableError
from .models import MemoryProcess, MemoryRegion

ALLOWED_PLUGINS: tuple[str, ...] = (
    "windows.info.Info",
    "windows.pslist.PsList",
    "windows.pstree.PsTree",
    "windows.dlllist.DllList",
    "windows.netscan.NetScan",
)


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
            raise IntegrationUnavailableError("Volatility 3 is not installed or configured.")
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
                detail = stderr_path.read_bytes()[-2_000:].decode("utf-8", errors="replace")
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

    def analyze(
        self, dump_path: Path
    ) -> tuple[tuple[MemoryProcess, ...], tuple[MemoryRegion, ...], tuple[str, ...]]:
        """Run only server-selected plugins; callers cannot supply plugin names."""
        processes: list[MemoryProcess] = []
        warnings: list[str] = []
        try:
            payload = self._run(dump_path, "windows.pslist.PsList")
            rows = payload if isinstance(payload, list) else []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                processes.append(
                    MemoryProcess(
                        pid=int(row.get("PID", row.get("Pid", 0))),
                        ppid=(
                            int(row.get("PPID", row.get("PPid")))
                            if row.get("PPID", row.get("PPid")) is not None
                            else None
                        ),
                        name=str(row.get("ImageFileName", row.get("Name", "unknown"))),
                        command_line=None,
                        thread_count=(
                            int(row["Threads"]) if row.get("Threads") is not None else None
                        ),
                        module_count=None,
                        source_provider=self.name,
                    )
                )
        except IntegrationUnavailableError as exc:
            warnings.append(str(exc))
        return tuple(processes), (), tuple(warnings)
