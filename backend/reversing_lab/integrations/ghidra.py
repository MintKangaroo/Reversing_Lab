"""Ghidra integration (headless analyzer).

Ghidra ships an ``analyzeHeadless`` launcher. When ``GHIDRA_HOME`` (or ``GHIDRA_INSTALL_DIR``)
points at an install, this adapter imports the binary into a throwaway project and runs
non-interactive auto-analysis. Because a full headless run is heavy, ``analyze`` returns
a concise summary; deeper scripting is left to a user-supplied post-script.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..config import get_settings
from ..errors import IntegrationUnavailableError
from .base import IntegrationAdapter, IntegrationInfo, IntegrationResult

logger = logging.getLogger(__name__)


class GhidraAdapter(IntegrationAdapter):
    """Adapter around Ghidra's headless analyzer."""

    name = "ghidra"

    def _headless_path(self) -> Path | None:
        home = os.environ.get("GHIDRA_HOME") or os.environ.get("GHIDRA_INSTALL_DIR")
        if not home:
            return None
        script = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
        candidate = Path(home) / "support" / script
        return candidate if candidate.is_file() else None

    def info(self) -> IntegrationInfo:
        headless = self._headless_path()
        if headless is None:
            return IntegrationInfo(
                name=self.name,
                available=False,
                detail="Set GHIDRA_HOME to a Ghidra install to enable headless analysis.",
            )
        version = None
        version_file = headless.parents[1] / "Ghidra" / "application.properties"
        if version_file.is_file():
            for line in version_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("application.version="):
                    version = line.split("=", 1)[1].strip()
                    break
        return IntegrationInfo(name=self.name, available=True, version=version)

    def analyze(self, file_path: str) -> IntegrationResult:
        headless = self._headless_path()
        if headless is None:
            raise IntegrationUnavailableError("Ghidra is not configured (GHIDRA_HOME unset).")

        with tempfile.TemporaryDirectory(prefix="rlab-ghidra-") as project_dir:
            command = [
                str(headless),
                project_dir,
                "rlab_project",
                "-import",
                file_path,
                "-analysisTimeoutPerFile",
                str(int(get_settings().integration_timeout_seconds)),
                "-deleteProject",
            ]
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=get_settings().integration_timeout_seconds + 30,
                    check=True,
                )
            except subprocess.TimeoutExpired as exc:
                raise IntegrationUnavailableError("Ghidra analysis timed out.") from exc
            except subprocess.SubprocessError as exc:
                raise IntegrationUnavailableError(f"Ghidra headless run failed: {exc}.") from exc

        tail = "\n".join(completed.stdout.splitlines()[-5:])
        return IntegrationResult(
            name=self.name,
            summary="Ghidra headless auto-analysis completed.",
            data={"log_tail": tail},
        )
