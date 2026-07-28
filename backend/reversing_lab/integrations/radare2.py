"""radare2 integration.

Uses the ``r2`` command-line tool in batch mode to run analysis and dump the function
list as JSON. No shell is invoked and the command vector is fixed; only the file path
(a server-controlled content-hash path) varies.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess

from ..config import get_settings
from ..errors import IntegrationUnavailableError
from .base import IntegrationAdapter, IntegrationInfo, IntegrationResult

logger = logging.getLogger(__name__)


class Radare2Adapter(IntegrationAdapter):
    """Adapter around the radare2 CLI (``r2``)."""

    name = "radare2"

    def _executable(self) -> str | None:
        return shutil.which(get_settings().radare2_path)

    def info(self) -> IntegrationInfo:
        executable = self._executable()
        if executable is None:
            return IntegrationInfo(
                name=self.name,
                available=False,
                detail="radare2 (`r2`) not found on PATH. Install it to enable this integration.",
            )
        try:
            version = subprocess.run(
                [executable, "-v"],
                capture_output=True,
                text=True,
                timeout=get_settings().integration_timeout_seconds,
                check=False,
            ).stdout.splitlines()[0].strip()
        except (subprocess.SubprocessError, OSError, IndexError):
            version = None
        return IntegrationInfo(name=self.name, available=True, version=version)

    def analyze(self, file_path: str) -> IntegrationResult:
        executable = self._executable()
        if executable is None:
            raise IntegrationUnavailableError("radare2 is not installed.")

        # -q quit after commands, -c run commands: analyze all (aa) then list funcs (aflj).
        command = [executable, "-q", "-e", "scr.color=0", "-c", "aa;aflj", file_path]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=get_settings().integration_timeout_seconds,
                check=True,
            )
        except subprocess.TimeoutExpired as exc:
            raise IntegrationUnavailableError("radare2 analysis timed out.") from exc
        except subprocess.SubprocessError as exc:
            raise IntegrationUnavailableError(f"radare2 failed: {exc}.") from exc

        functions: list[str] = []
        try:
            for entry in json.loads(completed.stdout or "[]"):
                name = entry.get("name")
                if name:
                    functions.append(name)
        except json.JSONDecodeError:
            logger.warning("radare2 produced non-JSON output; returning empty function list.")

        return IntegrationResult(
            name=self.name,
            summary=f"radare2 identified {len(functions)} function(s).",
            functions=tuple(functions),
            data={"command": " ".join(command[:-1] + ["<file>"])},
        )
