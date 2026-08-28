"""r2ghidra decompiler adapter (radare2 + the r2ghidra plugin's ``pdgj`` command).

Runs radare2 in batch mode with a fixed, non-shell argument vector; only the
content-addressed sample path and the target address vary. The Ghidra decompiler
(the p-code engine) is invoked in-process by the plugin, so no separate Ghidra
install is required — just radare2 with the ``r2ghidra`` plugin.

Availability reports on the radare2 executable alone; the plugin may still be
absent, in which case ``decompile_function`` degrades to a typed
:class:`IntegrationUnavailableError` and the registry falls back to pseudo-C.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from ..config import get_settings
from ..errors import IntegrationUnavailableError
from .base import DecompileOptions, DecompiledFunction


class R2GhidraDecompilerAdapter:
    name = "r2ghidra"

    def _executable(self) -> str | None:
        return shutil.which(get_settings().radare2_path)

    def is_available(self) -> bool:
        # radare2 present is a cheap, non-executing signal; a missing r2ghidra plugin
        # is handled at decompile time so list_decompilers stays fast.
        return self._executable() is not None

    def decompile_function(
        self, binary_path: Path, address: int, options: DecompileOptions
    ) -> DecompiledFunction:
        executable = self._executable()
        if executable is None:
            raise IntegrationUnavailableError("radare2 (`r2`) is not installed.")
        if not binary_path.is_file():
            raise IntegrationUnavailableError("The content-addressed sample path is missing.")

        # -q quit after commands, colours off, no rc files. Seek to the target, analyze
        # just that function, then emit r2ghidra's JSON pseudo-C (`pdgj`).
        script = f"s 0x{address:x}; af; pdgj"
        command = [
            executable,
            "-q",
            "-e",
            "scr.color=0",
            "-N",
            "-c",
            script,
            str(binary_path.resolve()),
        ]
        environment = {"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"}
        # radare2 discovers user-installed plugins (the common `r2pm -ci r2ghidra` path)
        # under $HOME/.local/share/radare2/plugins; without HOME it silently loads none
        # and `pdg` is unavailable. Pass HOME through when set, like the Ghidra adapter
        # forwards JAVA_HOME — a tool-required variable, not the full ambient environment.
        home = os.environ.get("HOME")
        if home:
            environment["HOME"] = home
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=options.timeout_seconds,
                check=False,
                shell=False,
                env=environment,
            )
        except subprocess.TimeoutExpired as exc:
            raise IntegrationUnavailableError(
                f"r2ghidra decompilation exceeded {options.timeout_seconds:g} seconds."
            ) from exc

        if completed.returncode != 0:
            detail = completed.stderr[-2_000:].decode("utf-8", errors="replace")
            raise IntegrationUnavailableError(
                f"r2ghidra decompilation failed: {detail or 'no output'}."
            )
        if len(completed.stdout) > options.max_output_bytes:
            raise IntegrationUnavailableError("r2ghidra output exceeded the configured size limit.")

        try:
            payload = json.loads(completed.stdout.decode("utf-8", errors="replace") or "{}")
        except ValueError as exc:
            # Non-JSON almost always means the r2ghidra plugin is not installed.
            raise IntegrationUnavailableError(
                "r2ghidra produced no JSON; the plugin may not be installed."
            ) from exc
        code = payload.get("code") if isinstance(payload, dict) else None
        if not code:
            raise IntegrationUnavailableError("r2ghidra returned no decompiled code.")

        return DecompiledFunction(
            function_address=address,
            function_name=f"sub_{address:x}",
            language="C-like",
            code=str(code),
            warnings=(),
            confidence=0.8,
            variables=(),
            parameters=(),
            return_type=None,
            source_map=(),
            provider=self.name,
            elapsed_ms=round((time.monotonic() - started) * 1000),
        )
