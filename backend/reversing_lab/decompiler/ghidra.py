"""Ghidra headless decompiler adapter with fixed, non-shell arguments."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

from ..analysis.models import ProvenanceKind
from ..errors import IntegrationUnavailableError
from .base import DecompileOptions, DecompiledFunction, SourceMapEntry


class GhidraDecompilerAdapter:
    name = "ghidra"

    def _executable(self) -> Path | None:
        home = os.environ.get("GHIDRA_HOME")
        if not home:
            return None
        executable = Path(home).resolve() / "support" / "analyzeHeadless"
        return executable if executable.is_file() and os.access(executable, os.X_OK) else None

    def is_available(self) -> bool:
        return self._executable() is not None

    def decompile_function(
        self, binary_path: Path, address: int, options: DecompileOptions
    ) -> DecompiledFunction:
        executable = self._executable()
        if executable is None:
            raise IntegrationUnavailableError("Ghidra headless is not configured.")
        if not binary_path.is_file():
            raise IntegrationUnavailableError("The content-addressed sample path is missing.")

        script_dir = Path(__file__).with_name("scripts").resolve()
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="rlab-ghidra-") as temporary:
            root = Path(temporary)
            output = root / "decompiled.json"
            command = [
                str(executable),
                str(root),
                "ReversingLab",
                "-import",
                str(binary_path.resolve()),
                "-scriptPath",
                str(script_dir),
                "-postScript",
                "RLabDecompile.java",
                f"0x{address:x}",
                str(output),
                "-deleteProject",
            ]
            environment = {"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"}
            if os.environ.get("JAVA_HOME"):
                environment["JAVA_HOME"] = os.environ["JAVA_HOME"]
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
                    f"Ghidra decompilation exceeded {options.timeout_seconds:g} seconds."
                ) from exc
            if completed.returncode != 0 or not output.is_file():
                detail = completed.stderr[-2_000:].decode("utf-8", errors="replace")
                raise IntegrationUnavailableError(
                    f"Ghidra decompilation failed: {detail or 'no structured output'}."
                )
            if output.stat().st_size > options.max_output_bytes:
                raise IntegrationUnavailableError("Ghidra output exceeded the configured size limit.")
            payload = json.loads(output.read_text(encoding="utf-8"))

        return DecompiledFunction(
            function_address=address,
            function_name=str(payload.get("function_name") or f"sub_{address:x}"),
            language="C-like",
            code=str(payload["code"]),
            warnings=tuple(str(item) for item in payload.get("warnings", [])),
            confidence=0.8,
            variables=(),
            parameters=(),
            return_type=payload.get("return_type"),
            source_map=tuple(
                SourceMapEntry(
                    line=int(item["line"]),
                    address_start=int(item["address_start"]),
                    address_end=int(item["address_end"]),
                    confidence=0.75,
                    provenance=ProvenanceKind.INFERRED,
                )
                for item in payload.get("source_map", [])
            ),
            provider=self.name,
            elapsed_ms=round((time.monotonic() - started) * 1000),
        )
