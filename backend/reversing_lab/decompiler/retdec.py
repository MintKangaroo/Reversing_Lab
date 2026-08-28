"""RetDec decompiler adapter (Avast's ``retdec-decompiler`` CLI).

Runs the decompiler with a fixed, non-shell argument vector into a private temp
directory, bounded by a timeout and an output-size cap. Only the content-addressed
sample path and the target address vary.

Function selection uses ``--select-ranges``/``--select-decode-only`` so RetDec decodes
only the requested function rather than the whole image. RetDec emits the C to the
``-o`` path; a companion ``<out>.config.json`` maps addresses to functions, which we use
to name the result. Any operational problem degrades to a typed
:class:`IntegrationUnavailableError` so the registry falls back to pseudo-C.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from ..analysis.models import ProvenanceKind
from ..config import get_settings
from ..errors import IntegrationUnavailableError
from .base import DecompileOptions, DecompiledFunction, SourceMapEntry

# RetDec annotates decompiled lines with the originating address, e.g. `// 0x401008`.
_ADDR_COMMENT = re.compile(r"//\s*(0x[0-9a-fA-F]+)")


# Upper bound on the byte range fed to --select-ranges. RetDec follows the function's
# control flow from the start address and stops at its natural end, so this is only a
# ceiling: large enough to cover essentially any single function without pulling in a
# neighbour. A zero-length range decodes nothing ("No instructions were decoded").
_DECODE_WINDOW = 0x2000


class RetDecDecompilerAdapter:
    name = "retdec"

    def _executable(self) -> str | None:
        return shutil.which(get_settings().retdec_path)

    def is_available(self) -> bool:
        return self._executable() is not None

    def decompile_function(
        self, binary_path: Path, address: int, options: DecompileOptions
    ) -> DecompiledFunction:
        executable = self._executable()
        if executable is None:
            raise IntegrationUnavailableError("RetDec (`retdec-decompiler`) is not installed.")
        if not binary_path.is_file():
            raise IntegrationUnavailableError("The content-addressed sample path is missing.")

        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="rlab-retdec-") as temporary:
            output = Path(temporary) / "decompiled.c"
            command = [
                executable,
                str(binary_path.resolve()),
                "-o",
                str(output),
                "--select-ranges",
                f"0x{address:x}-0x{address + _DECODE_WINDOW:x}",
                "--select-decode-only",
                "--cleanup",
            ]
            environment = {"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"}
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
                    f"RetDec decompilation exceeded {options.timeout_seconds:g} seconds."
                ) from exc

            if completed.returncode != 0 or not output.is_file():
                detail = completed.stderr[-2_000:].decode("utf-8", errors="replace")
                raise IntegrationUnavailableError(
                    f"RetDec decompilation failed: {detail or 'no structured output'}."
                )
            if output.stat().st_size > options.max_output_bytes:
                raise IntegrationUnavailableError("RetDec output exceeded the configured size limit.")

            code = output.read_text(encoding="utf-8", errors="replace")
            function_name = _function_name_at(output.with_suffix(".config.json"), address)

        if not code.strip():
            raise IntegrationUnavailableError("RetDec returned no decompiled code.")

        return DecompiledFunction(
            function_address=address,
            function_name=function_name or f"sub_{address:x}",
            language="C",
            code=code,
            warnings=(),
            confidence=0.8,
            variables=(),
            parameters=(),
            return_type=None,
            source_map=_source_map(code),
            provider=self.name,
            elapsed_ms=round((time.monotonic() - started) * 1000),
        )


def _source_map(code: str) -> tuple[SourceMapEntry, ...]:
    """Build a per-line address map from RetDec's ``// 0xADDR`` line comments so the UI
    can sync a clicked decompiled line back to the disassembly."""
    entries: list[SourceMapEntry] = []
    for index, line in enumerate(code.splitlines(), start=1):
        match = _ADDR_COMMENT.search(line)
        if match is None:
            continue
        try:
            address = int(match.group(1), 16)
        except ValueError:
            continue
        entries.append(
            SourceMapEntry(
                line=index,
                address_start=address,
                address_end=address,
                confidence=0.7,
                provenance=ProvenanceKind.INFERRED,
            )
        )
    return tuple(entries)


def _function_name_at(config_path: Path, address: int) -> str | None:
    """Best-effort function name for ``address`` from RetDec's config JSON. Never raises:
    a missing or unexpected config simply yields ``None`` (the caller uses a sub_ name)."""
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        for function in config.get("functions", []):
            start = function.get("startAddr")
            if start is None:
                continue
            if int(str(start), 0) == address and function.get("name"):
                return str(function["name"])
    except (OSError, ValueError, TypeError, AttributeError):
        return None
    return None
