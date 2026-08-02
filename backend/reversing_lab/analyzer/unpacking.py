"""Explicit UPX unpack adapter that never overwrites the original sample."""

from __future__ import annotations

import hashlib
import os
import resource
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..config import get_settings
from ..errors import IntegrationUnavailableError, ParseError
from ..parser import parse_binary


@dataclass(frozen=True, slots=True)
class SectionChange:
    name: str
    original_size: int | None
    unpacked_size: int | None


@dataclass(frozen=True, slots=True)
class UnpackResult:
    provider: str
    original_sha256: str
    unpacked_sha256: str
    original_size: int
    unpacked_size: int
    section_changes: tuple[SectionChange, ...]
    warnings: tuple[str, ...]


def upx_executable() -> Path | None:
    configured = get_settings().upx_path
    found = shutil.which(configured)
    if found is None:
        return None
    resolved = Path(found).resolve()
    return resolved if resolved.is_file() and os.access(resolved, os.X_OK) else None


def _limit_child() -> None:
    settings = get_settings()
    cpu = max(1, int(settings.max_decompiler_seconds))
    memory = 512 * 1024 * 1024
    output = max(settings.max_upload_bytes * 2, 16 * 1024 * 1024)
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
    resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    resource.setrlimit(resource.RLIMIT_FSIZE, (output, output))


def unpack_upx(sample_path: Path, original_sha256: str) -> tuple[UnpackResult, bytes]:
    """Run `upx -d` with a fixed argument vector in a private temporary directory."""
    executable = upx_executable()
    if executable is None:
        raise IntegrationUnavailableError("UPX is not installed or configured.")
    sample = sample_path.resolve()
    if not sample.is_file() or sample.name != original_sha256:
        raise IntegrationUnavailableError("Sample path is not a validated content-addressed file.")

    settings = get_settings()
    original = sample.read_bytes()
    original_info = parse_binary(original)
    with tempfile.TemporaryDirectory(prefix="rlab-upx-") as temporary:
        root = Path(temporary)
        output_path = root / "unpacked.bin"
        stdout_path = root / "stdout.log"
        stderr_path = root / "stderr.log"
        command = [str(executable), "-d", "-o", str(output_path), str(sample)]
        environment = {"PATH": str(executable.parent), "LANG": "C.UTF-8"}
        try:
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                completed = subprocess.run(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=settings.integration_timeout_seconds,
                    check=False,
                    shell=False,
                    env=environment,
                    preexec_fn=_limit_child if os.name == "posix" else None,
                )
        except subprocess.TimeoutExpired as exc:
            raise IntegrationUnavailableError("UPX unpacking exceeded the configured timeout.") from exc
        if completed.returncode != 0 or not output_path.is_file():
            detail = stderr_path.read_bytes()[-2_000:].decode("utf-8", errors="replace")
            raise IntegrationUnavailableError(f"UPX failed: {detail or 'no output artifact'}.")
        if output_path.stat().st_size > settings.max_upload_bytes * 2:
            raise IntegrationUnavailableError("UPX output exceeded the configured derived-file limit.")
        unpacked = output_path.read_bytes()

    try:
        unpacked_info = parse_binary(unpacked)
    except Exception as exc:
        raise ParseError("UPX produced an artifact that is not a supported executable.") from exc
    original_sections = {section.name: section.size for section in original_info.sections}
    unpacked_sections = {section.name: section.size for section in unpacked_info.sections}
    changes = tuple(
        SectionChange(
            name=name,
            original_size=original_sections.get(name),
            unpacked_size=unpacked_sections.get(name),
        )
        for name in sorted(original_sections.keys() | unpacked_sections.keys())
        if original_sections.get(name) != unpacked_sections.get(name)
    )
    result_sha256 = hashlib.sha256(unpacked).hexdigest()
    return (
        UnpackResult(
            provider="upx",
            original_sha256=original_sha256,
            unpacked_sha256=result_sha256,
            original_size=len(original),
            unpacked_size=len(unpacked),
            section_changes=changes,
            warnings=(
                "The derived artifact was not executed.",
                "A successful UPX command does not prove the artifact is safe or fully unpacked.",
            ),
        ),
        unpacked,
    )
