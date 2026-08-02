"""Safe memory metadata, strings/IOC extraction, and provider orchestration."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

from ..analyzer.strings import extract_strings
from ..config import get_settings
from ..jobs import JobContext
from .models import MemoryAnalysisResult, MemoryFinding, MemoryMetadata
from .volatility import VolatilityAdapter

_URL = re.compile(r"https?://[^\s\"'<>]{4,512}", re.IGNORECASE)
_IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_DOMAIN = re.compile(
    r"(?<![A-Za-z0-9.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})\.)+[A-Za-z]{2,24}(?![A-Za-z0-9.-])"
)


def detect_dump_format(data: bytes) -> tuple[str, str | None, float]:
    if data.startswith(b"PAGEDUMP") or data.startswith(b"DUMP"):
        return "windows-memory-dump", "Windows", 0.92
    if data.startswith(b"MDMP"):
        return "windows-minidump", "Windows", 0.98
    if data.startswith(b"\x7fELF") and len(data) >= 18:
        elf_type = int.from_bytes(data[16:18], "little")
        return (
            ("linux-core" if elf_type == 4 else "elf-process-image"),
            "Linux",
            0.9 if elf_type == 4 else 0.55,
        )
    return "raw-memory-region", None, 0.35


def _valid_ips(values: set[str]) -> tuple[str, ...]:
    valid = []
    for value in sorted(values):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        valid.append(value)
    return tuple(valid)


def analyze_memory(
    dump_path: Path,
    *,
    use_volatility: bool = True,
    context: JobContext | None = None,
) -> MemoryAnalysisResult:
    settings = get_settings()
    data = dump_path.read_bytes()
    if context:
        context.update(12, "Reading dump metadata")
    dump_format, os_guess, metadata_confidence = detect_dump_format(data)
    metadata = MemoryMetadata(
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        dump_format=dump_format,
        os_guess=os_guess,
        architecture=None,
        confidence=metadata_confidence,
    )

    if context:
        context.update(30, "Extracting bounded strings and IOCs")
    extracted = extract_strings(
        data,
        min_length=5,
        max_results=settings.max_strings,
    )
    strings = tuple(item.value for item in extracted)
    urls = tuple(sorted({match.group(0) for value in strings for match in _URL.finditer(value)}))
    ips = _valid_ips({match.group(0) for value in strings for match in _IP.finditer(value)})
    domains = {
        match.group(0).lower()
        for value in strings
        for match in _DOMAIN.finditer(value)
    }
    for url in urls:
        host = urlparse(url).hostname
        if host:
            domains.add(host.lower())

    findings: list[MemoryFinding] = []
    if b"-----BEGIN PRIVATE KEY-----" in data:
        offset = data.index(b"-----BEGIN PRIVATE KEY-----")
        findings.append(
            MemoryFinding(
                id=f"possible-secret-{offset:x}",
                title="Possible secret material",
                severity="high",
                confidence=0.88,
                summary="A private-key PEM marker is present in memory.",
                evidence=(f"PEM marker at file offset 0x{offset:x}.",),
                false_positive_note="The key may be public test data, stale memory, or inaccessible material.",
            )
        )

    processes = ()
    regions = ()
    provider = "basic"
    unavailable = [
        "threads",
        "handles",
        "environment variables",
        "registry artifacts",
        "memory protection map",
        "process dump export",
    ]
    warnings: list[str] = []
    volatility = VolatilityAdapter()
    if use_volatility and dump_format == "windows-memory-dump":
        if volatility.is_available():
            if context:
                context.update(55, "Running allowlisted Volatility plugins")
            processes, regions, provider_warnings = volatility.analyze(dump_path)
            warnings.extend(provider_warnings)
            provider = volatility.name
            if processes:
                unavailable.remove("threads")
        else:
            warnings.append(
                "Volatility 3 is unavailable; returned basic metadata, strings, and IOCs only."
            )

    if context:
        context.update(82, "Finalizing compressed result artifact")
    return MemoryAnalysisResult(
        metadata=metadata,
        processes=processes,
        regions=regions,
        strings=strings,
        urls=urls,
        ip_addresses=ips,
        domains=tuple(sorted(domains)),
        findings=tuple(findings),
        provider=provider,
        unavailable=tuple(unavailable),
        warnings=tuple(warnings),
    )
