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
from .models import MemoryAnalysisResult, MemoryFinding, MemoryMetadata, MemoryRegion
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


def _region_findings(
    regions: tuple[MemoryRegion, ...], limit: int
) -> tuple[list[MemoryFinding], bool]:
    findings: list[MemoryFinding] = []
    truncated = False
    for region in regions:
        if not region.suspicious:
            continue
        if len(findings) >= limit:
            truncated = True
            break
        writable_executable = bool(
            region.reason and region.reason.startswith("Writable and executable")
        )
        pid = str(region.pid) if region.pid is not None else "unknown"
        process = region.process_name or "unknown"
        mapped = region.mapped_file or "none observed"
        findings.append(
            MemoryFinding(
                id=f"memory-region-{pid}-{region.start:x}",
                title=(
                    "Writable and executable memory region"
                    if writable_executable
                    else "Private executable memory region"
                ),
                severity="high" if writable_executable else "medium",
                confidence=0.9 if writable_executable else 0.76,
                summary=(
                    "Volatility reported a region with write and execute permissions."
                    if writable_executable
                    else "Volatility reported private executable memory without a mapped file."
                ),
                evidence=(
                    f"PID {pid} ({process}), range 0x{region.start:x}-0x{region.end:x}.",
                    f"Protection: {region.protection}; private: {region.private_memory}; mapped file: {mapped}.",
                    f"Source provider: {region.source_provider}.",
                ),
                false_positive_note=(
                    "JIT runtimes, unpackers, instrumentation, and compatibility layers can "
                    "legitimately create executable private or writable memory. Correlate with "
                    "process identity, bytes, and dynamic observations before escalating."
                ),
            )
        )
    return findings, truncated


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
    urls = tuple(
        sorted({match.group(0) for value in strings for match in _URL.finditer(value)})
    )
    ips = _valid_ips(
        {match.group(0) for value in strings for match in _IP.finditer(value)}
    )
    domains = {
        match.group(0).lower() for value in strings for match in _DOMAIN.finditer(value)
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
    modules = ()
    regions = ()
    provider = "basic"
    unavailable = [
        "process list",
        "thread details",
        "command lines",
        "loaded modules",
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
            volatility_result = volatility.analyze(dump_path)
            processes = volatility_result.processes
            modules = volatility_result.modules
            regions = volatility_result.regions
            warnings.extend(volatility_result.warnings)
            provider = volatility.name
            completed = set(volatility_result.completed_plugins)
            if "windows.pslist.PsList" in completed:
                unavailable.remove("process list")
            if "windows.dlllist.DllList" in completed:
                unavailable.remove("loaded modules")
            if "windows.vadinfo.VadInfo" in completed:
                unavailable.remove("memory protection map")
        else:
            warnings.append(
                "Volatility 3 is unavailable; returned basic metadata, strings, and IOCs only."
            )

    region_findings, truncated_findings = _region_findings(
        regions, max(settings.max_memory_findings - len(findings), 0)
    )
    findings.extend(region_findings)
    if truncated_findings:
        warnings.append(
            "Suspicious memory-region findings exceeded the configured limit; "
            f"retained {settings.max_memory_findings}."
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
        modules=modules,
    )
