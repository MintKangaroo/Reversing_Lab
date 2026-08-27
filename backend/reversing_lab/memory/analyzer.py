"""Safe memory metadata, strings/IOC extraction, and provider orchestration."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from bisect import bisect_right
from pathlib import Path
from urllib.parse import urlparse

from ..analyzer.strings import extract_strings
from ..config import get_settings
from ..jobs import JobContext
from .models import (
    MemoryAnalysisResult,
    MemoryFinding,
    MemoryMetadata,
    MemoryNetworkArtifact,
    MemoryRegion,
    MemoryThread,
)
from .volatility import VolatilityAdapter

_URL = re.compile(r"https?://[^\s\"'<>]{4,512}", re.IGNORECASE)
_IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_DOMAIN = re.compile(
    r"(?<![A-Za-z0-9.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})\.)+[A-Za-z]{2,24}(?![A-Za-z0-9.-])"
)


def detect_dump_format(data: bytes) -> tuple[str, str | None, float]:
    if data.startswith((b"PAGEDUMP", b"DUMP")):
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


def _parsed_endpoint(
    value: str | None,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not value:
        return None
    candidate = value.strip().strip("[]").split("%", 1)[0]
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


def _network_findings(
    records: tuple[MemoryNetworkArtifact, ...], limit: int
) -> tuple[list[MemoryFinding], bool]:
    findings: list[MemoryFinding] = []
    truncated = False
    seen: set[tuple[str, int | None, str | None, int | None, int | None]] = set()
    for index, record in enumerate(records):
        remote_ip = _parsed_endpoint(record.remote_address)
        public_remote = bool(
            remote_ip and remote_ip.is_global and record.remote_port not in {None, 0}
        )
        state = (record.state or "").upper()
        local_ip = _parsed_endpoint(record.local_address)
        wildcard_listener = (
            "LISTEN" in state
            and (
                record.local_address == "*"
                or bool(local_ip and local_ip.is_unspecified)
            )
            and (not record.process_name or record.process_name.casefold() == "unknown")
        )
        if not public_remote and not wildcard_listener:
            continue
        key = (
            record.protocol,
            record.pid,
            record.remote_address if public_remote else record.local_address,
            record.remote_port if public_remote else record.local_port,
            1 if public_remote else 0,
        )
        if key in seen:
            continue
        seen.add(key)
        if len(findings) >= limit:
            truncated = True
            break
        pid = str(record.pid) if record.pid is not None else "unknown"
        process = record.process_name or "unattributed"
        finding_id = (
            f"memory-network-{record.offset:x}"
            if record.offset is not None
            else f"memory-network-{index}"
        )
        if public_remote:
            findings.append(
                MemoryFinding(
                    id=finding_id,
                    title="Public remote network endpoint observed",
                    severity="info",
                    confidence=0.9,
                    summary=(
                        "Volatility reported a process endpoint connected to a public "
                        "IP address. This is an observation, not a maliciousness verdict."
                    ),
                    evidence=(
                        f"PID {pid} ({process}), protocol {record.protocol}, state {record.state or 'unknown'}.",
                        f"Local {record.local_address}:{record.local_port}; remote {record.remote_address}:{record.remote_port}.",
                        f"Source provider: {record.source_provider}.",
                    ),
                    false_positive_note=(
                        "Normal browsers, update agents, DNS clients, and enterprise software "
                        "routinely connect to public endpoints. Validate ownership and timing."
                    ),
                )
            )
        else:
            findings.append(
                MemoryFinding(
                    id=finding_id,
                    title="Unattributed wildcard listener",
                    severity="low",
                    confidence=0.62,
                    summary=(
                        "Volatility reported a wildcard listening socket without process "
                        "attribution; review it with adjacent process and handle evidence."
                    ),
                    evidence=(
                        f"Protocol {record.protocol}, local {record.local_address}:{record.local_port}, state {record.state}.",
                        f"PID {pid}; source provider: {record.source_provider}.",
                    ),
                    false_positive_note=(
                        "Kernel-owned sockets, terminated processes, symbol gaps, and normal "
                        "services can leave a listener without reliable attribution."
                    ),
                )
            )
    return findings, truncated


def _thread_findings(
    threads: tuple[MemoryThread, ...],
    regions: tuple[MemoryRegion, ...],
    limit: int,
) -> tuple[list[MemoryFinding], bool]:
    suspicious_by_pid: dict[int, list[MemoryRegion]] = {}
    for region in regions:
        if region.suspicious and region.pid is not None:
            suspicious_by_pid.setdefault(region.pid, []).append(region)
    starts_by_pid: dict[int, list[int]] = {}
    for pid, candidates in suspicious_by_pid.items():
        candidates.sort(key=lambda item: item.start)
        starts_by_pid[pid] = [item.start for item in candidates]

    findings: list[MemoryFinding] = []
    for thread in threads:
        candidates = suspicious_by_pid.get(thread.pid)
        if not candidates:
            continue
        matched: tuple[int, str, MemoryRegion] | None = None
        for address, label in (
            (thread.win32_start_address, "Win32 start"),
            (thread.start_address, "kernel start"),
        ):
            if address is None:
                continue
            index = bisect_right(starts_by_pid[thread.pid], address) - 1
            if index >= 0 and address <= candidates[index].end:
                matched = (address, label, candidates[index])
                break
        if matched is None:
            continue
        if len(findings) >= limit:
            return findings, True
        address, label, region = matched
        process = thread.process_name or region.process_name or "unknown"
        findings.append(
            MemoryFinding(
                id=f"memory-thread-{thread.pid}-{thread.tid}-{address:x}",
                title="Thread starts in a suspicious memory region",
                severity="medium",
                confidence=0.78,
                summary=(
                    "Volatility reported a thread start address inside a region already "
                    "flagged for executable private or writable memory."
                ),
                evidence=(
                    f"PID {thread.pid} ({process}), TID {thread.tid}, {label} 0x{address:x}.",
                    f"Region 0x{region.start:x}-0x{region.end:x}, protection {region.protection}.",
                    f"Sources: {thread.source_provider} thread and {region.source_provider} VAD records.",
                ),
                false_positive_note=(
                    "JIT runtimes, instrumentation, unpackers, stale thread records, and "
                    "symbol gaps can produce this correlation. Inspect the region bytes and "
                    "process context before treating it as injection evidence."
                ),
            )
        )
    return findings, False


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
    network = ()
    handles = ()
    threads = ()
    provider = "basic"
    unavailable = [
        "process list",
        "process tree",
        "thread details",
        "command lines",
        "loaded modules",
        "handles",
        "environment variables",
        "registry artifacts",
        "memory protection map",
        "network connections",
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
            network = volatility_result.network
            handles = volatility_result.handles
            threads = volatility_result.threads
            warnings.extend(volatility_result.warnings)
            provider = volatility.name
            completed = set(volatility_result.completed_plugins)
            if completed.intersection(
                {"windows.pslist.PsList", "windows.pstree.PsTree"}
            ):
                unavailable.remove("process list")
            if "windows.pstree.PsTree" in completed:
                unavailable.remove("process tree")
            if "windows.dlllist.DllList" in completed:
                unavailable.remove("loaded modules")
            if "windows.vadinfo.VadInfo" in completed:
                unavailable.remove("memory protection map")
            if "windows.netscan.NetScan" in completed:
                unavailable.remove("network connections")
            if "windows.handles.Handles" in completed:
                unavailable.remove("handles")
            if "windows.cmdline.CmdLine" in completed:
                unavailable.remove("command lines")
            if "windows.threads.Threads" in completed:
                unavailable.remove("thread details")
        else:
            warnings.append(
                "Volatility 3 is unavailable; returned basic metadata, strings, and IOCs only."
            )

    region_findings, truncated_findings = _region_findings(
        regions, max(settings.max_memory_findings - len(findings), 0)
    )
    findings.extend(region_findings)
    thread_findings, truncated_thread_findings = _thread_findings(
        threads, regions, max(settings.max_memory_findings - len(findings), 0)
    )
    findings.extend(thread_findings)
    network_findings, truncated_network_findings = _network_findings(
        network, max(settings.max_memory_findings - len(findings), 0)
    )
    findings.extend(network_findings)
    if (
        truncated_findings
        or truncated_thread_findings
        or truncated_network_findings
    ):
        warnings.append(
            "Memory findings exceeded the configured limit; "
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
        network=network,
        handles=handles,
        threads=threads,
    )
