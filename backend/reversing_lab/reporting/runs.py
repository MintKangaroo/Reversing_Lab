"""Evidence-linked reports for dynamic runs and memory dumps.

Both builders consume the normalized result dictionary exactly as it is persisted
by the dynamic and memory pipelines, so they never re-run analysis or touch a
sample. Everything they emit is bounded to keep an export deterministic in size.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from .generator import html_document

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_MAX_EVENTS = 1_000
_MAX_ARTIFACTS = 500
_MAX_PROCESSES = 500
_MAX_REGIONS = 500
_MAX_NETWORK = 500
_MAX_MODULES = 500
_MAX_LIST_IOCS = 200


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _severity_key(item: dict[str, object]) -> tuple[int, str]:
    severity = str(item.get("severity", "info")).lower()
    return (_SEVERITY_ORDER.get(severity, 99), str(item.get("timestamp", "")))


def _counts_by(items: list[dict[str, object]], field: str) -> dict[str, int]:
    counter = Counter(str(item.get(field, "unknown")) for item in items)
    return dict(sorted(counter.items(), key=lambda pair: (-pair[1], pair[0])))


# --------------------------------------------------------------------------- #
# Dynamic run report
# --------------------------------------------------------------------------- #


def build_dynamic_report(
    *,
    run_id: str,
    job_id: str,
    binary_sha256: str,
    created_at: datetime,
    result: dict[str, object],
) -> dict[str, object]:
    """Build the canonical dynamic-run report from a stored result payload."""
    provider = str(result.get("provider", "unknown"))
    events = list(result.get("events", []))
    artifacts = list(result.get("artifacts", []))
    unavailable = list(result.get("unavailable_events", []))
    warnings = list(result.get("warnings", []))

    executed = any(
        str(event.get("result", "")).lower() != "not_executed" for event in events
    )
    ordered_events = sorted(events, key=_severity_key)

    recommendations = [
        "Corroborate each behavioral event against its process, target, and call stack.",
        "Treat dropped artifacts as untrusted; hash and detonate them only in isolation.",
    ]
    if not executed:
        recommendations.append(
            "This provider did not execute the sample; no behavior was observed. "
            "Use a managed VM sandbox for real dynamic analysis."
        )
    if warnings:
        recommendations.append("Review provider warnings before trusting the timeline.")

    return {
        "schema_version": "1.0",
        "report_type": "dynamic",
        "generated_at": _now(),
        "executive_summary": {
            "run_id": run_id,
            "binary_sha256": binary_sha256,
            "provider": provider,
            "sample_executed": executed,
            "event_count": len(events),
            "artifact_count": len(artifacts),
            "highest_severity": (
                ordered_events[0].get("severity") if ordered_events else None
            ),
            "statement": (
                "Behavioral timeline captured from an isolated sandbox run."
                if executed
                else "No behavior was observed; the provider did not execute the sample."
            ),
        },
        "run_metadata": {
            "run_id": run_id,
            "job_id": job_id,
            "binary_sha256": binary_sha256,
            "provider": provider,
            "created_at": created_at.isoformat(),
            "provenance": "verified",
        },
        "event_summary": {
            "total": len(events),
            "by_category": _counts_by(events, "category"),
            "by_severity": _counts_by(events, "severity"),
            "provenance": "observed" if executed else "not_observed",
        },
        "behavioral_timeline": {
            "events": ordered_events[:_MAX_EVENTS],
            "truncated": len(events) > _MAX_EVENTS,
            "ordering": "severity, then timestamp",
        },
        "dropped_artifacts": {
            "artifacts": artifacts[:_MAX_ARTIFACTS],
            "truncated": len(artifacts) > _MAX_ARTIFACTS,
        },
        "unobserved_behaviors": unavailable,
        "warnings": warnings,
        "limitations": [
            "Sandbox coverage is incomplete; absence of an event is not proof of absence.",
            "Evasive samples can detect instrumentation and suppress behavior.",
            "Event severities are heuristic and require analyst validation.",
            "Reports reflect a single run under one policy and may not generalize.",
        ],
        "recommended_next_steps": recommendations,
    }


def render_dynamic_markdown(report: dict[str, object]) -> str:
    """Render a dynamic-run report as analyst-friendly Markdown."""
    summary = report["executive_summary"]
    metadata = report["run_metadata"]
    event_summary = report["event_summary"]
    timeline = report["behavioral_timeline"]
    artifacts = report["dropped_artifacts"]

    lines = [
        f"# Dynamic Analysis Report — run `{summary['run_id']}`",
        "",
        "> Behavioral report from a sandbox run. Coverage is incomplete and "
        "severities are heuristic; validate against evidence.",
        "",
        "## 1. Executive Summary",
        "",
        summary["statement"],
        f"- Sample executed: {summary['sample_executed']}",
        f"- Events captured: {summary['event_count']}",
        f"- Dropped artifacts: {summary['artifact_count']}",
        f"- Highest severity: {summary['highest_severity'] or 'none'}",
        "",
        "## 2. Run Metadata",
        "",
        f"- Run ID: `{metadata['run_id']}`",
        f"- Job ID: `{metadata['job_id']}`",
        f"- Sample SHA-256: `{metadata['binary_sha256']}`",
        f"- Provider: {metadata['provider']}",
        f"- Created: {metadata['created_at']}",
        "",
        "## 3. Event Summary",
        "",
        f"- Total events: {event_summary['total']}",
        *[f"- Category `{name}`: {count}" for name, count in event_summary["by_category"].items()],
        *[f"- Severity `{name}`: {count}" for name, count in event_summary["by_severity"].items()],
        "",
        "## 4. Behavioral Timeline",
        "",
    ]
    if timeline["events"]:
        for event in timeline["events"]:
            target = event.get("target") or "—"
            lines.append(
                f"- `{event.get('severity', 'info')}` **{event.get('category')}** "
                f"{event.get('operation')} → {target} "
                f"(result: {event.get('result')})"
            )
        if timeline["truncated"]:
            lines.append(f"- _Timeline truncated to {_MAX_EVENTS} events._")
    else:
        lines.append("_No events were recorded for this run._")
    lines.extend(
        [
            "",
            "## 5. Dropped Artifacts",
            "",
        ]
    )
    if artifacts["artifacts"]:
        for item in artifacts["artifacts"]:
            digest = item.get("content_sha256") or "unhashed"
            lines.append(
                f"- **{item.get('name')}** ({item.get('kind')}, "
                f"{item.get('size')} bytes) — `{digest}`"
            )
    else:
        lines.append("_No artifacts were dropped or captured._")
    lines.extend(
        [
            "",
            "## 6. Unobserved Behaviors",
            "",
            *(
                [f"- {item}" for item in report["unobserved_behaviors"]]
                or ["_All monitored behavior classes were observed._"]
            ),
            "",
            "## 7. Warnings",
            "",
            *([f"- {item}" for item in report["warnings"]] or ["_No provider warnings._"]),
            "",
            "## 8. Limitations",
            "",
            *[f"- {item}" for item in report["limitations"]],
            "",
            "## 9. Recommended Next Steps",
            "",
            *[f"- {item}" for item in report["recommended_next_steps"]],
            "",
        ]
    )
    return "\n".join(lines)


def render_dynamic_html(report: dict[str, object]) -> str:
    """Render a dynamic-run report as standalone escaped HTML."""
    return html_document(
        subject=f"dynamic run {report['executive_summary']['run_id']}",
        notice="Behavioral sandbox output. Coverage is incomplete; validate every event.",
        markdown=render_dynamic_markdown(report),
    )


# --------------------------------------------------------------------------- #
# Memory dump report
# --------------------------------------------------------------------------- #


def build_memory_report(
    *,
    dump_id: str,
    filename: str,
    created_at: datetime,
    result: dict[str, object],
) -> dict[str, object]:
    """Build the canonical memory-dump report from a stored analysis payload."""
    metadata = dict(result.get("metadata", {}))
    provider = str(result.get("provider", "unknown"))
    processes = list(result.get("processes", []))
    regions = list(result.get("regions", []))
    modules = list(result.get("modules", []))
    network = list(result.get("network", []))
    handles = list(result.get("handles", []))
    threads = list(result.get("threads", []))
    findings = sorted(result.get("findings", []), key=_severity_key)
    strings = list(result.get("strings", []))
    urls = list(result.get("urls", []))
    ips = list(result.get("ip_addresses", []))
    domains = list(result.get("domains", []))
    unavailable = list(result.get("unavailable", []))
    warnings = list(result.get("warnings", []))

    suspicious = [region for region in regions if region.get("suspicious")]

    recommendations = [
        "Confirm each finding against the cited evidence and false-positive note.",
        "Dump and scan suspicious regions before drawing conclusions.",
    ]
    if urls or ips or domains:
        recommendations.append(
            "Treat recovered network indicators as unverified until corroborated."
        )
    if not findings:
        recommendations.append(
            "No bounded finding was produced; triage manually before clearing the dump."
        )

    return {
        "schema_version": "1.0",
        "report_type": "memory",
        "generated_at": _now(),
        "executive_summary": {
            "dump_id": dump_id,
            "sample": filename,
            "provider": provider,
            "os_guess": metadata.get("os_guess"),
            "architecture": metadata.get("architecture"),
            "process_count": len(processes),
            "region_count": len(regions),
            "suspicious_region_count": len(suspicious),
            "finding_count": len(findings),
            "highest_severity": findings[0].get("severity") if findings else None,
            "statement": (
                "Memory dump analyzed without executing any recovered code. "
                "Findings are heuristic and require analyst validation."
            ),
        },
        "dump_metadata": {
            "dump_id": dump_id,
            "filename": filename,
            "created_at": created_at.isoformat(),
            "provider": provider,
            **{key: metadata.get(key) for key in (
                "sha256",
                "size",
                "dump_format",
                "os_guess",
                "architecture",
                "confidence",
            )},
            "provenance": "verified",
        },
        "findings": findings,
        "processes": {
            "items": processes[:_MAX_PROCESSES],
            "total": len(processes),
            "truncated": len(processes) > _MAX_PROCESSES,
        },
        "suspicious_regions": {
            "items": suspicious[:_MAX_REGIONS],
            "total": len(suspicious),
            "truncated": len(suspicious) > _MAX_REGIONS,
        },
        "network_artifacts": {
            "items": network[:_MAX_NETWORK],
            "total": len(network),
            "truncated": len(network) > _MAX_NETWORK,
        },
        "loaded_modules": {
            "total": len(modules),
            "sample": modules[:_MAX_MODULES],
            "truncated": len(modules) > _MAX_MODULES,
        },
        "handle_summary": {"total": len(handles)},
        "thread_summary": {"total": len(threads)},
        "strings_and_iocs": {
            "total_strings": len(strings),
            "urls": urls[:_MAX_LIST_IOCS],
            "ip_addresses": ips[:_MAX_LIST_IOCS],
            "domains": domains[:_MAX_LIST_IOCS],
            "provenance": "verified",
        },
        "unavailable_analyses": unavailable,
        "warnings": warnings,
        "limitations": [
            "No recovered code was executed while producing this report.",
            "Volatility and heuristic results can be incomplete or wrong.",
            "Region suspicion is a heuristic signal, not a verdict.",
            "Recovered strings and indicators are unverified.",
        ],
        "recommended_next_steps": recommendations,
    }


def render_memory_markdown(report: dict[str, object]) -> str:
    """Render a memory-dump report as analyst-friendly Markdown."""
    summary = report["executive_summary"]
    metadata = report["dump_metadata"]
    findings = report["findings"]
    processes = report["processes"]
    regions = report["suspicious_regions"]
    network = report["network_artifacts"]
    iocs = report["strings_and_iocs"]

    lines = [
        f"# Memory Analysis Report — `{summary['sample']}`",
        "",
        "> Memory-dump report. No recovered code was executed; findings are "
        "heuristic and require analyst validation.",
        "",
        "## 1. Executive Summary",
        "",
        summary["statement"],
        f"- OS guess / architecture: {summary['os_guess'] or 'unknown'} / "
        f"{summary['architecture'] or 'unknown'}",
        f"- Processes: {summary['process_count']}",
        f"- Suspicious regions: {summary['suspicious_region_count']} of {summary['region_count']}",
        f"- Findings: {summary['finding_count']} (highest {summary['highest_severity'] or 'none'})",
        "",
        "## 2. Dump Metadata",
        "",
        f"- Dump ID: `{metadata['dump_id']}`",
        f"- Filename: `{metadata['filename']}`",
        f"- SHA-256: `{metadata['sha256']}`",
        f"- Size: {metadata['size']} bytes",
        f"- Format: {metadata['dump_format']}",
        f"- Provider: {metadata['provider']}",
        f"- Created: {metadata['created_at']}",
        "",
        "## 3. Findings",
        "",
    ]
    if findings:
        for item in findings:
            lines.append(
                f"- **{str(item.get('severity', 'info')).upper()} — {item.get('title')}** "
                f"(confidence {float(item.get('confidence', 0.0)):.2f}): {item.get('summary')}"
            )
    else:
        lines.append("_No bounded heuristic finding was produced._")
    lines.extend(["", "## 4. Processes", ""])
    if processes["items"]:
        for item in processes["items"][:100]:
            lines.append(
                f"- PID {item.get('pid')} (ppid {item.get('ppid')}) "
                f"`{item.get('name')}` — {item.get('command_line') or 'no command line'}"
            )
        if processes["total"] > 100:
            lines.append(f"- _{processes['total'] - 100} more processes not shown._")
    else:
        lines.append("_No processes were recovered._")
    lines.extend(["", "## 5. Suspicious Regions", ""])
    if regions["items"]:
        for item in regions["items"][:100]:
            start = item.get("start")
            end = item.get("end")
            span = (
                f"0x{start:x}–0x{end:x}"
                if isinstance(start, int) and isinstance(end, int)
                else "unknown range"
            )
            lines.append(
                f"- PID {item.get('pid')} {span} [{item.get('protection')}] "
                f"— {item.get('reason') or 'flagged'}"
            )
        if regions["truncated"]:
            lines.append(f"- _Region list truncated to {_MAX_REGIONS}._")
    else:
        lines.append("_No suspicious regions were flagged._")
    lines.extend(["", "## 6. Network Artifacts", ""])
    if network["items"]:
        for item in network["items"][:100]:
            remote = item.get("remote_address")
            remote_port = item.get("remote_port")
            endpoint = f"{remote}:{remote_port}" if remote else "no remote"
            lines.append(
                f"- {item.get('protocol')} {item.get('local_address')}:{item.get('local_port')} "
                f"→ {endpoint} [{item.get('state') or '—'}] "
                f"pid {item.get('pid')} ({item.get('process_name') or '?'})"
            )
    else:
        lines.append("_No network artifacts were recovered._")
    lines.extend(
        [
            "",
            "## 7. Strings and IOCs",
            "",
            f"- Recovered strings: {iocs['total_strings']}",
            f"- Loaded modules: {report['loaded_modules']['total']} · "
            f"handles: {report['handle_summary']['total']} · "
            f"threads: {report['thread_summary']['total']}",
            *[f"- URL: `{item}`" for item in iocs["urls"]],
            *[f"- IP: `{item}`" for item in iocs["ip_addresses"]],
            *[f"- Domain: `{item}`" for item in iocs["domains"]],
            "",
            "## 8. Unavailable Analyses",
            "",
            *(
                [f"- {item}" for item in report["unavailable_analyses"]]
                or ["_All requested analyses were available._"]
            ),
            "",
            "## 9. Warnings",
            "",
            *([f"- {item}" for item in report["warnings"]] or ["_No provider warnings._"]),
            "",
            "## 10. Limitations",
            "",
            *[f"- {item}" for item in report["limitations"]],
            "",
            "## 11. Recommended Next Steps",
            "",
            *[f"- {item}" for item in report["recommended_next_steps"]],
            "",
        ]
    )
    return "\n".join(lines)


def render_memory_html(report: dict[str, object]) -> str:
    """Render a memory-dump report as standalone escaped HTML."""
    return html_document(
        subject=f"memory dump {report['executive_summary']['sample']}",
        notice="Memory-dump output. No code was executed; findings require validation.",
        markdown=render_memory_markdown(report),
    )
