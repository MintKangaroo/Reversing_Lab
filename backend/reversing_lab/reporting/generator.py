"""Generate JSON-safe analysis reports and deterministic text renderings."""

from __future__ import annotations

import hashlib
import html
import re
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from ..analysis import build_call_graph, summarize_program_flow
from ..analyzer import analyze_obfuscation, detect_packing, extract_strings
from ..decompiler import DecompileOptions, decompile_function

_URL = re.compile(r"https?://[^\s\"'<>]{4,}", re.IGNORECASE)
_IP = re.compile(
    r"(?<!\d)(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?!\d)"
)


def _hex(value: int | None) -> str | None:
    return f"0x{value:x}" if value is not None else None


def _annotation(record) -> dict[str, object]:
    return {
        "kind": record.kind,
        "address": record.address,
        "address_hex": _hex(record.address),
        "value": record.value,
        "provenance": "user",
        "updated_at": record.updated_at.isoformat(),
    }


def _bookmark(record) -> dict[str, object]:
    return {
        "address": record.address,
        "address_hex": _hex(record.address),
        "label": record.label,
        "note": record.note,
        "provenance": "user",
        "created_at": record.created_at.isoformat(),
    }


def build_report(
    *,
    record,
    data: bytes,
    info,
    functions,
    annotations,
    bookmarks,
    display_filename: str | None = None,
) -> dict[str, object]:
    """Build the canonical report dictionary without executing the sample."""
    packing = detect_packing(info, data)
    findings = analyze_obfuscation(info, data)
    flow = summarize_program_flow(info, data)
    graph = build_call_graph(functions, root_address=None, depth=3)
    strings = extract_strings(data, min_length=4, max_results=2_000)
    urls = sorted({match.group(0) for item in strings for match in _URL.finditer(item.value)})
    ips = sorted({match.group(0) for item in strings for match in _IP.finditer(item.value)})
    interesting = sorted(
        functions,
        key=lambda item: (
            item.address != info.entry_point,
            -item.suspicious_score,
            -item.cyclomatic_complexity,
            item.address,
        ),
    )[:20]

    snippets: list[dict[str, object]] = []
    for function in interesting[:3]:
        try:
            result = decompile_function(
                Path(record.storage_path),
                function.address,
                DecompileOptions(timeout_seconds=5, max_output_bytes=256 * 1024),
                provider="pseudo_c",
            )
            snippets.append(
                {
                    "function_address": result.function_address,
                    "function_address_hex": _hex(result.function_address),
                    "function_name": result.function_name,
                    "provider": result.provider,
                    "provenance": result.provenance,
                    "confidence": result.confidence,
                    "code": result.code,
                    "warnings": list(result.warnings),
                }
            )
        except Exception as exc:  # a partial report is preferable to a failed export
            snippets.append(
                {
                    "function_address": function.address,
                    "function_address_hex": _hex(function.address),
                    "function_name": function.name,
                    "provider": "pseudo_c",
                    "provenance": "inferred",
                    "confidence": 0.0,
                    "code": "",
                    "warnings": [f"Pseudo-C generation was unavailable: {type(exc).__name__}."],
                }
            )

    recommendations = [
        "Validate heuristic findings against the linked addresses and raw bytes.",
        "Preserve the original content-addressed sample and record analyst conclusions separately.",
    ]
    if packing.likely_packed:
        recommendations.append(
            "Confirm the packer manually; use explicit UPX extraction only for a verified UPX sample."
        )
    if findings:
        recommendations.append(
            "Prioritize high-confidence functions and document false-positive checks."
        )
    recommendations.append(
        "Use an isolated VM-backed provider for any authorized dynamic analysis."
    )

    filename = display_filename or record.filename
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "executive_summary": {
            "sample": filename,
            "format": info.binary_format,
            "architecture": info.architecture,
            "likely_packed": packing.likely_packed,
            "finding_count": len(findings),
            "function_count": len(functions),
            "statement": (
                "Static triage completed without executing the sample. "
                "Heuristic and inferred results require analyst validation."
            ),
        },
        "sample_metadata": {
            "filename": filename,
            "file_size": info.file_size,
            "format": info.binary_format,
            "architecture": info.architecture,
            "bits": info.bits,
            "endianness": info.endianness,
            "entry_point": info.entry_point,
            "entry_point_hex": _hex(info.entry_point),
            "parser_extra": info.extra,
            "provenance": "verified",
        },
        "hashes": {
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),
            "provenance": "verified",
        },
        "security_mitigations": {
            "pie_aslr": info.is_pie,
            "nx_dep": info.has_nx,
            "relro": info.has_relro,
            "provenance": "verified",
            "limitations": [
                "Format-specific mitigations not exposed by the normalized parser are unavailable."
            ],
        },
        "packer_analysis": asdict(packing),
        "obfuscation_analysis": [asdict(item) for item in findings],
        "functions_of_interest": [
            {
                **asdict(item),
                "address_hex": _hex(item.address),
                "callers_hex": [_hex(value) for value in item.callers],
                "callees_hex": [_hex(value) for value in item.callees],
            }
            for item in interesting
        ],
        "strings_and_iocs": {
            "strings": [asdict(item) for item in strings[:500]],
            "total_strings": len(strings),
            "urls": urls[:200],
            "ip_addresses": ips[:200],
            "truncated": len(strings) > 500,
            "provenance": "verified",
        },
        "imports_and_apis": {
            "imports": [asdict(item) for item in info.imports[:2_000]],
            "exports": [asdict(item) for item in info.exports[:2_000]],
            "truncated": len(info.imports) > 2_000 or len(info.exports) > 2_000,
            "provenance": "verified",
        },
        "static_call_flow": {
            "program_flow": asdict(flow),
            "call_graph": asdict(graph),
            "provenance": "heuristic",
        },
        "dynamic_timeline": {
            "status": "not_linked",
            "events": [],
            "message": "No dynamic run is associated with this static report.",
        },
        "memory_findings": {
            "status": "not_linked",
            "findings": [],
            "message": "No memory dump is associated with this static report.",
        },
        "decompiled_snippets": snippets,
        "analyst_notes": {
            "annotations": [_annotation(item) for item in annotations],
            "bookmarks": [_bookmark(item) for item in bookmarks],
        },
        "limitations": [
            "Pseudo-C is an estimate and is not recovered original source code.",
            "Static call targets, function boundaries, and types may be incomplete or incorrect.",
            "Packing and obfuscation results are heuristic and can produce false positives.",
            "The sample was not executed while producing this report.",
            "Dynamic and memory results appear only when explicitly associated in a future report schema.",
        ],
        "recommended_next_steps": recommendations,
    }


def render_markdown(report: dict[str, object]) -> str:
    """Render the canonical report as analyst-friendly Markdown."""
    metadata = report["sample_metadata"]
    hashes = report["hashes"]
    mitigations = report["security_mitigations"]
    packing = report["packer_analysis"]
    findings = report["obfuscation_analysis"]
    functions = report["functions_of_interest"]
    iocs = report["strings_and_iocs"]
    imports = report["imports_and_apis"]
    flow = report["static_call_flow"]["program_flow"]
    snippets = report["decompiled_snippets"]
    notes = report["analyst_notes"]

    lines = [
        f"# Reversing Lab Analysis Report — {metadata['filename']}",
        "",
        "> Static analysis report. Heuristic and inferred statements require analyst validation.",
        "",
        "## 1. Executive Summary",
        "",
        report["executive_summary"]["statement"],
        f"- Functions recovered: {report['executive_summary']['function_count']}",
        f"- Obfuscation findings: {report['executive_summary']['finding_count']}",
        f"- Likely packed: {packing['likely_packed']} (score {packing['score']}, confidence {packing['confidence']:.2f})",
        "",
        "## 2. Sample Metadata",
        "",
        f"- Filename: `{metadata['filename']}`",
        f"- Format / architecture: {metadata['format']} / {metadata['architecture']} ({metadata['bits']}-bit, {metadata['endianness']}-endian)",
        f"- Entry point: `{metadata['entry_point_hex']}`",
        f"- File size: {metadata['file_size']} bytes",
        "",
        "## 3. Hashes",
        "",
        f"- SHA-256: `{hashes['sha256']}`",
        f"- SHA-1: `{hashes['sha1']}`",
        f"- MD5: `{hashes['md5']}`",
        "",
        "## 4. Security Mitigations",
        "",
        f"- PIE / ASLR: {mitigations['pie_aslr']}",
        f"- NX / DEP: {mitigations['nx_dep']}",
        f"- RELRO: {mitigations['relro']}",
        "",
        "## 5. Packer Analysis",
        "",
        f"- Verdict: {'likely packed' if packing['likely_packed'] else 'not indicated'}",
        f"- Score / confidence: {packing['score']} / {packing['confidence']:.2f}",
        *[f"- Evidence: {item['message']}" for item in packing["evidence"]],
        "",
        "## 6. Obfuscation Analysis",
        "",
        *(
            [
                f"- **{item['severity'].upper()} — {item['title']}** "
                f"(confidence {item['confidence']:.2f}): {item['summary']}"
                for item in findings
            ]
            or ["_No bounded heuristic finding was produced._"]
        ),
        "",
        "## 7. Functions of Interest",
        "",
        *[
            f"- `{item['address_hex']}` {item.get('user_name') or item['name']} — "
            f"complexity {item['cyclomatic_complexity']}, suspicious score {item['suspicious_score']}"
            for item in functions
        ],
        "",
        "## 8. Strings and IOCs",
        "",
        f"- Extracted strings: {iocs['total_strings']} (report embeds at most 500)",
        *[f"- URL: `{item}`" for item in iocs["urls"]],
        *[f"- IP: `{item}`" for item in iocs["ip_addresses"]],
        "",
        "## 9. Imports and APIs",
        "",
        f"- Imports: {len(imports['imports'])}",
        *[
            f"- `{item.get('library') or '?'}!{item['name']}`"
            for item in imports["imports"][:100]
        ],
        "",
        "## 10. Static Call Flow",
        "",
        *[
            f"- **{stage['title']}**: {stage['summary']} "
            f"(confidence {stage['confidence']:.2f})"
            for stage in flow["stages"]
        ],
        "",
        "## 11. Dynamic Timeline",
        "",
        f"_{report['dynamic_timeline']['message']}_",
        "",
        "## 12. Memory Findings",
        "",
        f"_{report['memory_findings']['message']}_",
        "",
        "## 13. Decompiled Snippets",
        "",
    ]
    for snippet in snippets:
        lines.extend(
            [
                f"### {snippet['function_name']} @ {snippet['function_address_hex']}",
                "",
                f"Provider: `{snippet['provider']}` · confidence: {snippet['confidence']:.2f}",
                "",
                "```c",
                snippet["code"],
                "```",
                "",
            ]
        )
    lines.extend(
        [
            "## 14. Analyst Notes",
            "",
            *[
                f"- `{item['address_hex']}` **{item['kind']}**: {item['value']}"
                for item in notes["annotations"]
            ],
            *[
                f"- `{item['address_hex']}` **bookmark** {item['label']}: {item['note']}"
                for item in notes["bookmarks"]
            ],
            *(
                ["_No analyst annotations or bookmarks._"]
                if not notes["annotations"] and not notes["bookmarks"]
                else []
            ),
            "",
            "## 15. Limitations",
            "",
            *[f"- {item}" for item in report["limitations"]],
            "",
            "## 16. Recommended Next Steps",
            "",
            *[f"- {item}" for item in report["recommended_next_steps"]],
            "",
        ]
    )
    return "\n".join(lines)


def render_html(report: dict[str, object]) -> str:
    """Render a standalone escaped HTML report."""
    markdown = render_markdown(report)
    escaped = html.escape(markdown)
    filename = html.escape(str(report["sample_metadata"]["filename"]))
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reversing Lab Report — {filename}</title>
<style>
:root {{ color-scheme: dark; font-family: Inter, system-ui, sans-serif; }}
body {{ max-width: 1100px; margin: 0 auto; padding: 36px; color: #d8dee9; background: #10141b; }}
header {{ border-bottom: 1px solid #303849; margin-bottom: 22px; }}
h1 {{ color: #8eb4ff; }} .notice {{ color: #d7a84d; }}
pre {{ padding: 20px; overflow: auto; border: 1px solid #303849; border-radius: 6px; background: #0b0e13; white-space: pre-wrap; }}
</style>
</head>
<body>
<header><h1>Reversing Lab Analysis Report</h1><p>{filename}</p>
<p class="notice">Static, evidence-linked output. Inferences require analyst validation.</p></header>
<pre>{escaped}</pre>
</body>
</html>"""
