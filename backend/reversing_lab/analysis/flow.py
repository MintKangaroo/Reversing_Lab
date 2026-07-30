"""Evidence-linked, heuristic whole-program flow summary."""

from __future__ import annotations

from ..analyzer.obfuscation import analyze_obfuscation
from ..analyzer.strings import extract_strings
from ..parser.models import BinaryInfo
from .functions import analyze_functions
from .models import Evidence, FlowStage, ProgramFlowSummary, ProvenanceKind

_ARGUMENT_APIS = {"getopt", "getopt_long", "commandlinetoargvw"}
_INPUT_APIS = {"read", "fread", "gets", "fgets", "scanf", "recv", "readfile"}
_FILE_APIS = {"open", "fopen", "createfilea", "createfilew", "writefile", "unlink"}
_NETWORK_APIS = {"socket", "connect", "send", "recv", "winhttpopen", "internetopen"}
_PERSISTENCE_APIS = {"regsetvalueexa", "createservicea", "createservicew"}


def _import_matches(info: BinaryInfo, names: set[str]) -> list[str]:
    return sorted(item.name for item in info.imports if item.name.lower() in names)


def _stage(
    identifier: str,
    title: str,
    summary: str,
    addresses: tuple[int, ...],
    evidence: tuple[Evidence, ...],
    confidence: float,
) -> FlowStage:
    return FlowStage(
        id=identifier,
        title=title,
        summary=summary,
        function_addresses=addresses,
        evidence=evidence,
        confidence=confidence,
    )


def summarize_program_flow(info: BinaryInfo, data: bytes) -> ProgramFlowSummary:
    functions = analyze_functions(info, data)
    by_address = {function.address: function for function in functions}
    entry = by_address.get(info.entry_point)
    stages: list[FlowStage] = [
        _stage(
            "entry",
            "Entry Point",
            (
                f"Execution begins at {entry.name if entry else 'the binary entry point'} "
                f"(0x{info.entry_point:x})."
            ),
            (info.entry_point,),
            (
                Evidence(
                    source="binary-header",
                    message="Entry point read from the executable header.",
                    provenance=ProvenanceKind.VERIFIED,
                    address=info.entry_point,
                    function_address=info.entry_point if entry else None,
                ),
            ),
            1.0,
        )
    ]

    if entry and entry.callees:
        stages.append(
            _stage(
                "initialization",
                "Initialization",
                f"The entry function directly calls {len(entry.callees)} recovered function(s).",
                entry.callees,
                tuple(
                    Evidence(
                        source="static-call",
                        message=f"Direct call from 0x{entry.address:x} to 0x{target:x}.",
                        address=entry.address,
                        function_address=target,
                    )
                    for target in entry.callees
                ),
                0.68,
            )
        )

    argument_apis = _import_matches(info, _ARGUMENT_APIS)
    if argument_apis:
        stages.append(
            _stage(
                "arguments",
                "Argument Parsing",
                f"Argument parsing APIs are imported: {', '.join(argument_apis)}.",
                (),
                tuple(
                    Evidence(
                        source="imports",
                        message=f"Imported {name}.",
                        provenance=ProvenanceKind.VERIFIED,
                        raw_value=name,
                    )
                    for name in argument_apis
                ),
                0.72,
            )
        )

    input_apis = _import_matches(info, _INPUT_APIS)
    if input_apis:
        stages.append(
            _stage(
                "input",
                "Input Handling",
                f"Input-related APIs are present: {', '.join(input_apis)}.",
                (),
                tuple(
                    Evidence(
                        source="imports",
                        message=f"Imported {name}.",
                        provenance=ProvenanceKind.VERIFIED,
                        raw_value=name,
                    )
                    for name in input_apis
                ),
                0.75,
            )
        )

    complex_functions = sorted(
        (function for function in functions if function.cyclomatic_complexity > 1),
        key=lambda function: (-function.cyclomatic_complexity, function.address),
    )
    if complex_functions:
        selected = tuple(function.address for function in complex_functions[:5])
        stages.append(
            _stage(
                "validation",
                "Validation / Major Decisions",
                "Recovered functions contain conditional branches that may validate or route input.",
                selected,
                tuple(
                    Evidence(
                        source="cfg-metrics",
                        message=(
                            f"{function.name} has cyclomatic complexity "
                            f"{function.cyclomatic_complexity}."
                        ),
                        address=function.address,
                        function_address=function.address,
                        raw_value=str(function.cyclomatic_complexity),
                    )
                    for function in complex_functions[:5]
                ),
                0.58,
            )
        )

    obfuscation = analyze_obfuscation(info, data)
    decoder_findings = [
        finding
        for finding in obfuscation
        if finding.technique in {"xor_loop", "base64_data", "aes_constants", "stack_string"}
    ]
    if decoder_findings:
        addresses = tuple(
            sorted(
                {
                    finding.related_function
                    for finding in decoder_findings
                    if finding.related_function is not None
                }
            )
        )
        stages.append(
            _stage(
                "encoding",
                "Encoding / Decoding",
                "Static patterns suggest encoded data or a decoding routine.",
                addresses,
                tuple(
                    evidence
                    for finding in decoder_findings
                    for evidence in finding.evidence[:2]
                ),
                max(finding.confidence for finding in decoder_findings),
            )
        )

    for identifier, title, names in (
        ("file", "File Operations", _FILE_APIS),
        ("network", "Network-related Behavior", _NETWORK_APIS),
        ("persistence", "Persistence-related Behavior", _PERSISTENCE_APIS),
    ):
        matched = _import_matches(info, names)
        if matched:
            stages.append(
                _stage(
                    identifier,
                    title,
                    f"Capability inferred from imports: {', '.join(matched)}.",
                    (),
                    tuple(
                        Evidence(
                            source="imports",
                            message=f"Imported {name}.",
                            provenance=ProvenanceKind.VERIFIED,
                            raw_value=name,
                        )
                        for name in matched
                    ),
                    0.64,
                )
            )

    strings = extract_strings(data, min_length=4, max_results=5_000)
    failure_strings = [
        item
        for item in strings
        if any(token in item.value.lower() for token in ("error", "fail", "denied", "invalid"))
    ][:20]
    failure_paths = tuple(
        Evidence(
            source="strings",
            message=f"Potential failure-path string: {item.value[:160]!r}.",
            provenance=ProvenanceKind.VERIFIED,
            file_offset=item.offset,
            raw_value=item.value[:160],
        )
        for item in failure_strings
    )
    major_branches = tuple(
        Evidence(
            source="cfg-metrics",
            message=(
                f"{function.name} at 0x{function.address:x} contains "
                f"{function.cyclomatic_complexity - 1} decision point(s)."
            ),
            address=function.address,
            function_address=function.address,
            raw_value=str(function.cyclomatic_complexity),
        )
        for function in complex_functions[:20]
    )
    anti_analysis = tuple(
        evidence
        for finding in obfuscation
        if finding.technique
        in {"anti_debugging", "anti_vm", "timing_check", "self_modifying_code"}
        for evidence in finding.evidence[:3]
    )

    return ProgramFlowSummary(
        entry_point=info.entry_point,
        stages=tuple(stages),
        major_branches=major_branches,
        failure_paths=failure_paths,
        anti_analysis=anti_analysis,
        limitations=(
            "This summary is heuristic and does not represent recovered original source.",
            "Indirect calls, stripped symbols, callbacks, and exception flow may be missing.",
            "Imported capability does not prove that a behavior executes.",
        ),
    )
