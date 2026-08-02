"""Evidence-backed obfuscation and anti-analysis heuristics."""

from __future__ import annotations

import hashlib
import re

from ..analysis.functions import analyze_functions
from ..analysis.models import Evidence, Finding, ProvenanceKind
from ..disassembler import disassemble
from ..parser.models import BinaryInfo
from .strings import extract_strings

_BASE64 = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")
_ANTI_DEBUG_APIS = {
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "ntqueryinformationprocess",
    "ptrace",
}
_TIMING_APIS = {"queryperformancecounter", "gettickcount", "rdtsc", "clock_gettime"}
_DYNAMIC_APIS = {"getprocaddress", "loadlibrarya", "loadlibraryw", "dlsym", "dlopen"}
_VM_MARKERS = ("vbox", "virtualbox", "vmware", "qemu", "sandboxie", "wine_get_unix_file_name")
_AES_SBOX_PREFIX = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")


def _identifier(technique: str, address: int | None) -> str:
    material = f"obfuscation:{technique}:{address or 0}".encode()
    return hashlib.sha256(material).hexdigest()[:20]


def _finding(
    technique: str,
    title: str,
    severity: str,
    confidence: float,
    summary: str,
    evidence: list[Evidence],
    caveat: str,
    investigation: str,
    *,
    address_start: int | None = None,
    address_end: int | None = None,
    function_address: int | None = None,
    mitre_id: str | None = None,
) -> Finding:
    return Finding(
        id=_identifier(technique, address_start),
        category="obfuscation",
        title=title,
        severity=severity,
        confidence=confidence,
        summary=summary,
        evidence=tuple(evidence),
        recommendations=(investigation,),
        false_positive_notes=(caveat,),
        technique=technique,
        address_start=address_start,
        address_end=address_end,
        related_function=function_address,
        mitre_id=mitre_id,
    )


def analyze_obfuscation(info: BinaryInfo, data: bytes) -> tuple[Finding, ...]:
    """Return bounded heuristics without executing any sample code."""
    findings: list[Finding] = []
    functions = analyze_functions(info, data)

    for function in functions:
        result = disassemble(
            info, data, address=function.address, count=max(function.instruction_count, 1)
        )
        instructions = result.instructions
        backward_branches = []
        xor_instructions = []
        indirect_branches = []
        stack_immediates = []
        for instruction in instructions:
            if instruction.mnemonic == "xor":
                xor_instructions.append(instruction)
            if "jump" in instruction.groups:
                operand = instruction.op_str.strip().lstrip("#")
                try:
                    target = int(operand, 16) if operand.startswith("0x") else None
                except ValueError:
                    target = None
                if target is None:
                    indirect_branches.append(instruction)
                elif target < instruction.address:
                    backward_branches.append((instruction, target))
            if (
                instruction.mnemonic == "mov"
                and "[" in instruction.op_str
                and re.search(r",\s*(?:0x[0-9a-f]+|\d+)$", instruction.op_str)
            ):
                stack_immediates.append(instruction)

        if xor_instructions and backward_branches:
            first = xor_instructions[0]
            last = backward_branches[-1][0]
            findings.append(
                _finding(
                    "xor_loop",
                    "XOR decoder loop candidate",
                    "medium",
                    0.78,
                    "An XOR operation occurs in a function containing a backward branch.",
                    [
                        Evidence(
                            source="capstone",
                            message=f"XOR instruction: {first.text}.",
                            address=first.address,
                            function_address=function.address,
                            raw_value=first.bytes_hex,
                        ),
                        Evidence(
                            source="cfg-pattern",
                            message=f"Backward branch: {last.text}.",
                            address=last.address,
                            function_address=function.address,
                            raw_value=last.bytes_hex,
                        ),
                    ],
                    "Checksums, parsers, and ordinary loops also commonly use XOR.",
                    "Inspect data references and loop bounds; use the data-only XOR assistant on copied bytes.",
                    address_start=function.address,
                    address_end=function.address + function.size,
                    function_address=function.address,
                    mitre_id="T1027",
                )
            )

        if len(stack_immediates) >= 3:
            findings.append(
                _finding(
                    "stack_string",
                    "Stack string construction candidate",
                    "medium",
                    min(0.9, 0.55 + len(stack_immediates) * 0.05),
                    f"{len(stack_immediates)} immediate values are written through memory operands.",
                    [
                        Evidence(
                            source="capstone",
                            message=instruction.text,
                            address=instruction.address,
                            function_address=function.address,
                            raw_value=instruction.bytes_hex,
                        )
                        for instruction in stack_immediates[:12]
                    ],
                    "Structure initialization and numeric local arrays can resemble stack strings.",
                    "Reconstruct the immediate byte order and check whether the result is printable.",
                    address_start=stack_immediates[0].address,
                    address_end=stack_immediates[-1].address + stack_immediates[-1].size,
                    function_address=function.address,
                    mitre_id="T1027",
                )
            )

        if len(indirect_branches) >= 3:
            findings.append(
                _finding(
                    "indirect_branch_density",
                    "High indirect branch density",
                    "medium",
                    min(0.9, 0.5 + len(indirect_branches) * 0.06),
                    f"{len(indirect_branches)} indirect branches may indicate a dispatcher or virtualized code.",
                    [
                        Evidence(
                            source="capstone",
                            message=instruction.text,
                            address=instruction.address,
                            function_address=function.address,
                        )
                        for instruction in indirect_branches[:12]
                    ],
                    "Compilers use indirect branches for switch tables, virtual dispatch, and tail calls.",
                    "Resolve jump targets and compare the pattern with compiler-generated switch code.",
                    address_start=function.address,
                    address_end=function.address + function.size,
                    function_address=function.address,
                )
            )

    imports = {item.name.lower(): item for item in info.imports}
    dynamic = sorted(_DYNAMIC_APIS & imports.keys())
    if len(dynamic) >= 2:
        findings.append(
            _finding(
                "api_dynamic_resolution",
                "Dynamic API resolution",
                "medium",
                0.82,
                f"Imports used for runtime symbol resolution co-occur: {', '.join(dynamic)}.",
                [
                    Evidence(
                        source="imports",
                        message=f"Imported {imports[name].name}.",
                        raw_value=imports[name].name,
                        provenance=ProvenanceKind.VERIFIED,
                    )
                    for name in dynamic
                ],
                "Plugin loaders and compatibility layers legitimately resolve APIs at runtime.",
                "Trace resolved names in an isolated provider or inspect arguments to the resolver.",
            )
        )

    anti_debug = sorted(_ANTI_DEBUG_APIS & imports.keys())
    if anti_debug:
        findings.append(
            _finding(
                "anti_debugging",
                "Anti-debugging API reference",
                "high",
                0.88,
                f"Known debugger-detection API(s) imported: {', '.join(anti_debug)}.",
                [
                    Evidence(
                        source="imports",
                        message=f"Imported {imports[name].name}.",
                        raw_value=imports[name].name,
                        provenance=ProvenanceKind.VERIFIED,
                    )
                    for name in anti_debug
                ],
                "Diagnostics and software protection products may perform legitimate debugger checks.",
                "Inspect callers and branch outcomes; do not infer malicious intent from the import alone.",
                mitre_id="T1622",
            )
        )

    timing = sorted(_TIMING_APIS & imports.keys())
    if timing:
        findings.append(
            _finding(
                "timing_check",
                "Timing check capability",
                "low",
                0.62,
                f"Timing-related API(s) imported: {', '.join(timing)}.",
                [
                    Evidence(
                        source="imports",
                        message=f"Imported {imports[name].name}.",
                        raw_value=imports[name].name,
                        provenance=ProvenanceKind.VERIFIED,
                    )
                    for name in timing
                ],
                "Performance measurement and normal scheduling logic use the same APIs.",
                "Inspect whether elapsed-time comparisons gate error or evasion paths.",
            )
        )

    strings = extract_strings(data, min_length=4, max_results=5_000)
    encoded = [item for item in strings if _BASE64.fullmatch(item.value)]
    if encoded:
        item = encoded[0]
        findings.append(
            _finding(
                "base64_data",
                "Base64-encoded data candidate",
                "low",
                0.72,
                "A long string matches the standard Base64 alphabet and padding rules.",
                [
                    Evidence(
                        source="strings",
                        message=f"Base64 candidate at file offset 0x{item.offset:x}.",
                        file_offset=item.offset,
                        raw_value=item.value[:160],
                        provenance=ProvenanceKind.VERIFIED,
                    )
                ],
                "Certificates, embedded assets, and protocol payloads commonly use Base64.",
                "Decode a copy with the data-only playground and inspect the output format.",
                mitre_id="T1027",
            )
        )

    lowered_strings = "\n".join(item.value.lower() for item in strings)
    markers = [marker for marker in _VM_MARKERS if marker in lowered_strings]
    if markers:
        findings.append(
            _finding(
                "anti_vm",
                "Virtualization environment markers",
                "medium",
                0.7,
                f"Strings reference virtualization markers: {', '.join(markers)}.",
                [
                    Evidence(
                        source="strings",
                        message=f"Observed virtualization marker {marker!r}.",
                        raw_value=marker,
                        provenance=ProvenanceKind.VERIFIED,
                    )
                    for marker in markers
                ],
                "Guest utilities and inventory software legitimately mention hypervisors.",
                "Find code references to the strings and inspect how the result affects control flow.",
            )
        )

    if _AES_SBOX_PREFIX in data:
        offset = data.index(_AES_SBOX_PREFIX)
        findings.append(
            _finding(
                "aes_constants",
                "AES S-box constant prefix",
                "info",
                0.9,
                "The canonical AES S-box prefix is present in the sample.",
                [
                    Evidence(
                        source="byte-signature",
                        message="Matched the canonical AES S-box prefix.",
                        file_offset=offset,
                        raw_value=_AES_SBOX_PREFIX.hex(),
                        provenance=ProvenanceKind.VERIFIED,
                    )
                ],
                "Cryptographic libraries and benign encrypted formats contain the same constants.",
                "Cross-reference the constant and determine whether it belongs to a known library.",
            )
        )

    wx_sections = [
        section
        for section in info.sections
        if section.contains_code and any("WRITE" in flag.upper() for flag in section.flags)
    ]
    if wx_sections:
        findings.append(
            _finding(
                "self_modifying_code",
                "Writable executable section",
                "high",
                0.76,
                "A section is both writable and executable, enabling self-modifying code.",
                [
                    Evidence(
                        source="section-permissions",
                        message=f"Section {section.name!r} has executable and writable flags.",
                        address=section.virtual_address,
                        file_offset=section.offset,
                        raw_value="|".join(section.flags),
                        provenance=ProvenanceKind.VERIFIED,
                    )
                    for section in wx_sections
                ],
                "JIT runtimes and some embedded systems legitimately use writable executable memory.",
                "Inspect writes targeting the section and any subsequent instruction-cache transition.",
            )
        )

    return tuple(findings[:250])
