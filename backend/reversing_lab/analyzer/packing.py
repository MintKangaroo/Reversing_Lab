"""Packer / obfuscation detection heuristics.

No single signal proves a binary is packed, so this module aggregates several weak
indicators — high-entropy sections, known packer section names, a suspiciously small
import table, and writable+executable sections — into a weighted score with a clear,
human-readable rationale. The output is advisory and explains *why*, which is the
whole point for a learning platform.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..analysis.models import Evidence, ProvenanceKind
from ..parser.models import BinaryInfo
from .entropy import shannon_entropy

# Section-name fragments strongly associated with specific packers.
_KNOWN_PACKER_SECTIONS: dict[str, str] = {
    "upx": "UPX",
    "aspack": "ASPack",
    "petite": "Petite",
    ".themida": "Themida",
    "winlice": "WinLicense",
    "nsp": "NsPack",
    "mpress": "MPRESS",
    "vmp": "VMProtect",
    ".enigma": "Enigma",
    ".mackt": "ImpRec-patched",
    ".boom": "The Boomerang",
}

# Entropy at/above this (bits/byte) indicates compressed or encrypted content.
_HIGH_ENTROPY = 7.2


@dataclass(frozen=True, slots=True)
class PackingIndicator:
    """A single evidence item contributing to the verdict."""

    name: str
    detail: str
    weight: int


@dataclass(frozen=True, slots=True)
class PackingReport:
    """Aggregate packing verdict with the evidence behind it."""

    likely_packed: bool
    score: int
    detected_packer: str | None
    overall_entropy: float
    indicators: tuple[PackingIndicator, ...] = field(default_factory=tuple)
    confidence: float = 0.0
    detected_packers: tuple["DetectedPacker", ...] = field(default_factory=tuple)
    evidence: tuple[Evidence, ...] = field(default_factory=tuple)
    recommended_next_steps: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class DetectedPacker:
    name: str
    confidence: float
    evidence: tuple[Evidence, ...] = ()


# Score at/above which we call a binary "likely packed".
_PACKED_THRESHOLD = 3


def detect_packing(info: BinaryInfo, data: bytes) -> PackingReport:
    """Assess whether ``data`` (already parsed into ``info``) is packed."""
    indicators: list[PackingIndicator] = []
    evidence: list[Evidence] = []
    packer_evidence: dict[str, list[Evidence]] = {}
    detected_packer: str | None = None

    # 1) Known packer section names — the strongest single signal.
    for section in info.sections:
        lowered = section.name.lower()
        for fragment, packer in _KNOWN_PACKER_SECTIONS.items():
            if fragment in lowered:
                detected_packer = packer
                indicators.append(
                    PackingIndicator(
                        name="known_packer_section",
                        detail=f"Section '{section.name}' matches {packer}.",
                        weight=3,
                    )
                )
                item = Evidence(
                    source="section-name",
                    message=f"Section '{section.name}' matches a known {packer} marker.",
                    provenance=ProvenanceKind.VERIFIED,
                    address=section.virtual_address,
                    file_offset=section.offset,
                    raw_value=section.name,
                )
                evidence.append(item)
                packer_evidence.setdefault(packer, []).append(item)
                break

    # 2) High-entropy executable sections (compressed/encrypted code).
    high_entropy_sections = [
        s for s in info.sections if s.contains_code and s.entropy >= _HIGH_ENTROPY
    ]
    if high_entropy_sections:
        names = ", ".join(s.name for s in high_entropy_sections)
        indicators.append(
            PackingIndicator(
                name="high_entropy_code",
                detail=f"Executable section(s) with entropy ≥ {_HIGH_ENTROPY}: {names}.",
                weight=2,
            )
        )
        evidence.extend(
            Evidence(
                source="section-entropy",
                message=f"Executable section '{section.name}' entropy is {section.entropy:.4f}.",
                provenance=ProvenanceKind.VERIFIED,
                address=section.virtual_address,
                file_offset=section.offset,
                raw_value=str(section.entropy),
            )
            for section in high_entropy_sections
        )

    # 3) Whole-file entropy.
    overall_entropy = round(shannon_entropy(data), 4)
    if overall_entropy >= _HIGH_ENTROPY:
        indicators.append(
            PackingIndicator(
                name="high_overall_entropy",
                detail=f"Whole-file entropy {overall_entropy} ≥ {_HIGH_ENTROPY}.",
                weight=1,
            )
        )
        evidence.append(
            Evidence(
                source="whole-file-entropy",
                message=f"Whole-file entropy is {overall_entropy:.4f} bits per byte.",
                provenance=ProvenanceKind.VERIFIED,
                raw_value=str(overall_entropy),
            )
        )

    # 4) Suspiciously small import table (packers resolve APIs at runtime).
    if len(info.imports) <= 3 and info.binary_format.value in {"PE", "ELF"}:
        indicators.append(
            PackingIndicator(
                name="small_import_table",
                detail=f"Only {len(info.imports)} imports; packers often hide the IAT.",
                weight=1,
            )
        )
        evidence.append(
            Evidence(
                source="import-table",
                message=f"Only {len(info.imports)} imports were recovered.",
                provenance=ProvenanceKind.VERIFIED,
                raw_value=str(len(info.imports)),
            )
        )

    # 5) Writable + executable sections (self-modifying unpacking stubs).
    wx_sections = [
        s
        for s in info.sections
        if s.contains_code and any("WRITE" in f.upper() for f in s.flags)
    ]
    if wx_sections:
        names = ", ".join(s.name for s in wx_sections)
        indicators.append(
            PackingIndicator(
                name="writable_executable_section",
                detail=f"Writable+executable section(s): {names}.",
                weight=2,
            )
        )
        evidence.extend(
            Evidence(
                source="section-permissions",
                message=f"Section '{section.name}' is writable and executable.",
                provenance=ProvenanceKind.VERIFIED,
                address=section.virtual_address,
                file_offset=section.offset,
                raw_value="|".join(section.flags),
            )
            for section in wx_sections
        )

    # 6) Overlay bytes after the final declared section.
    section_end = max(
        (section.offset + section.size for section in info.sections if section.size > 0),
        default=len(data),
    )
    overlay_size = max(0, len(data) - section_end)
    if overlay_size >= 512:
        indicators.append(
            PackingIndicator(
                name="overlay_data",
                detail=f"{overlay_size} byte(s) exist after the final declared section.",
                weight=1,
            )
        )
        evidence.append(
            Evidence(
                source="overlay",
                message=f"Detected {overlay_size} bytes of overlay data.",
                provenance=ProvenanceKind.VERIFIED,
                file_offset=section_end,
                raw_value=str(overlay_size),
            )
        )

    # 7) Runtime API resolution often appears in unpacking stubs.
    resolution_names = {
        "getprocaddress",
        "loadlibrarya",
        "loadlibraryw",
        "virtualalloc",
        "virtualprotect",
    }
    matched_imports = sorted(
        item.name for item in info.imports if item.name.lower() in resolution_names
    )
    if len(matched_imports) >= 2:
        indicators.append(
            PackingIndicator(
                name="runtime_api_resolution",
                detail=f"Runtime resolution/memory APIs imported: {', '.join(matched_imports)}.",
                weight=1,
            )
        )
        evidence.append(
            Evidence(
                source="imports",
                message="Runtime API resolution and memory protection imports co-occur.",
                provenance=ProvenanceKind.VERIFIED,
                raw_value=", ".join(matched_imports),
            )
        )

    score = sum(indicator.weight for indicator in indicators)
    confidence = min(
        0.99,
        0.18 * score
        + (0.28 if detected_packer else 0.0)
        + (0.08 if len(indicators) >= 3 else 0.0),
    )
    detected_packers = tuple(
        DetectedPacker(
            name=name,
            confidence=min(0.99, 0.78 + 0.04 * len(items)),
            evidence=tuple(items),
        )
        for name, items in packer_evidence.items()
    )
    next_steps = (
        (
            "Confirm section layout and entry-point behavior before attempting unpacking.",
            "If the sample is confirmed UPX and local UPX is trusted, use the explicit unpack action.",
            "Preserve and compare the original and derived artifact hashes.",
        )
        if score >= _PACKED_THRESHOLD
        else ("Review entropy and import evidence if later findings suggest runtime unpacking.",)
    )
    return PackingReport(
        likely_packed=score >= _PACKED_THRESHOLD,
        score=score,
        detected_packer=detected_packer,
        overall_entropy=overall_entropy,
        indicators=tuple(indicators),
        confidence=round(confidence, 3),
        detected_packers=detected_packers,
        evidence=tuple(evidence),
        recommended_next_steps=next_steps,
    )
