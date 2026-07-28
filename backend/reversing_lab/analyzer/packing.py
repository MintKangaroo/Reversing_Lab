"""Packer / obfuscation detection heuristics.

No single signal proves a binary is packed, so this module aggregates several weak
indicators — high-entropy sections, known packer section names, a suspiciously small
import table, and writable+executable sections — into a weighted score with a clear,
human-readable rationale. The output is advisory and explains *why*, which is the
whole point for a learning platform.
"""

from __future__ import annotations

from dataclasses import dataclass, field

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


# Score at/above which we call a binary "likely packed".
_PACKED_THRESHOLD = 3


def detect_packing(info: BinaryInfo, data: bytes) -> PackingReport:
    """Assess whether ``data`` (already parsed into ``info``) is packed."""
    indicators: list[PackingIndicator] = []
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

    # 4) Suspiciously small import table (packers resolve APIs at runtime).
    if len(info.imports) <= 3 and info.binary_format.value in {"PE", "ELF"}:
        indicators.append(
            PackingIndicator(
                name="small_import_table",
                detail=f"Only {len(info.imports)} imports; packers often hide the IAT.",
                weight=1,
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

    score = sum(indicator.weight for indicator in indicators)
    return PackingReport(
        likely_packed=score >= _PACKED_THRESHOLD,
        score=score,
        detected_packer=detected_packer,
        overall_entropy=overall_entropy,
        indicators=tuple(indicators),
    )
