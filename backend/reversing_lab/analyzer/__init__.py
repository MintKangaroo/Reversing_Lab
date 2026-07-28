"""Format-agnostic content analysis: strings, hex, entropy, packing detection."""

from __future__ import annotations

from .entropy import EntropyReport, EntropyWindow, entropy_profile, shannon_entropy
from .hexdump import HexPage, HexRow, hex_page
from .packing import PackingIndicator, PackingReport, detect_packing
from .strings import ExtractedString, extract_strings

__all__ = [
    "EntropyReport",
    "EntropyWindow",
    "ExtractedString",
    "HexPage",
    "HexRow",
    "PackingIndicator",
    "PackingReport",
    "detect_packing",
    "entropy_profile",
    "extract_strings",
    "hex_page",
    "shannon_entropy",
]
