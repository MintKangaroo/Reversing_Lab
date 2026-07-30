"""Format-agnostic content analysis: strings, hex, entropy, packing detection."""

from __future__ import annotations

from .entropy import EntropyReport, EntropyWindow, entropy_profile, shannon_entropy
from .hexdump import HexPage, HexRow, hex_page
from .obfuscation import analyze_obfuscation
from .packing import DetectedPacker, PackingIndicator, PackingReport, detect_packing
from .strings import ExtractedString, extract_strings
from .transforms import TransformResult, transform_data
from .unpacking import SectionChange, UnpackResult, unpack_upx, upx_executable

__all__ = [
    "EntropyReport",
    "EntropyWindow",
    "DetectedPacker",
    "ExtractedString",
    "HexPage",
    "HexRow",
    "PackingIndicator",
    "PackingReport",
    "TransformResult",
    "SectionChange",
    "UnpackResult",
    "analyze_obfuscation",
    "detect_packing",
    "entropy_profile",
    "extract_strings",
    "hex_page",
    "shannon_entropy",
    "transform_data",
    "unpack_upx",
    "upx_executable",
]
