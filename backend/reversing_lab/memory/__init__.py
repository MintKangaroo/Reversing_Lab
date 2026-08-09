"""Memory dump parsing and optional Volatility 3 integration."""

from .analyzer import analyze_memory, detect_dump_format
from .inspection import RegionDisassembly, RegionInstruction, disassemble_region
from .models import (
    MemoryAnalysisResult,
    MemoryFinding,
    MemoryMetadata,
    MemoryModule,
    MemoryNetworkArtifact,
    MemoryProcess,
    MemoryRegion,
)
from .volatility import ALLOWED_PLUGINS, RegionExtraction, VolatilityAdapter

__all__ = [
    "ALLOWED_PLUGINS",
    "MemoryAnalysisResult",
    "MemoryFinding",
    "MemoryMetadata",
    "MemoryModule",
    "MemoryNetworkArtifact",
    "MemoryProcess",
    "MemoryRegion",
    "RegionDisassembly",
    "RegionExtraction",
    "RegionInstruction",
    "VolatilityAdapter",
    "analyze_memory",
    "detect_dump_format",
    "disassemble_region",
]
