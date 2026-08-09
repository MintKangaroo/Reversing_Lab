"""Memory dump parsing and optional Volatility 3 integration."""

from .analyzer import analyze_memory, detect_dump_format
from .models import (
    MemoryAnalysisResult,
    MemoryFinding,
    MemoryMetadata,
    MemoryModule,
    MemoryNetworkArtifact,
    MemoryProcess,
    MemoryRegion,
)
from .volatility import ALLOWED_PLUGINS, VolatilityAdapter

__all__ = [
    "ALLOWED_PLUGINS",
    "MemoryAnalysisResult",
    "MemoryFinding",
    "MemoryMetadata",
    "MemoryModule",
    "MemoryNetworkArtifact",
    "MemoryProcess",
    "MemoryRegion",
    "VolatilityAdapter",
    "analyze_memory",
    "detect_dump_format",
]
