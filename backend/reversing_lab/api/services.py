"""Analysis service — the glue between stored bytes and the analysis core.

Loads a binary's bytes (via the repository), parses it once, and caches the parsed
:class:`BinaryInfo` so repeated per-view requests (sections, strings, disassembly, ...)
don't re-parse. The cache is bounded to keep memory predictable.
"""

from __future__ import annotations

from collections import OrderedDict

from ..analysis import FunctionAnalysis, analyze_functions
from ..parser import BinaryInfo, parse_binary

# sha256 -> parsed BinaryInfo. Small and bounded; parsing is deterministic so a hit is
# always valid for the immutable content identified by that hash.
_PARSE_CACHE: "OrderedDict[str, BinaryInfo]" = OrderedDict()
_CACHE_CAPACITY = 64
_FUNCTION_CACHE: "OrderedDict[str, tuple[FunctionAnalysis, ...]]" = OrderedDict()


def parse_cached(sha256: str, data: bytes) -> BinaryInfo:
    """Return the parsed :class:`BinaryInfo` for ``sha256``, parsing on cache miss."""
    cached = _PARSE_CACHE.get(sha256)
    if cached is not None:
        _PARSE_CACHE.move_to_end(sha256)
        return cached

    info = parse_binary(data)
    _PARSE_CACHE[sha256] = info
    _PARSE_CACHE.move_to_end(sha256)
    while len(_PARSE_CACHE) > _CACHE_CAPACITY:
        _PARSE_CACHE.popitem(last=False)
    return info


def clear_cache() -> None:
    """Drop all cached parses (used by tests)."""
    _PARSE_CACHE.clear()
    _FUNCTION_CACHE.clear()


def functions_cached(
    sha256: str, info: BinaryInfo, data: bytes
) -> tuple[FunctionAnalysis, ...]:
    cached = _FUNCTION_CACHE.get(sha256)
    if cached is not None:
        _FUNCTION_CACHE.move_to_end(sha256)
        return cached
    functions = analyze_functions(info, data)
    _FUNCTION_CACHE[sha256] = functions
    _FUNCTION_CACHE.move_to_end(sha256)
    while len(_FUNCTION_CACHE) > _CACHE_CAPACITY:
        _FUNCTION_CACHE.popitem(last=False)
    return functions
