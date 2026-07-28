"""External RE-tool integrations (radare2, Ghidra, Binary Ninja).

All adapters degrade gracefully: a tool that is not installed reports ``available=False``
rather than failing the request.
"""

from __future__ import annotations

from ..errors import IntegrationUnavailableError
from .base import IntegrationAdapter, IntegrationInfo, IntegrationResult
from .binary_ninja import BinaryNinjaAdapter
from .ghidra import GhidraAdapter
from .radare2 import Radare2Adapter

# name -> adapter singleton
_ADAPTERS: dict[str, IntegrationAdapter] = {
    adapter.name: adapter
    for adapter in (Radare2Adapter(), GhidraAdapter(), BinaryNinjaAdapter())
}


def list_integrations() -> list[IntegrationInfo]:
    """Return availability info for every registered integration."""
    return [adapter.info() for adapter in _ADAPTERS.values()]


def get_adapter(name: str) -> IntegrationAdapter:
    """Return the adapter registered under ``name`` or raise ``IntegrationUnavailableError``."""
    try:
        return _ADAPTERS[name]
    except KeyError as exc:
        raise IntegrationUnavailableError(f"Unknown integration: {name!r}.") from exc


__all__ = [
    "BinaryNinjaAdapter",
    "GhidraAdapter",
    "IntegrationAdapter",
    "IntegrationInfo",
    "IntegrationResult",
    "IntegrationUnavailableError",
    "Radare2Adapter",
    "get_adapter",
    "list_integrations",
]
