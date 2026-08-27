"""Decompiler selection and graceful fallback."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from ..errors import IntegrationUnavailableError
from .base import DecompileOptions, DecompilerAdapter, DecompilerInfo, DecompiledFunction
from .fallback import FallbackPseudoCAdapter
from .ghidra import GhidraDecompilerAdapter
from .r2ghidra import R2GhidraDecompilerAdapter
from .retdec import RetDecDecompilerAdapter

_ADAPTERS: tuple[DecompilerAdapter, ...] = (
    GhidraDecompilerAdapter(),
    R2GhidraDecompilerAdapter(),
    RetDecDecompilerAdapter(),
    FallbackPseudoCAdapter(),
)


def list_decompilers() -> tuple[DecompilerInfo, ...]:
    return tuple(
        DecompilerInfo(
            name=adapter.name,
            available=adapter.is_available(),
            priority=index + 1,
            detail=(
                "Available."
                if adapter.is_available()
                else "Not installed or not configured; automatic fallback remains available."
            ),
        )
        for index, adapter in enumerate(_ADAPTERS)
    )


def decompile_function(
    binary_path: Path,
    address: int,
    options: DecompileOptions | None = None,
    provider: str = "auto",
) -> DecompiledFunction:
    """Use a requested/available provider and always degrade to pseudo-C."""
    options = options or DecompileOptions()
    warnings: list[str] = []
    if provider != "auto" and provider not in {adapter.name for adapter in _ADAPTERS}:
        warnings.append(f"Unknown provider {provider!r}; used built-in fallback.")

    candidates = (
        [adapter for adapter in _ADAPTERS if adapter.name == provider]
        if provider != "auto"
        else list(_ADAPTERS)
    )
    candidates.extend(
        adapter for adapter in _ADAPTERS if adapter.name == "pseudo_c" and adapter not in candidates
    )
    for adapter in candidates:
        if not adapter.is_available():
            warnings.append(f"{adapter.name} is unavailable.")
            continue
        try:
            result = adapter.decompile_function(binary_path, address, options)
            return replace(result, warnings=tuple(warnings) + result.warnings)
        except (IntegrationUnavailableError, OSError, ValueError) as exc:
            warnings.append(f"{adapter.name} failed safely: {exc}")
    # The fallback is always registered and available; this is defensive.
    raise IntegrationUnavailableError("No decompiler provider could produce a result.")
