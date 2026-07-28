"""Shannon entropy — the backbone of packing/encryption heuristics.

Entropy is measured in bits per byte (0.0 – 8.0). High, uniform entropy across a
file is a strong signal that its contents are compressed or encrypted, which is the
tell-tale sign of a packer.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EntropyWindow:
    """Entropy of one contiguous window of the file."""

    offset: int
    size: int
    entropy: float


@dataclass(frozen=True, slots=True)
class EntropyReport:
    """Whole-file entropy plus a windowed profile for visualization."""

    overall: float
    windows: tuple[EntropyWindow, ...]


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy of ``data`` in bits/byte (0.0 for empty input)."""
    if not data:
        return 0.0

    counts = [0] * 256
    for byte in data:
        counts[byte] += 1

    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return entropy


def entropy_profile(data: bytes, window_size: int = 4096) -> EntropyReport:
    """Compute overall entropy and a per-window profile.

    ``window_size`` must be positive; the final window may be shorter than the rest.
    """
    if window_size <= 0:
        raise ValueError("window_size must be a positive integer.")

    windows: list[EntropyWindow] = []
    for offset in range(0, len(data), window_size):
        chunk = data[offset : offset + window_size]
        windows.append(
            EntropyWindow(
                offset=offset,
                size=len(chunk),
                entropy=round(shannon_entropy(chunk), 4),
            )
        )

    return EntropyReport(
        overall=round(shannon_entropy(data), 4),
        windows=tuple(windows),
    )
