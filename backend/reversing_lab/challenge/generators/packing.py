"""Packing Detection challenge — identify the packer from its artifacts."""

from __future__ import annotations

import hashlib

from ..base import AbstractChallenge, make_flag
from ..models import BuiltChallenge, ChallengeCategory, Difficulty
from ..elfbuilder import build_elf64

_PACKER = "UPX"


def _high_entropy_bytes(length: int, seed: bytes) -> bytes:
    """Deterministically produce ``length`` high-entropy bytes from ``seed``.

    A SHA-256 keystream gives near-uniform byte distribution (entropy ≈ 8 bits/byte)
    while remaining fully reproducible, which the packing heuristic needs to flag.
    """
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(8, "little")).digest()
        counter += 1
    return bytes(out[:length])


class PackingChallenge(AbstractChallenge):
    slug = "packing-detection"
    title = "Packing Detection"
    category = ChallengeCategory.PACKING
    difficulty = Difficulty.MEDIUM
    description = (
        "This binary has been processed by an executable packer. Its telltale signs — a "
        "distinctive section name and near-maximal entropy in the code section — are "
        "visible in the Sections and Packing Detection views. Identify the packer by "
        "name and submit it wrapped as RLAB{name} (for example, a different packer "
        "would be RLAB{ASPack})."
    )
    hint = "Look at the unusual section name and the entropy score of the code section."
    artifact_filename = "packed.elf"

    def build(self) -> BuiltChallenge:
        # High-entropy 'compressed' payload in a section named like a UPX segment.
        payload = _high_entropy_bytes(2048, seed=b"reversing-lab-packing")
        rodata = _high_entropy_bytes(1024, seed=b"reversing-lab-rodata")
        artifact = build_elf64(code=payload, rodata=rodata, text_section_name=".UPX1")
        return BuiltChallenge(artifact=artifact, answer=make_flag(_PACKER))
