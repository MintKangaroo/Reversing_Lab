"""Base64 challenge — decode a Base64-encoded flag found in the binary."""

from __future__ import annotations

import base64

from ..base import AbstractChallenge, make_flag
from ..elfbuilder import build_elf64
from ..models import BuiltChallenge, ChallengeCategory, Difficulty

_SECRET = "b4se64_1s_just_3ncod1ng"


class Base64Challenge(AbstractChallenge):
    slug = "base64-decode"
    title = "Base64 Decode"
    category = ChallengeCategory.BASE64
    difficulty = Difficulty.EASY
    description = (
        "This binary stores its flag as a Base64 string. Extract the strings, spot the "
        "Base64 blob (only A-Z, a-z, 0-9, +, /, = characters), decode it, and submit "
        "the resulting RLAB{...} flag."
    )
    hint = "Base64 strings often end with '=' padding. Decode with any Base64 tool."
    artifact_filename = "base64_challenge.elf"

    def build(self) -> BuiltChallenge:
        flag = make_flag(_SECRET)
        encoded = base64.b64encode(flag.encode("ascii"))
        blob = b"config=" + encoded + b"\x00" + b"log initialized\x00"
        artifact = build_elf64(code=b"\xc3", rodata=blob)
        return BuiltChallenge(artifact=artifact, answer=flag)
