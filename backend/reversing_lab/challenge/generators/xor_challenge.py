"""XOR challenge — decode a single-byte XOR-encoded flag."""

from __future__ import annotations

from ..base import AbstractChallenge, make_flag
from ..elfbuilder import build_elf64
from ..models import BuiltChallenge, ChallengeCategory, Difficulty

_SECRET = "x0r_1s_not_encrypt10n"
_KEY = 0x5A


class XorChallenge(AbstractChallenge):
    slug = "xor-decode"
    title = "XOR Decode"
    category = ChallengeCategory.XOR
    difficulty = Difficulty.EASY
    description = (
        "The flag in this binary's .rodata section has been obscured with a repeating "
        "single-byte XOR. Locate the encoded bytes, XOR them back with the correct key, "
        "and submit the recovered RLAB{...} flag."
    )
    hint = f"It's a single-byte XOR. The key is 0x{_KEY:02X}. Try the Hex viewer to spot the encoded region."
    artifact_filename = "xor_challenge.elf"

    def build(self) -> BuiltChallenge:
        flag = make_flag(_SECRET)
        encoded = bytes(b ^ _KEY for b in flag.encode("ascii"))
        # Surround the encoded blob with markers so it is locatable in the hex view.
        blob = b"XOR:" + encoded + b":END\x00"
        artifact = build_elf64(code=b"\xc3", rodata=blob)
        return BuiltChallenge(artifact=artifact, answer=flag)
