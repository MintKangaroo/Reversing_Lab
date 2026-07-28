"""Hidden String challenge — recover a flag buried among decoy strings."""

from __future__ import annotations

from ..base import AbstractChallenge, make_flag
from ..elfbuilder import build_elf64
from ..models import BuiltChallenge, ChallengeCategory, Difficulty

_DECOYS = (
    b"Loading configuration...\x00",
    b"usage: %s [options] <file>\x00",
    b"error: permission denied\x00",
    b"/etc/passwd\x00",
    b"libc.so.6\x00",
)
_SECRET = "str1ngs_r3v34l_s3cr3ts"


class HiddenStringChallenge(AbstractChallenge):
    slug = "hidden-string"
    title = "Hidden String"
    category = ChallengeCategory.HIDDEN_STRING
    difficulty = Difficulty.EASY
    description = (
        "A flag is hidden in plain sight among ordinary-looking strings inside this "
        "binary. Use the Strings view (or the Hex viewer) to find the value wrapped "
        "in RLAB{...} and submit it."
    )
    hint = "Sort the extracted strings and look for the RLAB{ prefix."
    artifact_filename = "hidden_string.elf"

    def build(self) -> BuiltChallenge:
        flag = make_flag(_SECRET)
        # The flag is placed in the middle of the decoy strings, not first or last.
        blob = b"".join(_DECOYS[:3]) + flag.encode("ascii") + b"\x00" + b"".join(_DECOYS[3:])
        artifact = build_elf64(code=b"\xc3", rodata=blob)  # ret
        return BuiltChallenge(artifact=artifact, answer=flag)
