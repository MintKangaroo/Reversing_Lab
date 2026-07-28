"""CrackMe challenge — recover a password from the disassembly."""

from __future__ import annotations

from ..base import AbstractChallenge, make_flag
from ..elfbuilder import build_elf64, emit_load_al
from ..models import BuiltChallenge, ChallengeCategory, Difficulty

_PASSWORD = "sup3rs3cr3t"


class CrackMeChallenge(AbstractChallenge):
    slug = "crackme-disasm"
    title = "CrackMe (Disassembly)"
    category = ChallengeCategory.CRACKME
    difficulty = Difficulty.MEDIUM
    description = (
        "The entry point of this binary builds a password one character at a time using "
        "a sequence of 'mov al, imm8' instructions. Open the Disassembly view, read the "
        "immediate byte of each instruction, convert them to ASCII to recover the "
        "password, then submit it wrapped as RLAB{password}."
    )
    hint = "Each 'mov al, 0xNN' loads one ASCII character of the password, in order."
    artifact_filename = "crackme.elf"

    def build(self) -> BuiltChallenge:
        code = emit_load_al(_PASSWORD.encode("ascii"))
        rodata = b"Enter password: \x00Access granted\x00Access denied\x00"
        artifact = build_elf64(code=code, rodata=rodata)
        return BuiltChallenge(artifact=artifact, answer=make_flag(_PASSWORD))
