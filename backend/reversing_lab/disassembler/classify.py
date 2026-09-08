"""Architecture-neutral control-flow classification of decoded instructions.

One source of truth for "is this a call / branch / return, and where does it go?",
shared by the CFG builder and the function-inventory/call-graph recovery. It reads
Capstone instruction *groups* (``jump`` / ``call`` / ``return``) plus each
architecture's operand syntax, so x86, ARM, AArch64, and MIPS behave consistently.

A few idioms Capstone does not put in a group are matched by mnemonic: ARM ``bx lr``
and MIPS ``jr $ra`` (returns), and MIPS ``jal`` / ``bal`` / ``jalr`` (calls).
"""

from __future__ import annotations

from .disassembler import Instruction

# Bare unconditional direct-branch mnemonics (x86 jmp; ARM/ARM64 b; MIPS j/b). A
# conditional branch is a distinct mnemonic (je, beq, b.eq, cbz, bne, ...), so it is
# never in this set and always falls through.
_UNCONDITIONAL = {"jmp", "b", "j"}

# Calls Capstone (MIPS) does not tag with the ``call`` group; matched by mnemonic.
_MIPS_CALL_MNEMONICS = {"jal", "bal", "jalr"}

# Return idioms outside the ``return`` group: ARM ``bx lr`` / ``bxj lr`` and MIPS
# ``jr $ra`` (``$31``).
_ARM_RETURN_MNEMONICS = {"bx", "bxj"}
_MIPS_RETURN_REGISTERS = {"$ra", "$31"}


def _last_operand(op_str: str) -> str:
    """The final comma-separated operand — where ARM/ARM64/MIPS print a branch target."""
    return op_str.rsplit(",", 1)[-1].strip()


def direct_target(insn: Instruction) -> int | None:
    """Return the immediate target of a direct branch/call, or ``None`` if not static.

    Normalizes per-architecture syntax: x86 ``0x401000``, ARM/ARM64 ``#0x1010``, and
    the target as the last operand (ARM64 ``cbz w0, #0x18``; MIPS ``beq $a, $b, 0x24``).
    """
    operand = _last_operand(insn.op_str).lstrip("#")
    if operand.startswith("0x"):
        try:
            return int(operand, 16)
        except ValueError:
            return None
    return None


def is_call(insn: Instruction) -> bool:
    return "call" in insn.groups or insn.mnemonic in _MIPS_CALL_MNEMONICS


def is_jump(insn: Instruction) -> bool:
    # Calls (ARM ``bl``/``blr`` are in both the call and jump groups) are not branches.
    return "jump" in insn.groups and not is_call(insn)


def is_return(insn: Instruction) -> bool:
    if "ret" in insn.groups or "return" in insn.groups:
        return True
    operand = _last_operand(insn.op_str)
    if insn.mnemonic in _ARM_RETURN_MNEMONICS and operand == "lr":
        return True
    return insn.mnemonic == "jr" and operand in _MIPS_RETURN_REGISTERS


def is_unconditional_jump(insn: Instruction) -> bool:
    """A branch that never falls through: a bare unconditional or any indirect jump."""
    return is_jump(insn) and (
        insn.mnemonic in _UNCONDITIONAL or direct_target(insn) is None
    )


def falls_through(insn: Instruction) -> bool:
    """A conditional branch continues to the next instruction when not taken."""
    return is_jump(insn) and not is_unconditional_jump(insn)
