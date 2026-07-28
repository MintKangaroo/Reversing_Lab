"""Challenge round-trip tests: generate → solve programmatically → verify."""

from __future__ import annotations

import base64

import pytest

from reversing_lab.analyzer import detect_packing, extract_strings
from reversing_lab.challenge import get_registry
from reversing_lab.disassembler import disassemble
from reversing_lab.parser import parse_binary


def _first_flag_string(artifact: bytes) -> str:
    for item in extract_strings(artifact):
        if item.value.startswith("RLAB{"):
            return item.value
    raise AssertionError("No RLAB{ flag string found.")


def _solve_hidden_string(artifact: bytes) -> str:
    return _first_flag_string(artifact)


def _solve_xor(artifact: bytes) -> str:
    encoded = artifact[artifact.index(b"XOR:") + 4 : artifact.index(b":END")]
    return bytes(b ^ 0x5A for b in encoded).decode()


def _solve_base64(artifact: bytes) -> str:
    for item in extract_strings(artifact):
        if item.value.startswith("config="):
            return base64.b64decode(item.value[len("config=") :]).decode()
    raise AssertionError("No base64 config found.")


def _solve_crackme(artifact: bytes) -> str:
    info = parse_binary(artifact)
    result = disassemble(info, artifact, address=info.entry_point, count=64)
    chars = [
        chr(int(insn.op_str.split(",")[1].strip(), 16))
        for insn in result.instructions
        if insn.mnemonic == "mov" and insn.op_str.startswith("al,")
    ]
    return "RLAB{" + "".join(chars) + "}"


def _solve_packing(artifact: bytes) -> str:
    info = parse_binary(artifact)
    report = detect_packing(info, artifact)
    return "RLAB{" + str(report.detected_packer) + "}"


def _solve_malware(artifact: bytes) -> str:
    for item in extract_strings(artifact):
        if item.value.startswith("config:"):
            raw = base64.b64decode(item.value[len("config:") :])
            return bytes(b ^ 0x3C for b in raw).decode()
    raise AssertionError("No config blob found.")


_SOLVERS = {
    "hidden-string": _solve_hidden_string,
    "xor-decode": _solve_xor,
    "base64-decode": _solve_base64,
    "crackme-disasm": _solve_crackme,
    "packing-detection": _solve_packing,
    "malware-triage": _solve_malware,
}


def test_catalog_has_six_challenges() -> None:
    slugs = {view.slug for view in get_registry().list_views()}
    assert slugs == set(_SOLVERS)


@pytest.mark.parametrize("slug", list(_SOLVERS))
def test_challenge_is_solvable_and_verifies(slug: str) -> None:
    registry = get_registry()
    _, artifact = registry.artifact(slug)
    answer = _SOLVERS[slug](artifact)

    assert registry.verify(slug, answer).correct is True
    assert registry.verify(slug, answer + " ").correct is True  # whitespace tolerant
    assert registry.verify(slug, "RLAB{definitely-wrong}").correct is False


@pytest.mark.parametrize("slug", list(_SOLVERS))
def test_artifacts_are_valid_binaries(slug: str) -> None:
    _, artifact = get_registry().artifact(slug)
    info = parse_binary(artifact)  # must parse without raising
    assert info.file_size == len(artifact)


def test_build_is_deterministic() -> None:
    a = get_registry().artifact("packing-detection")[1]
    from reversing_lab.challenge.registry import ChallengeRegistry

    b = ChallengeRegistry().artifact("packing-detection")[1]
    assert a == b


def test_answer_never_leaks_in_view() -> None:
    registry = get_registry()
    for view in registry.list_views():
        answer = registry.get(view.slug).answer
        serialized = f"{view.title}{view.description}{view.hint}{view.artifact_filename}"
        assert answer not in serialized, f"{view.slug} leaks its answer in metadata"


def test_unknown_challenge_raises() -> None:
    from reversing_lab.errors import ChallengeError

    with pytest.raises(ChallengeError):
        get_registry().get("does-not-exist")
