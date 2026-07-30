"""CTF workspace persistence, notes, checklist, transforms, and export."""

from __future__ import annotations

from .fixtures import sample_elf


def test_ctf_workspace_roundtrip_and_markdown_export(api_client) -> None:
    upload = api_client.post(
        "/api/binaries", files={"file": ("crackme.elf", sample_elf())}
    )
    sha256 = upload.json()["sha256"]
    created = api_client.post(
        "/api/ctf-workspaces",
        json={
            "title": "Local CrackMe",
            "description": "Authorized fixture",
            "category": "reversing",
            "difficulty": "medium",
            "binary_sha256": sha256,
        },
    )
    assert created.status_code == 201, created.text
    workspace_id = created.json()["id"]
    assert len(created.json()["checklist"]) == 15

    checklist = created.json()["checklist"]
    checklist["file identification"] = True
    patched = api_client.patch(
        f"/api/ctf-workspaces/{workspace_id}",
        json={
            "hypotheses": ["entry validates an integer"],
            "flag_candidates": ["RLAB{candidate}"],
            "checklist": checklist,
            "writeup_steps": ["Uploaded safe fixture", "Reviewed entry CFG"],
        },
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["checklist"]["file identification"] is True

    note = api_client.post(
        f"/api/ctf-workspaces/{workspace_id}/notes",
        json={
            "kind": "address",
            "content": "Conditional validation branch",
            "address": 0x401000,
        },
    )
    assert note.status_code == 201
    loaded = api_client.get(f"/api/ctf-workspaces/{workspace_id}").json()
    assert loaded["notes"][0]["address"] == 0x401000

    exported = api_client.get(
        f"/api/ctf-workspaces/{workspace_id}/export?format=markdown"
    )
    assert exported.status_code == 200
    assert "# Local CrackMe" in exported.text
    assert "0x401000" in exported.text
    assert "Automated disassembly and pseudo-C are estimates" in exported.text


def test_ctf_decoder_extensions_do_not_persist_input(api_client) -> None:
    hashed = api_client.post(
        "/api/tools/decode",
        json={
            "operation": "hash",
            "input": "ctf-data",
            "parameters": {"algorithm": "sha256"},
        },
    )
    assert hashed.status_code == 200
    assert len(hashed.json()["text"]) == 64
    signed = api_client.post(
        "/api/tools/decode",
        json={
            "operation": "signed_convert",
            "input": "0xffffffff",
            "parameters": {"bits": 32},
        },
    )
    assert signed.json()["text"] == "signed=-1\nunsigned=4294967295"
