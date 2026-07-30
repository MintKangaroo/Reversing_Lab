"""API contracts for functions, call graph, projects, and analyst overlays."""

from __future__ import annotations

from reversing_lab.challenge.elfbuilder import build_elf64


def _upload(client, data: bytes) -> str:
    response = client.post("/api/binaries", files={"file": ("calls.elf", data)})
    assert response.status_code == 201, response.text
    return response.json()["sha256"]


def _call_fixture() -> bytes:
    return build_elf64(code=bytes.fromhex("e801000000c3c3"))


def test_function_inventory_detail_disassembly_and_callgraph(api_client) -> None:
    sha256 = _upload(api_client, _call_fixture())

    listing = api_client.get(f"/api/binaries/{sha256}/functions?limit=1")
    assert listing.status_code == 200, listing.text
    assert listing.json()["total"] == 2
    assert listing.json()["items"][0]["address"] == 0x401000

    detail = api_client.get(f"/api/binaries/{sha256}/functions/0x401006")
    assert detail.status_code == 200
    assert detail.json()["callers"] == [0x401000]

    disassembly = api_client.get(
        f"/api/binaries/{sha256}/functions/0x401000/disassembly"
    )
    assert disassembly.status_code == 200
    assert disassembly.json()["instructions"][0]["mnemonic"] == "call"

    graph = api_client.get(f"/api/binaries/{sha256}/callgraph").json()
    assert len(graph["nodes"]) == 2
    assert graph["edges"][0]["source"] == 0x401000
    assert graph["edges"][0]["target"] == 0x401006


def test_malformed_function_address_is_rejected(api_client) -> None:
    sha256 = _upload(api_client, _call_fixture())
    response = api_client.get(f"/api/binaries/{sha256}/functions/0xnope")
    assert response.status_code == 422
    assert "Malformed address" in response.json()["detail"]


def test_annotation_overlays_function_and_bookmark_roundtrip(api_client) -> None:
    sha256 = _upload(api_client, _call_fixture())
    rename = api_client.post(
        f"/api/binaries/{sha256}/annotations",
        json={"address": 0x401006, "kind": "function_name", "value": "verify_input"},
    )
    assert rename.status_code == 200, rename.text
    assert rename.json()["provenance"] == "user"

    comment = api_client.post(
        f"/api/binaries/{sha256}/annotations",
        json={"address": 0x401006, "kind": "comment", "value": "Review branch logic"},
    )
    assert comment.status_code == 200
    detail = api_client.get(
        f"/api/binaries/{sha256}/functions/{0x401006}"
    ).json()
    assert detail["user_name"] == "verify_input"
    assert detail["user_comment"] == "Review branch logic"

    bookmark = api_client.post(
        f"/api/binaries/{sha256}/bookmarks",
        json={"address": 0x401006, "label": "validation", "note": "CTF lead"},
    )
    assert bookmark.status_code == 200
    assert len(api_client.get(f"/api/binaries/{sha256}/bookmarks").json()) == 1
    deleted = api_client.delete(
        f"/api/binaries/{sha256}/bookmarks/0x401006"
    )
    assert deleted.status_code == 204
    assert api_client.get(f"/api/binaries/{sha256}/bookmarks").json() == []


def test_project_crud_and_sample_membership(api_client) -> None:
    sha256 = _upload(api_client, _call_fixture())
    created = api_client.post(
        "/api/projects",
        json={"name": "Authorized crackme", "description": "Local CTF fixture"},
    )
    assert created.status_code == 201, created.text
    project_id = created.json()["id"]

    added = api_client.post(f"/api/projects/{project_id}/samples/{sha256}")
    assert added.status_code == 200
    assert added.json()["sample_sha256"] == [sha256]

    updated = api_client.patch(
        f"/api/projects/{project_id}", json={"name": "Renamed investigation"}
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Renamed investigation"
    assert api_client.get(f"/api/projects/{project_id}").status_code == 200
