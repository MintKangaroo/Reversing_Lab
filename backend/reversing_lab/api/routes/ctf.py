"""Persistent CTF investigation workspaces and write-up export."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from ...database import CtfWorkspaceRepository
from ..dependencies import get_ctf_workspace_repository
from ..schemas import (
    CtfNoteCreateSchema,
    CtfNoteSchema,
    CtfWorkspaceCreateSchema,
    CtfWorkspacePatchSchema,
    CtfWorkspaceSchema,
)

router = APIRouter(prefix="/ctf-workspaces", tags=["ctf-workspaces"])

_CHECKLIST = {
    "file identification": False,
    "security mitigations": False,
    "strings": False,
    "imports": False,
    "interesting functions": False,
    "entry point": False,
    "main candidate": False,
    "input function": False,
    "comparison function": False,
    "encoding function": False,
    "success path": False,
    "failure path": False,
    "packed": False,
    "anti-debug": False,
    "dynamic trace needed": False,
}


def _schema(record, repository: CtfWorkspaceRepository) -> CtfWorkspaceSchema:
    return CtfWorkspaceSchema(
        id=record.id,
        title=record.title,
        description=record.description,
        category=record.category,
        difficulty=record.difficulty,
        binary_sha256=record.binary_sha256,
        hypotheses=json.loads(record.hypotheses_json),
        flag_candidates=json.loads(record.flag_candidates_json),
        checklist=json.loads(record.checklist_json),
        writeup_steps=json.loads(record.writeup_steps_json),
        notes=[
            CtfNoteSchema.model_validate(note)
            for note in repository.notes(record.id)
        ],
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@router.get("", response_model=list[CtfWorkspaceSchema])
def list_ctf_workspaces(
    limit: int = Query(100, ge=1, le=500),
    repository: CtfWorkspaceRepository = Depends(get_ctf_workspace_repository),
) -> list[CtfWorkspaceSchema]:
    return [_schema(record, repository) for record in repository.list(limit)]


@router.post("", response_model=CtfWorkspaceSchema, status_code=201)
def create_ctf_workspace(
    payload: CtfWorkspaceCreateSchema,
    repository: CtfWorkspaceRepository = Depends(get_ctf_workspace_repository),
) -> CtfWorkspaceSchema:
    record = repository.create(
        payload.title,
        payload.description,
        payload.category,
        payload.difficulty,
        payload.binary_sha256,
        dict(_CHECKLIST),
    )
    return _schema(record, repository)


@router.get("/{workspace_id}", response_model=CtfWorkspaceSchema)
def get_ctf_workspace(
    workspace_id: str,
    repository: CtfWorkspaceRepository = Depends(get_ctf_workspace_repository),
) -> CtfWorkspaceSchema:
    return _schema(repository.get(workspace_id), repository)


@router.patch("/{workspace_id}", response_model=CtfWorkspaceSchema)
def patch_ctf_workspace(
    workspace_id: str,
    payload: CtfWorkspacePatchSchema,
    repository: CtfWorkspaceRepository = Depends(get_ctf_workspace_repository),
) -> CtfWorkspaceSchema:
    record = repository.update(
        workspace_id, payload.model_dump(exclude_unset=True)
    )
    return _schema(record, repository)


@router.post("/{workspace_id}/notes", response_model=CtfNoteSchema, status_code=201)
def add_ctf_note(
    workspace_id: str,
    payload: CtfNoteCreateSchema,
    repository: CtfWorkspaceRepository = Depends(get_ctf_workspace_repository),
) -> CtfNoteSchema:
    return CtfNoteSchema.model_validate(
        repository.add_note(
            workspace_id, payload.kind, payload.content, payload.address
        )
    )


@router.get("/{workspace_id}/export")
def export_ctf_workspace(
    workspace_id: str,
    format: str = Query(default="markdown", pattern="^(markdown|json)$"),
    repository: CtfWorkspaceRepository = Depends(get_ctf_workspace_repository),
) -> Response:
    workspace = _schema(repository.get(workspace_id), repository)
    if format == "json":
        return Response(
            content=workspace.model_dump_json(indent=2),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="ctf-{workspace_id}.json"'
            },
        )

    lines = [
        f"# {workspace.title}",
        "",
        f"- Category: {workspace.category}",
        f"- Difficulty: {workspace.difficulty}",
        f"- Sample SHA-256: {workspace.binary_sha256 or 'not linked'}",
        "",
        "## Description",
        "",
        workspace.description or "_No description._",
        "",
        "## Analysis checklist",
        "",
        *[
            f"- [{'x' if complete else ' '}] {item}"
            for item, complete in workspace.checklist.items()
        ],
        "",
        "## Hypotheses",
        "",
        *[f"- {item}" for item in workspace.hypotheses],
        "",
        "## Findings and notes",
        "",
        *[
            f"- **{note.kind}**"
            f"{f' @ 0x{note.address:x}' if note.address is not None else ''}: "
            f"{note.content}"
            for note in workspace.notes
        ],
        "",
        "## Flag candidates",
        "",
        *[f"- `{item}`" for item in workspace.flag_candidates],
        "",
        "## Solution steps",
        "",
        *[
            f"{index}. {step}"
            for index, step in enumerate(workspace.writeup_steps, start=1)
        ],
        "",
        "## Limitations",
        "",
        "- Automated disassembly and pseudo-C are estimates, not recovered original source.",
        "- Validate heuristic findings against binary evidence before drawing conclusions.",
    ]
    return Response(
        content="\n".join(lines),
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="ctf-{workspace_id}.md"'
        },
    )
