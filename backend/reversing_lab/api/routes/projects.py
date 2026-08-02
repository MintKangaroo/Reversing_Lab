"""Project CRUD and immutable sample membership."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from ...database import BinaryRepository, ProjectRepository
from ..auth import Principal, get_current_principal, resource_scope
from ..dependencies import get_binary_repository, get_project_repository
from ..schemas import ProjectCreateSchema, ProjectPatchSchema, ProjectSchema

router = APIRouter(prefix="/projects", tags=["projects"])


def _scope(principal: Principal) -> str | None:
    owner_id, unrestricted = resource_scope(principal)
    return None if unrestricted else owner_id


def _schema(
    project, repository: ProjectRepository, owner_scope: str | None
) -> ProjectSchema:
    return ProjectSchema(
        id=project.id,
        name=project.name,
        description=project.description,
        owner_id=project.owner_id,
        created_at=project.created_at,
        updated_at=project.updated_at,
        sample_sha256=repository.sample_hashes(project.id, owner_scope),
    )


@router.get("", response_model=list[ProjectSchema])
def list_projects(
    limit: int = Query(100, ge=1, le=500),
    repository: ProjectRepository = Depends(get_project_repository),
    principal: Principal = Depends(get_current_principal),
) -> list[ProjectSchema]:
    owner_scope = _scope(principal)
    return [
        _schema(project, repository, owner_scope)
        for project in repository.list(limit, owner_scope)
    ]


@router.post("", response_model=ProjectSchema, status_code=201)
def create_project(
    payload: ProjectCreateSchema,
    repository: ProjectRepository = Depends(get_project_repository),
    principal: Principal = Depends(get_current_principal),
) -> ProjectSchema:
    owner_id, _ = resource_scope(principal)
    return _schema(
        repository.create(payload.name, payload.description, owner_id),
        repository,
        _scope(principal),
    )


@router.get("/{project_id}", response_model=ProjectSchema)
def get_project(
    project_id: str,
    repository: ProjectRepository = Depends(get_project_repository),
    principal: Principal = Depends(get_current_principal),
) -> ProjectSchema:
    owner_scope = _scope(principal)
    return _schema(
        repository.get(project_id, owner_scope), repository, owner_scope
    )


@router.patch("/{project_id}", response_model=ProjectSchema)
def patch_project(
    project_id: str,
    payload: ProjectPatchSchema,
    repository: ProjectRepository = Depends(get_project_repository),
    principal: Principal = Depends(get_current_principal),
) -> ProjectSchema:
    owner_scope = _scope(principal)
    return _schema(
        repository.update(
            project_id, payload.name, payload.description, owner_scope
        ),
        repository,
        owner_scope,
    )


@router.post("/{project_id}/samples/{sha256}", response_model=ProjectSchema)
def add_project_sample(
    project_id: str,
    sha256: str,
    repository: ProjectRepository = Depends(get_project_repository),
    binaries: BinaryRepository = Depends(get_binary_repository),
    principal: Principal = Depends(get_current_principal),
) -> ProjectSchema:
    owner_scope = _scope(principal)
    binaries.get(sha256)
    repository.add_sample(project_id, sha256, owner_scope)
    return _schema(
        repository.get(project_id, owner_scope), repository, owner_scope
    )
