"""Project CRUD and immutable sample membership."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from ...database import ProjectRepository
from ..dependencies import get_project_repository
from ..schemas import ProjectCreateSchema, ProjectPatchSchema, ProjectSchema

router = APIRouter(prefix="/projects", tags=["projects"])


def _schema(project, repository: ProjectRepository) -> ProjectSchema:
    return ProjectSchema(
        id=project.id,
        name=project.name,
        description=project.description,
        created_at=project.created_at,
        updated_at=project.updated_at,
        sample_sha256=repository.sample_hashes(project.id),
    )


@router.get("", response_model=list[ProjectSchema])
def list_projects(
    limit: int = Query(100, ge=1, le=500),
    repository: ProjectRepository = Depends(get_project_repository),
) -> list[ProjectSchema]:
    return [_schema(project, repository) for project in repository.list(limit)]


@router.post("", response_model=ProjectSchema, status_code=201)
def create_project(
    payload: ProjectCreateSchema,
    repository: ProjectRepository = Depends(get_project_repository),
) -> ProjectSchema:
    return _schema(repository.create(payload.name, payload.description), repository)


@router.get("/{project_id}", response_model=ProjectSchema)
def get_project(
    project_id: str,
    repository: ProjectRepository = Depends(get_project_repository),
) -> ProjectSchema:
    return _schema(repository.get(project_id), repository)


@router.patch("/{project_id}", response_model=ProjectSchema)
def patch_project(
    project_id: str,
    payload: ProjectPatchSchema,
    repository: ProjectRepository = Depends(get_project_repository),
) -> ProjectSchema:
    return _schema(
        repository.update(project_id, payload.name, payload.description), repository
    )


@router.post("/{project_id}/samples/{sha256}", response_model=ProjectSchema)
def add_project_sample(
    project_id: str,
    sha256: str,
    repository: ProjectRepository = Depends(get_project_repository),
) -> ProjectSchema:
    repository.add_sample(project_id, sha256)
    return _schema(repository.get(project_id), repository)
