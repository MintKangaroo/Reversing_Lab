"""Challenge listing, artifact download, and answer submission."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import Response

from ...challenge import get_registry
from ...database import ChallengeAttemptRepository
from ..dependencies import get_attempt_repository
from ..schemas import ChallengeResultSchema, ChallengeSchema, ChallengeSubmission

router = APIRouter(prefix="/challenges", tags=["challenges"])


@router.get("", response_model=list[ChallengeSchema])
def list_challenges() -> list[ChallengeSchema]:
    """List all challenges (metadata only — never the answer)."""
    return [ChallengeSchema.model_validate(v) for v in get_registry().list_views()]


@router.get("/{slug}", response_model=ChallengeSchema)
def get_challenge(slug: str) -> ChallengeSchema:
    """Return a single challenge's metadata."""
    return ChallengeSchema.model_validate(get_registry().view(slug))


@router.get("/{slug}/artifact")
def download_artifact(slug: str) -> Response:
    """Download the challenge's binary artifact."""
    filename, data = get_registry().artifact(slug)
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/{slug}/submit", response_model=ChallengeResultSchema)
def submit_answer(
    slug: str,
    submission: ChallengeSubmission,
    attempts: ChallengeAttemptRepository = Depends(get_attempt_repository),
) -> ChallengeResultSchema:
    """Verify an answer server-side and record the attempt."""
    result = get_registry().verify(slug, submission.answer)
    attempts.record(slug, submission.answer, result.correct)
    return ChallengeResultSchema.model_validate(result)
