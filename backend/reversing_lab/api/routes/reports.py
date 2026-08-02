"""Analysis report export endpoints."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from ...database import AnnotationRepository, BinaryRepository, BookmarkRepository
from ...reporting import build_report, render_html, render_markdown
from ..dependencies import (
    get_annotation_repository,
    get_binary_repository,
    get_bookmark_repository,
)
from ..services import functions_cached, parse_cached

router = APIRouter(prefix="/binaries", tags=["reports"])


@router.get("/{sha256}/report")
def export_binary_report(
    sha256: str,
    format: str = Query(default="json", pattern="^(json|markdown|html)$"),
    binaries: BinaryRepository = Depends(get_binary_repository),
    annotations: AnnotationRepository = Depends(get_annotation_repository),
    bookmarks: BookmarkRepository = Depends(get_bookmark_repository),
) -> Response:
    """Export one bounded static report; the sample is never executed."""
    record = binaries.get(sha256)
    data = binaries.load_bytes(sha256)
    info = parse_cached(sha256, data)
    functions = functions_cached(sha256, info, data)
    report = build_report(
        record=record,
        data=data,
        info=info,
        functions=functions,
        annotations=annotations.list(sha256),
        bookmarks=bookmarks.list(sha256),
    )
    if format == "markdown":
        content = render_markdown(report)
        media_type = "text/markdown; charset=utf-8"
        suffix = "md"
    elif format == "html":
        content = render_html(report)
        media_type = "text/html; charset=utf-8"
        suffix = "html"
    else:
        content = json.dumps(report, indent=2, ensure_ascii=False)
        media_type = "application/json"
        suffix = "json"
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": (
                f'attachment; filename="analysis-{sha256[:12]}.{suffix}"'
            )
        },
    )
