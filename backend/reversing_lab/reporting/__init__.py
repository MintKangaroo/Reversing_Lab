"""Evidence-linked analysis report generation."""

from .generator import build_report, html_document, render_html, render_markdown
from .runs import (
    build_dynamic_report,
    build_memory_report,
    render_dynamic_html,
    render_dynamic_markdown,
    render_memory_html,
    render_memory_markdown,
)

__all__ = [
    "build_dynamic_report",
    "build_memory_report",
    "build_report",
    "html_document",
    "render_dynamic_html",
    "render_dynamic_markdown",
    "render_html",
    "render_markdown",
    "render_memory_html",
    "render_memory_markdown",
]
