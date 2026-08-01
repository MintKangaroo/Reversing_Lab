"""Baseline the current Reversing Lab metadata schema.

Revision ID: 0001_initial_schema
Revises: None
Create Date: 2026-08-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "binaries",
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("filename", sa.String(length=512), nullable=False),
        sa.Column("binary_format", sa.String(length=16), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("storage_path", sa.String(length=1024), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("sha256"),
    )
    op.create_table(
        "challenge_attempts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("challenge_slug", sa.String(length=64), nullable=False),
        sa.Column("submission", sa.String(length=512), nullable=False),
        sa.Column("correct", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_challenge_attempts_challenge_slug",
        "challenge_attempts",
        ["challenge_slug"],
    )
    op.create_table(
        "projects",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "analysis_jobs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("target_id", sa.String(length=128), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("message", sa.String(length=512), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("result_ref", sa.String(length=1024), nullable=True),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    for name in ("kind", "state", "target_id"):
        op.create_index(f"ix_analysis_jobs_{name}", "analysis_jobs", [name])
    op.create_table(
        "memory_dumps",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("filename", sa.String(length=512), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("dump_format", sa.String(length=64), nullable=False),
        sa.Column("storage_path", sa.String(length=1024), nullable=False),
        sa.Column("analysis_path", sa.String(length=1024), nullable=True),
        sa.Column("analysis_provider", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_memory_dumps_sha256", "memory_dumps", ["sha256"])
    op.create_table(
        "project_samples",
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("binary_sha256", sa.String(length=64), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["binary_sha256"], ["binaries.sha256"]),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
        sa.PrimaryKeyConstraint("project_id", "binary_sha256"),
    )
    op.create_table(
        "user_annotations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("binary_sha256", sa.String(length=64), nullable=False),
        sa.Column("address", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["binary_sha256"], ["binaries.sha256"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "binary_sha256", "address", "kind", name="uq_annotation_target"
        ),
    )
    op.create_index(
        "ix_user_annotations_binary_sha256", "user_annotations", ["binary_sha256"]
    )
    op.create_index("ix_user_annotations_address", "user_annotations", ["address"])
    op.create_table(
        "bookmarks",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("binary_sha256", sa.String(length=64), nullable=False),
        sa.Column("address", sa.Integer(), nullable=False),
        sa.Column("label", sa.String(length=160), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["binary_sha256"], ["binaries.sha256"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("binary_sha256", "address", name="uq_bookmark_target"),
    )
    op.create_index("ix_bookmarks_binary_sha256", "bookmarks", ["binary_sha256"])
    op.create_index("ix_bookmarks_address", "bookmarks", ["address"])
    op.create_table(
        "analysis_artifacts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("binary_sha256", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("storage_path", sa.String(length=1024), nullable=False),
        sa.Column("metadata_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["binary_sha256"], ["binaries.sha256"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "binary_sha256",
            "kind",
            "content_sha256",
            name="uq_artifact_content",
        ),
    )
    for name in ("binary_sha256", "content_sha256", "kind"):
        op.create_index(
            f"ix_analysis_artifacts_{name}", "analysis_artifacts", [name]
        )
    op.create_table(
        "dynamic_analysis_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("job_id", sa.String(length=36), nullable=False),
        sa.Column("binary_sha256", sa.String(length=64), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("policy_json", sa.Text(), nullable=False),
        sa.Column("result_path", sa.String(length=1024), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["binary_sha256"], ["binaries.sha256"]),
        sa.ForeignKeyConstraint(["job_id"], ["analysis_jobs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("job_id", name="uq_dynamic_analysis_runs_job_id"),
    )
    op.create_index(
        "ix_dynamic_analysis_runs_binary_sha256",
        "dynamic_analysis_runs",
        ["binary_sha256"],
    )
    op.create_table(
        "ctf_workspaces",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("difficulty", sa.String(length=32), nullable=False),
        sa.Column("binary_sha256", sa.String(length=64), nullable=True),
        sa.Column("hypotheses_json", sa.Text(), nullable=False),
        sa.Column("flag_candidates_json", sa.Text(), nullable=False),
        sa.Column("checklist_json", sa.Text(), nullable=False),
        sa.Column("writeup_steps_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["binary_sha256"], ["binaries.sha256"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_ctf_workspaces_binary_sha256", "ctf_workspaces", ["binary_sha256"]
    )
    op.create_table(
        "ctf_notes",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("workspace_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("address", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["ctf_workspaces.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ctf_notes_workspace_id", "ctf_notes", ["workspace_id"])
    op.create_index("ix_ctf_notes_address", "ctf_notes", ["address"])


def downgrade() -> None:
    op.drop_index("ix_ctf_notes_address", table_name="ctf_notes")
    op.drop_index("ix_ctf_notes_workspace_id", table_name="ctf_notes")
    op.drop_table("ctf_notes")
    op.drop_index("ix_ctf_workspaces_binary_sha256", table_name="ctf_workspaces")
    op.drop_table("ctf_workspaces")
    op.drop_index(
        "ix_dynamic_analysis_runs_binary_sha256",
        table_name="dynamic_analysis_runs",
    )
    op.drop_table("dynamic_analysis_runs")
    for name in ("kind", "content_sha256", "binary_sha256"):
        op.drop_index(f"ix_analysis_artifacts_{name}", table_name="analysis_artifacts")
    op.drop_table("analysis_artifacts")
    op.drop_index("ix_bookmarks_address", table_name="bookmarks")
    op.drop_index("ix_bookmarks_binary_sha256", table_name="bookmarks")
    op.drop_table("bookmarks")
    op.drop_index("ix_user_annotations_address", table_name="user_annotations")
    op.drop_index(
        "ix_user_annotations_binary_sha256", table_name="user_annotations"
    )
    op.drop_table("user_annotations")
    op.drop_table("project_samples")
    op.drop_index("ix_memory_dumps_sha256", table_name="memory_dumps")
    op.drop_table("memory_dumps")
    for name in ("target_id", "state", "kind"):
        op.drop_index(f"ix_analysis_jobs_{name}", table_name="analysis_jobs")
    op.drop_table("analysis_jobs")
    op.drop_table("projects")
    op.drop_index(
        "ix_challenge_attempts_challenge_slug", table_name="challenge_attempts"
    )
    op.drop_table("challenge_attempts")
    op.drop_table("binaries")
