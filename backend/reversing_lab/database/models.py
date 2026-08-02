"""SQLAlchemy ORM models for metadata indexes and analyst-owned state.

Large binary, memory, and event bodies remain content-addressed filesystem artifacts;
these tables store identities, state, relationships, and artifact references.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

DEFAULT_OWNER_ID = "local"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


class BinaryRecord(Base):
    """Metadata for an uploaded binary. The SHA-256 is the primary key."""

    __tablename__ = "binaries"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    binary_format: Mapped[str] = mapped_column(String(16), nullable=False)
    size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    storage_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class BinaryAccessRecord(Base):
    """Principal grant for one immutable content-addressed binary."""

    __tablename__ = "binary_access"

    owner_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    binary_sha256: Mapped[str] = mapped_column(
        String(64), ForeignKey("binaries.sha256"), primary_key=True
    )
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class ChallengeAttempt(Base):
    """A single challenge submission (append-only)."""

    __tablename__ = "challenge_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_id: Mapped[str] = mapped_column(
        String(128), default=DEFAULT_OWNER_ID, nullable=False, index=True
    )
    challenge_slug: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    submission: Mapped[str] = mapped_column(String(512), nullable=False)
    correct: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class ProjectRecord(Base):
    """An analyst-owned collection of samples and notes."""

    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    owner_id: Mapped[str] = mapped_column(
        String(128), default=DEFAULT_OWNER_ID, nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )


class ProjectSampleRecord(Base):
    """Many-to-many link between a project and immutable sample."""

    __tablename__ = "project_samples"

    project_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.id"), primary_key=True
    )
    binary_sha256: Mapped[str] = mapped_column(
        String(64), ForeignKey("binaries.sha256"), primary_key=True
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class UserAnnotationRecord(Base):
    """User-authored name or comment overlay for an address."""

    __tablename__ = "user_annotations"
    __table_args__ = (
        UniqueConstraint(
            "owner_id",
            "binary_sha256",
            "address",
            "kind",
            name="uq_annotation_target",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_id: Mapped[str] = mapped_column(
        String(128), default=DEFAULT_OWNER_ID, nullable=False, index=True
    )
    binary_sha256: Mapped[str] = mapped_column(
        String(64), ForeignKey("binaries.sha256"), nullable=False, index=True
    )
    address: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )


class BookmarkRecord(Base):
    """Persistent analyst bookmark at a binary virtual address."""

    __tablename__ = "bookmarks"
    __table_args__ = (
        UniqueConstraint(
            "owner_id", "binary_sha256", "address", name="uq_bookmark_target"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_id: Mapped[str] = mapped_column(
        String(128), default=DEFAULT_OWNER_ID, nullable=False, index=True
    )
    binary_sha256: Mapped[str] = mapped_column(
        String(64), ForeignKey("binaries.sha256"), nullable=False, index=True
    )
    address: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(160), default="", nullable=False)
    note: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class AnalysisArtifactRecord(Base):
    """Metadata index for an immutable, content-addressed derived artifact."""

    __tablename__ = "analysis_artifacts"
    __table_args__ = (
        UniqueConstraint(
            "owner_id",
            "binary_sha256",
            "kind",
            "content_sha256",
            name="uq_artifact_content",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(
        String(128), default=DEFAULT_OWNER_ID, nullable=False, index=True
    )
    binary_sha256: Mapped[str] = mapped_column(
        String(64), ForeignKey("binaries.sha256"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    storage_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class AnalysisJobRecord(Base):
    """Persistent state for a bounded background analysis."""

    __tablename__ = "analysis_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(
        String(128), default=DEFAULT_OWNER_ID, nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    message: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class MemoryDumpRecord(Base):
    """Content-addressed memory dump metadata."""

    __tablename__ = "memory_dumps"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(
        String(128), default=DEFAULT_OWNER_ID, nullable=False, index=True
    )
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    dump_format: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    analysis_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    analysis_provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class DynamicAnalysisRunRecord(Base):
    """Metadata/index for one sandbox-provider invocation."""

    __tablename__ = "dynamic_analysis_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(
        String(128), default=DEFAULT_OWNER_ID, nullable=False, index=True
    )
    job_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("analysis_jobs.id"), nullable=False, unique=True
    )
    binary_sha256: Mapped[str] = mapped_column(
        String(64), ForeignKey("binaries.sha256"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_json: Mapped[str] = mapped_column(Text, nullable=False)
    result_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class CtfWorkspaceRecord(Base):
    """Persistent analyst state for one CTF/CrackMe investigation."""

    __tablename__ = "ctf_workspaces"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(
        String(128), default=DEFAULT_OWNER_ID, nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    category: Mapped[str] = mapped_column(String(64), default="reversing", nullable=False)
    difficulty: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False)
    binary_sha256: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("binaries.sha256"), nullable=True, index=True
    )
    hypotheses_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    flag_candidates_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    checklist_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    writeup_steps_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )


class CtfNoteRecord(Base):
    """Address-aware note/bookmark/string collected during a CTF investigation."""

    __tablename__ = "ctf_notes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("ctf_workspaces.id"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    address: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
