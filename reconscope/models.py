"""SQLAlchemy models (PRD §9.1).

Milestone 0 persists the entities needed for the safety boundary: projects,
scope entries, the authorization record, jobs, and the append-only activity log.
Findings, evidence, relationships, scan plans, worksheets, and report snapshots
are added with the milestones that produce them.
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> dt.datetime:
    # Naive UTC: SQLite does not preserve tzinfo, so we keep timestamps naive
    # and consistently in UTC to avoid naive/aware comparison bugs.
    return dt.datetime.now(dt.UTC).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text, default=None)
    notes: Mapped[str | None] = mapped_column(Text, default=None)
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )

    seed_targets: Mapped[list[SeedTarget]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    scope_entries: Mapped[list[ScopeEntry]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    authorizations: Mapped[list[AuthorizationRecord]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class SeedTarget(Base):
    __tablename__ = "seed_targets"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    target_type: Mapped[str] = mapped_column(String(16))  # "domain" | "ip"
    normalized_value: Mapped[str] = mapped_column(String(255))
    entered_value: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)

    project: Mapped[Project] = relationship(back_populates="seed_targets")


class ScopeEntry(Base):
    __tablename__ = "scope_entries"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    entry_type: Mapped[str] = mapped_column(String(20))  # EntryType value
    normalized_value: Mapped[str] = mapped_column(String(255))
    entered_value: Mapped[str] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)

    project: Mapped[Project] = relationship(back_populates="scope_entries")


class AuthorizationRecord(Base):
    __tablename__ = "authorization_records"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    attestation_text: Mapped[str] = mapped_column(Text)
    notice_version: Mapped[str] = mapped_column(String(32))
    accepted_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    # When set, this attestation is no longer current (e.g. scope was expanded).
    invalidated_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    invalidated_reason: Mapped[str | None] = mapped_column(String(255), default=None)

    project: Mapped[Project] = relationship(back_populates="authorizations")

    @property
    def is_current(self) -> bool:
        return self.invalidated_at is None


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    module_id: Mapped[str] = mapped_column(String(64))
    module_version: Mapped[str] = mapped_column(String(32))
    target: Mapped[str] = mapped_column(String(255))
    target_type: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(20), default="queued")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    started_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    finished_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    error_code: Mapped[str | None] = mapped_column(String(64), default=None)


class ActivityLog(Base):
    __tablename__ = "activity_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[str | None] = mapped_column(String(32), default=None)
    timestamp: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    action: Mapped[str] = mapped_column(String(64))
    module_id: Mapped[str | None] = mapped_column(String(64), default=None)
    target: Mapped[str | None] = mapped_column(String(255), default=None)
    scope_decision: Mapped[str | None] = mapped_column(String(64), default=None)
    matched_entry: Mapped[str | None] = mapped_column(String(255), default=None)
    detail: Mapped[str | None] = mapped_column(Text, default=None)


class ResearchSubject(Base):
    """An organization/product/handle the user wants to research (PRD §5.2, P14)."""

    __tablename__ = "research_subjects"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    # organization | product | public_handle | public_profile_url
    subject_type: Mapped[str] = mapped_column(String(24))
    normalized_value: Mapped[str] = mapped_column(String(512))
    entered_value: Mapped[str] = mapped_column(String(512))
    approved_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Evidence(Base):
    """Metadata for a raw evidence blob stored on disk (PRD §8.2)."""

    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"))
    provider: Mapped[str | None] = mapped_column(String(64), default=None)
    name: Mapped[str] = mapped_column(String(128))
    relative_path: Mapped[str] = mapped_column(String(512))
    media_type: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64))
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Finding(Base):
    """A normalized observation linked to its evidence and context (PRD §8.1)."""

    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    job_id: Mapped[str] = mapped_column(ForeignKey("jobs.id"))
    evidence_id: Mapped[str | None] = mapped_column(
        ForeignKey("evidence.id"), default=None
    )
    module_id: Mapped[str] = mapped_column(String(64))
    finding_type: Mapped[str] = mapped_column(String(48))
    value: Mapped[str] = mapped_column(String(512))
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    # confirmed-by-response | tool-inferred | derived-hint
    confidence: Mapped[str] = mapped_column(String(24))
    source: Mapped[str | None] = mapped_column(String(64), default=None)
    target_requested: Mapped[str | None] = mapped_column(String(255), default=None)
    target_contacted: Mapped[str | None] = mapped_column(String(255), default=None)
    first_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AssignmentWorksheet(Base):
    """Learner-authored worksheet, kept separate from observations (PRD §8.5)."""

    __tablename__ = "assignment_worksheets"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"), unique=True)
    title: Mapped[str | None] = mapped_column(String(255), default=None)
    prompt: Mapped[str | None] = mapped_column(Text, default=None)
    hypothesis: Mapped[str | None] = mapped_column(Text, default=None)
    method: Mapped[str | None] = mapped_column(Text, default=None)
    predicted_traffic: Mapped[str | None] = mapped_column(Text, default=None)
    interpretation: Mapped[str | None] = mapped_column(Text, default=None)
    false_positive_considerations: Mapped[str | None] = mapped_column(Text, default=None)
    defender_interpretation: Mapped[str | None] = mapped_column(Text, default=None)
    conclusion: Mapped[str | None] = mapped_column(Text, default=None)
    remaining_unknowns: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_now, onupdate=_now
    )


class ReportSnapshot(Base):
    """Audit record of a generated report (PRD §9.1, §11)."""

    __tablename__ = "report_snapshots"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id"))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)
    fmt: Mapped[str] = mapped_column(String(16))  # "markdown" | "zip"
    manifest_hash: Mapped[str] = mapped_column(String(64))
    job_count: Mapped[int] = mapped_column(Integer, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
