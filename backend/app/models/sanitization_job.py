"""Administrative sanitization workflow jobs with no execution capability."""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy import DateTime, Enum as SqlEnum, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import DataSensitivity, SanitizationJobStatus


class SanitizationJob(Base):
    __tablename__ = "sanitization_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    status: Mapped[SanitizationJobStatus] = mapped_column(
        SqlEnum(SanitizationJobStatus, name="sanitization_job_status", native_enum=False),
        nullable=False,
        default=SanitizationJobStatus.REQUESTED,
        index=True,
    )
    planned_method: Mapped[str] = mapped_column(String(150), nullable=False)
    requested_by: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    data_sensitivity: Mapped[Optional[DataSensitivity]] = mapped_column(
        SqlEnum(DataSensitivity, name="data_sensitivity", native_enum=False),
        nullable=True,
        default=DataSensitivity.STANDARD,
    )
    deadline: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    estimated_duration_minutes: Mapped[Optional[int]] = mapped_column(nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    asset: Mapped["Asset"] = relationship(back_populates="sanitization_jobs")
    events: Mapped[list["SanitizationJobEvent"]] = relationship(
        back_populates="job", order_by="SanitizationJobEvent.occurred_at"
    )
    sanitization_records: Mapped[list["SanitizationRecord"]] = relationship(
        back_populates="job", order_by="SanitizationRecord.created_at"
    )
    disposition_recommendations: Mapped[list["DispositionRecommendation"]] = relationship(
        back_populates="sanitization_job", order_by="DispositionRecommendation.created_at"
    )
    schedule_assignments: Mapped[list["ScheduleAssignment"]] = relationship(
        back_populates="job", order_by="ScheduleAssignment.created_at"
    )
    dependencies: Mapped[list["JobDependency"]] = relationship(
        "JobDependency", foreign_keys="JobDependency.child_job_id", back_populates="child_job"
    )
    dependents: Mapped[list["JobDependency"]] = relationship(
        "JobDependency", foreign_keys="JobDependency.parent_job_id", back_populates="parent_job"
    )


class SanitizationJobEvent(Base):
    """Append-only state transition log for an administrative job."""

    __tablename__ = "sanitization_job_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    job_id: Mapped[str] = mapped_column(ForeignKey("sanitization_jobs.id"), index=True)
    previous_status: Mapped[Optional[SanitizationJobStatus]] = mapped_column(
        SqlEnum(SanitizationJobStatus, name="sanitization_job_status", native_enum=False), nullable=True
    )
    new_status: Mapped[SanitizationJobStatus] = mapped_column(
        SqlEnum(SanitizationJobStatus, name="sanitization_job_status", native_enum=False), nullable=False
    )
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    job: Mapped["SanitizationJob"] = relationship(back_populates="events")
