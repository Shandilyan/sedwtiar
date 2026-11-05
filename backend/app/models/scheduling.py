"""Scheduling engine models for resource-aware sanitization job ordering."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Enum as SqlEnum, Float, ForeignKey, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import (
    DataSensitivity,
    JobDependencyType,
    ResourceStatus,
    ScheduleAssignmentStatus,
    ScheduleEventType,
    SchedulePriority,
)


class SanitizationResource(Base):
    """A sanitization tool, workstation bay, or physical wiping rig."""

    __tablename__ = "sanitization_resources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(150), unique=True, nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[ResourceStatus] = mapped_column(
        SqlEnum(ResourceStatus, name="resource_status", native_enum=False),
        nullable=False,
        default=ResourceStatus.AVAILABLE,
        index=True,
    )
    supported_media_types: Mapped[Optional[list[str]]] = mapped_column(JSON, nullable=True)
    supported_methods: Mapped[Optional[list[str]]] = mapped_column(JSON, nullable=True)
    max_capacity_gb: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    throughput_gbps: Mapped[Optional[float]] = mapped_column(Float, nullable=True, default=0.25)
    concurrency_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    location: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    assignments: Mapped[list["ScheduleAssignment"]] = relationship(
        back_populates="resource", order_by="ScheduleAssignment.created_at"
    )
    events: Mapped[list["ScheduleEvent"]] = relationship(
        back_populates="resource", order_by="ScheduleEvent.occurred_at"
    )


class ScheduleAssignment(Base):
    """Binding between one sanitization job and a compatible resource queue."""

    __tablename__ = "schedule_assignments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    job_id: Mapped[str] = mapped_column(ForeignKey("sanitization_jobs.id"), index=True, nullable=False)
    resource_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("sanitization_resources.id"), index=True, nullable=True
    )
    priority: Mapped[SchedulePriority] = mapped_column(
        SqlEnum(SchedulePriority, name="schedule_priority", native_enum=False),
        nullable=False,
        default=SchedulePriority.NORMAL,
        index=True,
    )
    status: Mapped[ScheduleAssignmentStatus] = mapped_column(
        SqlEnum(ScheduleAssignmentStatus, name="schedule_assignment_status", native_enum=False),
        nullable=False,
        default=ScheduleAssignmentStatus.PENDING,
        index=True,
    )
    priority_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0, index=True)
    data_sensitivity: Mapped[DataSensitivity] = mapped_column(
        SqlEnum(DataSensitivity, name="data_sensitivity", native_enum=False),
        nullable=False,
        default=DataSensitivity.STANDARD,
        index=True,
    )
    estimated_minutes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    actual_minutes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    deadline: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    queue_position: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    slot_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, default=1)
    scheduled_start: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    scheduled_end: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    reassigned_from_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("schedule_assignments.id"), nullable=True
    )
    reassign_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    job: Mapped["SanitizationJob"] = relationship(back_populates="schedule_assignments")
    resource: Mapped[Optional["SanitizationResource"]] = relationship(back_populates="assignments")
    events: Mapped[list["ScheduleEvent"]] = relationship(
        back_populates="assignment", order_by="ScheduleEvent.occurred_at"
    )


class JobDependency(Base):
    """Prerequisite relationship defining DAG workflow constraints between sanitization jobs."""

    __tablename__ = "job_dependencies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    parent_job_id: Mapped[str] = mapped_column(ForeignKey("sanitization_jobs.id"), index=True, nullable=False)
    child_job_id: Mapped[str] = mapped_column(ForeignKey("sanitization_jobs.id"), index=True, nullable=False)
    dependency_type: Mapped[JobDependencyType] = mapped_column(
        SqlEnum(JobDependencyType, name="job_dependency_type", native_enum=False),
        nullable=False,
        default=JobDependencyType.PREREQUISITE,
    )
    is_satisfied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    satisfied_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    parent_job: Mapped["SanitizationJob"] = relationship(
        "SanitizationJob", foreign_keys=[parent_job_id], back_populates="dependents"
    )
    child_job: Mapped["SanitizationJob"] = relationship(
        "SanitizationJob", foreign_keys=[child_job_id], back_populates="dependencies"
    )


class ScheduleEvent(Base):
    """Immutable audit trail for all scheduling, optimization, and reassignment actions."""

    __tablename__ = "schedule_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    assignment_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("schedule_assignments.id"), nullable=True, index=True
    )
    resource_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("sanitization_resources.id"), nullable=True, index=True
    )
    event_type: Mapped[ScheduleEventType] = mapped_column(
        SqlEnum(ScheduleEventType, name="schedule_event_type", native_enum=False), nullable=False, index=True
    )
    details: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

    assignment: Mapped[Optional["ScheduleAssignment"]] = relationship(back_populates="events")
    resource: Mapped[Optional["SanitizationResource"]] = relationship(back_populates="events")
