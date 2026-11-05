"""Pydantic schemas for the sanitization scheduling and resource optimization engine."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import (
    DataSensitivity,
    JobDependencyType,
    ResourceStatus,
    ScheduleAssignmentStatus,
    ScheduleEventType,
    SchedulePriority,
)


class SanitizationResourceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150, examples=["Purge Bay A"])
    resource_type: str = Field(min_length=1, max_length=100, examples=["NVMe Hardware Eraser"])
    status: ResourceStatus = ResourceStatus.AVAILABLE
    supported_media_types: list[str] = Field(default_factory=lambda: ["SSD", "NVMe"])
    supported_methods: list[str] = Field(default_factory=lambda: ["Cryptographic Erase", "Block Overwrite", "NIST Purge"])
    max_capacity_gb: Optional[int] = Field(default=None, ge=1, le=100_000)
    throughput_gbps: Optional[float] = Field(default=0.25, ge=0.01, le=100.0)
    concurrency_limit: int = Field(default=1, ge=1, le=64)
    location: Optional[str] = Field(default=None, max_length=255)
    notes: Optional[str] = None


class SanitizationResourceUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=150)
    resource_type: Optional[str] = None
    status: Optional[ResourceStatus] = None
    supported_media_types: Optional[list[str]] = None
    supported_methods: Optional[list[str]] = None
    max_capacity_gb: Optional[int] = None
    throughput_gbps: Optional[float] = None
    concurrency_limit: Optional[int] = Field(default=None, ge=1, le=64)
    location: Optional[str] = None
    notes: Optional[str] = None


class SanitizationResourceStatusUpdate(BaseModel):
    status: ResourceStatus
    reason: Optional[str] = None


class SanitizationResourceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    resource_type: str
    status: ResourceStatus
    supported_media_types: Optional[list[str]]
    supported_methods: Optional[list[str]]
    max_capacity_gb: Optional[int]
    throughput_gbps: Optional[float]
    concurrency_limit: int
    version: int
    location: Optional[str]
    notes: Optional[str]
    created_at: datetime
    updated_at: datetime


class JobDependencyCreate(BaseModel):
    parent_job_id: str = Field(description="The prerequisite job that must complete first")
    child_job_id: str = Field(description="The dependent job that cannot run until prerequisite completes")
    dependency_type: JobDependencyType = JobDependencyType.PREREQUISITE
    notes: Optional[str] = None


class JobDependencyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    parent_job_id: str
    child_job_id: str
    dependency_type: JobDependencyType
    is_satisfied: bool
    satisfied_at: Optional[datetime]
    notes: Optional[str]
    created_at: datetime


class JobDependenciesRead(BaseModel):
    job_id: str
    incoming_prerequisites: list[JobDependencyRead]
    outgoing_dependents: list[JobDependencyRead]
    dependencies_satisfied: bool
    pending_prerequisites_count: int


class ScheduleEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    assignment_id: Optional[str]
    resource_id: Optional[str]
    event_type: ScheduleEventType
    details: Optional[dict[str, Any]]
    occurred_at: datetime


class ScheduleAssignmentCreate(BaseModel):
    job_id: str
    resource_id: Optional[str] = None
    data_sensitivity: DataSensitivity = DataSensitivity.STANDARD
    deadline: Optional[datetime] = None


class ScheduleAssignmentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_id: str
    resource_id: Optional[str]
    priority: SchedulePriority
    status: ScheduleAssignmentStatus
    priority_score: float
    data_sensitivity: DataSensitivity
    estimated_minutes: Optional[int]
    actual_minutes: Optional[int]
    deadline: Optional[datetime]
    queue_position: Optional[int]
    slot_number: Optional[int] = 1
    scheduled_start: Optional[datetime]
    scheduled_end: Optional[datetime]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    reassigned_from_id: Optional[str]
    reassign_reason: Optional[str]
    created_at: datetime
    updated_at: datetime


class QueueItemRead(BaseModel):
    assignment_id: Optional[str] = None
    job_id: str
    asset_id: str
    asset_tag: str
    asset_type: str
    storage_type: Optional[str]
    storage_capacity_gb: Optional[int]
    planned_method: str
    data_sensitivity: DataSensitivity
    deadline: Optional[datetime]
    priority: SchedulePriority
    priority_score: float
    status: ScheduleAssignmentStatus
    queue_position: Optional[int]
    slot_number: Optional[int] = 1
    assigned_resource_id: Optional[str]
    assigned_resource_name: Optional[str]
    estimated_minutes: int
    scheduled_start: Optional[datetime]
    scheduled_end: Optional[datetime]
    is_overdue: bool = False
    security_critical: bool = False
    dependencies_satisfied: bool = True
    pending_dependencies_count: int = 0
    compatible_resource_count: int = 0


class TransactionalAssignmentRequest(BaseModel):
    job_id: str
    resource_id: str
    expected_version: Optional[int] = None
    slot_number: int = Field(default=1, ge=1)
    force_override: bool = False


class OptimizationSummary(BaseModel):
    total_jobs_evaluated: int
    assigned_count: int
    unassigned_count: int
    critical_jobs_prioritized: int
    urgent_jobs_count: int
    estimated_total_makespan_minutes: int
    average_wait_minutes: float
    resource_utilization: dict[str, float]
    schedule_generated_at: datetime
    security_guarantee: str = (
        "Enforced: Critical and urgent data sensitivity jobs are strictly prioritized. "
        "Throughput optimization never delays security-critical assets."
    )


class OptimizationResult(BaseModel):
    summary: OptimizationSummary
    queue: list[QueueItemRead]


class DynamicRebalanceRequest(BaseModel):
    unavailable_resource_id: Optional[str] = None
    reason: Optional[str] = "Resource unavailable or job delay detected"
    preserve_running_jobs: bool = True


class DynamicRebalanceResult(BaseModel):
    reassigned_count: int
    preserved_running_count: int
    unassigned_due_to_no_resource: int
    affected_resource_id: Optional[str]
    reason: str
    reassigned_assignments: list[ScheduleAssignmentRead]


class WorkloadSimulationRequest(BaseModel):
    device_count: int = Field(default=100, ge=5, le=1000)
    seed: Optional[int] = 42
    auto_create_resources_if_empty: bool = True


class WorkloadSimulationResult(BaseModel):
    device_count: int
    jobs_created: int
    resources_available: int
    optimization_summary: OptimizationSummary
    first_10_queue_items: list[QueueItemRead]
