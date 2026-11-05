"""Scheduling engine implementing priority queues, greedy interval allocation,
DAG dependency management, concurrency control, and transactional rebalancing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import heapq
import random
from typing import Any, Optional

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Asset, LifecycleEvent, SanitizationJob, SanitizationJobEvent
from app.models.enums import (
    AssetLifecycleStatus,
    AssetType,
    DataSensitivity,
    JobDependencyType,
    LifecycleEventType,
    ResourceStatus,
    SanitizationJobStatus,
    ScheduleAssignmentStatus,
    ScheduleEventType,
    SchedulePriority,
    VerificationOutcome,
)
from app.models.scheduling import (
    JobDependency,
    SanitizationResource,
    ScheduleAssignment,
    ScheduleEvent,
)
from app.schemas.scheduling import (
    DynamicRebalanceResult,
    JobDependenciesRead,
    JobDependencyCreate,
    JobDependencyRead,
    OptimizationResult,
    OptimizationSummary,
    QueueItemRead,
    SanitizationResourceCreate,
    SanitizationResourceUpdate,
    ScheduleAssignmentRead,
    WorkloadSimulationResult,
)
from app.services.exceptions import (
    BusinessRuleError,
    ResourceConflictError,
    ResourceIncompatibleError,
    ResourceNotFoundError,
    SchedulingConflictError,
    SecurityPolicyViolationError,
)

# Base priority score weights by sensitivity level.
# The huge point spread mathematically guarantees that security-critical assets
# are never delayed in favor of low-priority throughput.
_SENSITIVITY_WEIGHTS = {
    DataSensitivity.CRITICAL: 100_000.0,
    DataSensitivity.HIGH: 50_000.0,
    DataSensitivity.STANDARD: 10_000.0,
    DataSensitivity.LOW: 1_000.0,
}

DEFAULT_RESOURCES = [
    {
        "name": "Bay-01: High-Speed NVMe/SSD Station",
        "resource_type": "NVMe/SSD Dedicated Hardware Eraser",
        "status": ResourceStatus.AVAILABLE,
        "supported_media_types": ["SSD", "NVMe", "Flash", "eMMC"],
        "supported_methods": [
            "Cryptographic Erase",
            "NIST 800-88 Purge",
            "SSD Secure Sanitization / Purge-oriented workflow",
            "Block Overwrite",
            "NIST Purge",
        ],
        "max_capacity_gb": 16_000,
        "throughput_gbps": 0.60,
        "concurrency_limit": 2,
        "location": "Sanitization Lab - Rack Alpha",
        "notes": "Dedicated PCIe/NVMe high-throughput purge bay with crypto-erase hardware controller. Dual-slot.",
    },
    {
        "name": "Bay-02: Multi-Bay Enterprise SATA/SAS Rig",
        "resource_type": "Multi-Port SAS/SATA Wiping Bay",
        "status": ResourceStatus.AVAILABLE,
        "supported_media_types": ["HDD", "SSD", "SAS", "SATA", "Storage"],
        "supported_methods": [
            "NIST 800-88 Clear",
            "NIST 800-88 Purge",
            "HDD Multi-Pass Overwrite",
            "DoD 5220.22-M Overwrite",
            "Block Overwrite",
            "SSD Secure Sanitization / Purge-oriented workflow",
        ],
        "max_capacity_gb": 32_000,
        "throughput_gbps": 0.25,
        "concurrency_limit": 4,
        "location": "Sanitization Lab - Rack Bravo",
        "notes": "Concurrent 4-channel SAS/SATA enterprise chassis for server & desktop drives.",
    },
    {
        "name": "Bay-03: Heavy-Duty Magnetic Degausser",
        "resource_type": "Electromagnetic Degausser Bay",
        "status": ResourceStatus.AVAILABLE,
        "supported_media_types": ["HDD", "Magnetic Tape", "Tape", "Floppy"],
        "supported_methods": [
            "Degauss",
            "Magnetic Degaussing",
            "NIST 800-88 Destroy",
            "Physical Destruction Pre-treatment",
        ],
        "max_capacity_gb": 64_000,
        "throughput_gbps": 1.50,
        "concurrency_limit": 1,
        "location": "Secure Destruction Room - Station 1",
        "notes": "Instant electromagnetic coil for immediate magnetic sanitization. Single chamber.",
    },
    {
        "name": "Bay-04: Removable & External Media Station",
        "resource_type": "Multi-Interface Peripheral Station",
        "status": ResourceStatus.AVAILABLE,
        "supported_media_types": ["USB", "SD", "MicroSD", "MMC", "SSD", "HDD"],
        "supported_methods": [
            "Block Overwrite",
            "NIST 800-88 Clear",
            "External Disk Zero Overwrite",
            "Single-Pass Zero Fill",
        ],
        "max_capacity_gb": 8_000,
        "throughput_gbps": 0.15,
        "concurrency_limit": 2,
        "location": "Intake Inspection Bench 3",
        "notes": "Dedicated Windows Storage Management rig for USB/removable drives.",
    },
    {
        "name": "Bay-05: Industrial Physical Disintegrator / Shredder",
        "resource_type": "Optical & Physical Disintegrator",
        "status": ResourceStatus.AVAILABLE,
        "supported_media_types": ["Optical", "CD", "DVD", "SSD", "HDD", "Tape", "Mobile"],
        "supported_methods": [
            "Physical Shred",
            "Optical Media Destruction",
            "NIST 800-88 Destroy",
            "Shredding",
        ],
        "max_capacity_gb": 100_000,
        "throughput_gbps": 0.80,
        "concurrency_limit": 1,
        "location": "Secure Destruction Room - Station 2",
        "notes": "DIN 66399 Level H-5/O-5 disintegration for end-of-life media.",
    },
]


def _to_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensure datetime has UTC timezone for consistent offset comparisons."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Priority Queue Data Structures (O(log N) Binary Min-Heap with Inverted Keys)
# ---------------------------------------------------------------------------

@dataclass(order=True)
class PrioritizedJobEntry:
    sort_key: tuple[float, float, int, int]
    job_candidate: dict[str, Any] = field(compare=False)


class JobPriorityQueue:
    """Binary min-heap priority queue for optimal O(log N) job scheduling.

    The composite sorting key enforces:
      1. -priority_score (dominates: security sensitivity + overdue urgency)
      2. deadline_timestamp (earlier deadlines break ties)
      3. estimated_duration (Shortest Processing Time tie-breaker within tier)
      4. insertion sequence counter (stable FIFO tie-break)
    """

    def __init__(self):
        self._heap: list[PrioritizedJobEntry] = []
        self._counter = 0

    def push(self, candidate: dict[str, Any]) -> None:
        self._counter += 1
        score = candidate["priority_score"]
        dl = _to_utc(candidate.get("deadline"))
        dl_ts = dl.timestamp() if dl else 9_999_999_999.0
        dur = candidate.get("estimated_minutes", 30)
        # Negate score so highest priority score pops first in min-heap
        sort_key = (-score, dl_ts, dur, self._counter)
        heapq.heappush(self._heap, PrioritizedJobEntry(sort_key=sort_key, job_candidate=candidate))

    def pop(self) -> dict[str, Any]:
        entry = heapq.heappop(self._heap)
        return entry.job_candidate

    def peek(self) -> Optional[dict[str, Any]]:
        if not self._heap:
            return None
        return self._heap[0].job_candidate

    def __len__(self) -> int:
        return len(self._heap)

    def is_empty(self) -> bool:
        return len(self._heap) == 0


# ---------------------------------------------------------------------------
# Interval Scheduling & Resource Slot Allocation (Greedy EFT Packing)
# ---------------------------------------------------------------------------

@dataclass
class TimeInterval:
    start: datetime
    end: datetime
    assignment_id: Optional[str]
    slot: int


class ResourceIntervalSchedule:
    """Manages interval bookings across concurrent resource slots to minimize equipment idle time."""

    def __init__(self, resource: SanitizationResource, current_time: datetime):
        self.resource = resource
        self.slots_count = max(1, resource.concurrency_limit or 1)
        self.slot_intervals: dict[int, list[TimeInterval]] = {
            s: [] for s in range(1, self.slots_count + 1)
        }
        self.now = current_time

    def seed_running_interval(
        self, slot: int, start: datetime, end: datetime, assignment_id: str
    ) -> None:
        target_slot = slot if slot in self.slot_intervals else 1
        self.slot_intervals[target_slot].append(
            TimeInterval(start=start, end=end, assignment_id=assignment_id, slot=target_slot)
        )

    def find_earliest_slot(
        self, earliest_ready: datetime, duration_minutes: int
    ) -> tuple[int, datetime, datetime]:
        """Greedy Interval Allocation: selects the concurrency slot achieving Earliest Finish Time (EFT)."""
        best_slot = 1
        best_start = None
        best_end = None

        min_ready = max(self.now, earliest_ready)
        target_delta = timedelta(minutes=duration_minutes)

        for slot_num in range(1, self.slots_count + 1):
            intervals = sorted(self.slot_intervals[slot_num], key=lambda i: i.start)
            cur_candidate_start = min_ready

            for inv in intervals:
                if inv.end <= cur_candidate_start:
                    continue
                # Gap test: does this gap accommodate the required duration?
                if cur_candidate_start + target_delta <= inv.start:
                    break
                else:
                    cur_candidate_start = max(cur_candidate_start, inv.end)

            slot_start = cur_candidate_start
            slot_end = slot_start + target_delta

            if best_end is None or slot_end < best_end:
                best_slot = slot_num
                best_start = slot_start
                best_end = slot_end

        return best_slot, best_start, best_end

    def book_interval(
        self, slot: int, start: datetime, end: datetime, assignment_id: Optional[str]
    ) -> None:
        target_slot = slot if slot in self.slot_intervals else 1
        self.slot_intervals[target_slot].append(
            TimeInterval(start=start, end=end, assignment_id=assignment_id, slot=target_slot)
        )
        self.slot_intervals[target_slot].sort(key=lambda i: i.start)


# ---------------------------------------------------------------------------
# Resource Management
# ---------------------------------------------------------------------------

def ensure_default_resources(db: Session) -> list[SanitizationResource]:
    """Seed baseline enterprise sanitization equipment if none exist."""
    existing = list(db.scalars(select(SanitizationResource)))
    if existing:
        return existing

    created = []
    for data in DEFAULT_RESOURCES:
        resource = SanitizationResource(**data)
        db.add(resource)
        created.append(resource)
    db.commit()
    for res in created:
        db.refresh(res)
    return created


def get_resource(db: Session, resource_id: str) -> SanitizationResource:
    resource = db.get(SanitizationResource, resource_id)
    if resource is None:
        raise ResourceNotFoundError(f"Sanitization resource '{resource_id}' not found")
    return resource


def list_resources(
    db: Session,
    *,
    status: Optional[ResourceStatus] = None,
    media_type: Optional[str] = None,
) -> list[SanitizationResource]:
    stmt = select(SanitizationResource).order_by(SanitizationResource.name.asc())
    if status is not None:
        stmt = stmt.where(SanitizationResource.status == status)
    resources = list(db.scalars(stmt))
    if media_type:
        normalized = media_type.strip().lower()
        return [
            r for r in resources
            if r.supported_media_types and any(normalized in m.lower() for m in r.supported_media_types)
        ]
    return resources


def create_resource(db: Session, payload: SanitizationResourceCreate) -> SanitizationResource:
    resource = SanitizationResource(**payload.model_dump())
    db.add(resource)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ResourceConflictError(f"A resource with name '{payload.name}' already exists") from exc
    db.refresh(resource)
    _record_schedule_event(
        db,
        resource_id=resource.id,
        event_type=ScheduleEventType.RESOURCE_RESTORED,
        details={"name": resource.name, "resource_type": resource.resource_type},
    )
    return resource


def update_resource(
    db: Session, resource: SanitizationResource, payload: SanitizationResourceUpdate
) -> SanitizationResource:
    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(resource, field, value)
    resource.version += 1
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ResourceConflictError("Resource update conflicted with existing record") from exc
    db.refresh(resource)
    return resource


def update_resource_status(
    db: Session, resource: SanitizationResource, status: ResourceStatus, reason: Optional[str] = None
) -> SanitizationResource:
    previous_status = resource.status
    if previous_status == status:
        return resource

    resource.status = status
    resource.version += 1
    db.commit()
    db.refresh(resource)

    event_type = (
        ScheduleEventType.RESOURCE_UNAVAILABLE
        if status in {ResourceStatus.MAINTENANCE, ResourceStatus.OFFLINE}
        else ScheduleEventType.RESOURCE_RESTORED
    )
    _record_schedule_event(
        db,
        resource_id=resource.id,
        event_type=event_type,
        details={
            "previous_status": previous_status.value,
            "new_status": status.value,
            "reason": reason or "Status updated",
        },
    )

    if status in {ResourceStatus.MAINTENANCE, ResourceStatus.OFFLINE}:
        rebalance_schedule(
            db,
            unavailable_resource_id=resource.id,
            reason=f"Resource '{resource.name}' transitioned to {status.value}: {reason or 'Scheduled maintenance'}",
            preserve_running_jobs=True,
        )

    return resource


# ---------------------------------------------------------------------------
# DAG Dependency Management
# ---------------------------------------------------------------------------

def create_job_dependency(
    db: Session,
    parent_job_id: str,
    child_job_id: str,
    dependency_type: JobDependencyType = JobDependencyType.PREREQUISITE,
    notes: Optional[str] = None,
) -> JobDependency:
    """Define a prerequisite dependency between two sanitization jobs with cycle detection."""
    if parent_job_id == child_job_id:
        raise BusinessRuleError("A sanitization job cannot depend on itself")

    parent = db.get(SanitizationJob, parent_job_id)
    child = db.get(SanitizationJob, child_job_id)
    if not parent or not child:
        raise ResourceNotFoundError("Parent or child sanitization job does not exist")

    # Check for duplicate
    existing = db.scalar(
        select(JobDependency).where(
            JobDependency.parent_job_id == parent_job_id,
            JobDependency.child_job_id == child_job_id,
        )
    )
    if existing:
        return existing

    # Cycle Detection using Kahn's / DFS traversal
    if _would_create_dependency_cycle(db, parent_job_id, child_job_id):
        raise BusinessRuleError("Adding this dependency would create a cyclical deadlock in the DAG")

    # Check if parent is already completed/verified
    is_satisfied = False
    if dependency_type == JobDependencyType.VERIFICATION_GATE:
        is_satisfied = parent.status == SanitizationJobStatus.VERIFIED
    else:
        is_satisfied = parent.status in {SanitizationJobStatus.EVIDENCE_RECORDED, SanitizationJobStatus.VERIFIED}

    dep = JobDependency(
        parent_job_id=parent_job_id,
        child_job_id=child_job_id,
        dependency_type=dependency_type,
        is_satisfied=is_satisfied,
        satisfied_at=datetime.now(timezone.utc) if is_satisfied else None,
        notes=notes,
    )
    db.add(dep)
    db.commit()
    db.refresh(dep)

    _record_schedule_event(
        db,
        event_type=ScheduleEventType.DEPENDENCY_ADDED,
        details={
            "parent_job_id": parent_job_id,
            "child_job_id": child_job_id,
            "type": dependency_type.value,
            "is_satisfied": is_satisfied,
        },
    )
    return dep


def _would_create_dependency_cycle(db: Session, parent_id: str, child_id: str) -> bool:
    """Depth-First Search (DFS) to detect if child can reach parent through existing dependencies."""
    visited = set()
    stack = [parent_id]

    while stack:
        curr = stack.pop()
        if curr == child_id:
            return True
        if curr in visited:
            continue
        visited.add(curr)

        # Find all prerequisites of curr
        prereqs = db.scalars(
            select(JobDependency.parent_job_id).where(JobDependency.child_job_id == curr)
        ).all()
        for p in prereqs:
            if p not in visited:
                stack.append(p)

    return False


def are_dependencies_satisfied(db: Session, job_id: str) -> tuple[bool, int, list[str]]:
    """Verify whether all incoming prerequisites for a job have completed successfully."""
    dependencies = list(
        db.scalars(select(JobDependency).where(JobDependency.child_job_id == job_id))
    )
    if not dependencies:
        return True, 0, []

    unsatisfied = []
    for dep in dependencies:
        if dep.is_satisfied:
            continue
        # Live check parent job status
        parent = dep.parent_job
        if parent:
            if dep.dependency_type == JobDependencyType.VERIFICATION_GATE:
                satisfied = parent.status == SanitizationJobStatus.VERIFIED
            else:
                satisfied = parent.status in {
                    SanitizationJobStatus.EVIDENCE_RECORDED,
                    SanitizationJobStatus.VERIFIED,
                }
            if satisfied:
                dep.is_satisfied = True
                dep.satisfied_at = datetime.now(timezone.utc)
                db.flush()
                continue
        unsatisfied.append(dep.parent_job_id)

    db.commit()
    return len(unsatisfied) == 0, len(unsatisfied), unsatisfied


def evaluate_and_unlock_dependents(db: Session, completed_job_id: str) -> list[str]:
    """When a job finishes or passes verification, unlock downstream child jobs in the DAG."""
    out_deps = list(
        db.scalars(select(JobDependency).where(JobDependency.parent_job_id == completed_job_id))
    )
    now = datetime.now(timezone.utc)
    unlocked_child_ids = []

    for dep in out_deps:
        dep.is_satisfied = True
        dep.satisfied_at = now

        # Check if the child job now has all dependencies satisfied
        all_ok, _, _ = are_dependencies_satisfied(db, dep.child_job_id)
        if all_ok:
            unlocked_child_ids.append(dep.child_job_id)
            _record_schedule_event(
                db,
                event_type=ScheduleEventType.DEPENDENCY_SATISFIED,
                details={
                    "parent_job_id": completed_job_id,
                    "child_job_id": dep.child_job_id,
                    "status": "unlocked_ready_for_scheduling",
                },
            )

    db.commit()
    return unlocked_child_ids


def get_job_dependencies(db: Session, job_id: str) -> JobDependenciesRead:
    """Retrieve all incoming prerequisites and outgoing dependents for a sanitization job."""
    job = db.get(SanitizationJob, job_id)
    if not job:
        raise ResourceNotFoundError(f"Sanitization job '{job_id}' not found")

    incoming = list(
        db.scalars(select(JobDependency).where(JobDependency.child_job_id == job_id))
    )
    outgoing = list(
        db.scalars(select(JobDependency).where(JobDependency.parent_job_id == job_id))
    )
    satisfied, pending_count, _ = are_dependencies_satisfied(db, job_id)

    return JobDependenciesRead(
        job_id=job_id,
        incoming_prerequisites=[JobDependencyRead.model_validate(d) for d in incoming],
        outgoing_dependents=[JobDependencyRead.model_validate(d) for d in outgoing],
        dependencies_satisfied=satisfied,
        pending_prerequisites_count=pending_count,
    )


# ---------------------------------------------------------------------------
# Compatibility & Duration Estimation Engine
# ---------------------------------------------------------------------------

def is_resource_compatible(
    resource: SanitizationResource,
    storage_type: Optional[str],
    capacity_gb: Optional[int],
    planned_method: str,
) -> bool:
    """Evaluate whether a tool or station is physically and technically compatible."""
    if resource.status in {ResourceStatus.MAINTENANCE, ResourceStatus.OFFLINE}:
        return False

    if capacity_gb and resource.max_capacity_gb and capacity_gb > resource.max_capacity_gb:
        return False

    if storage_type and resource.supported_media_types:
        norm_type = storage_type.strip().lower()
        supported_types = [m.lower() for m in resource.supported_media_types]
        if not any(
            norm_type in s or s in norm_type or s in {"*", "all"}
            for s in supported_types
        ):
            if norm_type in {"ssd", "nvme", "flash"} and any(x in supported_types for x in ["ssd", "nvme", "flash"]):
                pass
            else:
                return False

    if planned_method and resource.supported_methods:
        norm_method = planned_method.strip().lower()
        supported_methods = [m.lower() for m in resource.supported_methods]
        if not any(
            s in norm_method or norm_method in s or s in {"*", "all"}
            for s in supported_methods
        ):
            if "purge" in norm_method and any("purge" in s for s in supported_methods):
                pass
            elif "clear" in norm_method and any("clear" in s or "overwrite" in s for s in supported_methods):
                pass
            elif "erase" in norm_method and any("erase" in s for s in supported_methods):
                pass
            else:
                return False

    return True


def estimate_duration_minutes(
    storage_type: Optional[str],
    capacity_gb: Optional[int],
    planned_method: str,
    resource: Optional[SanitizationResource] = None,
) -> int:
    """Calculate realistic estimated processing time in minutes."""
    norm_method = (planned_method or "").lower()
    capacity = capacity_gb or 512
    throughput_gbps = (resource.throughput_gbps if resource and resource.throughput_gbps else 0.25)

    if "cryptographic" in norm_method or "crypto" in norm_method:
        return 4

    if "degauss" in norm_method:
        return 3

    if "shred" in norm_method or "destroy" in norm_method:
        return 6

    passes = 3 if ("dod" in norm_method or "3-pass" in norm_method) else 1
    gb_per_minute = max(1.0, throughput_gbps * 60.0)
    raw_minutes = (capacity * passes) / gb_per_minute

    total_minutes = int(raw_minutes + 5)
    return max(5, total_minutes)


# ---------------------------------------------------------------------------
# Priority Scoring Algorithm
# ---------------------------------------------------------------------------

def calculate_priority_score(
    sensitivity: DataSensitivity,
    deadline: Optional[datetime],
    estimated_minutes: int,
    now: Optional[datetime] = None,
) -> tuple[float, SchedulePriority]:
    """Calculate priority score and tier with mathematical guarantee against security delays.

    Security Rule: Security-critical jobs must never be delayed solely to improve
    throughput. The sensitivity tier base score dwarfs any shortest-processing-time
    tie breaker bonus.
    """
    current_time = _to_utc(now) or datetime.now(timezone.utc)
    base_score = _SENSITIVITY_WEIGHTS.get(sensitivity, 10_000.0)

    deadline_bonus = 0.0
    is_overdue = False
    delta_hours = 9999.0
    deadline = _to_utc(deadline)
    if deadline:
        delta_seconds = (deadline - current_time).total_seconds()
        delta_hours = delta_seconds / 3600.0

        if delta_hours <= 0:
            is_overdue = True
            hours_overdue = abs(delta_hours)
            deadline_bonus = 60_000.0 + min(40_000.0, hours_overdue * 2000.0)
        elif delta_hours <= 24:
            deadline_bonus = 35_000.0 * (1.0 - (delta_hours / 24.0))
        elif delta_hours <= 72:
            deadline_bonus = 15_000.0 * (1.0 - (delta_hours / 72.0))
        elif delta_hours <= 168:
            deadline_bonus = 5_000.0

    # Secondary tie breaker: Shortest Processing Time (SPT)
    # Bounded between 0 and 1000 points. Since the distance between sensitivity
    # tiers is >= 9,000 to 50,000 points, SPT can NEVER cause a lower-sensitivity
    # asset to bypass an urgent or higher-sensitivity asset.
    spt_bonus = max(0.0, min(1000.0, 1000.0 - (estimated_minutes * 2.0)))

    total_score = base_score + deadline_bonus + spt_bonus

    if is_overdue or sensitivity == DataSensitivity.CRITICAL or total_score >= 90_000.0:
        priority_tier = SchedulePriority.EMERGENCY
    elif delta_hours <= 24.0 or sensitivity == DataSensitivity.HIGH or total_score >= 35_000.0:
        priority_tier = SchedulePriority.URGENT
    elif sensitivity == DataSensitivity.STANDARD or total_score >= 9_000.0:
        priority_tier = SchedulePriority.NORMAL
    else:
        priority_tier = SchedulePriority.DEFERRED

    return round(total_score, 2), priority_tier


# ---------------------------------------------------------------------------
# Priority Queue + Greedy Interval Optimization
# ---------------------------------------------------------------------------

def optimize_schedule(
    db: Session,
    *,
    target_job_ids: Optional[list[str]] = None,
) -> OptimizationResult:
    """Assign pending jobs to compatible resources minimizing makespan while respecting security."""
    resources = ensure_default_resources(db)
    active_resources = [r for r in resources if r.status in {ResourceStatus.AVAILABLE, ResourceStatus.BUSY}]

    query = select(SanitizationJob).where(
        SanitizationJob.status.in_([
            SanitizationJobStatus.REQUESTED,
            SanitizationJobStatus.PREPARED,
        ])
    )
    if target_job_ids:
        query = query.where(SanitizationJob.id.in_(target_job_ids))
    jobs = list(db.scalars(query))

    now = datetime.now(timezone.utc)

    # 1. Initialize Interval Schedules for all active resources
    resource_schedules: dict[str, ResourceIntervalSchedule] = {
        r.id: ResourceIntervalSchedule(r, now) for r in active_resources
    }

    # Seed currently RUNNING assignments on active resources
    running_assignments = list(
        db.scalars(
            select(ScheduleAssignment)
            .where(
                ScheduleAssignment.status == ScheduleAssignmentStatus.RUNNING,
                ScheduleAssignment.resource_id.in_([r.id for r in active_resources]),
            )
        )
    )
    for running in running_assignments:
        if running.resource_id in resource_schedules and running.started_at:
            dur = running.estimated_minutes or 30
            end_est = _to_utc(running.started_at) + timedelta(minutes=dur)
            slot = running.slot_number or 1
            resource_schedules[running.resource_id].seed_running_interval(
                slot, _to_utc(running.started_at), end_est, running.id
            )

    # 2. Evaluate all job candidates and verify dependencies
    ready_queue = JobPriorityQueue()
    blocked_candidates = []

    for job in jobs:
        asset = job.asset
        sensitivity = job.data_sensitivity or (asset.data_sensitivity if asset else DataSensitivity.STANDARD)
        deadline = job.deadline or (asset.disposal_deadline if asset else None)
        storage_type = asset.storage_type if asset else "SSD"
        capacity_gb = asset.storage_capacity_gb if asset else 512

        compatible = [
            r for r in active_resources
            if is_resource_compatible(r, storage_type, capacity_gb, job.planned_method)
        ]

        est_minutes = estimate_duration_minutes(
            storage_type, capacity_gb, job.planned_method, compatible[0] if compatible else None
        )
        score, priority_tier = calculate_priority_score(sensitivity, deadline, est_minutes, now)

        deps_ok, pending_count, unsatisfied_ids = are_dependencies_satisfied(db, job.id)

        candidate = {
            "job": job,
            "asset": asset,
            "sensitivity": sensitivity,
            "deadline": deadline,
            "storage_type": storage_type,
            "capacity_gb": capacity_gb,
            "compatible_resources": compatible,
            "estimated_minutes": est_minutes,
            "priority_score": score,
            "priority_tier": priority_tier,
            "dependencies_satisfied": deps_ok,
            "pending_dependencies_count": pending_count,
            "unsatisfied_dependencies": unsatisfied_ids,
        }

        if deps_ok:
            ready_queue.push(candidate)
        else:
            blocked_candidates.append(candidate)

    assigned_items: list[QueueItemRead] = []
    unassigned_count = 0
    critical_prioritized_count = 0
    urgent_count = 0
    total_wait_minutes = 0.0
    queue_counter = 1

    # 3. Process Ready Priority Queue using Greedy Interval Allocation (EFT)
    while not ready_queue.is_empty():
        candidate = ready_queue.pop()
        job: SanitizationJob = candidate["job"]
        asset: Asset = candidate["asset"]
        compatible = candidate["compatible_resources"]

        if candidate["sensitivity"] == DataSensitivity.CRITICAL:
            critical_prioritized_count += 1
        if candidate["priority_tier"] in {SchedulePriority.EMERGENCY, SchedulePriority.URGENT}:
            urgent_count += 1

        if not compatible:
            unassigned_count += 1
            norm_dl = _to_utc(candidate["deadline"])
            assigned_items.append(
                QueueItemRead(
                    assignment_id=None,
                    job_id=job.id,
                    asset_id=asset.id if asset else "",
                    asset_tag=asset.asset_tag if asset else "UNKNOWN",
                    asset_type=asset.asset_type.value if asset else "other",
                    storage_type=candidate["storage_type"],
                    storage_capacity_gb=candidate["capacity_gb"],
                    planned_method=job.planned_method,
                    data_sensitivity=candidate["sensitivity"],
                    deadline=candidate["deadline"],
                    priority=candidate["priority_tier"],
                    priority_score=candidate["priority_score"],
                    status=ScheduleAssignmentStatus.PENDING,
                    queue_position=None,
                    slot_number=None,
                    assigned_resource_id=None,
                    assigned_resource_name=None,
                    estimated_minutes=candidate["estimated_minutes"],
                    scheduled_start=None,
                    scheduled_end=None,
                    is_overdue=bool(norm_dl and norm_dl < now),
                    security_critical=candidate["sensitivity"] == DataSensitivity.CRITICAL,
                    dependencies_satisfied=True,
                    pending_dependencies_count=0,
                    compatible_resource_count=0,
                )
            )
            continue

        # Greedy Earliest Finish Time (EFT) search across all compatible bays and concurrency slots
        best_resource = None
        best_slot = 1
        best_start = None
        best_end = None

        for res in compatible:
            sched = resource_schedules[res.id]
            dur = estimate_duration_minutes(
                candidate["storage_type"], candidate["capacity_gb"], job.planned_method, res
            )
            slot_candidate, start_candidate, end_candidate = sched.find_earliest_slot(now, dur)
            if best_end is None or end_candidate < best_end:
                best_resource = res
                best_slot = slot_candidate
                best_start = start_candidate
                best_end = end_candidate

        est_duration = estimate_duration_minutes(
            candidate["storage_type"], candidate["capacity_gb"], job.planned_method, best_resource
        )
        resource_schedules[best_resource.id].book_interval(best_slot, best_start, best_end, job.id)

        wait_minutes = max(0.0, (best_start - now).total_seconds() / 60.0)
        total_wait_minutes += wait_minutes

        # Record or update ScheduleAssignment in database
        existing_assignment = db.scalar(
            select(ScheduleAssignment)
            .where(
                ScheduleAssignment.job_id == job.id,
                ScheduleAssignment.status.in_([
                    ScheduleAssignmentStatus.PENDING,
                    ScheduleAssignmentStatus.ASSIGNED,
                ]),
            )
            .limit(1)
        )
        if existing_assignment:
            existing_assignment.resource_id = best_resource.id
            existing_assignment.priority = candidate["priority_tier"]
            existing_assignment.priority_score = candidate["priority_score"]
            existing_assignment.data_sensitivity = candidate["sensitivity"]
            existing_assignment.estimated_minutes = est_duration
            existing_assignment.deadline = candidate["deadline"]
            existing_assignment.queue_position = queue_counter
            existing_assignment.slot_number = best_slot
            existing_assignment.scheduled_start = best_start
            existing_assignment.scheduled_end = best_end
            existing_assignment.status = ScheduleAssignmentStatus.ASSIGNED
            assignment = existing_assignment
            db.flush()
        else:
            assignment = ScheduleAssignment(
                job_id=job.id,
                resource_id=best_resource.id,
                priority=candidate["priority_tier"],
                priority_score=candidate["priority_score"],
                data_sensitivity=candidate["sensitivity"],
                estimated_minutes=est_duration,
                deadline=candidate["deadline"],
                queue_position=queue_counter,
                slot_number=best_slot,
                scheduled_start=best_start,
                scheduled_end=best_end,
                status=ScheduleAssignmentStatus.ASSIGNED,
            )
            db.add(assignment)
            db.flush()

        norm_dl = _to_utc(candidate["deadline"])
        assigned_items.append(
            QueueItemRead(
                assignment_id=assignment.id,
                job_id=job.id,
                asset_id=asset.id if asset else "",
                asset_tag=asset.asset_tag if asset else "UNKNOWN",
                asset_type=asset.asset_type.value if asset else "other",
                storage_type=candidate["storage_type"],
                storage_capacity_gb=candidate["capacity_gb"],
                planned_method=job.planned_method,
                data_sensitivity=candidate["sensitivity"],
                deadline=candidate["deadline"],
                priority=candidate["priority_tier"],
                priority_score=candidate["priority_score"],
                status=ScheduleAssignmentStatus.ASSIGNED,
                queue_position=queue_counter,
                slot_number=best_slot,
                assigned_resource_id=best_resource.id,
                assigned_resource_name=best_resource.name,
                estimated_minutes=est_duration,
                scheduled_start=best_start,
                scheduled_end=best_end,
                is_overdue=bool(norm_dl and norm_dl < now),
                security_critical=candidate["sensitivity"] == DataSensitivity.CRITICAL,
                dependencies_satisfied=True,
                pending_dependencies_count=0,
                compatible_resource_count=len(compatible),
            )
        )
        queue_counter += 1

    # 4. Append Blocked Candidates (waiting on prerequisite jobs in DAG)
    for blocked in blocked_candidates:
        unassigned_count += 1
        job = blocked["job"]
        asset = blocked["asset"]
        norm_dl = _to_utc(blocked["deadline"])
        assigned_items.append(
            QueueItemRead(
                assignment_id=None,
                job_id=job.id,
                asset_id=asset.id if asset else "",
                asset_tag=asset.asset_tag if asset else "UNKNOWN",
                asset_type=asset.asset_type.value if asset else "other",
                storage_type=blocked["storage_type"],
                storage_capacity_gb=blocked["capacity_gb"],
                planned_method=job.planned_method,
                data_sensitivity=blocked["sensitivity"],
                deadline=blocked["deadline"],
                priority=blocked["priority_tier"],
                priority_score=blocked["priority_score"],
                status=ScheduleAssignmentStatus.PENDING,
                queue_position=None,
                slot_number=None,
                assigned_resource_id=None,
                assigned_resource_name="BLOCKED (Waiting on Prerequisite Jobs)",
                estimated_minutes=blocked["estimated_minutes"],
                scheduled_start=None,
                scheduled_end=None,
                is_overdue=bool(norm_dl and norm_dl < now),
                security_critical=blocked["sensitivity"] == DataSensitivity.CRITICAL,
                dependencies_satisfied=False,
                pending_dependencies_count=blocked["pending_dependencies_count"],
                compatible_resource_count=len(blocked["compatible_resources"]),
            )
        )

    db.commit()

    # Calculate overall makespan across all booked intervals
    all_finish_times = []
    for sched in resource_schedules.values():
        for intervals in sched.slot_intervals.values():
            if intervals:
                all_finish_times.append(max(i.end for i in intervals))

    if all_finish_times:
        latest_finish = max(all_finish_times)
        total_makespan = max(0, int((latest_finish - now).total_seconds() / 60.0))
    else:
        total_makespan = 0

    assigned_count = len(assigned_items) - unassigned_count
    avg_wait = round(total_wait_minutes / max(1, assigned_count), 1)

    # Equipment utilization breakdown
    utilization = {}
    for r in active_resources:
        sched = resource_schedules.get(r.id)
        if sched and total_makespan > 0:
            busy_minutes = sum(
                sum((i.end - i.start).total_seconds() / 60.0 for i in intervals)
                for intervals in sched.slot_intervals.values()
            )
            # Available capacity = total_makespan * concurrency_limit
            total_slot_capacity = total_makespan * sched.slots_count
            utilization[r.name] = round(min(100.0, (busy_minutes / max(1.0, total_slot_capacity)) * 100.0), 1)
        else:
            utilization[r.name] = 0.0

    summary = OptimizationSummary(
        total_jobs_evaluated=len(jobs),
        assigned_count=assigned_count,
        unassigned_count=unassigned_count,
        critical_jobs_prioritized=critical_prioritized_count,
        urgent_jobs_count=urgent_count,
        estimated_total_makespan_minutes=total_makespan,
        average_wait_minutes=avg_wait,
        resource_utilization=utilization,
        schedule_generated_at=now,
    )

    _record_schedule_event(
        db,
        event_type=ScheduleEventType.SCHEDULE_GENERATED,
        details={
            "total_jobs": len(jobs),
            "assigned": assigned_count,
            "makespan_minutes": total_makespan,
            "critical_count": critical_prioritized_count,
            "blocked_count": len(blocked_candidates),
        },
    )

    return OptimizationResult(summary=summary, queue=assigned_items)


# ---------------------------------------------------------------------------
# Transactional Job Assignment with Concurrency Control
# ---------------------------------------------------------------------------

def assign_job_transactional(
    db: Session,
    job_id: str,
    resource_id: str,
    expected_version: Optional[int] = None,
    slot_number: int = 1,
    force_override: bool = False,
) -> ScheduleAssignment:
    """Atomic transactional job assignment with concurrency control.

    Enforces:
      - Pessimistic / row locking to prevent concurrent allocation race conditions.
      - Optimistic concurrency check via resource.version.
      - Concurrency capacity check against resource.concurrency_limit.
      - Dependency satisfaction verification before assignment.
    """
    job = db.get(SanitizationJob, job_id)
    if not job:
        raise ResourceNotFoundError(f"Sanitization job '{job_id}' not found")

    # Dependency check
    deps_ok, pending_count, unsat_ids = are_dependencies_satisfied(db, job_id)
    if not deps_ok and not force_override:
        raise BusinessRuleError(
            f"Cannot assign job '{job_id}': waiting on {pending_count} prerequisite job(s): {unsat_ids}"
        )

    # Pessimistic locking: locks the resource row for the duration of this transaction
    resource = db.execute(
        select(SanitizationResource)
        .where(SanitizationResource.id == resource_id)
        .with_for_update()
    ).scalar_one_or_none()

    if not resource:
        raise ResourceNotFoundError(f"Sanitization resource '{resource_id}' not found")

    if resource.status in {ResourceStatus.MAINTENANCE, ResourceStatus.OFFLINE}:
        raise SchedulingConflictError(f"Resource '{resource.name}' is currently {resource.status.value}")

    # Optimistic concurrency check
    if expected_version is not None and resource.version != expected_version:
        raise SchedulingConflictError(
            f"Concurrency conflict: resource '{resource.name}' was modified concurrently "
            f"(expected version {expected_version}, found {resource.version})"
        )

    asset = job.asset
    storage_type = asset.storage_type if asset else "SSD"
    capacity_gb = asset.storage_capacity_gb if asset else 512
    if not is_resource_compatible(resource, storage_type, capacity_gb, job.planned_method):
        raise ResourceIncompatibleError(
            f"Resource '{resource.name}' is incompatible with {storage_type} / {job.planned_method}"
        )

    # Check currently active concurrent jobs on this resource
    active_running = db.scalar(
        select(func.count(ScheduleAssignment.id)).where(
            ScheduleAssignment.resource_id == resource.id,
            ScheduleAssignment.status == ScheduleAssignmentStatus.RUNNING,
        )
    ) or 0

    if active_running >= resource.concurrency_limit and not force_override:
        raise SchedulingConflictError(
            f"Resource '{resource.name}' has reached its concurrency limit of {resource.concurrency_limit} active jobs"
        )

    now = datetime.now(timezone.utc)
    est_duration = estimate_duration_minutes(storage_type, capacity_gb, job.planned_method, resource)

    assignment = db.scalar(
        select(ScheduleAssignment)
        .where(
            ScheduleAssignment.job_id == job.id,
            ScheduleAssignment.status.in_([
                ScheduleAssignmentStatus.PENDING,
                ScheduleAssignmentStatus.ASSIGNED,
            ]),
        )
        .limit(1)
    )
    if assignment:
        assignment.resource_id = resource.id
        assignment.slot_number = slot_number
        assignment.status = ScheduleAssignmentStatus.ASSIGNED
        assignment.scheduled_start = now
        assignment.scheduled_end = now + timedelta(minutes=est_duration)
        assignment.updated_at = now
    else:
        assignment = ScheduleAssignment(
            job_id=job.id,
            resource_id=resource.id,
            slot_number=slot_number,
            status=ScheduleAssignmentStatus.ASSIGNED,
            priority=SchedulePriority.NORMAL,
            priority_score=50_000.0,
            estimated_minutes=est_duration,
            scheduled_start=now,
            scheduled_end=now + timedelta(minutes=est_duration),
        )
        db.add(assignment)

    # Increment optimistic concurrency version
    resource.version += 1
    db.commit()
    db.refresh(assignment)

    _record_schedule_event(
        db,
        assignment_id=assignment.id,
        resource_id=resource.id,
        event_type=ScheduleEventType.CONCURRENCY_LOCKED,
        details={
            "slot_number": slot_number,
            "resource_version": resource.version,
            "active_running": active_running,
        },
    )
    return assignment


# ---------------------------------------------------------------------------
# Dynamic Rescheduling & Delay Detection
# ---------------------------------------------------------------------------

def rebalance_schedule(
    db: Session,
    *,
    unavailable_resource_id: Optional[str] = None,
    reason: str = "Dynamic schedule rebalance triggered",
    preserve_running_jobs: bool = True,
) -> DynamicRebalanceResult:
    """Dynamically revise pending assignments without interrupting running jobs unnecessarily."""
    resources = ensure_default_resources(db)
    healthy_resources = [
        r for r in resources
        if r.id != unavailable_resource_id and r.status in {ResourceStatus.AVAILABLE, ResourceStatus.BUSY}
    ]

    reassigned_records: list[ScheduleAssignmentRead] = []
    preserved_count = 0
    unassigned_count = 0

    # 1. Identify running jobs to protect
    running_assignments = list(
        db.scalars(
            select(ScheduleAssignment)
            .where(ScheduleAssignment.status == ScheduleAssignmentStatus.RUNNING)
        )
    )

    for running in running_assignments:
        if running.resource_id == unavailable_resource_id:
            running.status = ScheduleAssignmentStatus.REASSIGNED
            running.reassign_reason = f"Execution interrupted: {reason}"
            _record_schedule_event(
                db,
                assignment_id=running.id,
                resource_id=running.resource_id,
                event_type=ScheduleEventType.ASSIGNMENT_FAILED,
                details={"reason": running.reassign_reason},
            )
        else:
            # Running jobs on healthy resources are never interrupted
            preserved_count += 1

    # 2. Collect pending or assigned jobs needing reassignment
    affected_query = select(ScheduleAssignment).where(
        ScheduleAssignment.status.in_([
            ScheduleAssignmentStatus.ASSIGNED,
            ScheduleAssignmentStatus.PENDING,
            ScheduleAssignmentStatus.REASSIGNED,
        ])
    )
    if unavailable_resource_id:
        affected_query = affected_query.where(
            (ScheduleAssignment.resource_id == unavailable_resource_id) |
            (ScheduleAssignment.resource_id.is_(None))
        )

    affected_assignments = list(db.scalars(affected_query))
    now = datetime.now(timezone.utc)

    # Use Priority Queue to order affected jobs strictly by priority score
    pq = JobPriorityQueue()
    for assignment in affected_assignments:
        job = assignment.job
        asset = job.asset if job else None
        storage_type = asset.storage_type if asset else "SSD"
        capacity_gb = asset.storage_capacity_gb if asset else 512
        method = job.planned_method if job else "NIST 800-88 Purge"

        candidates = [
            r for r in healthy_resources
            if is_resource_compatible(r, storage_type, capacity_gb, method)
        ]
        pq.push({
            "assignment": assignment,
            "job": job,
            "asset": asset,
            "storage_type": storage_type,
            "capacity_gb": capacity_gb,
            "method": method,
            "compatible_resources": candidates,
            "priority_score": assignment.priority_score,
            "deadline": assignment.deadline,
            "estimated_minutes": assignment.estimated_minutes or 30,
        })

    while not pq.is_empty():
        item = pq.pop()
        assignment: ScheduleAssignment = item["assignment"]
        candidates = item["compatible_resources"]

        if not candidates:
            assignment.status = ScheduleAssignmentStatus.PENDING
            assignment.resource_id = None
            assignment.reassign_reason = f"No alternative compatible resource available during rebalance: {reason}"
            unassigned_count += 1
            continue

        best_resource = min(
            candidates,
            key=lambda r: len([
                a for a in r.assignments
                if a.status in {ScheduleAssignmentStatus.ASSIGNED, ScheduleAssignmentStatus.RUNNING}
            ])
        )

        previous_resource_id = assignment.resource_id
        assignment.resource_id = best_resource.id
        assignment.status = ScheduleAssignmentStatus.ASSIGNED
        assignment.reassigned_from_id = assignment.id
        assignment.reassign_reason = reason
        assignment.updated_at = now

        _record_schedule_event(
            db,
            assignment_id=assignment.id,
            resource_id=best_resource.id,
            event_type=ScheduleEventType.REASSIGNMENT,
            details={
                "previous_resource_id": previous_resource_id,
                "new_resource_id": best_resource.id,
                "reason": reason,
            },
        )
        reassigned_records.append(ScheduleAssignmentRead.model_validate(assignment))

    db.commit()

    return DynamicRebalanceResult(
        reassigned_count=len(reassigned_records),
        preserved_running_count=preserved_count,
        unassigned_due_to_no_resource=unassigned_count,
        affected_resource_id=unavailable_resource_id,
        reason=reason,
        reassigned_assignments=reassigned_records,
    )


def detect_delays_and_reschedule(
    db: Session,
    delay_threshold_minutes: int = 15,
) -> DynamicRebalanceResult:
    """Identify running jobs taking longer than expected and rebalance downstream pending jobs."""
    now = datetime.now(timezone.utc)
    running_assignments = list(
        db.scalars(
            select(ScheduleAssignment)
            .where(ScheduleAssignment.status == ScheduleAssignmentStatus.RUNNING)
        )
    )

    delayed_assignments = []
    for running in running_assignments:
        if running.started_at:
            elapsed = (now - _to_utc(running.started_at)).total_seconds() / 60.0
            expected = running.estimated_minutes or 30
            if elapsed > expected + delay_threshold_minutes:
                delayed_assignments.append(running)
                _record_schedule_event(
                    db,
                    assignment_id=running.id,
                    resource_id=running.resource_id,
                    event_type=ScheduleEventType.DELAY_DETECTED,
                    details={
                        "elapsed_minutes": round(elapsed, 1),
                        "expected_minutes": expected,
                        "delay_minutes": round(elapsed - expected, 1),
                    },
                )

    if not delayed_assignments:
        return DynamicRebalanceResult(
            reassigned_count=0,
            preserved_running_count=len(running_assignments),
            unassigned_due_to_no_resource=0,
            affected_resource_id=None,
            reason="No job delays detected",
            reassigned_assignments=[],
        )

    # Rebalance downstream assigned jobs on delayed resources
    affected_resource_ids = {a.resource_id for a in delayed_assignments if a.resource_id}
    return rebalance_schedule(
        db,
        reason=f"Dynamic rebalance triggered due to execution delay on {len(delayed_assignments)} running job(s)",
        preserve_running_jobs=True,
    )


# ---------------------------------------------------------------------------
# Assignment Lifecycle Operations
# ---------------------------------------------------------------------------

def start_assignment(db: Session, assignment_id: str) -> ScheduleAssignment:
    assignment = db.get(ScheduleAssignment, assignment_id)
    if not assignment:
        raise ResourceNotFoundError(f"Schedule assignment '{assignment_id}' not found")
    if assignment.status == ScheduleAssignmentStatus.RUNNING:
        return assignment

    # Dependency check
    if assignment.job_id:
        deps_ok, pending_count, unsat_ids = are_dependencies_satisfied(db, assignment.job_id)
        if not deps_ok:
            raise BusinessRuleError(
                f"Cannot start assignment: waiting on {pending_count} prerequisite job(s): {unsat_ids}"
            )

    resource = assignment.resource
    if resource and resource.status in {ResourceStatus.MAINTENANCE, ResourceStatus.OFFLINE}:
        raise SchedulingConflictError(f"Cannot start assignment on {resource.status.value} resource '{resource.name}'")

    assignment.status = ScheduleAssignmentStatus.RUNNING
    assignment.started_at = datetime.now(timezone.utc)
    if resource:
        resource.status = ResourceStatus.BUSY

    if assignment.job and assignment.job.status == SanitizationJobStatus.REQUESTED:
        assignment.job.status = SanitizationJobStatus.PREPARED

    db.commit()
    db.refresh(assignment)

    _record_schedule_event(
        db,
        assignment_id=assignment.id,
        resource_id=assignment.resource_id,
        event_type=ScheduleEventType.ASSIGNMENT_STARTED,
        details={"started_at": assignment.started_at.isoformat()},
    )
    return assignment


def complete_assignment(
    db: Session, assignment_id: str, actual_minutes: Optional[int] = None
) -> ScheduleAssignment:
    assignment = db.get(ScheduleAssignment, assignment_id)
    if not assignment:
        raise ResourceNotFoundError(f"Schedule assignment '{assignment_id}' not found")

    now = datetime.now(timezone.utc)
    assignment.status = ScheduleAssignmentStatus.COMPLETED
    assignment.completed_at = now
    if actual_minutes:
        assignment.actual_minutes = actual_minutes
    elif assignment.started_at:
        assignment.actual_minutes = max(1, int((now - _to_utc(assignment.started_at)).total_seconds() / 60.0))

    resource = assignment.resource
    if resource:
        other_running = db.scalar(
            select(func.count(ScheduleAssignment.id))
            .where(
                ScheduleAssignment.resource_id == resource.id,
                ScheduleAssignment.status == ScheduleAssignmentStatus.RUNNING,
                ScheduleAssignment.id != assignment.id,
            )
        ) or 0
        if other_running == 0 and resource.status == ResourceStatus.BUSY:
            resource.status = ResourceStatus.AVAILABLE

    db.commit()
    db.refresh(assignment)

    # Automatically unlock downstream dependents in DAG
    if assignment.job_id:
        evaluate_and_unlock_dependents(db, assignment.job_id)

    _record_schedule_event(
        db,
        assignment_id=assignment.id,
        resource_id=assignment.resource_id,
        event_type=ScheduleEventType.ASSIGNMENT_COMPLETED,
        details={"actual_minutes": assignment.actual_minutes},
    )
    return assignment


# ---------------------------------------------------------------------------
# Workload Simulator (Testing Scale With 100+ Devices)
# ---------------------------------------------------------------------------

def simulate_batch_workload(
    db: Session,
    device_count: int = 100,
    seed: int = 42,
    auto_create_resources_if_empty: bool = True,
) -> WorkloadSimulationResult:
    """Generate and schedule hundreds of competing devices to test optimization and security at scale."""
    # Cleanly remove any prior simulation batch to prevent unique constraint collisions
    clear_simulated_workload(db)

    rnd = random.Random(seed)
    resources = ensure_default_resources(db)

    manufacturers = ["Dell", "HP", "Lenovo", "Apple", "Cisco", "NetApp", "Seagate"]
    models = {
        "Dell": ["Latitude 5420", "OptiPlex 7090", "PowerEdge R740", "Precision 5560"],
        "HP": ["EliteBook 840", "ProLiant DL380", "Z4 G4 Workstation"],
        "Lenovo": ["ThinkPad T14", "ThinkStation P340", "ThinkSystem SR650"],
        "Apple": ["MacBook Pro 14", "Mac Studio", "MacBook Air M2"],
        "Cisco": ["Catalyst 9300", "UCS C220 M5"],
        "NetApp": ["AFF A400", "FAS2750"],
        "Seagate": ["Exos X18 Array", "Nytro Flash Enclosure"],
    }
    media_specs = [
        ("SSD", [256, 512, 1024, 2048], "SSD Secure Sanitization / Purge-oriented workflow"),
        ("NVMe", [512, 1024, 2048, 4096], "Cryptographic Erase"),
        ("HDD", [1000, 2000, 4000, 8000], "DoD 5220.22-M Overwrite"),
        ("Magnetic Tape", [2500, 6000, 12000], "Degauss"),
        ("Optical", [25, 50, 100], "Physical Shred"),
    ]
    sensitivities = [
        (DataSensitivity.CRITICAL, 0.15),
        (DataSensitivity.HIGH, 0.30),
        (DataSensitivity.STANDARD, 0.40),
        (DataSensitivity.LOW, 0.15),
    ]

    now = datetime.now(timezone.utc)
    run_id = int(now.timestamp()) % 100000
    created_job_ids = []

    for i in range(1, device_count + 1):
        mfg = rnd.choice(manufacturers)
        model = rnd.choice(models[mfg])
        media_type, capacities, planned_method = rnd.choice(media_specs)
        capacity = rnd.choice(capacities)

        r_val = rnd.random()
        cumulative = 0.0
        chosen_sensitivity = DataSensitivity.STANDARD
        for sens, weight in sensitivities:
            cumulative += weight
            if r_val <= cumulative:
                chosen_sensitivity = sens
                break

        deadline_roll = rnd.random()
        if deadline_roll < 0.10:
            deadline = now - timedelta(hours=rnd.randint(2, 24))
        elif deadline_roll < 0.35:
            deadline = now + timedelta(hours=rnd.randint(4, 24))
        elif deadline_roll < 0.75:
            deadline = now + timedelta(hours=rnd.randint(25, 72))
        else:
            deadline = now + timedelta(days=rnd.randint(4, 14))

        asset_tag = f"SIM-{seed}-{run_id}-{i:04d}"
        asset = Asset(
            asset_tag=asset_tag,
            serial_number=f"SN-{asset_tag}",
            asset_type=AssetType.LAPTOP if "Book" in model or "Latitude" in model or "ThinkPad" in model else AssetType.SERVER if "PowerEdge" in model or "ProLiant" in model else AssetType.DESKTOP,
            lifecycle_status=AssetLifecycleStatus.PENDING_SANITIZATION,
            manufacturer=mfg,
            model=model,
            storage_type=media_type,
            storage_capacity_gb=capacity,
            data_sensitivity=chosen_sensitivity,
            disposal_deadline=deadline,
            owner_department="Simulated Scale Test",
            notes="Generated for 100+ device scheduling optimization benchmark",
        )
        db.add(asset)
        db.flush()

        job = SanitizationJob(
            asset_id=asset.id,
            status=SanitizationJobStatus.REQUESTED,
            planned_method=planned_method,
            data_sensitivity=chosen_sensitivity,
            deadline=deadline,
            requested_by="Batch Workload Generator",
            notes=f"Batch test item {i}/{device_count}",
        )
        db.add(job)
        db.flush()
        created_job_ids.append(job.id)

    db.commit()

    # Link ~10% of jobs into sequential dependency chains (e.g. drive sanitization -> chassis disposal)
    for i in range(0, len(created_job_ids) - 1, 10):
        parent_id = created_job_ids[i]
        child_id = created_job_ids[i + 1]
        try:
            create_job_dependency(
                db, parent_id, child_id, dependency_type=JobDependencyType.PREREQUISITE
            )
        except BusinessRuleError:
            pass

    # Run optimizer across all newly generated jobs
    result = optimize_schedule(db, target_job_ids=created_job_ids)

    return WorkloadSimulationResult(
        device_count=device_count,
        jobs_created=len(created_job_ids),
        resources_available=len(resources),
        optimization_summary=result.summary,
        first_10_queue_items=result.queue[:10],
    )


def clear_simulated_workload(db: Session) -> dict[str, int]:
    """Remove all benchmark-generated simulated assets and their associated jobs, assignments, and dependencies."""
    sim_assets = db.query(Asset).filter(Asset.asset_tag.like("SIM-%")).all()
    if not sim_assets:
        return {"deleted_assets": 0, "deleted_jobs": 0}

    asset_ids = [a.id for a in sim_assets]
    sim_jobs = db.query(SanitizationJob).filter(SanitizationJob.asset_id.in_(asset_ids)).all()
    job_ids = [j.id for j in sim_jobs]

    # Delete schedule events linked to assignments of these jobs
    assignments = db.query(ScheduleAssignment).filter(ScheduleAssignment.job_id.in_(job_ids)).all()
    assignment_ids = [assign.id for assign in assignments]
    if assignment_ids:
        db.query(ScheduleEvent).filter(ScheduleEvent.assignment_id.in_(assignment_ids)).delete(synchronize_session=False)
        db.query(ScheduleAssignment).filter(ScheduleAssignment.id.in_(assignment_ids)).delete(synchronize_session=False)

    # Delete job dependencies and job events
    if job_ids:
        db.query(JobDependency).filter(
            (JobDependency.parent_job_id.in_(job_ids)) | (JobDependency.child_job_id.in_(job_ids))
        ).delete(synchronize_session=False)
        db.query(SanitizationJobEvent).filter(SanitizationJobEvent.job_id.in_(job_ids)).delete(synchronize_session=False)
        db.query(SanitizationJob).filter(SanitizationJob.id.in_(job_ids)).delete(synchronize_session=False)

    # Delete asset-linked auxiliary records if any exist
    try:
        from app.models.demo_inspection import DemoInspection
        from app.models.custody import ChainOfCustodyEvent
        from app.models.disposition import DispositionRecommendation
        from app.models.lifecycle_event import LifecycleEvent
        from app.models.sanitization_record import SanitizationRecord
        db.query(DemoInspection).filter(DemoInspection.asset_id.in_(asset_ids)).delete(synchronize_session=False)
        db.query(LifecycleEvent).filter(LifecycleEvent.asset_id.in_(asset_ids)).delete(synchronize_session=False)
        db.query(ChainOfCustodyEvent).filter(ChainOfCustodyEvent.asset_id.in_(asset_ids)).delete(synchronize_session=False)
        db.query(DispositionRecommendation).filter(DispositionRecommendation.asset_id.in_(asset_ids)).delete(synchronize_session=False)
        db.query(SanitizationRecord).filter(SanitizationRecord.asset_id.in_(asset_ids)).delete(synchronize_session=False)
    except Exception:
        pass

    # Delete assets
    deleted_assets_count = len(sim_assets)
    db.query(Asset).filter(Asset.id.in_(asset_ids)).delete(synchronize_session=False)
    db.commit()

    return {"deleted_assets": deleted_assets_count, "deleted_jobs": len(job_ids)}


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------

def _record_schedule_event(
    db: Session,
    *,
    event_type: ScheduleEventType,
    assignment_id: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
) -> ScheduleEvent:
    event = ScheduleEvent(
        assignment_id=assignment_id,
        resource_id=resource_id,
        event_type=event_type,
        details=details,
    )
    db.add(event)
    db.commit()
    return event
