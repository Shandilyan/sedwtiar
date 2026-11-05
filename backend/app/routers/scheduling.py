"""Versioned endpoints for the sanitization scheduling and resource optimization engine."""

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.enums import ResourceStatus, ScheduleAssignmentStatus
from app.schemas.scheduling import (
    DynamicRebalanceRequest,
    DynamicRebalanceResult,
    JobDependenciesRead,
    JobDependencyCreate,
    JobDependencyRead,
    OptimizationResult,
    QueueItemRead,
    SanitizationResourceCreate,
    SanitizationResourceRead,
    SanitizationResourceStatusUpdate,
    SanitizationResourceUpdate,
    ScheduleAssignmentRead,
    TransactionalAssignmentRequest,
    WorkloadSimulationRequest,
    WorkloadSimulationResult,
)
from app.services import scheduling as scheduling_service
from app.services.exceptions import (
    BusinessRuleError,
    ResourceConflictError,
    ResourceIncompatibleError,
    ResourceNotFoundError,
    SchedulingConflictError,
)

router = APIRouter(prefix="/scheduling", tags=["Scheduling & Optimization"])


def _not_found(error: ResourceNotFoundError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))


def _conflict(error: ResourceConflictError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error))


def _unprocessable(error: Exception) -> HTTPException:
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(error))


# ---------------------------------------------------------------------------
# Resources Management Endpoints
# ---------------------------------------------------------------------------

@router.get("/resources", response_model=list[SanitizationResourceRead])
def list_sanitization_resources(
    resource_status: Optional[ResourceStatus] = Query(default=None, alias="status"),
    media_type: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
) -> list[SanitizationResourceRead]:
    """Retrieve available sanitization tools, stations, and bays."""
    scheduling_service.ensure_default_resources(db)
    return scheduling_service.list_resources(db, status=resource_status, media_type=media_type)


@router.post("/resources", response_model=SanitizationResourceRead, status_code=status.HTTP_201_CREATED)
def create_sanitization_resource(
    payload: SanitizationResourceCreate,
    db: Session = Depends(get_db),
) -> SanitizationResourceRead:
    """Register a new sanitization tool, wiping rig, or shredder bay."""
    try:
        return scheduling_service.create_resource(db, payload)
    except ResourceConflictError as error:
        raise _conflict(error) from error


@router.get("/resources/{resource_id}", response_model=SanitizationResourceRead)
def get_sanitization_resource(
    resource_id: str,
    db: Session = Depends(get_db),
) -> SanitizationResourceRead:
    try:
        return scheduling_service.get_resource(db, resource_id)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


@router.patch("/resources/{resource_id}", response_model=SanitizationResourceRead)
def update_sanitization_resource(
    resource_id: str,
    payload: SanitizationResourceUpdate,
    db: Session = Depends(get_db),
) -> SanitizationResourceRead:
    try:
        resource = scheduling_service.get_resource(db, resource_id)
        return scheduling_service.update_resource(db, resource, payload)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error
    except ResourceConflictError as error:
        raise _conflict(error) from error


@router.patch("/resources/{resource_id}/status", response_model=SanitizationResourceRead)
def update_resource_operational_status(
    resource_id: str,
    payload: SanitizationResourceStatusUpdate,
    db: Session = Depends(get_db),
) -> SanitizationResourceRead:
    """Update resource availability. Transitioning to OFFLINE or MAINTENANCE triggers dynamic rebalance."""
    try:
        resource = scheduling_service.get_resource(db, resource_id)
        return scheduling_service.update_resource_status(
            db, resource, payload.status, reason=payload.reason
        )
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


# ---------------------------------------------------------------------------
# Scheduling Optimization & Queue Endpoints
# ---------------------------------------------------------------------------

@router.post("/optimize", response_model=OptimizationResult)
def run_schedule_optimization(
    target_job_ids: Optional[list[str]] = None,
    db: Session = Depends(get_db),
) -> OptimizationResult:
    """Execute multi-resource optimization: prioritize critical/urgent assets and minimize makespan."""
    try:
        return scheduling_service.optimize_schedule(db, target_job_ids=target_job_ids)
    except BusinessRuleError as error:
        raise _unprocessable(error) from error


@router.get("/queue", response_model=OptimizationResult)
def get_current_schedule_queue(
    db: Session = Depends(get_db),
) -> OptimizationResult:
    """Retrieve the current prioritized sanitization queue with priority scores and timing."""
    return scheduling_service.optimize_schedule(db)


@router.post("/rebalance", response_model=DynamicRebalanceResult)
def trigger_dynamic_rebalance(
    payload: DynamicRebalanceRequest,
    db: Session = Depends(get_db),
) -> DynamicRebalanceResult:
    """Dynamically reassign pending jobs when a resource fails, without interrupting running jobs."""
    try:
        return scheduling_service.rebalance_schedule(
            db,
            unavailable_resource_id=payload.unavailable_resource_id,
            reason=payload.reason or "Dynamic rebalance requested",
            preserve_running_jobs=payload.preserve_running_jobs,
        )
    except BusinessRuleError as error:
        raise _unprocessable(error) from error


# ---------------------------------------------------------------------------
# Dependency Management Endpoints
# ---------------------------------------------------------------------------

@router.post("/dependencies", response_model=JobDependencyRead, status_code=status.HTTP_201_CREATED)
def create_job_dependency_endpoint(
    payload: JobDependencyCreate,
    db: Session = Depends(get_db),
) -> JobDependencyRead:
    """Register a DAG prerequisite dependency between two sanitization jobs with cycle detection."""
    try:
        return scheduling_service.create_job_dependency(
            db,
            parent_job_id=payload.parent_job_id,
            child_job_id=payload.child_job_id,
            dependency_type=payload.dependency_type,
            notes=payload.notes,
        )
    except ResourceNotFoundError as error:
        raise _not_found(error) from error
    except BusinessRuleError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@router.get("/dependencies/{job_id}", response_model=JobDependenciesRead)
def get_job_dependencies_endpoint(
    job_id: str,
    db: Session = Depends(get_db),
) -> JobDependenciesRead:
    """Retrieve all incoming prerequisite and outgoing dependent edges in the DAG for a job."""
    try:
        return scheduling_service.get_job_dependencies(db, job_id)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


# ---------------------------------------------------------------------------
# Assignment Operations
# ---------------------------------------------------------------------------

@router.post("/assignments/transactional", response_model=ScheduleAssignmentRead)
def assign_job_transactional_endpoint(
    payload: TransactionalAssignmentRequest,
    db: Session = Depends(get_db),
) -> ScheduleAssignmentRead:
    """Atomic transactional job assignment with row-level pessimistic locking and optimistic concurrency checks."""
    try:
        return scheduling_service.assign_job_transactional(
            db,
            job_id=payload.job_id,
            resource_id=payload.resource_id,
            expected_version=payload.expected_version,
            slot_number=payload.slot_number,
            force_override=payload.force_override,
        )
    except ResourceNotFoundError as error:
        raise _not_found(error) from error
    except (SchedulingConflictError, ResourceConflictError) as error:
        raise _conflict(error) from error
    except (ResourceIncompatibleError, BusinessRuleError) as error:
        raise _unprocessable(error) from error


@router.post("/assignments/{assignment_id}/start", response_model=ScheduleAssignmentRead)
def start_scheduled_assignment(
    assignment_id: str,
    db: Session = Depends(get_db),
) -> ScheduleAssignmentRead:
    """Mark an assignment as RUNNING and set the associated resource to BUSY."""
    try:
        return scheduling_service.start_assignment(db, assignment_id)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error
    except SchedulingConflictError as error:
        raise _unprocessable(error) from error


@router.post("/assignments/{assignment_id}/complete", response_model=ScheduleAssignmentRead)
def complete_scheduled_assignment(
    assignment_id: str,
    actual_minutes: Optional[int] = Query(default=None, ge=1),
    db: Session = Depends(get_db),
) -> ScheduleAssignmentRead:
    """Mark an assignment as COMPLETED and return the resource to AVAILABLE."""
    try:
        return scheduling_service.complete_assignment(db, assignment_id, actual_minutes)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


@router.post("/detect-delays", response_model=DynamicRebalanceResult)
def detect_delays_and_reschedule_endpoint(
    delay_threshold_minutes: int = Query(default=15, ge=1),
    db: Session = Depends(get_db),
) -> DynamicRebalanceResult:
    """Identify overrun jobs exceeding expected duration and dynamically reschedule downstream pending tasks."""
    try:
        return scheduling_service.detect_delays_and_reschedule(
            db,
            delay_threshold_minutes=delay_threshold_minutes,
        )
    except BusinessRuleError as error:
        raise _unprocessable(error) from error


# ---------------------------------------------------------------------------
# Workload Simulator (Testing Scale)
# ---------------------------------------------------------------------------

@router.post("/simulate-workload", response_model=WorkloadSimulationResult)
def simulate_competing_workload(
    payload: WorkloadSimulationRequest,
    db: Session = Depends(get_db),
) -> WorkloadSimulationResult:
    """Benchmark the scheduling engine with 100+ competing devices of varied sensitivity and deadlines."""
    return scheduling_service.simulate_batch_workload(
        db,
        device_count=payload.device_count,
        seed=payload.seed or 42,
        auto_create_resources_if_empty=payload.auto_create_resources_if_empty,
    )


@router.post("/clear-simulation")
def clear_simulated_workload(
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Remove all benchmark-generated simulated devices and restore inventory."""
    result = scheduling_service.clear_simulated_workload(db)
    return {
        "status": "success",
        "message": f"Cleared {result['deleted_assets']} simulated assets and {result['deleted_jobs']} test jobs.",
        "details": result,
    }
