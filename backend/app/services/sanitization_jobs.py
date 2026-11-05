"""Administrative job workflow services; no operation is performed on a device."""

from hashlib import sha256
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import IndependentVerification, LifecycleEvent, SanitizationJob, SanitizationJobEvent, SanitizationRecord
from app.models.enums import LifecycleEventType, SanitizationJobStatus, SanitizationRecordStatus, VerificationOutcome
from app.schemas.sanitization_job import SanitizationJobCreate, SanitizationJobStatusUpdate
from app.services.assets import get_asset
from app.services.exceptions import BusinessRuleError, InvalidStateTransitionError, ResourceNotFoundError

_ALLOWED_TRANSITIONS = {
    SanitizationJobStatus.REQUESTED: {SanitizationJobStatus.PREPARED, SanitizationJobStatus.CANCELLED},
    SanitizationJobStatus.PREPARED: {SanitizationJobStatus.EVIDENCE_RECORDED, SanitizationJobStatus.CANCELLED},
    SanitizationJobStatus.EVIDENCE_RECORDED: {SanitizationJobStatus.VERIFIED, SanitizationJobStatus.CANCELLED},
    SanitizationJobStatus.VERIFIED: set(),
    SanitizationJobStatus.CANCELLED: set(),
}


def get_job(db: Session, job_id: str) -> SanitizationJob:
    job = db.get(SanitizationJob, job_id)
    if job is None:
        raise ResourceNotFoundError("Sanitization job not found")
    return job


def list_jobs(
    db: Session,
    *,
    asset_id: Optional[str] = None,
    status: Optional[SanitizationJobStatus] = None,
) -> list[SanitizationJob]:
    statement = select(SanitizationJob).order_by(SanitizationJob.created_at.desc())
    if asset_id is not None:
        statement = statement.where(SanitizationJob.asset_id == asset_id)
    if status is not None:
        statement = statement.where(SanitizationJob.status == status)
    return list(db.scalars(statement))


def create_job(db: Session, payload: SanitizationJobCreate) -> SanitizationJob:
    get_asset(db, payload.asset_id)
    job = SanitizationJob(**payload.model_dump())
    db.add(job)
    db.flush()
    db.add(
        SanitizationJobEvent(
            job_id=job.id,
            new_status=SanitizationJobStatus.REQUESTED,
            note="Administrative sanitization job requested; no operation was performed.",
        )
    )
    db.commit()
    db.refresh(job)
    return job


def transition_job(
    db: Session, job: SanitizationJob, payload: SanitizationJobStatusUpdate
) -> SanitizationJob:
    target_status = payload.status
    if target_status not in _ALLOWED_TRANSITIONS[job.status]:
        raise InvalidStateTransitionError(
            f"Cannot transition a job from {job.status.value} to {target_status.value}"
        )
    if target_status == SanitizationJobStatus.VERIFIED:
        passed_verification = db.scalar(
            select(IndependentVerification.id)
            .join(SanitizationRecord)
            .where(
                SanitizationRecord.job_id == job.id,
                IndependentVerification.outcome == VerificationOutcome.PASSED,
            )
            .limit(1)
        )
        if passed_verification is None:
            raise BusinessRuleError(
                "A job requires a passed independent verification before it can be verified"
            )
    previous_status = job.status
    job.status = target_status
    db.add(
        SanitizationJobEvent(
            job_id=job.id,
            previous_status=previous_status,
            new_status=target_status,
            note=payload.note,
        )
    )
    db.commit()
    db.refresh(job)
    return job


def list_job_events(db: Session, job_id: str) -> list[SanitizationJobEvent]:
    get_job(db, job_id)
    return list(
        db.scalars(
            select(SanitizationJobEvent)
            .where(SanitizationJobEvent.job_id == job_id)
            .order_by(SanitizationJobEvent.occurred_at.asc())
        )
    )


def controlled_simulation_evidence_hash(asset_id: str, job_id: str, planned_method: str) -> str:
    """Derive deterministic demo evidence without reading or modifying a storage device."""
    canonical = f"sedwtiar-controlled-simulation-v1|{asset_id}|{job_id}|{planned_method}"
    return sha256(canonical.encode("utf-8")).hexdigest()


def run_controlled_simulation(db: Session, job: SanitizationJob) -> SanitizationRecord:
    """Advance a job through safe administrative simulation stages.

    This function never enumerates a device, executes a command, or modifies media.
    """
    if job.status in {SanitizationJobStatus.CANCELLED, SanitizationJobStatus.VERIFIED}:
        raise BusinessRuleError("A cancelled or verified job cannot run a controlled simulation")
    asset = get_asset(db, job.asset_id)
    existing = db.scalar(
        select(SanitizationRecord)
        .where(
            SanitizationRecord.job_id == job.id,
            SanitizationRecord.notes.like("CONTROLLED SANITIZATION SIMULATION%"),
        )
        .order_by(SanitizationRecord.created_at.desc())
        .limit(1)
    )
    if existing is not None:
        return existing
    if job.status == SanitizationJobStatus.EVIDENCE_RECORDED:
        raise BusinessRuleError("This job already has evidence and cannot be simulated again")
    if job.status == SanitizationJobStatus.REQUESTED:
        transition_job(
            db,
            job,
            SanitizationJobStatusUpdate(
                status=SanitizationJobStatus.PREPARED,
                note="Prepared for controlled sanitization simulation; no physical device is involved.",
            ),
        )
    if job.status != SanitizationJobStatus.PREPARED:
        raise InvalidStateTransitionError("A controlled simulation requires a requested or prepared job")

    evidence_hash = controlled_simulation_evidence_hash(asset.id, job.id, job.planned_method)
    record = SanitizationRecord(
        asset_id=asset.id,
        job_id=job.id,
        status=SanitizationRecordStatus.PLANNED,
        method=f"CONTROLLED SANITIZATION SIMULATION — {job.planned_method}",
        requested_by="Controlled demo workflow",
        evidence_hash=evidence_hash,
        notes=(
            "CONTROLLED SANITIZATION SIMULATION COMPLETED. "
            "SIMULATION ONLY — NO PHYSICAL DRIVE WAS MODIFIED. "
            "The evidence hash is deterministic demo data for independent verification."
        ),
    )
    db.add(record)
    db.flush()
    db.add(
        LifecycleEvent(
            asset_id=asset.id,
            event_type=LifecycleEventType.CONTROLLED_SIMULATION_COMPLETED,
            new_status=asset.lifecycle_status,
            note="Controlled sanitization simulation completed. SIMULATION ONLY — NO PHYSICAL DRIVE WAS MODIFIED.",
        )
    )
    transition_job(
        db,
        job,
        SanitizationJobStatusUpdate(
            status=SanitizationJobStatus.EVIDENCE_RECORDED,
            note="Controlled sanitization simulation completed; demo evidence recorded.",
        ),
    )
    db.refresh(record)
    return record
