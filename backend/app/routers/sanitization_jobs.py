"""Administrative sanitization-job workflow endpoints; no execution endpoints exist."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.enums import SanitizationJobStatus
from app.schemas.sanitization_job import (
    SanitizationJobCreate,
    SanitizationJobEventRead,
    SanitizationJobRead,
    SanitizationJobStatusUpdate,
)
from app.schemas.sanitization_record import SanitizationRecordCreate, SanitizationRecordRead
from app.services import assets as asset_service
from app.services import sanitization_jobs as job_service
from app.services import sanitization_records as record_service
from app.services.exceptions import BusinessRuleError, InvalidStateTransitionError, ResourceNotFoundError

router = APIRouter(prefix="/sanitization-jobs", tags=["Sanitization jobs"])


def _not_found(error: ResourceNotFoundError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))


def _unprocessable(error: Exception) -> HTTPException:
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(error))


@router.post("", response_model=SanitizationJobRead, status_code=status.HTTP_201_CREATED)
def create_sanitization_job(
    payload: SanitizationJobCreate, db: Session = Depends(get_db)
) -> SanitizationJobRead:
    try:
        return job_service.create_job(db, payload)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


@router.get("", response_model=list[SanitizationJobRead])
def list_sanitization_jobs(
    asset_id: Optional[str] = None,
    job_status: Optional[SanitizationJobStatus] = None,
    db: Session = Depends(get_db),
) -> list[SanitizationJobRead]:
    return job_service.list_jobs(db, asset_id=asset_id, status=job_status)


@router.get("/{job_id}", response_model=SanitizationJobRead)
def get_sanitization_job(job_id: str, db: Session = Depends(get_db)) -> SanitizationJobRead:
    try:
        return job_service.get_job(db, job_id)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


@router.patch("/{job_id}/status", response_model=SanitizationJobRead)
def transition_sanitization_job(
    job_id: str,
    payload: SanitizationJobStatusUpdate,
    db: Session = Depends(get_db),
) -> SanitizationJobRead:
    try:
        job = job_service.get_job(db, job_id)
        return job_service.transition_job(db, job, payload)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error
    except (BusinessRuleError, InvalidStateTransitionError) as error:
        raise _unprocessable(error) from error


@router.get("/{job_id}/events", response_model=list[SanitizationJobEventRead])
def list_sanitization_job_events(
    job_id: str, db: Session = Depends(get_db)
) -> list[SanitizationJobEventRead]:
    try:
        return job_service.list_job_events(db, job_id)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


@router.post("/{job_id}/records", response_model=SanitizationRecordRead, status_code=status.HTTP_201_CREATED)
def create_job_sanitization_record(
    job_id: str,
    payload: SanitizationRecordCreate,
    db: Session = Depends(get_db),
) -> SanitizationRecordRead:
    try:
        job = job_service.get_job(db, job_id)
        asset = asset_service.get_asset(db, job.asset_id)
        return record_service.create_sanitization_record(db, asset, payload, job)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error
