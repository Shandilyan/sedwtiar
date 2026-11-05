"""Administrative sanitization-record operations with no device interaction."""

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from typing import Optional

from app.models import Asset, LifecycleEvent, SanitizationJob, SanitizationRecord
from app.models.enums import LifecycleEventType
from app.schemas.sanitization_record import SanitizationRecordCreate
from app.services.exceptions import ResourceConflictError, ResourceNotFoundError


def create_sanitization_record(
    db: Session,
    asset: Asset,
    payload: SanitizationRecordCreate,
    job: Optional[SanitizationJob] = None,
) -> SanitizationRecord:
    record = SanitizationRecord(asset_id=asset.id, job_id=job.id if job else None, **payload.model_dump())
    db.add(record)
    db.add(
        LifecycleEvent(
            asset_id=asset.id,
            event_type=LifecycleEventType.SANITIZATION_RECORDED,
            new_status=asset.lifecycle_status,
            note="Sanitization record added; no sanitization action was performed by this service.",
        )
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ResourceConflictError("certificate_reference already exists") from exc
    db.refresh(record)
    return record


def get_sanitization_record(db: Session, record_id: str) -> SanitizationRecord:
    record = db.get(SanitizationRecord, record_id)
    if record is None:
        raise ResourceNotFoundError("Sanitization record not found")
    return record


def list_asset_sanitization_records(db: Session, asset_id: str) -> list[SanitizationRecord]:
    if db.get(Asset, asset_id) is None:
        raise ResourceNotFoundError("Asset not found")
    statement = (
        select(SanitizationRecord)
        .where(SanitizationRecord.asset_id == asset_id)
        .order_by(SanitizationRecord.created_at.asc())
    )
    return list(db.scalars(statement))
