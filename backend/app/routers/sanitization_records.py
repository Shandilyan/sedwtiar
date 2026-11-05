"""Read/write endpoints for administrative sanitization records only."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.sanitization_record import SanitizationRecordCreate, SanitizationRecordRead
from app.services import assets as asset_service
from app.services import sanitization_records as record_service
from app.services.exceptions import ResourceConflictError, ResourceNotFoundError

asset_records_router = APIRouter(
    prefix="/assets/{asset_id}/sanitization-records", tags=["Sanitization records"]
)
router = APIRouter(prefix="/sanitization-records", tags=["Sanitization records"])


def _not_found(error: ResourceNotFoundError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))


@asset_records_router.post("", response_model=SanitizationRecordRead, status_code=status.HTTP_201_CREATED)
def create_asset_sanitization_record(
    asset_id: str,
    payload: SanitizationRecordCreate,
    db: Session = Depends(get_db),
) -> SanitizationRecordRead:
    try:
        asset = asset_service.get_asset(db, asset_id)
        return record_service.create_sanitization_record(db, asset, payload)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error
    except ResourceConflictError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@asset_records_router.get("", response_model=list[SanitizationRecordRead])
def list_asset_sanitization_records(
    asset_id: str, db: Session = Depends(get_db)
) -> list[SanitizationRecordRead]:
    try:
        return record_service.list_asset_sanitization_records(db, asset_id)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


@router.get("/{record_id}", response_model=SanitizationRecordRead)
def get_sanitization_record(
    record_id: str, db: Session = Depends(get_db)
) -> SanitizationRecordRead:
    try:
        return record_service.get_sanitization_record(db, record_id)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error
