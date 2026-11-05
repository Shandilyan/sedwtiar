"""Versioned inventory-asset endpoints."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.enums import AssetLifecycleStatus
from app.schemas.asset import AssetCreate, AssetRead, AssetUpdate
from app.schemas.lifecycle_event import LifecycleEventRead
from app.services import assets as asset_service
from app.services.exceptions import ResourceConflictError, ResourceNotFoundError

router = APIRouter(prefix="/assets", tags=["Assets"])


def _not_found(error: ResourceNotFoundError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))


@router.post("", response_model=AssetRead, status_code=status.HTTP_201_CREATED)
def create_asset(payload: AssetCreate, db: Session = Depends(get_db)) -> AssetRead:
    try:
        return asset_service.create_asset(db, payload)
    except ResourceConflictError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@router.get("", response_model=list[AssetRead])
def list_assets(
    lifecycle_status: Optional[AssetLifecycleStatus] = None,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=200),
    db: Session = Depends(get_db),
) -> list[AssetRead]:
    return asset_service.list_assets(
        db, lifecycle_status=lifecycle_status, offset=offset, limit=limit
    )


@router.get("/{asset_id}", response_model=AssetRead)
def get_asset(asset_id: str, db: Session = Depends(get_db)) -> AssetRead:
    try:
        return asset_service.get_asset(db, asset_id)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


@router.patch("/{asset_id}", response_model=AssetRead)
def update_asset(
    asset_id: str, payload: AssetUpdate, db: Session = Depends(get_db)
) -> AssetRead:
    try:
        asset = asset_service.get_asset(db, asset_id)
        return asset_service.update_asset(db, asset, payload)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error
    except ResourceConflictError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@router.get("/{asset_id}/events", response_model=list[LifecycleEventRead])
def list_asset_events(asset_id: str, db: Session = Depends(get_db)) -> list[LifecycleEventRead]:
    try:
        return asset_service.list_lifecycle_events(db, asset_id)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error
