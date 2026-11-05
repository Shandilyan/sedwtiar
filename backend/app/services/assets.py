"""Business operations for inventory assets and their lifecycle audit trail."""

from datetime import date
from typing import Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Asset, LifecycleEvent
from app.models.enums import AssetLifecycleStatus, AssetType, LifecycleEventType
from app.schemas.asset import AssetCreate, AssetUpdate
from app.services.exceptions import ResourceConflictError, ResourceNotFoundError


def get_asset(db: Session, asset_id: str) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise ResourceNotFoundError("Asset not found")
    return asset


def list_assets(
    db: Session,
    *,
    lifecycle_status: Optional[AssetLifecycleStatus] = None,
    offset: int = 0,
    limit: int = 100,
) -> list[Asset]:
    statement = select(Asset).order_by(Asset.created_at.desc()).offset(offset).limit(limit)
    if lifecycle_status is not None:
        statement = statement.where(Asset.lifecycle_status == lifecycle_status)
    return list(db.scalars(statement))


def create_asset(db: Session, payload: AssetCreate) -> Asset:
    asset = Asset(**payload.model_dump())
    db.add(asset)
    db.flush()
    db.add(
        LifecycleEvent(
            asset_id=asset.id,
            event_type=LifecycleEventType.CREATED,
            new_status=asset.lifecycle_status,
            note="Asset registered in the controlled demo workflow.",
        )
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ResourceConflictError("asset_tag or serial_number already exists") from exc
    db.refresh(asset)
    return asset


def update_asset(db: Session, asset: Asset, payload: AssetUpdate) -> Asset:
    changes = payload.model_dump(exclude_unset=True)
    previous_status = asset.lifecycle_status
    for field, value in changes.items():
        setattr(asset, field, value)

    if "lifecycle_status" in changes and asset.lifecycle_status != previous_status:
        event_type = LifecycleEventType.STATUS_CHANGED
        note = "Asset lifecycle status changed."
    else:
        event_type = LifecycleEventType.UPDATED
        note = "Asset inventory record updated."

    if changes:
        db.add(
            LifecycleEvent(
                asset_id=asset.id,
                event_type=event_type,
                previous_status=previous_status if event_type == LifecycleEventType.STATUS_CHANGED else None,
                new_status=asset.lifecycle_status if event_type == LifecycleEventType.STATUS_CHANGED else None,
                note=note,
            )
        )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ResourceConflictError("asset_tag or serial_number already exists") from exc
    db.refresh(asset)
    return asset


def list_lifecycle_events(db: Session, asset_id: str) -> list[LifecycleEvent]:
    get_asset(db, asset_id)
    statement = (
        select(LifecycleEvent)
        .where(LifecycleEvent.asset_id == asset_id)
        .order_by(LifecycleEvent.occurred_at.asc())
    )
    return list(db.scalars(statement))


def create_demo_asset(db: Session) -> Asset:
    """Create one new, uniquely tagged demo asset without touching existing records."""
    base_tag = "IT-2026-001"
    suffix = 1
    candidate = base_tag
    while db.scalar(select(Asset.id).where(Asset.asset_tag == candidate)) is not None:
        suffix += 1
        candidate = f"{base_tag}-{suffix}"
    return create_asset(
        db,
        AssetCreate(
            asset_tag=candidate,
            serial_number=f"DEMO-{candidate}",
            asset_type=AssetType.LAPTOP,
            manufacturer="Dell",
            model="Latitude 5420",
            storage_type="SSD",
            storage_capacity_gb=512,
            owner_department="Corporate IT",
            date_received=date.today(),
            intended_destination="reuse",
            notes="Controlled demo asset. No physical-device inspection or sanitization is represented.",
        ),
    )
