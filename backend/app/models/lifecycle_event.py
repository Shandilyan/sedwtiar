"""Append-only lifecycle events for assets."""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy import DateTime, Enum as SqlEnum, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import AssetLifecycleStatus, LifecycleEventType


class LifecycleEvent(Base):
    __tablename__ = "lifecycle_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    event_type: Mapped[LifecycleEventType] = mapped_column(
        SqlEnum(LifecycleEventType, name="lifecycle_event_type", native_enum=False, length=40), nullable=False
    )
    previous_status: Mapped[Optional[AssetLifecycleStatus]] = mapped_column(
        SqlEnum(AssetLifecycleStatus, name="asset_lifecycle_status", native_enum=False), nullable=True
    )
    new_status: Mapped[Optional[AssetLifecycleStatus]] = mapped_column(
        SqlEnum(AssetLifecycleStatus, name="asset_lifecycle_status", native_enum=False), nullable=True
    )
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    asset: Mapped["Asset"] = relationship(back_populates="lifecycle_events")
