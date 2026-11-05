"""SQLAlchemy model for an inventory asset."""

from __future__ import annotations

from datetime import date, datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy import DateTime, Enum as SqlEnum, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import AssetLifecycleStatus, AssetType, DataSensitivity


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    asset_tag: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    serial_number: Mapped[Optional[str]] = mapped_column(String(150), unique=True, nullable=True)
    asset_type: Mapped[AssetType] = mapped_column(
        SqlEnum(AssetType, name="asset_type", native_enum=False), nullable=False
    )
    lifecycle_status: Mapped[AssetLifecycleStatus] = mapped_column(
        SqlEnum(AssetLifecycleStatus, name="asset_lifecycle_status", native_enum=False),
        nullable=False,
        default=AssetLifecycleStatus.IN_INVENTORY,
        index=True,
    )
    data_sensitivity: Mapped[DataSensitivity] = mapped_column(
        SqlEnum(DataSensitivity, name="data_sensitivity", native_enum=False),
        nullable=False,
        default=DataSensitivity.STANDARD,
        index=True,
    )
    disposal_deadline: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    manufacturer: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    model: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    storage_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    storage_capacity_gb: Mapped[Optional[int]] = mapped_column(nullable=True)
    owner_department: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    date_received: Mapped[Optional[date]] = mapped_column(nullable=True)
    intended_destination: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    lifecycle_events: Mapped[list["LifecycleEvent"]] = relationship(
        back_populates="asset", order_by="LifecycleEvent.occurred_at"
    )
    sanitization_records: Mapped[list["SanitizationRecord"]] = relationship(
        back_populates="asset", order_by="SanitizationRecord.created_at"
    )
    sanitization_jobs: Mapped[list["SanitizationJob"]] = relationship(
        back_populates="asset", order_by="SanitizationJob.created_at"
    )
    custody_events: Mapped[list["ChainOfCustodyEvent"]] = relationship(
        back_populates="asset", order_by="ChainOfCustodyEvent.occurred_at"
    )
    disposition_recommendations: Mapped[list["DispositionRecommendation"]] = relationship(
        back_populates="asset", order_by="DispositionRecommendation.created_at"
    )
    demo_inspections: Mapped[list["DemoInspection"]] = relationship(
        back_populates="asset", order_by="DemoInspection.created_at"
    )
