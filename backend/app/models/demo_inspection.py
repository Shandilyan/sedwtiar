"""Explicitly simulated inspection records for the demonstration workflow."""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy import DateTime, Enum as SqlEnum, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import DemoInspectionStatus


class DemoInspection(Base):
    """Controlled demo data; it is never produced by a physical-device agent."""

    __tablename__ = "demo_inspections"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    storage_type: Mapped[str] = mapped_column(String(50), nullable=False)
    capacity_gb: Mapped[int] = mapped_column(Integer, nullable=False)
    device_model: Mapped[str] = mapped_column(String(150), nullable=False)
    health_percent: Mapped[int] = mapped_column(Integer, nullable=False)
    encryption_status: Mapped[str] = mapped_column(String(100), nullable=False)
    filesystem: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[DemoInspectionStatus] = mapped_column(
        SqlEnum(DemoInspectionStatus, name="demo_inspection_status", native_enum=False),
        nullable=False,
        default=DemoInspectionStatus.COMPLETED,
    )
    source_label: Mapped[str] = mapped_column(
        String(100), nullable=False, default="Controlled demo inspection data"
    )
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    asset: Mapped["Asset"] = relationship(back_populates="demo_inspections")
