"""Append-only custody events for physical or administrative asset hand-offs."""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy import DateTime, Enum as SqlEnum, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import CustodyEventType


class ChainOfCustodyEvent(Base):
    __tablename__ = "chain_of_custody_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    event_type: Mapped[CustodyEventType] = mapped_column(
        SqlEnum(CustodyEventType, name="custody_event_type", native_enum=False), nullable=False
    )
    from_custodian: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    to_custodian: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    location: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    recorded_by: Mapped[str] = mapped_column(String(150), nullable=False)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    asset: Mapped["Asset"] = relationship(back_populates="custody_events")
