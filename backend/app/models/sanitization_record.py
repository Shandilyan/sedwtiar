"""Administrative sanitization evidence records; no execution capability exists here."""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy import DateTime, Enum as SqlEnum, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import SanitizationRecordStatus


class SanitizationRecord(Base):
    __tablename__ = "sanitization_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    job_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("sanitization_jobs.id"), nullable=True, index=True
    )
    status: Mapped[SanitizationRecordStatus] = mapped_column(
        SqlEnum(SanitizationRecordStatus, name="sanitization_record_status", native_enum=False),
        nullable=False,
        default=SanitizationRecordStatus.PLANNED,
        index=True,
    )
    method: Mapped[str] = mapped_column(String(150), nullable=False)
    requested_by: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    verified_by: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    certificate_reference: Mapped[Optional[str]] = mapped_column(String(255), unique=True, nullable=True)
    evidence_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    asset: Mapped["Asset"] = relationship(back_populates="sanitization_records")
    job: Mapped[Optional["SanitizationJob"]] = relationship(back_populates="sanitization_records")
    verifications: Mapped[list["IndependentVerification"]] = relationship(
        back_populates="sanitization_record", order_by="IndependentVerification.created_at"
    )
