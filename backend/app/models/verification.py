"""Independent review of a sanitization evidence record."""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy import DateTime, Enum as SqlEnum, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import VerificationOutcome


class IndependentVerification(Base):
    __tablename__ = "independent_verifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    sanitization_record_id: Mapped[str] = mapped_column(
        ForeignKey("sanitization_records.id"), index=True
    )
    outcome: Mapped[VerificationOutcome] = mapped_column(
        SqlEnum(VerificationOutcome, name="verification_outcome", native_enum=False), nullable=False
    )
    verifier_name: Mapped[str] = mapped_column(String(150), nullable=False)
    verification_method: Mapped[str] = mapped_column(String(150), nullable=False)
    evidence_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    findings: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    sanitization_record: Mapped["SanitizationRecord"] = relationship(back_populates="verifications")
    certificate: Mapped[Optional["TamperEvidentCertificate"]] = relationship(
        back_populates="verification", uselist=False
    )
