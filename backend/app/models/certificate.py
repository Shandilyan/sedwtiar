"""Tamper-evident certificate metadata; issuance never performs cryptographic signing."""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class TamperEvidentCertificate(Base):
    __tablename__ = "tamper_evident_certificates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    verification_id: Mapped[str] = mapped_column(
        ForeignKey("independent_verifications.id"), unique=True, index=True
    )
    certificate_number: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    issuer: Mapped[str] = mapped_column(String(150), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    hash_algorithm: Mapped[str] = mapped_column(String(50), nullable=False, default="sha256")
    certificate_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    previous_certificate_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    certificate_version: Mapped[str] = mapped_column(String(50), nullable=False, default="v1-hash-chain")
    signature: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    signature_algorithm: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    signing_key_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    public_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    verification: Mapped["IndependentVerification"] = relationship(back_populates="certificate")
