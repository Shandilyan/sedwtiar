"""Non-binding asset disposition recommendations derived from recorded evidence."""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy import DateTime, Enum as SqlEnum, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.enums import DispositionType


class DispositionRecommendation(Base):
    __tablename__ = "disposition_recommendations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    sanitization_job_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("sanitization_jobs.id"), nullable=True, index=True
    )
    verification_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("independent_verifications.id"), nullable=True, index=True
    )
    recommendation: Mapped[DispositionType] = mapped_column(
        SqlEnum(DispositionType, name="disposition_type", native_enum=False), nullable=False
    )
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_by: Mapped[str] = mapped_column(String(150), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    asset: Mapped["Asset"] = relationship(back_populates="disposition_recommendations")
    sanitization_job: Mapped[Optional["SanitizationJob"]] = relationship(
        back_populates="disposition_recommendations"
    )
