"""Pydantic contracts for non-binding disposition recommendations."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import DispositionType


class DispositionRecommendationCreate(BaseModel):
    sanitization_job_id: Optional[str] = None
    verification_id: Optional[str] = None
    recommendation: DispositionType
    rationale: str = Field(min_length=1)
    recommended_by: str = Field(min_length=1, max_length=150)


class DispositionRecommendationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_id: str
    sanitization_job_id: Optional[str]
    verification_id: Optional[str]
    recommendation: DispositionType
    rationale: str
    recommended_by: str
    created_at: datetime
