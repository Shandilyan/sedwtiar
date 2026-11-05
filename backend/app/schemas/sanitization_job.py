"""Pydantic contracts for administrative sanitization workflow jobs."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import SanitizationJobStatus


class SanitizationJobCreate(BaseModel):
    asset_id: str
    planned_method: str = Field(min_length=1, max_length=150)
    requested_by: Optional[str] = Field(default=None, max_length=150)
    notes: Optional[str] = None


class SanitizationJobStatusUpdate(BaseModel):
    status: SanitizationJobStatus
    note: Optional[str] = None


class SanitizationJobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_id: str
    status: SanitizationJobStatus
    planned_method: str
    requested_by: Optional[str]
    notes: Optional[str]
    created_at: datetime
    updated_at: datetime


class SanitizationJobEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_id: str
    previous_status: Optional[SanitizationJobStatus]
    new_status: SanitizationJobStatus
    note: Optional[str]
    occurred_at: datetime
