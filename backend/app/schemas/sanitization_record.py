"""Pydantic contracts for sanitization record keeping, not sanitization execution."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.enums import SanitizationRecordStatus


class SanitizationRecordCreate(BaseModel):
    status: SanitizationRecordStatus = SanitizationRecordStatus.PLANNED
    method: str = Field(min_length=1, max_length=150, examples=["NIST 800-88 certificate review"])
    requested_by: Optional[str] = Field(default=None, max_length=150)
    verified_by: Optional[str] = Field(default=None, max_length=150)
    verified_at: Optional[datetime] = None
    certificate_reference: Optional[str] = Field(default=None, max_length=255)
    evidence_hash: Optional[str] = Field(default=None, max_length=255)
    notes: Optional[str] = None

    @model_validator(mode="after")
    def require_verification_details_when_verified(self) -> "SanitizationRecordCreate":
        if self.status == SanitizationRecordStatus.VERIFIED and (
            not self.verified_by or not self.verified_at
        ):
            raise ValueError("verified_by and verified_at are required for a verified record")
        return self


class SanitizationRecordRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_id: str
    job_id: Optional[str]
    status: SanitizationRecordStatus
    method: str
    requested_by: Optional[str]
    verified_by: Optional[str]
    verified_at: Optional[datetime]
    certificate_reference: Optional[str]
    evidence_hash: Optional[str]
    notes: Optional[str]
    created_at: datetime
    updated_at: datetime
