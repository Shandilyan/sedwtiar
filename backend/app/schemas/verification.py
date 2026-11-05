"""Pydantic contracts for independent evidence review."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import VerificationOutcome


class IndependentVerificationCreate(BaseModel):
    outcome: VerificationOutcome
    verifier_name: str = Field(min_length=1, max_length=150)
    verification_method: str = Field(min_length=1, max_length=150)
    evidence_hash: Optional[str] = Field(default=None, max_length=255)
    findings: Optional[str] = None
    verified_at: datetime


class IndependentVerificationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    sanitization_record_id: str
    outcome: VerificationOutcome
    verifier_name: str
    verification_method: str
    evidence_hash: Optional[str]
    findings: Optional[str]
    verified_at: datetime
    created_at: datetime
