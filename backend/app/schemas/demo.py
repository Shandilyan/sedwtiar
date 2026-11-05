"""Demo-only API contracts. No contract represents physical device inspection or wiping."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import DemoInspectionStatus, DispositionType, SanitizationJobStatus
from app.schemas.asset import AssetRead
from app.schemas.sanitization_job import SanitizationJobRead
from app.schemas.sanitization_record import SanitizationRecordRead
from app.schemas.verification import IndependentVerificationRead


class DemoInspectionCreate(BaseModel):
    storage_type: str = Field(default="SSD", min_length=1, max_length=50)
    capacity_gb: int = Field(default=512, ge=1, le=10_000_000)
    device_model: str = Field(default="Dell Latitude 5420", min_length=1, max_length=150)
    health_percent: int = Field(default=92, ge=0, le=100)
    encryption_status: str = Field(default="Detected / Demo value", min_length=1, max_length=100)
    filesystem: str = Field(default="NTFS / Demo value", min_length=1, max_length=50)
    notes: Optional[str] = None


class DemoInspectionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_id: str
    storage_type: str
    capacity_gb: int
    device_model: str
    health_percent: int
    encryption_status: str
    filesystem: str
    status: DemoInspectionStatus
    source_label: str
    notes: Optional[str]
    created_at: datetime


class SanitizationRecommendationRead(BaseModel):
    asset_id: str
    recommended_method: str
    recommendation_status: str
    rationale: list[str]
    safety_notice: str
    rule_name: str


class DispositionRuleRead(BaseModel):
    asset_id: str
    recommendation: DispositionType
    rationale: str
    rule_name: str


class ControlledSimulationRead(BaseModel):
    job: SanitizationJobRead
    evidence: SanitizationRecordRead
    simulation_status: str
    safety_notice: str
    evidence_integrity_hash: str


class DemoVerificationRead(BaseModel):
    verification: IndependentVerificationRead
    job_status: SanitizationJobStatus
    evidence_integrity_hash: str
    verification_message: str


class DemoAssetRead(BaseModel):
    asset: AssetRead
    message: str
