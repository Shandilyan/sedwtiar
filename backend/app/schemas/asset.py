"""Pydantic contracts for asset inventory data."""

from datetime import date, datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import AssetLifecycleStatus, AssetType


class AssetCreate(BaseModel):
    asset_tag: str = Field(min_length=1, max_length=100, examples=["LAP-0042"])
    asset_type: AssetType
    serial_number: Optional[str] = Field(default=None, max_length=150)
    manufacturer: Optional[str] = Field(default=None, max_length=100)
    model: Optional[str] = Field(default=None, max_length=150)
    storage_type: Optional[str] = Field(default=None, max_length=50)
    storage_capacity_gb: Optional[int] = Field(default=None, ge=1, le=10_000_000)
    owner_department: Optional[str] = Field(default=None, max_length=150)
    date_received: Optional[date] = None
    intended_destination: Optional[str] = Field(default=None, max_length=100)
    notes: Optional[str] = None
    lifecycle_status: AssetLifecycleStatus = AssetLifecycleStatus.IN_INVENTORY


class AssetUpdate(BaseModel):
    asset_tag: Optional[str] = Field(default=None, min_length=1, max_length=100)
    asset_type: Optional[AssetType] = None
    serial_number: Optional[str] = Field(default=None, max_length=150)
    manufacturer: Optional[str] = Field(default=None, max_length=100)
    model: Optional[str] = Field(default=None, max_length=150)
    storage_type: Optional[str] = Field(default=None, max_length=50)
    storage_capacity_gb: Optional[int] = Field(default=None, ge=1, le=10_000_000)
    owner_department: Optional[str] = Field(default=None, max_length=150)
    date_received: Optional[date] = None
    intended_destination: Optional[str] = Field(default=None, max_length=100)
    notes: Optional[str] = None
    lifecycle_status: Optional[AssetLifecycleStatus] = None


class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_tag: str
    serial_number: Optional[str]
    asset_type: AssetType
    lifecycle_status: AssetLifecycleStatus
    manufacturer: Optional[str]
    model: Optional[str]
    storage_type: Optional[str]
    storage_capacity_gb: Optional[int]
    owner_department: Optional[str]
    date_received: Optional[date]
    intended_destination: Optional[str]
    notes: Optional[str]
    created_at: datetime
    updated_at: datetime
