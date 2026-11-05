"""Pydantic response contracts for lifecycle audit events."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict

from app.models.enums import AssetLifecycleStatus, LifecycleEventType


class LifecycleEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_id: str
    event_type: LifecycleEventType
    previous_status: Optional[AssetLifecycleStatus]
    new_status: Optional[AssetLifecycleStatus]
    note: Optional[str]
    occurred_at: datetime
