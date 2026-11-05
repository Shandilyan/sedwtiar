"""Pydantic contracts for append-only custody events."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.enums import CustodyEventType


class ChainOfCustodyEventCreate(BaseModel):
    event_type: CustodyEventType
    from_custodian: Optional[str] = Field(default=None, max_length=150)
    to_custodian: Optional[str] = Field(default=None, max_length=150)
    location: Optional[str] = Field(default=None, max_length=255)
    recorded_by: str = Field(min_length=1, max_length=150)
    note: Optional[str] = None
    occurred_at: datetime

    @model_validator(mode="after")
    def require_counterparty_for_transfer(self) -> "ChainOfCustodyEventCreate":
        if self.event_type == CustodyEventType.TRANSFERRED and (
            not self.from_custodian or not self.to_custodian
        ):
            raise ValueError("from_custodian and to_custodian are required for a transfer")
        return self


class ChainOfCustodyEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_id: str
    event_type: CustodyEventType
    from_custodian: Optional[str]
    to_custodian: Optional[str]
    location: Optional[str]
    recorded_by: str
    note: Optional[str]
    occurred_at: datetime
    created_at: datetime
