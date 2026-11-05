"""Read-only dashboard metrics calculated from persisted PostgreSQL data."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class DashboardActivityRead(BaseModel):
    asset_id: str
    asset_tag: str
    event_type: str
    note: Optional[str]
    occurred_at: datetime


class DashboardSummaryRead(BaseModel):
    total_assets: int
    sanitization_jobs: int
    verified_assets: int
    certificates: int
    reuse: int
    recycle: int
    recent_activity: list[DashboardActivityRead]
