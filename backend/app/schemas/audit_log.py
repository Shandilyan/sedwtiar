"""Public read contract for append-only audit entries."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.enums import AuditOutcome


class AuditLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    actor_user_id: str | None
    action: str
    resource_type: str
    resource_id: str | None
    outcome: AuditOutcome
    details: dict[str, Any] | None
    occurred_at: datetime
