"""Append-only security audit-log helpers."""

from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLog
from app.models.enums import AuditOutcome


def record_audit_log(
    db: Session,
    *,
    action: str,
    resource_type: str,
    outcome: AuditOutcome,
    actor_user_id: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
) -> AuditLog:
    """Stage an immutable audit entry in the caller's current transaction.

    Callers must never include passwords, tokens, or other secrets in ``details``.
    """
    audit_log = AuditLog(
        actor_user_id=actor_user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        details=details,
    )
    db.add(audit_log)
    return audit_log


def list_audit_logs(
    db: Session,
    *,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    actor_user_id: Optional[str] = None,
    limit: int = 100,
) -> list[AuditLog]:
    """Read audit history; no service operation updates or deletes log rows."""
    statement = select(AuditLog).order_by(AuditLog.occurred_at.desc()).limit(limit)
    if resource_type is not None:
        statement = statement.where(AuditLog.resource_type == resource_type)
    if resource_id is not None:
        statement = statement.where(AuditLog.resource_id == resource_id)
    if actor_user_id is not None:
        statement = statement.where(AuditLog.actor_user_id == actor_user_id)
    return list(db.scalars(statement))
