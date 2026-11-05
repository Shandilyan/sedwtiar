"""Read-only dashboard metrics calculated from persisted application data."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (
    Asset,
    DispositionRecommendation,
    LifecycleEvent,
    SanitizationJob,
    TamperEvidentCertificate,
)
from app.models.enums import DispositionType, SanitizationJobStatus
from app.schemas.dashboard import DashboardActivityRead, DashboardSummaryRead


def dashboard_summary(db: Session) -> DashboardSummaryRead:
    total_assets = db.scalar(select(func.count()).select_from(Asset)) or 0
    jobs = db.scalar(select(func.count()).select_from(SanitizationJob)) or 0
    verified_assets = db.scalar(
        select(func.count(func.distinct(SanitizationJob.asset_id))).where(
            SanitizationJob.status == SanitizationJobStatus.VERIFIED
        )
    ) or 0
    certificates = db.scalar(select(func.count()).select_from(TamperEvidentCertificate)) or 0
    reuse = db.scalar(
        select(func.count()).select_from(DispositionRecommendation).where(
            DispositionRecommendation.recommendation.in_([DispositionType.REDEPLOY, DispositionType.DONATE])
        )
    ) or 0
    recycle = db.scalar(
        select(func.count()).select_from(DispositionRecommendation).where(
            DispositionRecommendation.recommendation == DispositionType.RECYCLE
        )
    ) or 0
    rows = db.execute(
        select(LifecycleEvent, Asset.asset_tag)
        .join(Asset)
        .order_by(LifecycleEvent.occurred_at.desc())
        .limit(10)
    ).all()
    return DashboardSummaryRead(
        total_assets=total_assets,
        sanitization_jobs=jobs,
        verified_assets=verified_assets,
        certificates=certificates,
        reuse=reuse,
        recycle=recycle,
        recent_activity=[
            DashboardActivityRead(
                asset_id=event.asset_id,
                asset_tag=asset_tag,
                event_type=event.event_type.value,
                note=event.note,
                occurred_at=event.occurred_at,
            )
            for event, asset_tag in rows
        ],
    )
