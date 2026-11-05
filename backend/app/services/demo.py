"""Safe demonstration helpers: simulated inspection and transparent rules only."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, DemoInspection, IndependentVerification, LifecycleEvent, SanitizationRecord
from app.models.enums import DemoInspectionStatus, DispositionType, LifecycleEventType, VerificationOutcome
from app.schemas.demo import DemoInspectionCreate, DispositionRuleRead, SanitizationRecommendationRead
from app.services.exceptions import ResourceNotFoundError


def latest_demo_inspection(db: Session, asset_id: str) -> DemoInspection:
    inspection = db.scalar(
        select(DemoInspection)
        .where(DemoInspection.asset_id == asset_id)
        .order_by(DemoInspection.created_at.desc())
        .limit(1)
    )
    if inspection is None:
        raise ResourceNotFoundError("No demo inspection has been recorded for this asset")
    return inspection


def create_demo_inspection(
    db: Session, asset: Asset, payload: DemoInspectionCreate
) -> DemoInspection:
    """Persist user-supplied demo values; no hardware detection takes place."""
    inspection = DemoInspection(
        asset_id=asset.id,
        status=DemoInspectionStatus.COMPLETED,
        notes=payload.notes or "Simulated inspection for demonstration; no physical device was queried.",
        **payload.model_dump(exclude={"notes"}),
    )
    db.add(inspection)
    db.add(
        LifecycleEvent(
            asset_id=asset.id,
            event_type=LifecycleEventType.DEMO_INSPECTION_RECORDED,
            note="Demo inspection completed using controlled demonstration data; no physical device was detected.",
        )
    )
    db.commit()
    db.refresh(inspection)
    return inspection


def recommend_sanitization(db: Session, asset: Asset) -> SanitizationRecommendationRead:
    """Explainable deterministic policy logic, intentionally not AI or ML."""
    inspection = db.scalar(
        select(DemoInspection)
        .where(DemoInspection.asset_id == asset.id)
        .order_by(DemoInspection.created_at.desc())
        .limit(1)
    )
    storage_type = (inspection.storage_type if inspection else asset.storage_type or "unknown").upper()
    destination = (asset.intended_destination or "unspecified").lower()
    rationale = [f"Target storage type is {storage_type}.", f"Intended destination is {destination}."]
    if storage_type == "SSD" and destination in {"reuse", "redeploy", "resale", "donate"}:
        method = "SSD Secure Sanitization / Purge-oriented workflow"
        rationale.extend(
            [
                "Ordinary file deletion is insufficient to represent media sanitization.",
                "The controlled demo selects the SSD sanitization workflow for reuse-oriented disposition.",
            ]
        )
        rule_name = "SSD + reuse-oriented destination"
    else:
        method = "Controlled sanitization evidence workflow"
        rationale.append("The demo uses a conservative evidence workflow because the SSD/reuse rule does not apply.")
        rule_name = "Fallback controlled workflow"
    return SanitizationRecommendationRead(
        asset_id=asset.id,
        recommended_method=method,
        recommendation_status="recommended",
        rationale=rationale,
        safety_notice="RULE-BASED DEMO ONLY — no AI/ML decision and no physical-media action is performed.",
        rule_name=rule_name,
    )


def recommend_disposition(db: Session, asset: Asset) -> DispositionRuleRead:
    """Deterministic demonstration rule based on stored inspection and verification data."""
    inspection = db.scalar(
        select(DemoInspection)
        .where(DemoInspection.asset_id == asset.id)
        .order_by(DemoInspection.created_at.desc())
        .limit(1)
    )
    passed_verification = db.scalar(
        select(IndependentVerification.id)
        .join(SanitizationRecord)
        .where(
            SanitizationRecord.asset_id == asset.id,
            IndependentVerification.outcome == VerificationOutcome.PASSED,
        )
        .limit(1)
    )
    health = inspection.health_percent if inspection else None
    if health is not None and health >= 80 and passed_verification is not None:
        recommendation = DispositionType.REDEPLOY
        rationale = (
            f"Asset passed sanitization verification and has a recorded demo health value of {health}%, "
            "so reuse is recommended under the demonstration rule."
        )
        rule_name = "health >= 80% AND verification = PASS"
    elif health is not None and passed_verification is not None:
        recommendation = DispositionType.DONATE
        rationale = (
            f"Asset passed sanitization verification and has a recorded demo health value of {health}%, "
            "so resale/refurbishment is recommended under the demonstration rule."
        )
        rule_name = "health < 80% AND verification = PASS"
    else:
        recommendation = DispositionType.RECYCLE
        rationale = (
            "A passed verification and recorded demo health value are required before reuse-oriented disposition; "
            "the demonstration rule recommends recycling otherwise."
        )
        rule_name = "missing inspection health or passed verification"
    return DispositionRuleRead(
        asset_id=asset.id,
        recommendation=recommendation,
        rationale=rationale,
        rule_name=rule_name,
    )
