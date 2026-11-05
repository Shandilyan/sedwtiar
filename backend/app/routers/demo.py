"""Clearly labelled, non-destructive endpoints used only by the live demonstration."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.dashboard import DashboardSummaryRead
from app.schemas.demo import (
    ControlledSimulationRead,
    DemoAssetRead,
    DemoInspectionCreate,
    DemoInspectionRead,
    DemoVerificationRead,
    DispositionRuleRead,
    SanitizationRecommendationRead,
)
from app.services import assets as asset_service
from app.services import dashboard as dashboard_service
from app.services import demo as demo_service
from app.services import evidence as evidence_service
from app.services import sanitization_jobs as job_service
from app.services.exceptions import BusinessRuleError, InvalidStateTransitionError, ResourceNotFoundError

asset_demo_router = APIRouter(prefix="/assets/{asset_id}", tags=["Controlled demo"])
job_demo_router = APIRouter(prefix="/sanitization-jobs", tags=["Controlled demo"])
record_demo_router = APIRouter(prefix="/sanitization-records", tags=["Controlled demo"])
demo_router = APIRouter(prefix="/demo", tags=["Controlled demo"])
dashboard_router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


def _not_found(error: ResourceNotFoundError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))


def _unprocessable(error: Exception) -> HTTPException:
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(error))


@demo_router.post("/assets", response_model=DemoAssetRead, status_code=status.HTTP_201_CREATED)
def create_demo_asset(db: Session = Depends(get_db)) -> DemoAssetRead:
    asset = asset_service.create_demo_asset(db)
    return DemoAssetRead(
        asset=asset,
        message="Demo asset created. It contains controlled demo metadata only.",
    )


@asset_demo_router.post("/demo-inspections", response_model=DemoInspectionRead, status_code=status.HTTP_201_CREATED)
def create_demo_inspection(
    asset_id: str,
    payload: DemoInspectionCreate,
    db: Session = Depends(get_db),
) -> DemoInspectionRead:
    try:
        return demo_service.create_demo_inspection(db, asset_service.get_asset(db, asset_id), payload)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


@asset_demo_router.get("/demo-inspections/latest", response_model=DemoInspectionRead)
def get_latest_demo_inspection(asset_id: str, db: Session = Depends(get_db)) -> DemoInspectionRead:
    try:
        return demo_service.latest_demo_inspection(db, asset_id)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


@asset_demo_router.get("/sanitization-recommendation", response_model=SanitizationRecommendationRead)
def get_sanitization_recommendation(
    asset_id: str, db: Session = Depends(get_db)
) -> SanitizationRecommendationRead:
    try:
        return demo_service.recommend_sanitization(db, asset_service.get_asset(db, asset_id))
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


@asset_demo_router.get("/disposition-rule", response_model=DispositionRuleRead)
def get_disposition_rule(asset_id: str, db: Session = Depends(get_db)) -> DispositionRuleRead:
    try:
        return demo_service.recommend_disposition(db, asset_service.get_asset(db, asset_id))
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


@job_demo_router.post("/{job_id}/controlled-simulation", response_model=ControlledSimulationRead)
def run_controlled_sanitization_simulation(
    job_id: str, db: Session = Depends(get_db)
) -> ControlledSimulationRead:
    try:
        job = job_service.get_job(db, job_id)
        evidence = job_service.run_controlled_simulation(db, job)
        return ControlledSimulationRead(
            job=job,
            evidence=evidence,
            simulation_status="completed",
            safety_notice="SIMULATION ONLY — NO PHYSICAL DRIVE WAS MODIFIED.",
            evidence_integrity_hash=evidence.evidence_hash or "",
        )
    except ResourceNotFoundError as error:
        raise _not_found(error) from error
    except (BusinessRuleError, InvalidStateTransitionError) as error:
        raise _unprocessable(error) from error


@record_demo_router.post("/{record_id}/run-demo-verification", response_model=DemoVerificationRead)
def run_independent_demo_verification(
    record_id: str, db: Session = Depends(get_db)
) -> DemoVerificationRead:
    try:
        record = evidence_service.get_record(db, record_id)
        verification = evidence_service.run_demo_verification(db, record)
        job_status = record.job.status if record.job is not None else None
        return DemoVerificationRead(
            verification=verification,
            job_status=job_status,
            evidence_integrity_hash=record.evidence_hash or "",
            verification_message=(
                "Verification passed: deterministic controlled simulation evidence matched. "
                "No physical media was inspected or modified."
                if verification.outcome.value == "passed"
                else "Verification failed: deterministic controlled simulation evidence did not match."
            ),
        )
    except ResourceNotFoundError as error:
        raise _not_found(error) from error
    except BusinessRuleError as error:
        raise _unprocessable(error) from error


@dashboard_router.get("/summary", response_model=DashboardSummaryRead)
def get_dashboard_summary(db: Session = Depends(get_db)) -> DashboardSummaryRead:
    return dashboard_service.dashboard_summary(db)
