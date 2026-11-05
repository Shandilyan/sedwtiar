"""Endpoints for evidence, certificates, custody, and disposition records."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.certificate import (
    CertificateVerificationRead,
    TamperEvidentCertificateCreate,
    TamperEvidentCertificateRead,
)
from app.schemas.custody import ChainOfCustodyEventCreate, ChainOfCustodyEventRead
from app.schemas.disposition import DispositionRecommendationCreate, DispositionRecommendationRead
from app.schemas.verification import IndependentVerificationCreate, IndependentVerificationRead
from app.services import assets as asset_service
from app.services import evidence as evidence_service
from app.services.exceptions import BusinessRuleError, ResourceConflictError, ResourceNotFoundError

asset_custody_router = APIRouter(prefix="/assets/{asset_id}/chain-of-custody", tags=["Chain of custody"])
asset_disposition_router = APIRouter(
    prefix="/assets/{asset_id}/disposition-recommendations", tags=["Disposition recommendations"]
)
record_verifications_router = APIRouter(
    prefix="/sanitization-records/{record_id}/verifications", tags=["Independent verifications"]
)
verification_certificates_router = APIRouter(
    prefix="/verifications/{verification_id}/certificate", tags=["Tamper-evident certificates"]
)
router = APIRouter(tags=["Evidence"])


def _not_found(error: ResourceNotFoundError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))


def _unprocessable(error: BusinessRuleError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(error))


@record_verifications_router.post("", response_model=IndependentVerificationRead, status_code=status.HTTP_201_CREATED)
def create_independent_verification(
    record_id: str,
    payload: IndependentVerificationCreate,
    db: Session = Depends(get_db),
) -> IndependentVerificationRead:
    try:
        return evidence_service.create_verification(db, evidence_service.get_record(db, record_id), payload)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


@record_verifications_router.get("", response_model=list[IndependentVerificationRead])
def list_independent_verifications(
    record_id: str, db: Session = Depends(get_db)
) -> list[IndependentVerificationRead]:
    try:
        return evidence_service.list_record_verifications(db, record_id)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


@router.get("/verifications/{verification_id}", response_model=IndependentVerificationRead)
def get_independent_verification(
    verification_id: str, db: Session = Depends(get_db)
) -> IndependentVerificationRead:
    try:
        return evidence_service.get_verification(db, verification_id)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


@verification_certificates_router.post("", response_model=TamperEvidentCertificateRead, status_code=status.HTTP_201_CREATED)
def create_tamper_evident_certificate(
    verification_id: str,
    payload: TamperEvidentCertificateCreate,
    db: Session = Depends(get_db),
) -> TamperEvidentCertificateRead:
    try:
        verification = evidence_service.get_verification(db, verification_id)
        return evidence_service.create_certificate(db, verification, payload)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error
    except BusinessRuleError as error:
        raise _unprocessable(error) from error
    except ResourceConflictError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error)) from error


@verification_certificates_router.get("", response_model=TamperEvidentCertificateRead)
def get_verification_certificate(
    verification_id: str, db: Session = Depends(get_db)
) -> TamperEvidentCertificateRead:
    try:
        return evidence_service.get_verification_certificate(
            db, evidence_service.get_verification(db, verification_id)
        )
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


@router.get("/certificates/{certificate_id}", response_model=TamperEvidentCertificateRead)
def get_tamper_evident_certificate(
    certificate_id: str, db: Session = Depends(get_db)
) -> TamperEvidentCertificateRead:
    try:
        return evidence_service.get_certificate(db, certificate_id)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


@router.get("/certificates/{certificate_id}/verify", response_model=CertificateVerificationRead)
def verify_tamper_evident_certificate(
    certificate_id: str, db: Session = Depends(get_db)
) -> CertificateVerificationRead:
    try:
        return evidence_service.verify_certificate(
            db, evidence_service.get_certificate(db, certificate_id)
        )
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


@asset_custody_router.post("", response_model=ChainOfCustodyEventRead, status_code=status.HTTP_201_CREATED)
def create_chain_of_custody_event(
    asset_id: str,
    payload: ChainOfCustodyEventCreate,
    db: Session = Depends(get_db),
) -> ChainOfCustodyEventRead:
    try:
        return evidence_service.create_custody_event(db, asset_service.get_asset(db, asset_id), payload)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


@asset_custody_router.get("", response_model=list[ChainOfCustodyEventRead])
def list_chain_of_custody_events(
    asset_id: str, db: Session = Depends(get_db)
) -> list[ChainOfCustodyEventRead]:
    try:
        return evidence_service.list_custody_events(db, asset_id)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


@asset_disposition_router.post("", response_model=DispositionRecommendationRead, status_code=status.HTTP_201_CREATED)
def create_disposition_recommendation(
    asset_id: str,
    payload: DispositionRecommendationCreate,
    db: Session = Depends(get_db),
) -> DispositionRecommendationRead:
    try:
        return evidence_service.create_disposition_recommendation(
            db, asset_service.get_asset(db, asset_id), payload
        )
    except ResourceNotFoundError as error:
        raise _not_found(error) from error
    except BusinessRuleError as error:
        raise _unprocessable(error) from error


@asset_disposition_router.get("", response_model=list[DispositionRecommendationRead])
def list_disposition_recommendations(
    asset_id: str, db: Session = Depends(get_db)
) -> list[DispositionRecommendationRead]:
    try:
        return evidence_service.list_disposition_recommendations(db, asset_id)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error


@router.get("/disposition-recommendations/{recommendation_id}", response_model=DispositionRecommendationRead)
def get_disposition_recommendation(
    recommendation_id: str, db: Session = Depends(get_db)
) -> DispositionRecommendationRead:
    try:
        return evidence_service.get_disposition_recommendation(db, recommendation_id)
    except ResourceNotFoundError as error:
        raise _not_found(error) from error
