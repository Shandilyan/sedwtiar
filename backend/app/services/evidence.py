"""Evidence, certificate, custody, and disposition services with append-only APIs."""

from hashlib import sha256
from json import dumps
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import (
    Asset,
    ChainOfCustodyEvent,
    DispositionRecommendation,
    IndependentVerification,
    LifecycleEvent,
    SanitizationJob,
    SanitizationRecord,
    TamperEvidentCertificate,
)
from app.models.enums import AssetLifecycleStatus, CustodyEventType, LifecycleEventType, VerificationOutcome
from app.schemas.certificate import CertificateVerificationRead, TamperEvidentCertificateCreate
from app.services.certificate_signing import (
    CertificateSigningError,
    local_signing_key_identity,
    sign_certificate_hash,
    verify_certificate_hash,
)
from app.schemas.custody import ChainOfCustodyEventCreate
from app.schemas.disposition import DispositionRecommendationCreate
from app.schemas.verification import IndependentVerificationCreate
from app.services.exceptions import (
    BusinessRuleError,
    ResourceConflictError,
    ResourceNotFoundError,
    SecurityPolicyViolationError,
)
from app.services.sanitization_jobs import controlled_simulation_evidence_hash


def get_record(db: Session, record_id: str) -> SanitizationRecord:
    record = db.get(SanitizationRecord, record_id)
    if record is None:
        raise ResourceNotFoundError("Sanitization record not found")
    return record


def create_verification(
    db: Session, record: SanitizationRecord, payload: IndependentVerificationCreate
) -> IndependentVerification:
    verification = IndependentVerification(sanitization_record_id=record.id, **payload.model_dump())
    db.add(verification)
    db.commit()
    db.refresh(verification)
    return verification


def run_demo_verification(db: Session, record: SanitizationRecord) -> IndependentVerification:
    """Verify deterministic simulation evidence only; this does not inspect physical media."""
    if record.job is None:
        raise BusinessRuleError("Demo verification requires evidence linked to a sanitization job")
    job = record.job
    expected_hash = controlled_simulation_evidence_hash(record.asset_id, job.id, job.planned_method)
    if not record.notes or not record.notes.startswith("CONTROLLED SANITIZATION SIMULATION"):
        raise BusinessRuleError("This evidence record was not produced by the controlled demo simulation")
    existing = db.scalar(
        select(IndependentVerification)
        .where(
            IndependentVerification.sanitization_record_id == record.id,
            IndependentVerification.verification_method == "Controlled demo evidence integrity verification",
        )
        .limit(1)
    )
    if existing is not None:
        return existing
    passed = record.evidence_hash == expected_hash
    verification = IndependentVerification(
        sanitization_record_id=record.id,
        outcome=VerificationOutcome.PASSED if passed else VerificationOutcome.FAILED,
        verifier_name="Independent demo verifier",
        verification_method="Controlled demo evidence integrity verification",
        evidence_hash=record.evidence_hash,
        findings=(
            "Deterministic controlled simulation evidence matched the expected integrity hash. "
            "No physical media was inspected or modified."
            if passed
            else "Demo evidence integrity hash did not match the expected deterministic value."
        ),
        verified_at=datetime.now(timezone.utc),
    )
    db.add(verification)
    if passed:
        db.add(
            LifecycleEvent(
                asset_id=record.asset_id,
                event_type=LifecycleEventType.DEMO_VERIFICATION_PASSED,
                note="Independent demo verification passed against controlled simulation evidence.",
            )
        )
    db.commit()
    db.refresh(verification)
    return verification


def get_verification(db: Session, verification_id: str) -> IndependentVerification:
    verification = db.get(IndependentVerification, verification_id)
    if verification is None:
        raise ResourceNotFoundError("Independent verification not found")
    return verification


def list_record_verifications(db: Session, record_id: str) -> list[IndependentVerification]:
    get_record(db, record_id)
    return list(
        db.scalars(
            select(IndependentVerification)
            .where(IndependentVerification.sanitization_record_id == record_id)
            .order_by(IndependentVerification.created_at.asc())
        )
    )


def _certificate_hash(
    payload: TamperEvidentCertificateCreate,
    verification_id: str,
    previous_hash: str | None,
    signing_key_id: str | None = None,
    public_key: str | None = None,
) -> str:
    issued_at = payload.issued_at
    if issued_at.tzinfo is None:
        issued_at = issued_at.replace(tzinfo=timezone.utc)
    else:
        issued_at = issued_at.astimezone(timezone.utc)
    canonical_payload = {
        "certificate_number": payload.certificate_number,
        "certificate_version": "v2-ed25519",
        "hash_algorithm": payload.hash_algorithm,
        "issuer": payload.issuer,
        "issued_at": issued_at.isoformat(),
        "payload_hash": payload.payload_hash,
        "previous_certificate_hash": previous_hash,
        "public_key": public_key,
        "signing_key_id": signing_key_id,
        "verification_id": verification_id,
    }
    return sha256(dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def create_certificate(
    db: Session, verification: IndependentVerification, payload: TamperEvidentCertificateCreate
) -> TamperEvidentCertificate:
    if verification.outcome != VerificationOutcome.PASSED:
        raise BusinessRuleError("A certificate can be issued only for a passed verification")
    previous_hash = db.scalar(
        select(TamperEvidentCertificate.certificate_hash)
        .order_by(TamperEvidentCertificate.created_at.desc())
        .limit(1)
    )
    # The service, rather than the API caller, selects the certificate signer.
    # This prevents a request from claiming an arbitrary signature.
    try:
        signer = sign_certificate_hash("0" * 64)  # Establish key identity before the canonical hash is built.
    except CertificateSigningError as exc:
        raise BusinessRuleError(f"Certificate signing is unavailable: {exc}") from exc
    certificate_hash = _certificate_hash(
        payload, verification.id, previous_hash, signer["signing_key_id"], signer["public_key"]
    )
    try:
        signer = sign_certificate_hash(certificate_hash)
    except CertificateSigningError as exc:
        raise BusinessRuleError(f"Certificate signing is unavailable: {exc}") from exc
    certificate = TamperEvidentCertificate(
        verification_id=verification.id,
        previous_certificate_hash=previous_hash,
        certificate_hash=certificate_hash,
        certificate_version="v2-ed25519",
        signature=signer["signature"],
        signature_algorithm=signer["signature_algorithm"],
        signing_key_id=signer["signing_key_id"],
        public_key=signer["public_key"],
        **payload.model_dump(),
    )
    db.add(certificate)
    db.add(
        LifecycleEvent(
            asset_id=verification.sanitization_record.asset_id,
            event_type=LifecycleEventType.CERTIFICATE_ISSUED,
            note="Tamper-evident certificate issued with a local Ed25519 signature and SHA-256 integrity chain.",
        )
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ResourceConflictError("certificate_number already exists or a certificate already exists for this verification") from exc
    db.refresh(certificate)
    return certificate


def get_certificate(db: Session, certificate_id: str) -> TamperEvidentCertificate:
    certificate = db.get(TamperEvidentCertificate, certificate_id)
    if certificate is None:
        raise ResourceNotFoundError("Certificate not found")
    return certificate


def verify_certificate(db: Session, certificate: TamperEvidentCertificate) -> CertificateVerificationRead:
    """Verify the stored canonical hash and Ed25519 signature without issuing a new certificate."""
    legacy_payload = TamperEvidentCertificateCreate(
        certificate_number=certificate.certificate_number,
        issuer=certificate.issuer,
        payload_hash=certificate.payload_hash,
        hash_algorithm=certificate.hash_algorithm,
        issued_at=certificate.issued_at,
    )
    if certificate.certificate_version == "v1-hash-chain":
        legacy_canonical_payload = {
            "certificate_number": certificate.certificate_number,
            "hash_algorithm": certificate.hash_algorithm,
            "issuer": certificate.issuer,
            "issued_at": certificate.issued_at.isoformat(),
            "payload_hash": certificate.payload_hash,
            "previous_certificate_hash": certificate.previous_certificate_hash,
            "signature": certificate.signature,
            "signature_algorithm": certificate.signature_algorithm,
            "verification_id": certificate.verification_id,
        }
        expected_hash = sha256(
            dumps(legacy_canonical_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        integrity_hash_valid = expected_hash == certificate.certificate_hash
    else:
        expected_hash = _certificate_hash(
            legacy_payload,
            certificate.verification_id,
            certificate.previous_certificate_hash,
            certificate.signing_key_id,
            certificate.public_key,
        )
        integrity_hash_valid = certificate.certificate_version == "v2-ed25519" and expected_hash == certificate.certificate_hash
    signature_valid = bool(
        integrity_hash_valid
        and certificate.signature_algorithm == "Ed25519"
        and certificate.signature
        and certificate.public_key
        and verify_certificate_hash(certificate.certificate_hash, certificate.signature, certificate.public_key)
    )
    local_identity = local_signing_key_identity()
    locally_trusted = bool(
        local_identity
        and certificate.signing_key_id == local_identity[0]
        and certificate.public_key == local_identity[1]
    )
    if certificate.certificate_version == "v1-hash-chain" and integrity_hash_valid:
        status_value = "LEGACY_HASH_VALID"
        detail = "The legacy SHA-256 hash-chain record is internally consistent but was not Ed25519 signed."
    elif signature_valid and locally_trusted:
        status_value = "VALID"
        detail = "The certificate hash and Ed25519 signature are valid for this local signing identity."
    elif signature_valid:
        status_value = "VALID_UNTRUSTED_KEY"
        detail = "The certificate hash and Ed25519 signature are valid, but this workstation does not recognize the signer as its local development key."
    else:
        status_value = "INVALID"
        detail = "The certificate hash or Ed25519 signature did not validate. Do not rely on this certificate."
    return CertificateVerificationRead(
        certificate_id=certificate.id,
        certificate_number=certificate.certificate_number,
        certificate_version=certificate.certificate_version,
        integrity_hash_valid=integrity_hash_valid,
        signature_valid=signature_valid,
        locally_trusted_signing_key=locally_trusted,
        status=status_value,
        detail=detail,
    )


def get_verification_certificate(
    db: Session, verification: IndependentVerification
) -> TamperEvidentCertificate:
    """Return the one certificate associated with a verification, if issued."""
    certificate = verification.certificate
    if certificate is None:
        raise ResourceNotFoundError("No certificate has been issued for this verification")
    return certificate


def create_custody_event(
    db: Session, asset: Asset, payload: ChainOfCustodyEventCreate
) -> ChainOfCustodyEvent:
    if payload.event_type == CustodyEventType.RELEASED:
        # Mandatory Security Requirement: An asset must not be released until
        # its sanitization has been successfully verified.
        passed_verification = db.scalar(
            select(IndependentVerification.id)
            .join(SanitizationRecord)
            .where(
                SanitizationRecord.asset_id == asset.id,
                IndependentVerification.outcome == VerificationOutcome.PASSED,
            )
            .limit(1)
        )
        if passed_verification is None and asset.lifecycle_status != AssetLifecycleStatus.SANITIZED:
            raise SecurityPolicyViolationError(
                "Security policy violation: Asset cannot be released until its sanitization "
                "has been successfully verified."
            )

    event = ChainOfCustodyEvent(asset_id=asset.id, **payload.model_dump())
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def list_custody_events(db: Session, asset_id: str) -> list[ChainOfCustodyEvent]:
    if db.get(Asset, asset_id) is None:
        raise ResourceNotFoundError("Asset not found")
    return list(
        db.scalars(
            select(ChainOfCustodyEvent)
            .where(ChainOfCustodyEvent.asset_id == asset_id)
            .order_by(ChainOfCustodyEvent.occurred_at.asc())
        )
    )


def create_disposition_recommendation(
    db: Session, asset: Asset, payload: DispositionRecommendationCreate
) -> DispositionRecommendation:
    job = db.get(SanitizationJob, payload.sanitization_job_id) if payload.sanitization_job_id else None
    if payload.sanitization_job_id and (job is None or job.asset_id != asset.id):
        raise BusinessRuleError("sanitization_job_id must reference a job for this asset")
    verification = db.get(IndependentVerification, payload.verification_id) if payload.verification_id else None
    if payload.verification_id and (
        verification is None or verification.sanitization_record.asset_id != asset.id
    ):
        raise BusinessRuleError("verification_id must reference evidence for this asset")
    recommendation = DispositionRecommendation(asset_id=asset.id, **payload.model_dump())
    db.add(recommendation)
    db.add(
        LifecycleEvent(
            asset_id=asset.id,
            event_type=LifecycleEventType.DISPOSITION_RECOMMENDED,
            note=f"Disposition recommendation recorded: {payload.recommendation.value}.",
        )
    )
    db.commit()
    db.refresh(recommendation)
    return recommendation


def get_disposition_recommendation(db: Session, recommendation_id: str) -> DispositionRecommendation:
    recommendation = db.get(DispositionRecommendation, recommendation_id)
    if recommendation is None:
        raise ResourceNotFoundError("Disposition recommendation not found")
    return recommendation


def list_disposition_recommendations(db: Session, asset_id: str) -> list[DispositionRecommendation]:
    if db.get(Asset, asset_id) is None:
        raise ResourceNotFoundError("Asset not found")
    return list(
        db.scalars(
            select(DispositionRecommendation)
            .where(DispositionRecommendation.asset_id == asset_id)
            .order_by(DispositionRecommendation.created_at.asc())
        )
    )
