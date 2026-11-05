"""Non-destructive tests using an in-memory SQLite database only."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi.openapi.utils import get_openapi
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# These values only allow the application modules to load. No PostgreSQL connection is made.
os.environ.setdefault("DB_HOST", "test-host")
os.environ.setdefault("DB_PORT", "5432")
os.environ.setdefault("DB_NAME", "test-db")
os.environ.setdefault("DB_USER", "test-user")
os.environ.setdefault("DB_PASSWORD", "test-password")
os.environ.setdefault(
    "SEDWTIAR_SIGNING_KEY_PATH",
    str(Path(tempfile.mkdtemp(prefix="sedwtiar-signing-test-")) / "certificate-ed25519.dpapi"),
)

from app.database import Base  # noqa: E402
from app.main import app, health_check  # noqa: E402
from app.models.enums import (  # noqa: E402
    AssetLifecycleStatus,
    AssetType,
    CustodyEventType,
    DispositionType,
    SanitizationJobStatus,
    SanitizationRecordStatus,
    VerificationOutcome,
    RoleName,
)
from app.schemas.identity import UserCreate, UserRead  # noqa: E402
from app.schemas.asset import AssetCreate, AssetUpdate  # noqa: E402
from app.schemas.certificate import TamperEvidentCertificateCreate  # noqa: E402
from app.schemas.custody import ChainOfCustodyEventCreate  # noqa: E402
from app.schemas.disposition import DispositionRecommendationCreate  # noqa: E402
from app.schemas.demo import DemoInspectionCreate  # noqa: E402
from app.schemas.sanitization_job import SanitizationJobCreate, SanitizationJobStatusUpdate  # noqa: E402
from app.schemas.sanitization_record import SanitizationRecordCreate  # noqa: E402
from app.schemas.verification import IndependentVerificationCreate  # noqa: E402
from app.routers.system import database_readiness  # noqa: E402
from app.services import assets as asset_service  # noqa: E402
from app.services import evidence as evidence_service  # noqa: E402
from app.services import sanitization_jobs as job_service  # noqa: E402
from app.services import sanitization_records as record_service  # noqa: E402
from app.services import audit_logs as audit_log_service  # noqa: E402
from app.services import dashboard as dashboard_service  # noqa: E402
from app.services import demo as demo_service  # noqa: E402
from app.services import users as user_service  # noqa: E402


class FoundationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.session = Session(self.engine)

    def tearDown(self) -> None:
        self.session.close()
        self.engine.dispose()

    def test_health_endpoint_function(self) -> None:
        self.assertEqual(
            health_check(), {"status": "ok", "service": "sedwtiar-backend"}
        )

    def test_versioned_routes_are_registered(self) -> None:
        paths = set(
            get_openapi(title=app.title, version=app.version, routes=app.routes)["paths"]
        )
        self.assertTrue(
            {
                "/api/v1/system/readiness",
                "/api/v1/assets",
                "/api/v1/assets/{asset_id}",
                "/api/v1/assets/{asset_id}/events",
                "/api/v1/assets/{asset_id}/sanitization-records",
                "/api/v1/sanitization-records/{record_id}",
                "/api/v1/sanitization-jobs",
                "/api/v1/sanitization-jobs/{job_id}/status",
                "/api/v1/sanitization-jobs/{job_id}/records",
                "/api/v1/sanitization-records/{record_id}/verifications",
                "/api/v1/verifications/{verification_id}/certificate",
                "/api/v1/certificates/{certificate_id}",
                "/api/v1/certificates/{certificate_id}/verify",
                "/api/v1/assets/{asset_id}/chain-of-custody",
                "/api/v1/assets/{asset_id}/disposition-recommendations",
                "/api/v1/demo/assets",
                "/api/v1/assets/{asset_id}/demo-inspections",
                "/api/v1/assets/{asset_id}/demo-inspections/latest",
                "/api/v1/assets/{asset_id}/sanitization-recommendation",
                "/api/v1/assets/{asset_id}/disposition-rule",
                "/api/v1/sanitization-jobs/{job_id}/controlled-simulation",
                "/api/v1/sanitization-records/{record_id}/run-demo-verification",
                "/api/v1/dashboard/summary",
            }.issubset(paths)
        )

    def test_asset_lifecycle_and_record_are_persisted_in_memory(self) -> None:
        asset = asset_service.create_asset(
            self.session,
            AssetCreate(asset_tag="TEST-001", asset_type=AssetType.LAPTOP),
        )
        updated_asset = asset_service.update_asset(
            self.session,
            asset,
            AssetUpdate(lifecycle_status=AssetLifecycleStatus.PENDING_SANITIZATION),
        )
        record = record_service.create_sanitization_record(
            self.session,
            updated_asset,
            SanitizationRecordCreate(
                status=SanitizationRecordStatus.VERIFIED,
                method="Evidence import",
                verified_by="test operator",
                verified_at="2026-08-25T00:00:00Z",
                certificate_reference="TEST-CERT-001",
            ),
        )

        self.assertEqual(record.asset_id, asset.id)
        self.assertEqual(record.status, SanitizationRecordStatus.VERIFIED)
        self.assertEqual(len(asset_service.list_lifecycle_events(self.session, asset.id)), 3)
        self.assertEqual(
            len(record_service.list_asset_sanitization_records(self.session, asset.id)), 1
        )

    def test_readiness_accepts_an_in_memory_database(self) -> None:
        response = database_readiness(self.session)
        self.assertEqual(response.status, "ready")
        self.assertEqual(response.database, "reachable")

    def test_phase_two_evidence_workflow_is_record_only(self) -> None:
        asset = asset_service.create_asset(
            self.session,
            AssetCreate(asset_tag="TEST-002", asset_type=AssetType.DESKTOP),
        )
        job = job_service.create_job(
            self.session,
            SanitizationJobCreate(
                asset_id=asset.id,
                planned_method="Certificate evidence review",
                requested_by="test requester",
            ),
        )
        job_service.transition_job(
            self.session, job, SanitizationJobStatusUpdate(status=SanitizationJobStatus.PREPARED)
        )
        record = record_service.create_sanitization_record(
            self.session,
            asset,
            SanitizationRecordCreate(method="Evidence import"),
            job,
        )
        job_service.transition_job(
            self.session,
            job,
            SanitizationJobStatusUpdate(status=SanitizationJobStatus.EVIDENCE_RECORDED),
        )
        verification = evidence_service.create_verification(
            self.session,
            record,
            IndependentVerificationCreate(
                outcome=VerificationOutcome.PASSED,
                verifier_name="independent reviewer",
                verification_method="evidence review",
                verified_at="2026-09-01T00:00:00Z",
            ),
        )
        job_service.transition_job(
            self.session, job, SanitizationJobStatusUpdate(status=SanitizationJobStatus.VERIFIED)
        )
        certificate = evidence_service.create_certificate(
            self.session,
            verification,
            TamperEvidentCertificateCreate(
                certificate_number="TEST-CERT-P2-001",
                issuer="test issuer",
                payload_hash="evidence-hash",
                issued_at="2026-09-01T00:00:00Z",
            ),
        )
        custody_event = evidence_service.create_custody_event(
            self.session,
            asset,
            ChainOfCustodyEventCreate(
                event_type=CustodyEventType.TRANSFERRED,
                from_custodian="receiving team",
                to_custodian="review team",
                recorded_by="test recorder",
                occurred_at="2026-09-01T00:00:00Z",
            ),
        )
        recommendation = evidence_service.create_disposition_recommendation(
            self.session,
            asset,
            DispositionRecommendationCreate(
                sanitization_job_id=job.id,
                verification_id=verification.id,
                recommendation=DispositionType.REDEPLOY,
                rationale="Passed independent verification is recorded.",
                recommended_by="test reviewer",
            ),
        )

        self.assertEqual(job.status, SanitizationJobStatus.VERIFIED)
        self.assertEqual(certificate.verification_id, verification.id)
        self.assertEqual(len(certificate.certificate_hash), 64)
        self.assertIsNone(certificate.previous_certificate_hash)
        self.assertEqual(certificate.certificate_version, "v2-ed25519")
        self.assertEqual(certificate.signature_algorithm, "Ed25519")
        self.assertTrue(certificate.signature)
        self.assertTrue(certificate.public_key)
        certificate_check = evidence_service.verify_certificate(self.session, certificate)
        self.assertEqual(certificate_check.status, "VALID")
        self.assertEqual(custody_event.asset_id, asset.id)
        self.assertEqual(recommendation.asset_id, asset.id)
        self.assertEqual(len(job_service.list_job_events(self.session, job.id)), 4)

    def test_user_roles_password_hashing_and_audit_log_are_persisted(self) -> None:
        user = user_service.create_user(
            self.session,
            UserCreate(
                email="Operator@Example.Test",
                display_name="Demo Operator",
                password="a-safe-test-password",
                roles=[RoleName.OPERATOR, RoleName.VIEWER],
            ),
        )

        self.assertEqual(user.email, "operator@example.test")
        self.assertTrue(user_service.verify_password(user, "a-safe-test-password"))
        self.assertFalse(user_service.verify_password(user, "incorrect-password"))
        self.assertNotEqual(user.password_hash, "a-safe-test-password")
        self.assertEqual({role.name for role in user.roles}, {RoleName.OPERATOR, RoleName.VIEWER})
        self.assertEqual(len(user_service.ensure_default_roles(self.session)), 5)
        self.assertEqual(
            UserRead.model_validate(user).model_dump().get("password_hash"), None
        )
        audit_logs = audit_log_service.list_audit_logs(
            self.session, resource_type="user", resource_id=user.id
        )
        self.assertEqual(len(audit_logs), 1)
        self.assertEqual(audit_logs[0].action, "user.created")

    def test_controlled_demo_flow_uses_only_deterministic_evidence(self) -> None:
        asset = asset_service.create_asset(
            self.session,
            AssetCreate(
                asset_tag="IT-2026-001",
                asset_type=AssetType.LAPTOP,
                manufacturer="Dell",
                model="Latitude 5420",
                storage_type="SSD",
                storage_capacity_gb=512,
                intended_destination="reuse",
            ),
        )
        inspection = demo_service.create_demo_inspection(
            self.session, asset, DemoInspectionCreate()
        )
        recommendation = demo_service.recommend_sanitization(self.session, asset)
        job = job_service.create_job(
            self.session,
            SanitizationJobCreate(
                asset_id=asset.id,
                planned_method=recommendation.recommended_method,
                requested_by="Demo operator",
            ),
        )
        evidence = job_service.run_controlled_simulation(self.session, job)
        verification = evidence_service.run_demo_verification(self.session, evidence)
        rule_disposition = demo_service.recommend_disposition(self.session, asset)
        job_service.transition_job(
            self.session,
            job,
            SanitizationJobStatusUpdate(status=SanitizationJobStatus.VERIFIED),
        )
        certificate = evidence_service.create_certificate(
            self.session,
            verification,
            TamperEvidentCertificateCreate(
                certificate_number="DEMO-CERT-001",
                issuer="SEDWTIAR controlled demo",
                payload_hash=evidence.evidence_hash or "",
                issued_at="2026-09-24T00:00:00Z",
            ),
        )
        disposition = evidence_service.create_disposition_recommendation(
            self.session,
            asset,
            DispositionRecommendationCreate(
                sanitization_job_id=job.id,
                verification_id=verification.id,
                recommendation=rule_disposition.recommendation,
                rationale=rule_disposition.rationale,
                recommended_by="Demo rules engine",
            ),
        )
        summary = dashboard_service.dashboard_summary(self.session)

        self.assertEqual(inspection.source_label, "Controlled demo inspection data")
        self.assertEqual(recommendation.recommended_method, "SSD Secure Sanitization / Purge-oriented workflow")
        self.assertIn("SIMULATION ONLY", evidence.notes or "")
        self.assertEqual(len(evidence.evidence_hash or ""), 64)
        self.assertEqual(verification.outcome, VerificationOutcome.PASSED)
        self.assertEqual(rule_disposition.recommendation, DispositionType.REDEPLOY)
        self.assertEqual(job.status, SanitizationJobStatus.VERIFIED)
        self.assertEqual(certificate.payload_hash, evidence.evidence_hash)
        self.assertEqual(disposition.recommendation, DispositionType.REDEPLOY)
        self.assertEqual(summary.total_assets, 1)
        self.assertEqual(summary.verified_assets, 1)
        self.assertEqual(summary.certificates, 1)
        self.assertEqual(summary.reuse, 1)

    def test_gemma_file_based_sanitization_advisory(self) -> None:
        from app.routers.system import ask_gemma_advisory, GemmaAskRequest

        req = GemmaAskRequest(
            volume_name="D: · Seagate Expansion HDD — 2000.0 GB",
            categories=[
                {"category": "Databases & structured data", "files": 1, "size": "400.0 B", "risk": "Critical Sensitivity"},
                {"category": "Hidden files · Documents & office files", "files": 2, "size": "942.6 KB", "risk": "High Risk"},
                {"category": "Windows system marked items", "files": 1, "size": "129.0 B", "risk": "Protected System Data"},
            ],
            query="sanitization method according to the files"
        )
        res = ask_gemma_advisory(req)
        self.assertIsNotNone(res.file_method_matrix)
        self.assertEqual(len(res.file_method_matrix), 3)

        # Verify database sanitization mapping
        db_spec = next(item for item in res.file_method_matrix if "Database" in item["category"])
        self.assertEqual(db_spec["action_type"], "PURGE")
        self.assertIn("NIST SP 800-88", db_spec["recommended_method"])
        self.assertIn("slack", db_spec["failure_mode_of_deletion"])
        self.assertIn("Bay-01", db_spec["target_fleet_bay"])

        # Verify hidden office documents mapping
        hidden_spec = next(item for item in res.file_method_matrix if "Hidden" in item["category"])
        self.assertEqual(hidden_spec["action_type"], "PURGE")
        self.assertIn("wear-leveling", hidden_spec["failure_mode_of_deletion"])
        self.assertIn("Bay-04", hidden_spec["target_fleet_bay"])

        # Verify query answer breakdown
        self.assertIn("Gemma Sanitization Methodology Breakdown", res.answer)
        self.assertIn("NIST SP 800-88 Rev. 1 PURGE", res.sanitization_advice)


if __name__ == "__main__":
    unittest.main()
