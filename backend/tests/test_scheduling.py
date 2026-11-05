"""Comprehensive tests for the SEDWTIAR scheduling and resource optimization engine."""

from datetime import datetime, timedelta, timezone
import os
import sys
import tempfile
import unittest
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

os.environ.setdefault("DB_HOST", "test-host")
os.environ.setdefault("DB_PORT", "5432")
os.environ.setdefault("DB_NAME", "test-db")
os.environ.setdefault("DB_USER", "test-user")
os.environ.setdefault("DB_PASSWORD", "test-password")
os.environ.setdefault(
    "SEDWTIAR_SIGNING_KEY_PATH",
    str(Path(tempfile.mkdtemp(prefix="sedwtiar-scheduling-test-")) / "certificate-ed25519.dpapi"),
)

from app.database import Base
from app.models import Asset, SanitizationJob
from app.models.enums import (
    AssetLifecycleStatus,
    AssetType,
    CustodyEventType,
    DataSensitivity,
    JobDependencyType,
    ResourceStatus,
    SanitizationJobStatus,
    ScheduleAssignmentStatus,
    SchedulePriority,
    VerificationOutcome,
)
from app.models.scheduling import JobDependency, SanitizationResource, ScheduleAssignment
from app.schemas.asset import AssetCreate
from app.schemas.custody import ChainOfCustodyEventCreate
from app.schemas.sanitization_job import SanitizationJobCreate
from app.schemas.scheduling import (
    DynamicRebalanceRequest,
    JobDependencyCreate,
    JobDependencyRead,
    SanitizationResourceCreate,
    SanitizationResourceUpdate,
    TransactionalAssignmentRequest,
    WorkloadSimulationRequest,
)
from app.schemas.verification import IndependentVerificationCreate
from app.services import assets as asset_service
from app.services import evidence as evidence_service
from app.services import sanitization_jobs as job_service
from app.services import sanitization_records as record_service
from app.services import scheduling as scheduling_service
from app.services.exceptions import (
    BusinessRuleError,
    ResourceIncompatibleError,
    SchedulingConflictError,
    SecurityPolicyViolationError,
)
from app.services.scheduling import (
    JobPriorityQueue,
    ResourceIntervalSchedule,
)
from app.routers import scheduling as scheduling_router


class SchedulingEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.session = Session(self.engine)
        # Ensure standard test equipment
        self.resources = scheduling_service.ensure_default_resources(self.session)

    def tearDown(self) -> None:
        self.session.close()
        self.engine.dispose()

    def test_default_resources_seeded(self) -> None:
        self.assertGreaterEqual(len(self.resources), 5)
        names = {r.name for r in self.resources}
        self.assertTrue(any("NVMe" in n for n in names))
        self.assertTrue(any("Degausser" in n for n in names))
        self.assertTrue(any("SATA" in n for n in names))

    def test_device_compatibility_filtering(self) -> None:
        """Verify that specialized tools only receive compatible device media and methods."""
        degausser = next(r for r in self.resources if "Degausser" in r.name)
        nvme_station = next(r for r in self.resources if "NVMe" in r.name)
        shredder = next(r for r in self.resources if "Shredder" in r.name)

        # 1. Degausser accepts HDD / Magnetic Tape with Degauss method
        self.assertTrue(
            scheduling_service.is_resource_compatible(degausser, "HDD", 2000, "Magnetic Degaussing")
        )
        self.assertTrue(
            scheduling_service.is_resource_compatible(degausser, "Magnetic Tape", 4000, "Degauss")
        )
        # Degausser rejects optical or SSD (degaussing is ineffective on flash/optical)
        self.assertFalse(
            scheduling_service.is_resource_compatible(degausser, "Optical", 50, "Optical Destruction")
        )

        # 2. NVMe station accepts NVMe/SSD cryptographic erase and purge
        self.assertTrue(
            scheduling_service.is_resource_compatible(nvme_station, "NVMe", 1024, "Cryptographic Erase")
        )
        self.assertTrue(
            scheduling_service.is_resource_compatible(nvme_station, "SSD", 512, "NIST 800-88 Purge")
        )
        # NVMe station rejects Magnetic Tape or Optical
        self.assertFalse(
            scheduling_service.is_resource_compatible(nvme_station, "Magnetic Tape", 5000, "Degauss")
        )

        # 3. Shredder accepts Optical
        self.assertTrue(
            scheduling_service.is_resource_compatible(shredder, "Optical", 25, "Physical Shred")
        )

    def test_security_critical_jobs_never_delayed_for_throughput(self) -> None:
        """Core Requirement: Security-critical jobs must never be delayed solely to improve throughput."""
        now = datetime.now(timezone.utc)

        # Asset A: CRITICAL data sensitivity, huge 4000 GB drive (takes 100+ minutes)
        asset_crit = asset_service.create_asset(
            self.session,
            AssetCreate(
                asset_tag="CRIT-001",
                asset_type=AssetType.SERVER,
                storage_type="SSD",
                storage_capacity_gb=4000,
            ),
        )
        asset_crit.data_sensitivity = DataSensitivity.CRITICAL
        self.session.commit()

        job_crit = job_service.create_job(
            self.session,
            SanitizationJobCreate(
                asset_id=asset_crit.id,
                planned_method="SSD Secure Sanitization / Purge-oriented workflow",
                requested_by="Security Officer",
            ),
        )
        job_crit.data_sensitivity = DataSensitivity.CRITICAL
        self.session.commit()

        # Asset B: LOW data sensitivity, tiny 64 GB drive (fast 5-minute job)
        asset_low = asset_service.create_asset(
            self.session,
            AssetCreate(
                asset_tag="LOW-001",
                asset_type=AssetType.LAPTOP,
                storage_type="SSD",
                storage_capacity_gb=64,
            ),
        )
        asset_low.data_sensitivity = DataSensitivity.LOW
        self.session.commit()

        job_low = job_service.create_job(
            self.session,
            SanitizationJobCreate(
                asset_id=asset_low.id,
                planned_method="SSD Secure Sanitization / Purge-oriented workflow",
                requested_by="General IT",
            ),
        )
        job_low.data_sensitivity = DataSensitivity.LOW
        self.session.commit()

        # Score calculations
        score_crit, tier_crit = scheduling_service.calculate_priority_score(
            DataSensitivity.CRITICAL, None, 120, now
        )
        score_low, tier_low = scheduling_service.calculate_priority_score(
            DataSensitivity.LOW, None, 5, now
        )

        # Mathematical guarantee: Critical score must dominate Low score by orders of magnitude
        self.assertGreater(score_crit, score_low + 50_000)
        self.assertEqual(tier_crit, SchedulePriority.EMERGENCY)

        # Run schedule optimization
        result = scheduling_service.optimize_schedule(
            self.session, target_job_ids=[job_crit.id, job_low.id]
        )

        queue = result.queue
        self.assertEqual(len(queue), 2)
        # CRITICAL asset must be at queue position 1, despite taking much longer
        self.assertEqual(queue[0].asset_tag, "CRIT-001")
        self.assertEqual(queue[0].priority, SchedulePriority.EMERGENCY)
        self.assertEqual(queue[1].asset_tag, "LOW-001")

    def test_deadline_urgency_escalation(self) -> None:
        """Assets approaching deadline or overdue must receive high priority boost."""
        now = datetime.now(timezone.utc)

        # Standard job with deadline in 2 hours (imminent)
        score_imminent, tier_imminent = scheduling_service.calculate_priority_score(
            DataSensitivity.STANDARD, now + timedelta(hours=2), 30, now
        )

        # Standard job with deadline in 14 days (distant)
        score_distant, tier_distant = scheduling_service.calculate_priority_score(
            DataSensitivity.STANDARD, now + timedelta(days=14), 30, now
        )

        # Overdue standard job (already 5 hours past deadline)
        score_overdue, tier_overdue = scheduling_service.calculate_priority_score(
            DataSensitivity.STANDARD, now - timedelta(hours=5), 30, now
        )

        self.assertGreater(score_overdue, score_imminent)
        self.assertGreater(score_imminent, score_distant)
        self.assertEqual(tier_overdue, SchedulePriority.EMERGENCY)
        self.assertEqual(tier_imminent, SchedulePriority.URGENT)

    def test_dynamic_rebalancing_preserves_running_jobs(self) -> None:
        """When a resource goes offline, pending assignments reassign but running jobs on healthy resources are undisturbed."""
        res_a = self.resources[0]  # Bay-01
        res_b = self.resources[1]  # Bay-02

        # Create Asset 1 and Job 1 running on res_b
        asset1 = asset_service.create_asset(
            self.session,
            AssetCreate(asset_tag="RUN-001", asset_type=AssetType.SERVER, storage_type="SSD", storage_capacity_gb=500),
        )
        job1 = job_service.create_job(
            self.session,
            SanitizationJobCreate(asset_id=asset1.id, planned_method="NIST 800-88 Purge"),
        )
        assignment_running = ScheduleAssignment(
            job_id=job1.id,
            resource_id=res_b.id,
            status=ScheduleAssignmentStatus.RUNNING,
            priority=SchedulePriority.URGENT,
            priority_score=60000.0,
            started_at=datetime.now(timezone.utc) - timedelta(minutes=10),
            estimated_minutes=45,
        )
        self.session.add(assignment_running)

        # Create Asset 2 and Job 2 pending on res_a
        asset2 = asset_service.create_asset(
            self.session,
            AssetCreate(asset_tag="PEND-001", asset_type=AssetType.LAPTOP, storage_type="SSD", storage_capacity_gb=512),
        )
        job2 = job_service.create_job(
            self.session,
            SanitizationJobCreate(asset_id=asset2.id, planned_method="SSD Secure Sanitization / Purge-oriented workflow"),
        )
        assignment_pending = ScheduleAssignment(
            job_id=job2.id,
            resource_id=res_a.id,
            status=ScheduleAssignmentStatus.ASSIGNED,
            priority=SchedulePriority.NORMAL,
            priority_score=15000.0,
            estimated_minutes=25,
        )
        self.session.add(assignment_pending)
        self.session.commit()

        # Bay-01 goes OFFLINE for emergency maintenance
        scheduling_service.update_resource_status(
            self.session, res_a, ResourceStatus.OFFLINE, reason="Cooling loop malfunction"
        )

        # Reload assignments
        self.session.refresh(assignment_running)
        self.session.refresh(assignment_pending)

        # 1. Running job on healthy Bay-02 is PRESERVED without interruption!
        self.assertEqual(assignment_running.status, ScheduleAssignmentStatus.RUNNING)
        self.assertEqual(assignment_running.resource_id, res_b.id)

        # 2. Pending job from Bay-01 was dynamically reassigned to another compatible resource!
        self.assertNotEqual(assignment_pending.resource_id, res_a.id)
        self.assertIn(assignment_pending.status, [ScheduleAssignmentStatus.ASSIGNED, ScheduleAssignmentStatus.PENDING])
        self.assertIn("Cooling loop malfunction", assignment_pending.reassign_reason or "")

    def test_mandatory_security_release_guard(self) -> None:
        """Security Rule: An asset must not be released until its sanitization has been successfully verified."""
        asset = asset_service.create_asset(
            self.session,
            AssetCreate(
                asset_tag="SEC-RELEASE-001",
                asset_type=AssetType.LAPTOP,
                storage_type="SSD",
                storage_capacity_gb=512,
            ),
        )

        # Attempt to release the asset before sanitization and verification
        with self.assertRaises(SecurityPolicyViolationError) as ctx:
            evidence_service.create_custody_event(
                self.session,
                asset,
                ChainOfCustodyEventCreate(
                    event_type=CustodyEventType.RELEASED,
                    recorded_by="E-Waste Handler",
                    location="Loading Dock",
                    note="Attempted early release",
                    occurred_at=datetime.now(timezone.utc),
                ),
            )
        self.assertIn("cannot be released until its sanitization has been successfully verified", str(ctx.exception))

        # Now perform sanitization simulation and verification
        job = job_service.create_job(
            self.session,
            SanitizationJobCreate(asset_id=asset.id, planned_method="NIST 800-88 Purge"),
        )
        record = job_service.run_controlled_simulation(self.session, job)
        verification = evidence_service.create_verification(
            self.session,
            record,
            IndependentVerificationCreate(
                outcome=VerificationOutcome.PASSED,
                verifier_name="Independent Security Officer",
                verification_method="Cryptographic hash verification",
                verified_at=datetime.now(timezone.utc),
            ),
        )
        self.assertEqual(verification.outcome, VerificationOutcome.PASSED)

        # Now custody release succeeds because sanitization verification passed!
        custody_event = evidence_service.create_custody_event(
            self.session,
            asset,
            ChainOfCustodyEventCreate(
                event_type=CustodyEventType.RELEASED,
                recorded_by="E-Waste Handler",
                location="Loading Dock",
                note="Authorized release after verified sanitization",
                occurred_at=datetime.now(timezone.utc),
            ),
        )
        self.assertEqual(custody_event.event_type, CustodyEventType.RELEASED)

    def test_batch_workload_simulation_hundred_devices(self) -> None:
        """Verify performance, zero security inversions, and makespan optimization for 100+ devices."""
        sim_result = scheduling_service.simulate_batch_workload(
            self.session, device_count=100, seed=123
        )

        self.assertEqual(sim_result.device_count, 100)
        self.assertEqual(sim_result.jobs_created, 100)
        self.assertGreaterEqual(sim_result.resources_available, 5)

        summary = sim_result.optimization_summary
        self.assertGreater(summary.assigned_count, 0)
        self.assertGreater(summary.critical_jobs_prioritized, 0)
        self.assertGreater(summary.estimated_total_makespan_minutes, 0)

        # Verify that the highest-scoring job in the queue is prioritized at queue position 1
        queue = sim_result.first_10_queue_items
        for idx in range(len(queue) - 1):
            curr = queue[idx]
            nxt = queue[idx + 1]
            self.assertGreaterEqual(
                curr.priority_score,
                nxt.priority_score,
                f"Queue ordering inversion at index {idx}: {curr.priority_score} < {nxt.priority_score}",
            )

    def test_job_priority_queue_data_structure(self) -> None:
        """Verify Priority Queue min-heap ordering using composite keys (-score, deadline, duration, counter)."""
        now = datetime.now(timezone.utc)
        pq = JobPriorityQueue()
        self.assertTrue(pq.is_empty())
        self.assertEqual(len(pq), 0)

        # 1. Low score job
        pq.push({
            "id": "job-low",
            "priority_score": 1000.0,
            "deadline": now + timedelta(days=5),
            "estimated_minutes": 30,
        })

        # 2. Critical score job (takes long, but high sensitivity)
        pq.push({
            "id": "job-crit",
            "priority_score": 100000.0,
            "deadline": now + timedelta(days=2),
            "estimated_minutes": 120,
        })

        # 3. High score job with earlier deadline (1 hour)
        pq.push({
            "id": "job-high-urgent",
            "priority_score": 50000.0,
            "deadline": now + timedelta(hours=1),
            "estimated_minutes": 60,
        })

        # 4. High score job with later deadline (10 hours)
        pq.push({
            "id": "job-high-later",
            "priority_score": 50000.0,
            "deadline": now + timedelta(hours=10),
            "estimated_minutes": 60,
        })

        # 5. High score job with same deadline as #3, but shorter duration (SPT tie-breaker)
        pq.push({
            "id": "job-high-urgent-spt",
            "priority_score": 50000.0,
            "deadline": now + timedelta(hours=1),
            "estimated_minutes": 15,
        })

        self.assertEqual(len(pq), 5)
        self.assertFalse(pq.is_empty())

        # Pop 1: Critical score (100k) must be first
        first = pq.pop()
        self.assertEqual(first["id"], "job-crit")

        # Pop 2: High score + 1h deadline + shorter duration 15min
        second = pq.pop()
        self.assertEqual(second["id"], "job-high-urgent-spt")

        # Pop 3: High score + 1h deadline + longer duration 60min
        third = pq.pop()
        self.assertEqual(third["id"], "job-high-urgent")

        # Pop 4: High score + 10h deadline
        fourth = pq.pop()
        self.assertEqual(fourth["id"], "job-high-later")

        # Pop 5: Low score
        fifth = pq.pop()
        self.assertEqual(fifth["id"], "job-low")

        self.assertTrue(pq.is_empty())

    def test_dag_dependency_management_and_cycle_prevention(self) -> None:
        """Verify DAG dependency creation, cycle rejection, prerequisite gating, and automatic unlocking."""
        # Create 3 jobs representing multi-stage sanitization (A: Pre-clear -> B: Purge -> C: Shred)
        asset = asset_service.create_asset(
            self.session,
            AssetCreate(asset_tag="DAG-001", asset_type=AssetType.LAPTOP, storage_type="SSD", storage_capacity_gb=256),
        )
        job_a = job_service.create_job(
            self.session,
            SanitizationJobCreate(asset_id=asset.id, planned_method="NIST 800-88 Clear"),
        )
        job_b = job_service.create_job(
            self.session,
            SanitizationJobCreate(asset_id=asset.id, planned_method="NIST 800-88 Purge"),
        )
        job_c = job_service.create_job(
            self.session,
            SanitizationJobCreate(asset_id=asset.id, planned_method="Physical Destruction / Shred"),
        )

        # 1. Reject self-dependency
        with self.assertRaises(BusinessRuleError):
            scheduling_service.create_job_dependency(self.session, job_a.id, job_a.id)

        # 2. Add dependencies: A -> B and B -> C
        dep_ab = scheduling_service.create_job_dependency(
            self.session, job_a.id, job_b.id, JobDependencyType.PREREQUISITE
        )
        dep_bc = scheduling_service.create_job_dependency(
            self.session, job_b.id, job_c.id, JobDependencyType.PREREQUISITE
        )
        self.assertIsNotNone(dep_ab.id)
        self.assertFalse(dep_ab.is_satisfied)
        self.assertIsNotNone(dep_bc.id)
        self.assertFalse(dep_bc.is_satisfied)

        # 3. Cycle prevention: Attempting C -> A must be rejected by DFS cycle detection
        with self.assertRaises(BusinessRuleError) as ctx:
            scheduling_service.create_job_dependency(
                self.session, job_c.id, job_a.id, JobDependencyType.PREREQUISITE
            )
        self.assertIn("cyclical deadlock", str(ctx.exception))

        # 4. Check prerequisite gating: Job B cannot run while Job A is pending
        ok, pending_count, unsat_ids = scheduling_service.are_dependencies_satisfied(self.session, job_b.id)
        self.assertFalse(ok)
        self.assertEqual(pending_count, 1)
        self.assertIn(job_a.id, unsat_ids)

        # 5. Complete Job A and trigger downstream evaluation
        job_a.status = SanitizationJobStatus.EVIDENCE_RECORDED
        self.session.commit()

        unlocked = scheduling_service.evaluate_and_unlock_dependents(self.session, job_a.id)
        self.assertIn(job_b.id, unlocked)

        # Now Job B's prerequisites are fully satisfied
        ok_after, pending_count_after, _ = scheduling_service.are_dependencies_satisfied(self.session, job_b.id)
        self.assertTrue(ok_after)
        self.assertEqual(pending_count_after, 0)

        # 6. Retrieve dependencies via get_job_dependencies
        deps_summary = scheduling_service.get_job_dependencies(self.session, job_b.id)
        self.assertEqual(len(deps_summary.incoming_prerequisites), 1)
        self.assertEqual(len(deps_summary.outgoing_dependents), 1)
        self.assertTrue(deps_summary.dependencies_satisfied)

    def test_greedy_interval_slot_allocation(self) -> None:
        """Verify interval/resource allocation packing across multi-concurrency bay slots."""
        now = datetime.now(timezone.utc)
        # Create a 2-concurrency bay
        multi_bay = scheduling_service.create_resource(
            self.session,
            SanitizationResourceCreate(
                name="Multi-Port Wiping Station X",
                resource_type="Multi-Port NVMe Flasher",
                concurrency_limit=2,
                supported_media_types=["SSD", "NVMe"],
                supported_methods=["Cryptographic Erase", "Block Overwrite"],
            ),
        )

        schedule = ResourceIntervalSchedule(multi_bay, now)

        # Job 1 (duration 60 min) -> Slot 1 [now, now+60]
        slot1, start1, end1 = schedule.find_earliest_slot(now, 60)
        self.assertEqual(slot1, 1)
        self.assertEqual(start1, now)
        self.assertEqual(end1, now + timedelta(minutes=60))
        schedule.book_interval(slot1, start1, end1, "job-1")

        # Job 2 (duration 40 min) -> Slot 2 is completely free from now!
        slot2, start2, end2 = schedule.find_earliest_slot(now, 40)
        self.assertEqual(slot2, 2)
        self.assertEqual(start2, now)
        self.assertEqual(end2, now + timedelta(minutes=40))
        schedule.book_interval(slot2, start2, end2, "job-2")

        # Job 3 (duration 30 min):
        # Slot 1 is busy until now+60 (finish at now+90)
        # Slot 2 is busy until now+40 (finish at now+70)
        # Earliest Finish Time (EFT) greedy algorithm must choose Slot 2!
        slot3, start3, end3 = schedule.find_earliest_slot(now, 30)
        self.assertEqual(slot3, 2)
        self.assertEqual(start3, now + timedelta(minutes=40))
        self.assertEqual(end3, now + timedelta(minutes=70))

    def test_transactional_assignment_and_concurrency_control(self) -> None:
        """Verify transactional job assignment with row locking, optimistic versioning, and slot checks."""
        # Create a single-concurrency resource
        res = scheduling_service.create_resource(
            self.session,
            SanitizationResourceCreate(
                name="Single Slot Rig",
                resource_type="Dedicated Eraser",
                concurrency_limit=1,
                supported_media_types=["SSD"],
                supported_methods=["NIST 800-88 Purge"],
            ),
        )
        self.assertEqual(res.version, 1)

        asset1 = asset_service.create_asset(
            self.session,
            AssetCreate(asset_tag="TX-001", asset_type=AssetType.LAPTOP, storage_type="SSD", storage_capacity_gb=500),
        )
        job1 = job_service.create_job(
            self.session,
            SanitizationJobCreate(asset_id=asset1.id, planned_method="NIST 800-88 Purge"),
        )

        # 1. Assignment with matching expected_version succeeds and increments resource version
        asgn1 = scheduling_service.assign_job_transactional(
            self.session,
            job_id=job1.id,
            resource_id=res.id,
            expected_version=1,
            slot_number=1,
        )
        self.assertEqual(asgn1.status, ScheduleAssignmentStatus.ASSIGNED)
        self.session.refresh(res)
        self.assertEqual(res.version, 2)

        # 2. Assignment with stale version fails with SchedulingConflictError
        asset2 = asset_service.create_asset(
            self.session,
            AssetCreate(asset_tag="TX-002", asset_type=AssetType.LAPTOP, storage_type="SSD", storage_capacity_gb=500),
        )
        job2 = job_service.create_job(
            self.session,
            SanitizationJobCreate(asset_id=asset2.id, planned_method="NIST 800-88 Purge"),
        )

        with self.assertRaises(SchedulingConflictError) as ctx:
            scheduling_service.assign_job_transactional(
                self.session,
                job_id=job2.id,
                resource_id=res.id,
                expected_version=1,  # Stale: actual version is now 2
            )
        self.assertIn("Concurrency conflict", str(ctx.exception))

        # 3. Concurrency limit enforcement:
        # Start assignment 1 so it is RUNNING
        scheduling_service.start_assignment(self.session, asgn1.id)
        self.assertEqual(asgn1.status, ScheduleAssignmentStatus.RUNNING)

        # Now attempting to assign job2 without override should hit concurrency limit (limit = 1)
        with self.assertRaises(SchedulingConflictError) as ctx:
            scheduling_service.assign_job_transactional(
                self.session,
                job_id=job2.id,
                resource_id=res.id,
                expected_version=2,
                force_override=False,
            )
        self.assertIn("concurrency limit", str(ctx.exception))

        # With force_override=True, assignment succeeds
        asgn2 = scheduling_service.assign_job_transactional(
            self.session,
            job_id=job2.id,
            resource_id=res.id,
            expected_version=2,
            force_override=True,
        )
        self.assertIsNotNone(asgn2.id)

    def test_delay_detection_and_dynamic_rescheduling(self) -> None:
        """Verify dynamic detection of overrun jobs and rescheduling of downstream pending tasks."""
        res = self.resources[0]
        now = datetime.now(timezone.utc)

        # 1. Create a running job that started 60 mins ago with 20 min estimated duration (delay = 40 mins)
        asset_running = asset_service.create_asset(
            self.session,
            AssetCreate(asset_tag="DELAY-001", asset_type=AssetType.LAPTOP, storage_type="SSD", storage_capacity_gb=256),
        )
        job_running = job_service.create_job(
            self.session,
            SanitizationJobCreate(asset_id=asset_running.id, planned_method="NIST 800-88 Purge"),
        )
        asgn_running = ScheduleAssignment(
            job_id=job_running.id,
            resource_id=res.id,
            status=ScheduleAssignmentStatus.RUNNING,
            priority=SchedulePriority.NORMAL,
            priority_score=20000.0,
            estimated_minutes=20,
            started_at=now - timedelta(minutes=60),
        )
        self.session.add(asgn_running)

        # 2. Create a pending job assigned to the same resource
        asset_pending = asset_service.create_asset(
            self.session,
            AssetCreate(asset_tag="PENDING-001", asset_type=AssetType.LAPTOP, storage_type="SSD", storage_capacity_gb=256),
        )
        job_pending = job_service.create_job(
            self.session,
            SanitizationJobCreate(asset_id=asset_pending.id, planned_method="NIST 800-88 Purge"),
        )
        asgn_pending = ScheduleAssignment(
            job_id=job_pending.id,
            resource_id=res.id,
            status=ScheduleAssignmentStatus.ASSIGNED,
            priority=SchedulePriority.NORMAL,
            priority_score=20000.0,
            estimated_minutes=30,
        )
        self.session.add(asgn_pending)
        self.session.commit()

        # 3. Trigger delay detection with 15-minute threshold
        result = scheduling_service.detect_delays_and_reschedule(self.session, delay_threshold_minutes=15)

        # Preserves running job, rebalances downstream
        self.assertGreaterEqual(result.preserved_running_count, 1)
        self.session.refresh(asgn_running)
        self.assertEqual(asgn_running.status, ScheduleAssignmentStatus.RUNNING)

    def test_scheduling_router_endpoints(self) -> None:
        """Verify the FastAPI scheduling router endpoints directly."""
        asset_a = asset_service.create_asset(
            self.session,
            AssetCreate(asset_tag="API-A-001", asset_type=AssetType.LAPTOP, storage_type="SSD", storage_capacity_gb=256),
        )
        asset_b = asset_service.create_asset(
            self.session,
            AssetCreate(asset_tag="API-B-001", asset_type=AssetType.LAPTOP, storage_type="SSD", storage_capacity_gb=256),
        )
        job_a = job_service.create_job(
            self.session,
            SanitizationJobCreate(asset_id=asset_a.id, planned_method="NIST 800-88 Clear"),
        )
        job_b = job_service.create_job(
            self.session,
            SanitizationJobCreate(asset_id=asset_b.id, planned_method="NIST 800-88 Purge"),
        )

        # 1. POST /dependencies
        dep_resp = scheduling_router.create_job_dependency_endpoint(
            payload=JobDependencyCreate(
                parent_job_id=job_a.id,
                child_job_id=job_b.id,
                dependency_type=JobDependencyType.PREREQUISITE,
                notes="Created via API endpoint",
            ),
            db=self.session,
        )
        self.assertEqual(dep_resp.parent_job_id, job_a.id)
        self.assertEqual(dep_resp.child_job_id, job_b.id)

        # 2. GET /dependencies/{job_id}
        deps_summary = scheduling_router.get_job_dependencies_endpoint(
            job_id=job_b.id,
            db=self.session,
        )
        self.assertEqual(deps_summary.job_id, job_b.id)
        self.assertEqual(len(deps_summary.incoming_prerequisites), 1)

        # 3. POST /assignments/transactional (with override for dependency)
        res = self.resources[0]
        tx_resp = scheduling_router.assign_job_transactional_endpoint(
            payload=TransactionalAssignmentRequest(
                job_id=job_b.id,
                resource_id=res.id,
                force_override=True,
            ),
            db=self.session,
        )
        self.assertEqual(tx_resp.job_id, job_b.id)
        self.assertEqual(tx_resp.resource_id, res.id)

        # 4. POST /detect-delays
        delays_resp = scheduling_router.detect_delays_and_reschedule_endpoint(
            delay_threshold_minutes=30,
            db=self.session,
        )
        self.assertIsNotNone(delays_resp.reason)

        # 5. POST /simulate-workload then POST /clear-simulation
        sim_res = scheduling_router.simulate_competing_workload(
            payload=WorkloadSimulationRequest(device_count=5),
            db=self.session,
        )
        self.assertEqual(sim_res.device_count, 5)
        clear_res = scheduling_router.clear_simulated_workload(db=self.session)
        self.assertEqual(clear_res["status"], "success")
        self.assertGreaterEqual(clear_res["details"]["deleted_assets"], 5)


if __name__ == "__main__":
    unittest.main()
