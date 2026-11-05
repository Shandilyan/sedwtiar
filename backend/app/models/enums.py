"""Domain enumerations persisted by the data foundation."""

from enum import Enum


class AssetType(str, Enum):
    DESKTOP = "desktop"
    LAPTOP = "laptop"
    SERVER = "server"
    MOBILE = "mobile"
    STORAGE = "storage"
    NETWORK = "network"
    OTHER = "other"


class AssetLifecycleStatus(str, Enum):
    IN_INVENTORY = "in_inventory"
    ASSIGNED = "assigned"
    PENDING_SANITIZATION = "pending_sanitization"
    SANITIZED = "sanitized"
    RETIRED = "retired"


class SanitizationRecordStatus(str, Enum):
    """Administrative record status only; it never triggers sanitization work."""

    PLANNED = "planned"
    VERIFIED = "verified"
    CANCELLED = "cancelled"


class LifecycleEventType(str, Enum):
    CREATED = "created"
    UPDATED = "updated"
    STATUS_CHANGED = "status_changed"
    SANITIZATION_RECORDED = "sanitization_recorded"
    DEMO_INSPECTION_RECORDED = "demo_inspection_recorded"
    CONTROLLED_SIMULATION_COMPLETED = "controlled_simulation_completed"
    DEMO_VERIFICATION_PASSED = "demo_verification_passed"
    CERTIFICATE_ISSUED = "certificate_issued"
    DISPOSITION_RECOMMENDED = "disposition_recommended"


class DemoInspectionStatus(str, Enum):
    COMPLETED = "completed"


class SanitizationJobStatus(str, Enum):
    """Administrative workflow states; these states never initiate device actions."""

    REQUESTED = "requested"
    PREPARED = "prepared"
    EVIDENCE_RECORDED = "evidence_recorded"
    VERIFIED = "verified"
    CANCELLED = "cancelled"


class VerificationOutcome(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


class CustodyEventType(str, Enum):
    RECEIVED = "received"
    TRANSFERRED = "transferred"
    RELEASED = "released"
    OBSERVED = "observed"


class DispositionType(str, Enum):
    REDEPLOY = "redeploy"
    DONATE = "donate"
    RECYCLE = "recycle"
    RETAIN = "retain"
    HOLD_FOR_REVIEW = "hold_for_review"


class RoleName(str, Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VERIFIER = "verifier"
    AUDITOR = "auditor"
    VIEWER = "viewer"


class AuditOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class DataSensitivity(str, Enum):
    """Risk classification for data remaining on an IT asset."""
    CRITICAL = "critical"        # Highly confidential, PII, classified, or regulated
    HIGH = "high"                # Confidential business data
    STANDARD = "standard"        # General internal operational data
    LOW = "low"                  # Public or non-sensitive data


class SchedulePriority(str, Enum):
    """Computed urgency tier assigned by the scheduling engine."""
    EMERGENCY = "emergency"      # Security-critical or deadline-breaching; must execute next
    URGENT = "urgent"            # Approaching disposal deadline
    NORMAL = "normal"            # Standard queue processing
    DEFERRED = "deferred"        # Low-sensitivity, flexible disposal


class ResourceStatus(str, Enum):
    """Operational availability of a sanitization tool or workstation bay."""
    AVAILABLE = "available"
    BUSY = "busy"
    MAINTENANCE = "maintenance"
    OFFLINE = "offline"


class ScheduleAssignmentStatus(str, Enum):
    """Lifecycle state of a job-to-resource schedule assignment."""
    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    REASSIGNED = "reassigned"
    CANCELLED = "cancelled"


class ScheduleEventType(str, Enum):
    """Append-only audit trail events produced by the scheduling engine."""
    SCHEDULE_GENERATED = "schedule_generated"
    ASSIGNMENT_CREATED = "assignment_created"
    ASSIGNMENT_STARTED = "assignment_started"
    ASSIGNMENT_COMPLETED = "assignment_completed"
    ASSIGNMENT_FAILED = "assignment_failed"
    REASSIGNMENT = "reassignment"
    RESOURCE_UNAVAILABLE = "resource_unavailable"
    RESOURCE_RESTORED = "resource_restored"
    PRIORITY_OVERRIDE = "priority_override"
    DEADLINE_WARNING = "deadline_warning"
    DEPENDENCY_ADDED = "dependency_added"
    DEPENDENCY_SATISFIED = "dependency_satisfied"
    DELAY_DETECTED = "delay_detected"
    CONCURRENCY_LOCKED = "concurrency_locked"


class JobDependencyType(str, Enum):
    """Relationship constraint between sanitization jobs."""
    PREREQUISITE = "prerequisite"              # Job B cannot run until Job A completes
    VERIFICATION_GATE = "verification_gate"    # Job B requires Job A to pass independent verification
    CHASSIS_COMPONENT = "chassis_component"    # Chassis/enclosure requires internal media removal & sanitization first


