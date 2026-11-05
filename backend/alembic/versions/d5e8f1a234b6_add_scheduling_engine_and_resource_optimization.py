"""Add scheduling engine and resource optimization schema.

Revision ID: d5e8f1a234b6
Revises: c4e2d9f7a101
Create Date: 2026-11-03
"""

from alembic import op
import sqlalchemy as sa


revision = "d5e8f1a234b6"
down_revision = "c4e2d9f7a101"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Add fields to assets
    op.add_column(
        "assets",
        sa.Column("data_sensitivity", sa.String(length=50), nullable=True, server_default="standard"),
    )
    op.add_column(
        "assets",
        sa.Column("disposal_deadline", sa.DateTime(timezone=True), nullable=True),
    )

    # 2. Add fields to sanitization_jobs
    op.add_column(
        "sanitization_jobs",
        sa.Column("data_sensitivity", sa.String(length=50), nullable=True, server_default="standard"),
    )
    op.add_column(
        "sanitization_jobs",
        sa.Column("deadline", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "sanitization_jobs",
        sa.Column("estimated_duration_minutes", sa.Integer(), nullable=True),
    )

    # 3. Create sanitization_resources table
    op.create_table(
        "sanitization_resources",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=150), unique=True, nullable=False),
        sa.Column("resource_type", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="available"),
        sa.Column("supported_media_types", sa.JSON(), nullable=True),
        sa.Column("supported_methods", sa.JSON(), nullable=True),
        sa.Column("max_capacity_gb", sa.Integer(), nullable=True),
        sa.Column("throughput_gbps", sa.Float(), nullable=True, server_default="0.25"),
        sa.Column("location", sa.String(length=255), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_sanitization_resources_status", "sanitization_resources", ["status"])

    # 4. Create schedule_assignments table
    op.create_table(
        "schedule_assignments",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("job_id", sa.String(length=36), sa.ForeignKey("sanitization_jobs.id"), nullable=False),
        sa.Column("resource_id", sa.String(length=36), sa.ForeignKey("sanitization_resources.id"), nullable=True),
        sa.Column("priority", sa.String(length=50), nullable=False, server_default="normal"),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="pending"),
        sa.Column("priority_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("data_sensitivity", sa.String(length=50), nullable=False, server_default="standard"),
        sa.Column("estimated_minutes", sa.Integer(), nullable=True),
        sa.Column("actual_minutes", sa.Integer(), nullable=True),
        sa.Column("deadline", sa.DateTime(timezone=True), nullable=True),
        sa.Column("queue_position", sa.Integer(), nullable=True),
        sa.Column("scheduled_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scheduled_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reassigned_from_id", sa.String(length=36), sa.ForeignKey("schedule_assignments.id"), nullable=True),
        sa.Column("reassign_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_schedule_assignments_job_id", "schedule_assignments", ["job_id"])
    op.create_index("ix_schedule_assignments_resource_id", "schedule_assignments", ["resource_id"])
    op.create_index("ix_schedule_assignments_status", "schedule_assignments", ["status"])
    op.create_index("ix_schedule_assignments_priority", "schedule_assignments", ["priority"])
    op.create_index("ix_schedule_assignments_priority_score", "schedule_assignments", ["priority_score"])

    # 5. Create schedule_events table
    op.create_table(
        "schedule_events",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("assignment_id", sa.String(length=36), sa.ForeignKey("schedule_assignments.id"), nullable=True),
        sa.Column("resource_id", sa.String(length=36), sa.ForeignKey("sanitization_resources.id"), nullable=True),
        sa.Column("event_type", sa.String(length=50), nullable=False),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_schedule_events_assignment_id", "schedule_events", ["assignment_id"])
    op.create_index("ix_schedule_events_resource_id", "schedule_events", ["resource_id"])
    op.create_index("ix_schedule_events_event_type", "schedule_events", ["event_type"])


def downgrade() -> None:
    op.drop_table("schedule_events")
    op.drop_table("schedule_assignments")
    op.drop_table("sanitization_resources")
    op.drop_column("sanitization_jobs", "estimated_duration_minutes")
    op.drop_column("sanitization_jobs", "deadline")
    op.drop_column("sanitization_jobs", "data_sensitivity")
    op.drop_column("assets", "disposal_deadline")
    op.drop_column("assets", "data_sensitivity")
