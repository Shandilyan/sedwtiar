"""add Ed25519 certificate fields

Revision ID: c4e2d9f7a101
Revises: 6edd9fef8e85
Create Date: 2026-10-02
"""

from alembic import op
import sqlalchemy as sa


revision = "c4e2d9f7a101"
down_revision = "6edd9fef8e85"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tamper_evident_certificates",
        sa.Column("certificate_version", sa.String(length=50), nullable=True),
    )
    op.add_column(
        "tamper_evident_certificates",
        sa.Column("signing_key_id", sa.String(length=100), nullable=True),
    )
    op.add_column(
        "tamper_evident_certificates",
        sa.Column("public_key", sa.Text(), nullable=True),
    )
    op.execute(
        "UPDATE tamper_evident_certificates "
        "SET certificate_version = 'v1-hash-chain' "
        "WHERE certificate_version IS NULL"
    )
    op.alter_column("tamper_evident_certificates", "certificate_version", nullable=False)


def downgrade() -> None:
    op.drop_column("tamper_evident_certificates", "public_key")
    op.drop_column("tamper_evident_certificates", "signing_key_id")
    op.drop_column("tamper_evident_certificates", "certificate_version")
