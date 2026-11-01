"""ISP JAZE-3 compliance tables (ADDENDUM_05 J6 + J17).

Additive, ISP-owned tables only:

- ``isp_compliance_settings``: licence identity for the CAF, the CAF number
  series, NAT-feed / gigabit / churn thresholds (one row per ISP).
- ``isp_subscriber_kyc``: KYC + CAF record per subscriber. Aadhaar is stored
  masked (last four digits) only.
- ``isp_subscriber_documents``: uploaded KYC files (object-storage keys).
- ``isp_report_schedules``: monthly compliance-report emails.

No pre-ISP table is touched. ``downgrade`` drops exactly these.

Revision ID: 0179_isp_jaze3_compliance
Revises: 0178_merge_integ_parity_settings
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0179_isp_jaze3_compliance"
down_revision = "0179_isp_jaze2_enforcement"
branch_labels = None
depends_on = None

_BASE_INDEXED = ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by")
_TABLES = (
    "isp_report_schedules",
    "isp_subscriber_documents",
    "isp_subscriber_kyc",
    "isp_compliance_settings",
)


def _uuid(name: str, *args: object, **kw: object) -> sa.Column:
    return sa.Column(name, postgresql.UUID(as_uuid=True), *args, **kw)


def _base() -> list[sa.Column]:
    return [
        _uuid("id", primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_deleted", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        _uuid("created_by", nullable=True),
        _uuid("updated_by", nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    ]


def _org(name: str = "isp_organization_id") -> sa.Column:
    return _uuid(
        name, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )


def _sub() -> sa.Column:
    return _uuid(
        "subscriber_id",
        sa.ForeignKey("isp_subscribers.id", ondelete="CASCADE"),
        nullable=False,
    )


def _user(name: str) -> sa.Column:
    return _uuid(name, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)


def _ts(name: str) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=True)


def upgrade() -> None:
    op.create_table(
        "isp_compliance_settings",
        *_base(),
        _org(),
        sa.Column("legal_name", sa.String(255), nullable=True),
        sa.Column("licence_number", sa.String(80), nullable=True),
        sa.Column("licence_category", sa.String(80), nullable=True),
        sa.Column("registered_address", sa.Text(), nullable=True),
        sa.Column("gstin", sa.String(15), nullable=True),
        sa.Column("compliance_email", sa.String(255), nullable=True),
        sa.Column("caf_prefix", sa.String(10), nullable=False, server_default="CAF"),
        sa.Column("caf_next_seq", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "nat_feed_stale_minutes", sa.Integer(), nullable=False, server_default="60"
        ),
        sa.Column(
            "gigabit_threshold_mbps",
            sa.Integer(),
            nullable=False,
            server_default="1000",
        ),
        sa.Column(
            "churn_after_days", sa.Integer(), nullable=False, server_default="60"
        ),
    )
    op.create_table(
        "isp_subscriber_kyc",
        *_base(),
        _org(),
        _sub(),
        sa.Column(
            "applicant_type",
            sa.String(16),
            nullable=False,
            server_default="individual",
        ),
        sa.Column("full_name", sa.String(200), nullable=True),
        sa.Column("father_or_spouse_name", sa.String(200), nullable=True),
        sa.Column("gender", sa.String(12), nullable=True),
        sa.Column("date_of_birth", sa.Date(), nullable=True),
        sa.Column("nationality", sa.String(40), nullable=True),
        sa.Column("alternate_phone", sa.String(20), nullable=True),
        sa.Column("permanent_address", sa.Text(), nullable=True),
        sa.Column("installation_address", sa.Text(), nullable=True),
        sa.Column("installation_pincode", sa.String(10), nullable=True),
        sa.Column("id_proof_type", sa.String(20), nullable=True),
        sa.Column("id_number_masked", sa.String(40), nullable=True),
        sa.Column("id_number_last4", sa.String(4), nullable=True),
        sa.Column("address_proof_type", sa.String(20), nullable=True),
        sa.Column(
            "address_proof_same_as_id",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column("caf_number", sa.String(40), nullable=True),
        sa.Column("caf_number_source", sa.String(8), nullable=True),
        _ts("caf_generated_at"),
        _ts("installed_at"),
        _user("verified_by"),
        _ts("verified_at"),
        sa.Column("notes", sa.Text(), nullable=True),
    )
    op.create_table(
        "isp_subscriber_documents",
        *_base(),
        _org(),
        _sub(),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("storage_key", sa.String(400), nullable=False),
        sa.Column("filename", sa.String(200), nullable=False),
        sa.Column("content_type", sa.String(100), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        _user("uploaded_by"),
    )
    op.create_table(
        "isp_report_schedules",
        *_base(),
        _org(),
        sa.Column("report_key", sa.String(40), nullable=False),
        sa.Column("day_of_month", sa.SmallInteger(), nullable=False),
        sa.Column(
            "recipients",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")
        ),
        sa.Column("last_period_sent", sa.String(7), nullable=True),
        _ts("last_sent_at"),
        sa.Column("last_status", sa.String(200), nullable=True),
    )
    for table in _TABLES:
        for column in _BASE_INDEXED:
            op.create_index(f"ix_{table}_{column}", table, [column])
    live = sa.text("deleted_at IS NULL")
    op.create_index(
        "uq_isp_compliance_settings_isp",
        "isp_compliance_settings",
        ["isp_organization_id"],
        unique=True,
        postgresql_where=live,
    )
    op.create_index(
        "uq_isp_subscriber_kyc_subscriber",
        "isp_subscriber_kyc",
        ["subscriber_id"],
        unique=True,
        postgresql_where=live,
    )
    op.create_index(
        "uq_isp_subscriber_kyc_caf_number",
        "isp_subscriber_kyc",
        ["isp_organization_id", "caf_number"],
        unique=True,
        postgresql_where=sa.text("caf_number IS NOT NULL"),
    )
    op.create_index(
        "ix_isp_subscriber_kyc_isp", "isp_subscriber_kyc", ["isp_organization_id"]
    )
    op.create_index(
        "ix_isp_subscriber_documents_sub",
        "isp_subscriber_documents",
        ["subscriber_id", "kind"],
    )
    op.create_index(
        "uq_isp_report_schedules_isp_key",
        "isp_report_schedules",
        ["isp_organization_id", "report_key"],
        unique=True,
        postgresql_where=live,
    )


def downgrade() -> None:
    for table in _TABLES:
        op.drop_table(table)
