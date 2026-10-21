"""ISP Partner Dashboard + TR-069 control plane: seven new tables.

Additive only. Creates ``isp_partner_profiles``, ``isp_customer_profiles``,
``isp_staff_customer_scopes``, ``tr069_acs_credentials``, ``tr069_devices``,
``tr069_tasks`` and ``tr069_location_settings``. No existing table is altered,
no row is written, no enum or constraint on an existing table changes; every
foreign key lives on a new table. ``downgrade`` drops exactly these seven.

Revision ID: 0172_create_isp_partner_tables
Revises: 0171_create_monitored_device_health
Create Date: 2026-10-22
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0172_create_isp_partner_tables"
down_revision = "0171_create_monitored_device_health"
branch_labels = None
depends_on = None

_BASE_INDEXED = ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by")

TABLES = (
    "isp_partner_profiles",
    "isp_customer_profiles",
    "isp_staff_customer_scopes",
    "tr069_acs_credentials",
    "tr069_devices",
    "tr069_tasks",
    "tr069_location_settings",
)


def _uuid(name: str, *args: object, **kw: object) -> sa.Column:
    return sa.Column(name, postgresql.UUID(as_uuid=True), *args, **kw)


def _fk(target: str, ondelete: str | None = None) -> sa.ForeignKey:
    return sa.ForeignKey(target, ondelete=ondelete)


def _ts(name: str, nullable: bool = True) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _base_columns() -> list[sa.Column]:
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
        _ts("deleted_at"),
        sa.Column(
            "is_deleted", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        _uuid("created_by", nullable=True),
        _uuid("updated_by", nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    ]


def _base_indexes(table: str) -> None:
    for column in _BASE_INDEXED:
        op.create_index(f"ix_{table}_{column}", table, [column])


def upgrade() -> None:
    op.create_table(
        "isp_partner_profiles",
        *_base_columns(),
        _uuid(
            "organization_id",
            _fk("organizations.id", "CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "status", sa.String(20), nullable=False, server_default="active"
        ),
        sa.Column("gstin", sa.String(15), nullable=True),
        sa.Column("support_phone", sa.String(20), nullable=True),
        sa.Column("support_email", sa.String(255), nullable=True),
        _uuid("default_customer_plan_id", _fk("plans.id"), nullable=False),
        sa.Column("max_customers", sa.Integer(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        _ts("suspended_at"),
        sa.Column("suspended_reason", sa.String(255), nullable=True),
        sa.UniqueConstraint(
            "organization_id", name="uq_isp_partner_profiles_organization_id"
        ),
    )
    _base_indexes("isp_partner_profiles")
    op.create_index(
        "ix_isp_partner_profiles_status", "isp_partner_profiles", ["status"]
    )

    op.create_table(
        "isp_customer_profiles",
        *_base_columns(),
        _uuid("isp_organization_id", _fk("organizations.id"), nullable=False),
        _uuid("customer_organization_id", _fk("organizations.id"), nullable=False),
        sa.Column("external_ref", sa.String(64), nullable=True),
        sa.Column("contact_name", sa.String(200), nullable=True),
        sa.Column("gstin", sa.String(15), nullable=True),
        sa.Column("address_line1", sa.String(255), nullable=True),
        sa.Column("city", sa.String(100), nullable=True),
        sa.Column("state_province", sa.String(100), nullable=True),
        sa.Column("postal_code", sa.String(20), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.UniqueConstraint(
            "customer_organization_id",
            name="uq_isp_customer_profiles_customer_organization_id",
        ),
    )
    _base_indexes("isp_customer_profiles")
    op.create_index(
        "uq_isp_customer_profiles_isp_external_ref",
        "isp_customer_profiles",
        ["isp_organization_id", "external_ref"],
        unique=True,
        postgresql_where=sa.text("external_ref IS NOT NULL AND deleted_at IS NULL"),
    )
    op.create_index(
        "ix_isp_customer_profiles_isp_organization_id",
        "isp_customer_profiles",
        ["isp_organization_id"],
    )

    op.create_table(
        "isp_staff_customer_scopes",
        *_base_columns(),
        _uuid("isp_organization_id", _fk("organizations.id"), nullable=False),
        _uuid("user_id", _fk("users.id", "CASCADE"), nullable=False),
        _uuid(
            "customer_organization_id",
            _fk("organizations.id", "CASCADE"),
            nullable=False,
        ),
    )
    _base_indexes("isp_staff_customer_scopes")
    op.create_index(
        "uq_isp_staff_customer_scopes_user_customer",
        "isp_staff_customer_scopes",
        ["user_id", "customer_organization_id"],
        unique=True,
    )
    op.create_index(
        "ix_isp_staff_customer_scopes_isp_user",
        "isp_staff_customer_scopes",
        ["isp_organization_id", "user_id"],
    )

    op.create_table(
        "tr069_acs_credentials",
        *_base_columns(),
        _uuid("isp_organization_id", _fk("organizations.id"), nullable=False),
        _uuid("customer_organization_id", _fk("organizations.id"), nullable=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("password_encrypted", sa.Text(), nullable=False),
        sa.Column(
            "enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")
        ),
        _ts("rotated_at"),
        sa.UniqueConstraint("username", name="uq_tr069_acs_credentials_username"),
    )
    _base_indexes("tr069_acs_credentials")
    op.create_index(
        "uq_tr069_acs_credentials_isp_customer",
        "tr069_acs_credentials",
        ["isp_organization_id", "customer_organization_id"],
        unique=True,
        postgresql_where=sa.text("customer_organization_id IS NOT NULL"),
    )
    op.create_index(
        "uq_tr069_acs_credentials_isp_only",
        "tr069_acs_credentials",
        ["isp_organization_id"],
        unique=True,
        postgresql_where=sa.text("customer_organization_id IS NULL"),
    )

    op.create_table(
        "tr069_devices",
        *_base_columns(),
        _uuid("isp_organization_id", _fk("organizations.id"), nullable=False),
        _uuid("customer_organization_id", _fk("organizations.id"), nullable=True),
        _uuid("location_id", _fk("locations.id"), nullable=True),
        _uuid("router_id", _fk("routers.id"), nullable=True),
        sa.Column("genieacs_device_id", sa.String(255), nullable=False),
        _uuid("credential_id", _fk("tr069_acs_credentials.id"), nullable=True),
        sa.Column("oui", sa.String(6), nullable=True),
        sa.Column("product_class", sa.String(64), nullable=True),
        sa.Column("serial_number", sa.String(64), nullable=True),
        sa.Column("manufacturer", sa.String(64), nullable=True),
        sa.Column("model", sa.String(64), nullable=True),
        sa.Column("software_version", sa.String(64), nullable=True),
        sa.Column("data_model", sa.String(8), nullable=True),
        sa.Column("wan_ip", sa.String(45), nullable=True),
        _ts("last_inform_at"),
        _ts("first_seen_at", nullable=False),
        sa.Column("periodic_inform_interval_s", sa.Integer(), nullable=True),
        sa.Column(
            "params_cache",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        _ts("params_refreshed_at"),
        sa.Column("label", sa.String(200), nullable=True),
        sa.UniqueConstraint(
            "genieacs_device_id", name="uq_tr069_devices_genieacs_device_id"
        ),
    )
    _base_indexes("tr069_devices")
    op.create_index(
        "ix_tr069_devices_isp_customer",
        "tr069_devices",
        ["isp_organization_id", "customer_organization_id"],
    )
    op.create_index(
        "ix_tr069_devices_last_inform_at", "tr069_devices", ["last_inform_at"]
    )

    op.create_table(
        "tr069_tasks",
        *_base_columns(),
        _uuid("device_id", _fk("tr069_devices.id"), nullable=False),
        _uuid("isp_organization_id", nullable=False),
        _uuid("requested_by", _fk("users.id"), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("genieacs_task_id", sa.String(64), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("fault", postgresql.JSONB(), nullable=True),
        _ts("completed_at"),
    )
    _base_indexes("tr069_tasks")
    op.create_index(
        "ix_tr069_tasks_device_created",
        "tr069_tasks",
        ["device_id", sa.text("created_at DESC")],
    )

    op.create_table(
        "tr069_location_settings",
        *_base_columns(),
        _uuid("location_id", _fk("locations.id"), nullable=False),
        sa.Column(
            "enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "periodic_inform_interval_s",
            sa.Integer(),
            nullable=False,
            server_default="300",
        ),
        sa.UniqueConstraint(
            "location_id", name="uq_tr069_location_settings_location_id"
        ),
    )
    _base_indexes("tr069_location_settings")


def downgrade() -> None:
    # Reverse dependency order: tasks -> devices -> credentials.
    for table in reversed(TABLES):
        op.drop_table(table)
