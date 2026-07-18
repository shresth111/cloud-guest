"""Create Guest domain tables: guests, guest_devices, guest_sessions,
guest_login_history, guest_consents, radius_nas_clients.

Mirrors ``0014_create_captive_portal_tables``'s conventions: each table
gets the ``BaseModel`` column set (id, created_at, updated_at, soft-delete,
audit, version) plus its own base-model indexes, using the same
``_base_model_columns``/``_create_base_model_indexes`` helpers (duplicated
here, not imported -- Alembic migrations are meant to be self-contained
snapshots rather than depending on other migration modules).

This is BE-010 Part 4 (the final module in BE-010)'s migration -- six new
tables, created in FK-dependency order:

* ``guests`` -- a returning-guest identity, unique per
  ``(organization_id, identifier)``.
* ``guest_devices`` -- a physical device (by MAC address), **globally**
  unique on ``mac_address`` (not scoped per guest) -- see
  ``app.domains.guest.models.GuestDevice``'s module docstring for the full
  "MAC address uniqueness" write-up.
* ``guest_sessions`` -- one continuous guest WiFi connection interval,
  FK'd to ``guests``/``guest_devices`` (nullable)/``routers``/``locations``/
  ``organizations``/``vouchers`` (nullable).
* ``guest_login_history`` -- every login attempt, ``guest_id`` nullable
  (a failed attempt for an identifier with no ``Guest`` row yet never
  force-creates one -- see ``GuestLoginHistory``'s module docstring).
* ``guest_consents`` -- FK'd to ``guests``/``captive_portal_configs``
  (nullable).
* ``radius_nas_clients`` -- one-to-one with ``routers`` (unique
  ``router_id``), plus a unique ``nas_identifier``.

No RBAC FK follow-up migration is needed (unlike Modules 005/006/008's own
follow-ups): none of these tables are referenced by any RBAC scope column.

Revision ID: 0015_create_guest_tables
Revises: 0014_create_captive_portal_tables
Create Date: 2026-07-18
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0015_create_guest_tables"
down_revision = "0014_create_captive_portal_tables"
branch_labels = None
depends_on = None


def _base_model_columns() -> list[sa.Column]:
    """Columns provided by ``app.database.base.BaseModel`` for every table."""
    return [
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_deleted", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    ]


def _create_base_model_indexes(table_name: str) -> None:
    op.create_index(f"ix_{table_name}_created_at", table_name, ["created_at"])
    op.create_index(f"ix_{table_name}_deleted_at", table_name, ["deleted_at"])
    op.create_index(f"ix_{table_name}_is_deleted", table_name, ["is_deleted"])
    op.create_index(f"ix_{table_name}_created_by", table_name, ["created_by"])
    op.create_index(f"ix_{table_name}_updated_by", table_name, ["updated_by"])


def _drop_base_model_indexes(table_name: str) -> None:
    op.drop_index(f"ix_{table_name}_updated_by", table_name=table_name)
    op.drop_index(f"ix_{table_name}_created_by", table_name=table_name)
    op.drop_index(f"ix_{table_name}_is_deleted", table_name=table_name)
    op.drop_index(f"ix_{table_name}_deleted_at", table_name=table_name)
    op.drop_index(f"ix_{table_name}_created_at", table_name=table_name)


def upgrade() -> None:
    # -- guests ------------------------------------------------------------------
    op.create_table(
        "guests",
        *_base_model_columns(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("location_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("identifier", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(200), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "total_visit_count", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column(
            "is_blocked", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("blocked_reason", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_guests_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["location_id"],
            ["locations.id"],
            name="fk_guests_location_id_locations",
            ondelete="SET NULL",
        ),
    )
    _create_base_model_indexes("guests")
    op.create_index("ix_guests_organization_id", "guests", ["organization_id"])
    op.create_index("ix_guests_location_id", "guests", ["location_id"])
    op.create_index("ix_guests_identifier", "guests", ["identifier"])
    op.create_index("ix_guests_is_blocked", "guests", ["is_blocked"])
    op.create_index(
        "uq_guests_organization_id_identifier",
        "guests",
        ["organization_id", "identifier"],
        unique=True,
    )

    # -- guest_devices -------------------------------------------------------------
    op.create_table(
        "guest_devices",
        *_base_model_columns(),
        sa.Column("guest_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("mac_address", sa.String(17), nullable=False),
        sa.Column("device_name", sa.String(200), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["guest_id"],
            ["guests.id"],
            name="fk_guest_devices_guest_id_guests",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("guest_devices")
    op.create_index("ix_guest_devices_guest_id", "guest_devices", ["guest_id"])
    op.create_index(
        "ix_guest_devices_mac_address", "guest_devices", ["mac_address"], unique=True
    )

    # -- guest_sessions --------------------------------------------------------------
    op.create_table(
        "guest_sessions",
        *_base_model_columns(),
        sa.Column("guest_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("router_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("location_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("auth_method", sa.String(30), nullable=False),
        sa.Column("voucher_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column(
            "bytes_uploaded", sa.BigInteger(), nullable=False, server_default="0"
        ),
        sa.Column(
            "bytes_downloaded", sa.BigInteger(), nullable=False, server_default="0"
        ),
        sa.Column("data_limit_mb", sa.Integer(), nullable=True),
        sa.Column("session_timeout_minutes", sa.Integer(), nullable=True),
        sa.Column("disconnect_reason", sa.String(255), nullable=True),
        sa.ForeignKeyConstraint(
            ["guest_id"],
            ["guests.id"],
            name="fk_guest_sessions_guest_id_guests",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["guest_devices.id"],
            name="fk_guest_sessions_device_id_guest_devices",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["router_id"],
            ["routers.id"],
            name="fk_guest_sessions_router_id_routers",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["location_id"],
            ["locations.id"],
            name="fk_guest_sessions_location_id_locations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_guest_sessions_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["voucher_id"],
            ["vouchers.id"],
            name="fk_guest_sessions_voucher_id_vouchers",
            ondelete="SET NULL",
        ),
    )
    _create_base_model_indexes("guest_sessions")
    op.create_index("ix_guest_sessions_guest_id", "guest_sessions", ["guest_id"])
    op.create_index("ix_guest_sessions_device_id", "guest_sessions", ["device_id"])
    op.create_index("ix_guest_sessions_router_id", "guest_sessions", ["router_id"])
    op.create_index("ix_guest_sessions_location_id", "guest_sessions", ["location_id"])
    op.create_index(
        "ix_guest_sessions_organization_id", "guest_sessions", ["organization_id"]
    )
    op.create_index("ix_guest_sessions_voucher_id", "guest_sessions", ["voucher_id"])
    op.create_index("ix_guest_sessions_status", "guest_sessions", ["status"])
    op.create_index("ix_guest_sessions_started_at", "guest_sessions", ["started_at"])

    # -- guest_login_history -----------------------------------------------------
    op.create_table(
        "guest_login_history",
        *_base_model_columns(),
        sa.Column("guest_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("location_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("identifier", sa.String(255), nullable=False),
        sa.Column("auth_method", sa.String(30), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("failure_reason", sa.String(255), nullable=True),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.ForeignKeyConstraint(
            ["guest_id"],
            ["guests.id"],
            name="fk_guest_login_history_guest_id_guests",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_guest_login_history_organization_id_organizations",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["location_id"],
            ["locations.id"],
            name="fk_guest_login_history_location_id_locations",
            ondelete="SET NULL",
        ),
    )
    _create_base_model_indexes("guest_login_history")
    op.create_index(
        "ix_guest_login_history_guest_id", "guest_login_history", ["guest_id"]
    )
    op.create_index(
        "ix_guest_login_history_organization_id",
        "guest_login_history",
        ["organization_id"],
    )
    op.create_index(
        "ix_guest_login_history_location_id", "guest_login_history", ["location_id"]
    )
    op.create_index(
        "ix_guest_login_history_identifier", "guest_login_history", ["identifier"]
    )
    op.create_index(
        "ix_guest_login_history_auth_method", "guest_login_history", ["auth_method"]
    )
    op.create_index(
        "ix_guest_login_history_success", "guest_login_history", ["success"]
    )
    op.create_index(
        "ix_guest_login_history_attempted_at",
        "guest_login_history",
        ["attempted_at"],
    )

    # -- guest_consents ----------------------------------------------------------
    op.create_table(
        "guest_consents",
        *_base_model_columns(),
        sa.Column("guest_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "captive_portal_config_id", postgresql.UUID(as_uuid=True), nullable=True
        ),
        sa.Column("consented_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("terms_version", sa.String(50), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.ForeignKeyConstraint(
            ["guest_id"],
            ["guests.id"],
            name="fk_guest_consents_guest_id_guests",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["captive_portal_config_id"],
            ["captive_portal_configs.id"],
            name="fk_guest_consents_captive_portal_config_id_captive_portal_configs",
            ondelete="SET NULL",
        ),
    )
    _create_base_model_indexes("guest_consents")
    op.create_index("ix_guest_consents_guest_id", "guest_consents", ["guest_id"])
    op.create_index(
        "ix_guest_consents_captive_portal_config_id",
        "guest_consents",
        ["captive_portal_config_id"],
    )
    op.create_index(
        "ix_guest_consents_consented_at", "guest_consents", ["consented_at"]
    )

    # -- radius_nas_clients ------------------------------------------------------
    op.create_table(
        "radius_nas_clients",
        *_base_model_columns(),
        sa.Column("router_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("nas_identifier", sa.String(255), nullable=False),
        sa.Column("shared_secret_encrypted", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.ForeignKeyConstraint(
            ["router_id"],
            ["routers.id"],
            name="fk_radius_nas_clients_router_id_routers",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("radius_nas_clients")
    op.create_index(
        "ix_radius_nas_clients_router_id",
        "radius_nas_clients",
        ["router_id"],
        unique=True,
    )
    op.create_index(
        "ix_radius_nas_clients_nas_identifier",
        "radius_nas_clients",
        ["nas_identifier"],
        unique=True,
    )
    op.create_index(
        "ix_radius_nas_clients_is_active", "radius_nas_clients", ["is_active"]
    )


def downgrade() -> None:
    op.drop_index("ix_radius_nas_clients_is_active", table_name="radius_nas_clients")
    op.drop_index(
        "ix_radius_nas_clients_nas_identifier", table_name="radius_nas_clients"
    )
    op.drop_index("ix_radius_nas_clients_router_id", table_name="radius_nas_clients")
    _drop_base_model_indexes("radius_nas_clients")
    op.drop_table("radius_nas_clients")

    op.drop_index("ix_guest_consents_consented_at", table_name="guest_consents")
    op.drop_index(
        "ix_guest_consents_captive_portal_config_id", table_name="guest_consents"
    )
    op.drop_index("ix_guest_consents_guest_id", table_name="guest_consents")
    _drop_base_model_indexes("guest_consents")
    op.drop_table("guest_consents")

    op.drop_index(
        "ix_guest_login_history_attempted_at", table_name="guest_login_history"
    )
    op.drop_index("ix_guest_login_history_success", table_name="guest_login_history")
    op.drop_index(
        "ix_guest_login_history_auth_method", table_name="guest_login_history"
    )
    op.drop_index("ix_guest_login_history_identifier", table_name="guest_login_history")
    op.drop_index(
        "ix_guest_login_history_location_id", table_name="guest_login_history"
    )
    op.drop_index(
        "ix_guest_login_history_organization_id", table_name="guest_login_history"
    )
    op.drop_index("ix_guest_login_history_guest_id", table_name="guest_login_history")
    _drop_base_model_indexes("guest_login_history")
    op.drop_table("guest_login_history")

    op.drop_index("ix_guest_sessions_started_at", table_name="guest_sessions")
    op.drop_index("ix_guest_sessions_status", table_name="guest_sessions")
    op.drop_index("ix_guest_sessions_voucher_id", table_name="guest_sessions")
    op.drop_index("ix_guest_sessions_organization_id", table_name="guest_sessions")
    op.drop_index("ix_guest_sessions_location_id", table_name="guest_sessions")
    op.drop_index("ix_guest_sessions_router_id", table_name="guest_sessions")
    op.drop_index("ix_guest_sessions_device_id", table_name="guest_sessions")
    op.drop_index("ix_guest_sessions_guest_id", table_name="guest_sessions")
    _drop_base_model_indexes("guest_sessions")
    op.drop_table("guest_sessions")

    op.drop_index("ix_guest_devices_mac_address", table_name="guest_devices")
    op.drop_index("ix_guest_devices_guest_id", table_name="guest_devices")
    _drop_base_model_indexes("guest_devices")
    op.drop_table("guest_devices")

    op.drop_index("uq_guests_organization_id_identifier", table_name="guests")
    op.drop_index("ix_guests_is_blocked", table_name="guests")
    op.drop_index("ix_guests_identifier", table_name="guests")
    op.drop_index("ix_guests_location_id", table_name="guests")
    op.drop_index("ix_guests_organization_id", table_name="guests")
    _drop_base_model_indexes("guests")
    op.drop_table("guests")
