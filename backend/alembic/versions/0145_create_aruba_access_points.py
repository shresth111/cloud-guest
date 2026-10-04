"""Aruba Instant On multi-AP: ``aruba_access_points`` + ``guest_sessions.ap_mac``.

``aruba_access_points`` lists, per NAS-only (``aruba_instant_on``) router,
the access-point MACs the shared Aruba RADIUS listener accepts. Backfilled
with one ``approved``/``primary`` row per existing ``aruba_instant_on``
router from its own ``mac_address`` -- skipped when that MAC is a minted
placeholder (locally administered / multicast / zero / broadcast), which is
exactly the set ``aruba_shared.is_placeholder_mac`` already refuses, so the
listener accepts precisely what it accepted before this migration.

``guest_sessions.ap_mac`` / ``ap_ssid`` are nullable and written only by the
shared Aruba listener; every existing row stays NULL. MikroTik and Omada
rows are never touched.

Downgrade drops both.

Revision ID: 0145_create_aruba_access_points
Revises: 0144_create_location_speed_gateways
Create Date: 2026-10-04
"""

import re

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0145_create_aruba_access_points"
down_revision = "0144_create_location_speed_gateways"
branch_labels = None
depends_on = None

_TABLE = "aruba_access_points"
_BASE_INDEXED = ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by")


def _canonical_real_mac(raw: str | None) -> str | None:
    """Mirror of ``aruba_shared.recorded_ap_mac`` (copied, not imported: a
    migration must not change meaning when app code moves)."""
    if not raw:
        return None
    hexed = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    if len(hexed) != 12:
        return None
    mac = ":".join(hexed[i : i + 2] for i in range(0, 12, 2)).upper()
    if mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
        return None
    first = int(mac[:2], 16)
    if first & 0b11:
        return None
    return mac


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
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
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "location_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("locations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "router_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("routers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("mac", sa.String(17), nullable=False),
        sa.Column("name", sa.String(255), nullable=True),
        sa.Column("serial", sa.String(128), nullable=True),
        sa.Column("model", sa.String(128), nullable=True),
        sa.Column("source", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
    )
    for column in _BASE_INDEXED:
        op.create_index(f"ix_{_TABLE}_{column}", _TABLE, [column])
    op.create_index(f"ix_{_TABLE}_organization_id", _TABLE, ["organization_id"])
    op.create_index(f"ix_{_TABLE}_location_id", _TABLE, ["location_id"])
    op.create_index(
        f"uq_{_TABLE}_router_mac",
        _TABLE,
        ["router_id", "mac"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )

    op.add_column("guest_sessions", sa.Column("ap_mac", sa.String(17), nullable=True))
    op.add_column("guest_sessions", sa.Column("ap_ssid", sa.String(64), nullable=True))
    op.create_index(
        "ix_guest_sessions_router_ap_mac",
        "guest_sessions",
        ["router_id", "ap_mac"],
        postgresql_where=sa.text("ap_mac IS NOT NULL"),
    )

    # Backfill: one approved/primary row per Aruba router with a real MAC.
    bind = op.get_bind()
    routers = bind.execute(
        sa.text(
            "SELECT id, organization_id, location_id, mac_address, name "
            "FROM routers WHERE vendor = 'aruba_instant_on' "
            "AND is_deleted = false AND location_id IS NOT NULL"
        )
    ).fetchall()
    for row in routers:
        mac = _canonical_real_mac(row.mac_address)
        if mac is None:
            continue
        bind.execute(
            sa.text(
                f"INSERT INTO {_TABLE} (organization_id, location_id, router_id, "
                "mac, name, source, status) VALUES (:org, :loc, :rid, :mac, "
                ":name, 'primary', 'approved')"
            ),
            {
                "org": row.organization_id,
                "loc": row.location_id,
                "rid": row.id,
                "mac": mac,
                "name": row.name,
            },
        )


def downgrade() -> None:
    op.drop_index("ix_guest_sessions_router_ap_mac", table_name="guest_sessions")
    op.drop_column("guest_sessions", "ap_ssid")
    op.drop_column("guest_sessions", "ap_mac")
    op.drop_index(f"uq_{_TABLE}_router_mac", table_name=_TABLE)
    op.drop_index(f"ix_{_TABLE}_location_id", table_name=_TABLE)
    op.drop_index(f"ix_{_TABLE}_organization_id", table_name=_TABLE)
    for column in reversed(_BASE_INDEXED):
        op.drop_index(f"ix_{_TABLE}_{column}", table_name=_TABLE)
    op.drop_table(_TABLE)
