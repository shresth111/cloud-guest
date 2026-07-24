"""Fix radius_nas_clients unique indexes to exclude soft-deleted rows.

``ix_radius_nas_clients_router_id`` and ``ix_radius_nas_clients_nas_identifier``
were plain (non-partial) unique indexes, so a soft-deleted NAS client
(``is_deleted = true``) still counted toward uniqueness -- once a router's
NAS client was deleted, no new NAS client could ever be registered for that
router again (same for a reused ``nas_identifier``), a permanent dead end
discovered live while registering a real MikroTik CHR test device. Rebuilds
both as partial unique indexes scoped to ``WHERE is_deleted = false``,
matching the established convention already used elsewhere in this domain
(``uq_radius_nas_clients_nas_code``) and in sibling domains (see
``connected_devices``'s ``uq_connected_devices_router_id_mac_address``).
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0061_fix_radius_nas_soft_delete_uniqueness"
down_revision: str | None = "0060_create_support_ticket_replies_table"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_index("ix_radius_nas_clients_router_id", table_name="radius_nas_clients")
    op.create_index(
        "ix_radius_nas_clients_router_id",
        "radius_nas_clients",
        ["router_id"],
        unique=True,
        postgresql_where="is_deleted = false",
    )

    op.drop_index(
        "ix_radius_nas_clients_nas_identifier", table_name="radius_nas_clients"
    )
    op.create_index(
        "ix_radius_nas_clients_nas_identifier",
        "radius_nas_clients",
        ["nas_identifier"],
        unique=True,
        postgresql_where="is_deleted = false",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_radius_nas_clients_nas_identifier", table_name="radius_nas_clients"
    )
    op.create_index(
        "ix_radius_nas_clients_nas_identifier",
        "radius_nas_clients",
        ["nas_identifier"],
        unique=True,
    )

    op.drop_index("ix_radius_nas_clients_router_id", table_name="radius_nas_clients")
    op.create_index(
        "ix_radius_nas_clients_router_id",
        "radius_nas_clients",
        ["router_id"],
        unique=True,
    )
