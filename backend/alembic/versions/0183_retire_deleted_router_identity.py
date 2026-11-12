"""Free the serial/MAC still held by soft-deleted fleet rows.

``uq_routers_serial_number``/``uq_routers_mac_address`` are plain unique
indexes, so a soft-deleted ``routers`` row kept the device's real serial and
MAC and the same device could not be added again (prod 2026-11-12: an Aruba
AP21 removed from Master). ``RouterService._retire_router`` now moves a row's
identity to a retired one at decommission time; this applies the same values
to rows deleted before that existed.

Data only, additive, idempotent:

* touches ``is_deleted = true`` rows only, and among them only rows whose
  serial does not already carry ``-deleted-`` (already retired, by the
  service or by hand) -- a second run changes nothing;
* the real values are kept on the row in ``settings["retired_identity"]``;
* the retired values come from the same derivation as
  ``app.domains.router.service.retired_router_identity`` (copied, not
  imported: a migration must not change when app code does; a unit test pins
  the two together), dated by the row's own ``deleted_at``.

Downgrade is a no-op on purpose: once a live row has taken the device's real
serial/MAC, writing it back onto the tombstone would violate the index.

Revision ID: 0183_retire_deleted_router_identity
Revises: 0181_add_router_local_admin_password
Create Date: 2026-11-12
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa

from alembic import op

revision = "0183_retire_deleted_router_identity"
down_revision = "0181_add_router_local_admin_password"
branch_labels = None
depends_on = None

RETIRED_SERIAL_MARKER = "-deleted-"
SERIAL_NUMBER_MAX_LENGTH = 100

SELECT_CANDIDATES = sa.text(
    "SELECT id, serial_number, mac_address, deleted_at FROM routers "
    "WHERE is_deleted = true AND serial_number NOT LIKE '%-deleted-%'"
)

UPDATE_ROW = sa.text(
    "UPDATE routers SET serial_number = :serial, mac_address = :mac, "
    "settings = COALESCE(settings, '{}'::jsonb) || CAST(:retired AS jsonb) "
    "WHERE id = :id AND is_deleted = true"
)


def retired_identity(
    router_id: uuid.UUID, serial_number: str, retired_at: datetime
) -> tuple[str, str]:
    digest = hashlib.sha256(b"retired-router-identity:" + router_id.bytes).digest()
    first_octet = (digest[0] & 0b1111_1100) | 0b10
    mac = ":".join(f"{octet:02X}" for octet in (first_octet, *digest[1:6]))
    suffix = f"{RETIRED_SERIAL_MARKER}{retired_at:%Y%m%d}-{digest[6:10].hex()}"
    serial = f"{serial_number[: SERIAL_NUMBER_MAX_LENGTH - len(suffix)]}{suffix}"
    return serial, mac


def plan(rows: list[Any], *, now: datetime) -> list[dict[str, Any]]:
    """The UPDATE parameters for each candidate row. Re-checks the marker so
    the result is right even if handed a row the SELECT would have skipped."""
    updates: list[dict[str, Any]] = []
    for row in rows:
        router_id = row.id if isinstance(row.id, uuid.UUID) else uuid.UUID(str(row.id))
        if RETIRED_SERIAL_MARKER in (row.serial_number or ""):
            continue
        retired_at = row.deleted_at or now
        serial, mac = retired_identity(router_id, row.serial_number, retired_at)
        updates.append(
            {
                "id": router_id,
                "serial": serial,
                "mac": mac,
                "retired": json.dumps(
                    {
                        "retired_identity": {
                            "serial_number": row.serial_number,
                            "mac_address": row.mac_address,
                            "retired_at": retired_at.isoformat(),
                            "retired_by": revision,
                        }
                    }
                ),
            }
        )
    return updates


def upgrade() -> None:
    bind = op.get_bind()
    rows = list(bind.execute(SELECT_CANDIDATES))
    for params in plan(rows, now=datetime.now(UTC)):
        bind.execute(UPDATE_ROW, params)


def downgrade() -> None:
    # See the module docstring: the real values are in
    # settings["retired_identity"], but restoring them is not safe.
    pass
