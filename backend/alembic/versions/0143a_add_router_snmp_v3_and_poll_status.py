"""Router SNMP: SNMPv3 credentials, last-poll status, last device apply.

0079 gave ``routers`` an SNMP block (enabled/community/version/port) that
nothing in the product could set, and a poll sweep that wrote nothing when
it skipped a router -- so "is SNMP working on this router?" had no answer
anywhere. This adds:

* SNMPv3 credentials -- auth/privacy protocol plus Fernet-encrypted
  passphrases (``app.domains.router.crypto``, same as the community string).
  The v3 user name reuses ``snmp_community_encrypted``: on RouterOS a v3
  user *is* an ``/snmp community`` row, so it is the same field on the
  device.
* The outcome of the most recent poll of this router (``ok`` /
  ``no_response`` / ``error`` / ``not_configured``), when, a short detail,
  and the last time a poll succeeded. Written by the sweep for every router
  it considers, including the ones it skips -- a skip is an answer too.
* When the platform last pushed SNMP config to the device and read it back
  as matching.

All nullable, no backfill: NULL is the true value for every existing row
(no router has ever been polled successfully or configured by us).

Revision ID: 0143a_add_router_snmp_v3_and_poll_status
Revises: 0143_add_require_guest_name_to_captive_portal_configs
Create Date: 2026-10-06
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0143a_add_router_snmp_v3_and_poll_status"
down_revision = "0143_add_require_guest_name_to_captive_portal_configs"
branch_labels = None
depends_on = None

_COLUMNS: tuple[tuple[str, sa.types.TypeEngine], ...] = (
    ("snmp_v3_auth_protocol", sa.String(10)),
    ("snmp_v3_auth_password_encrypted", sa.Text()),
    ("snmp_v3_priv_protocol", sa.String(10)),
    ("snmp_v3_priv_password_encrypted", sa.Text()),
    ("snmp_last_poll_at", sa.DateTime(timezone=True)),
    ("snmp_last_poll_status", sa.String(20)),
    ("snmp_last_poll_detail", sa.String(500)),
    ("snmp_last_success_at", sa.DateTime(timezone=True)),
    ("snmp_device_applied_at", sa.DateTime(timezone=True)),
)


def _existing_columns() -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns("routers")}


def upgrade() -> None:
    # Idempotent on purpose: this is the main-branch copy of staging's
    # ``0150_add_router_snmp_v3_and_poll_status`` (same columns), so SNMP can
    # ship to prod before the rest of staging. 0150 is idempotent too, so
    # whichever runs second is a no-op.
    existing = _existing_columns()
    for name, type_ in _COLUMNS:
        if name not in existing:
            op.add_column("routers", sa.Column(name, type_, nullable=True))


def downgrade() -> None:
    existing = _existing_columns()
    for name, _type in reversed(_COLUMNS):
        if name in existing:
            op.drop_column("routers", name)
