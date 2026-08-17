"""Portal PIN: device-scoped guest quick-login. Additive-only schema
changes across two existing tables, no new table:

* ``guests`` gains ``hashed_pin``/``pin_set_at``/``pin_last_used_at``/
  ``pin_failed_attempts``/``pin_locked_until`` -- mirrors
  ``0064_add_guest_hashed_password``'s identical "nullable, opt-in"
  posture for the credential columns; ``pin_failed_attempts``/
  ``pin_locked_until`` are a best-effort, durable, admin-visible mirror of
  the real, authoritative Redis-backed lockout
  ``app.domains.guest.service.GuestPinSecurity`` checks on every
  ``login_via_pin`` request (see that class's own docstring) -- never the
  source of truth for that check itself.
* ``captive_portal_configs`` gains ``pin_login_enabled`` -- mirrors
  ``0074_add_otp_whatsapp_enabled_to_captive_portal_configs``'s identical
  shape one-for-one (a new, per-location opt-in login-method flag,
  ``NOT NULL`` with a ``server_default`` so every existing row keeps its
  previous, equivalent behavior -- "this feature didn't exist yet" reads
  the same as "this feature is off").

Revision ID: 0085_add_portal_pin_login
Revises: 0084_create_router_checklist_items_table
Create Date: 2026-08-17
"""

import sqlalchemy as sa

from alembic import op

revision = "0085_add_portal_pin_login"
down_revision = "0084_create_router_checklist_items_table"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "guests",
        sa.Column("hashed_pin", sa.String(255), nullable=True),
    )
    op.add_column(
        "guests",
        sa.Column("pin_set_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "guests",
        sa.Column("pin_last_used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "guests",
        sa.Column(
            "pin_failed_attempts",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.add_column(
        "guests",
        sa.Column("pin_locked_until", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "captive_portal_configs",
        sa.Column(
            "pin_login_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("captive_portal_configs", "pin_login_enabled")
    op.drop_column("guests", "pin_locked_until")
    op.drop_column("guests", "pin_failed_attempts")
    op.drop_column("guests", "pin_last_used_at")
    op.drop_column("guests", "pin_set_at")
    op.drop_column("guests", "hashed_pin")
