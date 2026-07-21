"""Cross-cutting PII masking layer: ``users.data_masking_enabled``.

New shared utility (``app.common.masking``), not a domain -- see that
module's own docstring and ``docs/masking/FLOW.md`` for the full design
write-up. One additive column, no new table:

* ``users.data_masking_enabled`` -- ``NOT NULL`` boolean, ``server_default
  true`` (every pre-existing row becomes ``true`` -- masked -- the safe,
  fail-closed default for every account that predates this feature; a
  privileged user must have this explicitly flipped to ``false`` via the
  existing admin ``PUT /api/v1/users/{id}`` endpoint) -- see
  ``app.domains.auth.models.User.data_masking_enabled``'s own docstring.
  Mirrors migration ``0026``'s identical ``must_change_password`` addition
  (same table, same "additive boolean, real server_default" shape).

No RBAC schema change beyond one additive ``AuditAction`` enum value
(``PII_VIEWED_UNMASKED``, ``rbac/enums.py``) -- no migration needed for
that (``permission_groups``/``permissions``/``permission_scopes``/
``role_permissions`` rows are all seeded idempotently at application/CLI
startup by ``seed_rbac``, never by a migration, per this codebase's own
established convention -- see e.g. migration ``0039``'s identical note).

Revision ID: 0047_add_user_data_masking_enabled
Revises: 0046_create_network_diagnostics_tables
Create Date: 2026-07-21
"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "0047_add_user_data_masking_enabled"
down_revision = "0046_create_network_diagnostics_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "data_masking_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "data_masking_enabled")
