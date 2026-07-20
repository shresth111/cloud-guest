"""Guest Teams: ``guest_teams``, ``guest_team_members``.

New domain (``app.domains.guest_teams``), an extension of
``app.domains.guest`` composing its real ``GuestService`` rather than
touching its tables. Two new tables:

* ``guest_teams`` -- a named group of guests sharing one access grant. A
  real FK to ``organizations`` (``NOT NULL``, ``ondelete="CASCADE"``) and an
  optional FK to ``locations`` (``ondelete="SET NULL"`` -- see
  ``app.domains.guest_teams.models``'s own module docstring for why this,
  not ``CASCADE``, mirroring ``Guest.location_id``'s identical reasoning
  rather than ``VoucherBatch.location_id``'s). ``team_code`` is globally
  unique (a real ``UNIQUE`` index), reusing
  ``app.domains.voucher.constants.VOUCHER_CODE_ALPHABET``'s exact
  print-friendly alphabet/generation approach for its value (a code-only
  reuse, no schema dependency on the ``vouchers`` tables at all).
* ``guest_team_members`` -- one membership stint of a ``Guest`` in a
  ``GuestTeam`` (FKs to both, both ``ondelete="CASCADE"``). Append-only per
  stint (see ``models.py``'s own docstring): a **partial** unique index
  (``WHERE is_active = true AND is_deleted = false``) enforces "a guest
  cannot be an ACTIVE member of the same team twice" as a real, DB-level
  constraint, while still allowing several terminal rows for the same
  ``(team_id, guest_id)`` pair to accumulate over the team's lifetime (one
  per join/leave cycle) -- mirrors migration ``0026``'s own
  ``uq_locations_location_code`` partial-unique-index precedent, and
  ``organization_members``' own membership-uniqueness index (migration
  ``0003``), for the identical reason.

No RBAC schema change -- this feature's only edit to ``app.domains.rbac``
is additive ``PermissionModule``/``AuditAction`` enum values (``enums.py``)
plus their corresponding seed data (``seed.py``), no migration needed
(``permission_groups``/``permissions``/``permission_scopes``/``role_permissions``
rows are all seeded idempotently at application/CLI startup by
``seed_rbac``, never by a migration, per this codebase's own established
convention -- see e.g. migration ``0026``'s identical note for
``PermissionModule.LOCATIONS``).

Revision ID: 0028_create_guest_team_tables
Revises: 0027_create_guest_access_tables
Create Date: 2026-07-20
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0028_create_guest_team_tables"
down_revision = "0027_create_guest_access_tables"
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
    # -- guest_teams ---------------------------------------------------------
    op.create_table(
        "guest_teams",
        *_base_model_columns(),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "location_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("locations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("team_code", sa.String(32), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("max_members", sa.Integer(), nullable=True),
        sa.Column("shared_data_limit_mb", sa.Integer(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.Text(), nullable=True),
    )
    _create_base_model_indexes("guest_teams")
    op.create_index(
        "ix_guest_teams_organization_id", "guest_teams", ["organization_id"]
    )
    op.create_index("ix_guest_teams_location_id", "guest_teams", ["location_id"])
    op.create_index("ix_guest_teams_status", "guest_teams", ["status"])
    op.create_index(
        "ix_guest_teams_team_code", "guest_teams", ["team_code"], unique=True
    )
    op.create_index("ix_guest_teams_expires_at", "guest_teams", ["expires_at"])

    # -- guest_team_members ----------------------------------------------------
    op.create_table(
        "guest_team_members",
        *_base_model_columns(),
        sa.Column(
            "team_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("guest_teams.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "guest_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("guests.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("joined_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("left_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("removal_reason", sa.String(500), nullable=True),
    )
    _create_base_model_indexes("guest_team_members")
    op.create_index("ix_guest_team_members_team_id", "guest_team_members", ["team_id"])
    op.create_index(
        "ix_guest_team_members_guest_id", "guest_team_members", ["guest_id"]
    )
    op.create_index(
        "ix_guest_team_members_is_active", "guest_team_members", ["is_active"]
    )
    op.create_index(
        "uq_guest_team_members_team_guest_active",
        "guest_team_members",
        ["team_id", "guest_id"],
        unique=True,
        postgresql_where=sa.text("is_active = true AND is_deleted = false"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_guest_team_members_team_guest_active", table_name="guest_team_members"
    )
    op.drop_index("ix_guest_team_members_is_active", table_name="guest_team_members")
    op.drop_index("ix_guest_team_members_guest_id", table_name="guest_team_members")
    op.drop_index("ix_guest_team_members_team_id", table_name="guest_team_members")
    _drop_base_model_indexes("guest_team_members")
    op.drop_table("guest_team_members")

    op.drop_index("ix_guest_teams_expires_at", table_name="guest_teams")
    op.drop_index("ix_guest_teams_team_code", table_name="guest_teams")
    op.drop_index("ix_guest_teams_status", table_name="guest_teams")
    op.drop_index("ix_guest_teams_location_id", table_name="guest_teams")
    op.drop_index("ix_guest_teams_organization_id", table_name="guest_teams")
    _drop_base_model_indexes("guest_teams")
    op.drop_table("guest_teams")
