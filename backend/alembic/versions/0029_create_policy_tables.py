"""Policy: ``policies``, ``policy_versions``, ``policy_assignments``.

New domain (``app.domains.policy``), the Unified Policy Engine
``docs/ARCHITECTURE_DESIGN.md`` §6.1/§13 designed before this migration was
written. Three new tables:

* ``policies`` -- the aggregate root. ``organization_id`` is nullable (NULL
  == a platform-wide policy definition, mirrors ``notification_templates
  .organization_id``'s identical "nullable FK signals platform default"
  convention already named in the design doc's §15). ``current_version_id``
  points at whichever ``policy_versions`` row is currently active.
* ``policy_versions`` -- an immutable, append-only snapshot of a policy's
  ``rules`` (JSONB). ``(policy_id, version_number)`` is uniquely indexed.
* ``policy_assignments`` -- attaches a policy to a scope. ``scope_type``
  reuses ``app.domains.rbac.enums.ScopeType``'s values (stored as a plain
  string, like every other status/type column in this codebase);
  ``scope_id`` is nullable (NULL iff ``scope_type == 'global'``) and is
  deliberately not a real foreign key -- it points at either
  ``organizations.id`` or ``locations.id`` depending on ``scope_type``, the
  same polymorphic-scope shape ``app.domains.rbac``'s own role assignments
  already use for an identical reason.

## The ``policies.current_version_id`` <-> ``policy_versions.policy_id``
## circular foreign key

``policies`` and ``policy_versions`` reference each other. This migration
creates ``policies`` first with ``current_version_id`` as a plain, FK-less
UUID column, then creates ``policy_versions`` (whose ``policy_id`` FK to
``policies`` is not circular), then adds ``policies.current_version_id``'s
foreign key constraint via a separate ``op.create_foreign_key`` call once
both tables exist -- the standard way to express two mutually-referencing
tables in a single migration. ``downgrade`` drops the constraint first, then
both tables in reverse order.

No RBAC schema change -- this feature's only edit to ``app.domains.rbac`` is
additive ``PermissionModule``/``AuditAction`` enum values (``enums.py``) plus
their corresponding seed data (``seed.py``), no migration needed
(``permission_groups``/``permissions``/``permission_scopes``/``role_permissions``
rows are all seeded idempotently at application/CLI startup by
``seed_rbac``, never by a migration, per this codebase's own established
convention -- see e.g. migration ``0028``'s identical note).

Revision ID: 0029_create_policy_tables
Revises: 0028_create_guest_team_tables
Create Date: 2026-07-20
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0029_create_policy_tables"
down_revision = "0028_create_guest_team_tables"
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


_CURRENT_VERSION_FK = "fk_policies_current_version_id_policy_versions"


def upgrade() -> None:
    # -- policies -------------------------------------------------------------
    op.create_table(
        "policies",
        *_base_model_columns(),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("policy_type", sa.String(30), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        # FK added below, once policy_versions exists -- see module docstring.
        sa.Column("current_version_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    _create_base_model_indexes("policies")
    op.create_index("ix_policies_organization_id", "policies", ["organization_id"])
    op.create_index("ix_policies_policy_type", "policies", ["policy_type"])
    op.create_index("ix_policies_is_active", "policies", ["is_active"])

    # -- policy_versions --------------------------------------------------------
    op.create_table(
        "policy_versions",
        *_base_model_columns(),
        sa.Column(
            "policy_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("policies.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column(
            "rules",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    _create_base_model_indexes("policy_versions")
    op.create_index("ix_policy_versions_policy_id", "policy_versions", ["policy_id"])
    op.create_index("ix_policy_versions_status", "policy_versions", ["status"])
    op.create_index(
        "uq_policy_versions_policy_id_version_number",
        "policy_versions",
        ["policy_id", "version_number"],
        unique=True,
    )

    # Now that both tables exist, add the deferred FK -- see module docstring.
    op.create_foreign_key(
        _CURRENT_VERSION_FK,
        "policies",
        "policy_versions",
        ["current_version_id"],
        ["id"],
        ondelete="SET NULL",
    )

    # -- policy_assignments -------------------------------------------------------
    op.create_table(
        "policy_assignments",
        *_base_model_columns(),
        sa.Column(
            "policy_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("policies.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("scope_type", sa.String(20), nullable=False),
        sa.Column("scope_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    _create_base_model_indexes("policy_assignments")
    op.create_index(
        "ix_policy_assignments_policy_id", "policy_assignments", ["policy_id"]
    )
    op.create_index(
        "ix_policy_assignments_scope_type", "policy_assignments", ["scope_type"]
    )
    op.create_index(
        "ix_policy_assignments_scope_id", "policy_assignments", ["scope_id"]
    )
    op.create_index(
        "ix_policy_assignments_is_active", "policy_assignments", ["is_active"]
    )


def downgrade() -> None:
    op.drop_index("ix_policy_assignments_is_active", table_name="policy_assignments")
    op.drop_index("ix_policy_assignments_scope_id", table_name="policy_assignments")
    op.drop_index("ix_policy_assignments_scope_type", table_name="policy_assignments")
    op.drop_index("ix_policy_assignments_policy_id", table_name="policy_assignments")
    _drop_base_model_indexes("policy_assignments")
    op.drop_table("policy_assignments")

    op.drop_constraint(_CURRENT_VERSION_FK, "policies", type_="foreignkey")

    op.drop_index(
        "uq_policy_versions_policy_id_version_number", table_name="policy_versions"
    )
    op.drop_index("ix_policy_versions_status", table_name="policy_versions")
    op.drop_index("ix_policy_versions_policy_id", table_name="policy_versions")
    _drop_base_model_indexes("policy_versions")
    op.drop_table("policy_versions")

    op.drop_index("ix_policies_is_active", table_name="policies")
    op.drop_index("ix_policies_policy_type", table_name="policies")
    op.drop_index("ix_policies_organization_id", table_name="policies")
    _drop_base_model_indexes("policies")
    op.drop_table("policies")
