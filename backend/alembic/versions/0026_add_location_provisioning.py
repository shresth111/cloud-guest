"""Smart Location Provisioning: extend ``locations``, add
``location_code_counters``, extend ``users``.

Single migration (all three changes are small, closely related to one
feature, and touch disjoint tables -- splitting them across separate
revisions would add ceremony without any real independent-deployability
benefit, since Smart Location Provisioning needs all three to function).

Three changes, in dependency order:

* ``locations.property_type`` -- nullable ``String(30)`` (see
  ``app.domains.location.enums.PropertyType``'s own docstring: every
  pre-existing row has none, and it stays optional on the plain create
  endpoint too).
* ``locations.location_code`` -- nullable ``String(30)`` at the column
  level (so this migration never has to backfill a value for any location
  row that existed before this addition), with a **partial** unique index
  (``WHERE location_code IS NOT NULL``) enforcing uniqueness only among rows
  that do have one -- mirrors ``organization_members``'s own partial-unique-
  index precedent (migration ``0003``) for the identical reason.
  ``LocationService.create_location`` always generates a real one for every
  newly-created location going forward (see
  ``app.domains.location.number_generator``).
* ``location_code_counters`` -- the dedicated, real, DB-level-atomic counter
  table backing that generator, an exact structural mirror of BE-013 Part
  4's ``invoice_number_counters`` (migration ``0025``): a unique
  ``counter_key`` column + ``last_value``, incremented via a single atomic
  ``INSERT ... ON CONFLICT DO UPDATE ... RETURNING`` statement (see
  ``app.domains.location.number_generator``'s own module docstring), never a
  racy ``SELECT MAX(...) + 1``.
* ``users.must_change_password`` -- ``NOT NULL`` boolean, ``server_default
  false`` (every pre-existing row becomes ``false``, the correct value for
  every account that predates this feature) -- see
  ``app.domains.auth.models.User.must_change_password``'s own docstring and
  ``docs/location/FLOW.md``'s "must_change_password" section for why this
  narrow, additive auth-domain column was judged necessary.

No RBAC schema change -- this feature's only edit to ``app.domains.rbac``
is additive ``AuditAction`` enum values (``enums.py``), no migration needed.
``PermissionModule.LOCATIONS`` was already seeded since BE-004 (create/
read/update/delete/manage); no new permission group/action/scope row is
seeded by this migration. No new ``PlanFeatureKey`` migration is needed
either -- ``app.domains.billing.constants.PlanFeatureKey`` is a plain
``String`` column value (``PlanFeature.feature_key``), never a native
Postgres enum type, per that module's own documented convention -- adding
enum members is a code-only change.

``alembic/env.py`` already imports ``app.domains.location.models`` and
``app.domains.auth.models`` as whole modules, so the new
``LocationCodeCounter`` class (defined in that same ``location/models.py``)
is registered on ``Base.metadata`` automatically -- no ``env.py`` edit
needed.

Revision ID: 0026_add_location_provisioning
Revises: 0025_create_billing_invoice_tax_tables
Create Date: 2026-07-20
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0026_add_location_provisioning"
down_revision = "0025_create_billing_invoice_tax_tables"
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
    # -- locations: property_type / location_code --------------------------
    op.add_column("locations", sa.Column("property_type", sa.String(30), nullable=True))
    op.add_column("locations", sa.Column("location_code", sa.String(30), nullable=True))
    op.create_index("ix_locations_property_type", "locations", ["property_type"])
    op.create_index(
        "uq_locations_location_code",
        "locations",
        ["location_code"],
        unique=True,
        postgresql_where=sa.text("location_code IS NOT NULL"),
    )

    # -- location_code_counters ----------------------------------------------
    op.create_table(
        "location_code_counters",
        *_base_model_columns(),
        sa.Column("counter_key", sa.String(50), nullable=False),
        sa.Column("last_value", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint(
            "counter_key", name="uq_location_code_counters_counter_key"
        ),
    )
    _create_base_model_indexes("location_code_counters")
    op.create_index(
        "ix_location_code_counters_counter_key",
        "location_code_counters",
        ["counter_key"],
        unique=True,
    )

    # -- users: must_change_password -----------------------------------------
    op.add_column(
        "users",
        sa.Column(
            "must_change_password",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "must_change_password")

    op.drop_index(
        "ix_location_code_counters_counter_key",
        table_name="location_code_counters",
    )
    _drop_base_model_indexes("location_code_counters")
    op.drop_table("location_code_counters")

    op.drop_index("uq_locations_location_code", table_name="locations")
    op.drop_index("ix_locations_property_type", table_name="locations")
    op.drop_column("locations", "location_code")
    op.drop_column("locations", "property_type")
