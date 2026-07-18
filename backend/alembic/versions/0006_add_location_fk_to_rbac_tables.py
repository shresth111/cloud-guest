"""Add a real ``locations.id`` ForeignKey to the ``location_id`` columns
already present on RBAC tables, now that the Location domain (Module 006)
exists.

This is a pure ALTER-TABLE follow-up -- it does not touch ``0002_create_
rbac_tables``'s (or ``0004``'s) already-applied column/index definitions,
only adds a constraint on top of the existing ``location_id`` columns.
Nullable columns with no rows referencing a nonexistent location pass the
constraint validation trivially on a fresh/empty table, and are unaffected
on a populated one as long as every existing ``location_id`` value already
corresponds to a real ``locations.id`` row (true for any environment where
RBAC data was seeded before Location data existed, since those columns were
always nullable/FK-less and unpopulated until now).

Tables affected (constraint name matches ``Base.metadata``'s naming
convention, ``fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s``):

* ``user_roles.location_id`` -- ON DELETE SET NULL (a role assignment
  losing its location context is safer than being destroyed outright,
  mirroring ``user_roles.organization_id``'s own ``SET NULL`` reasoning
  from migration ``0004``).
* ``permission_overrides.location_id`` -- ON DELETE SET NULL (same
  reasoning as ``user_roles``).
* ``location_roles.location_id`` -- ON DELETE CASCADE (this column was
  already ``NOT NULL`` -- it is a strict per-location config row with no
  meaning once its location is gone, the same reasoning
  ``organization_roles.organization_id`` used for its own ``CASCADE``).
* ``audit_log_entries.location_id`` -- ON DELETE SET NULL (preserve audit
  history even if the location row is later removed -- audit trails should
  outlive the entities they describe).

``roles``/``organization_roles``/``permission_scopes`` carry no
``location_id`` column at all and are intentionally not touched here.
``router_id``/``msp_id`` columns remain FK-less -- the Router (and future
MSP) domain(s) still do not exist (see ``rbac/models.py``'s module
docstring).

Revision ID: 0006_add_location_fk_to_rbac_tables
Revises: 0005_create_location_tables
Create Date: 2026-07-18
"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "0006_add_location_fk_to_rbac_tables"
down_revision = "0005_create_location_tables"
branch_labels = None
depends_on = None

_SET_NULL_TABLES = ("user_roles", "permission_overrides", "audit_log_entries")
_CASCADE_TABLES = ("location_roles",)


def upgrade() -> None:
    for table_name in _SET_NULL_TABLES:
        op.create_foreign_key(
            f"fk_{table_name}_location_id_locations",
            table_name,
            "locations",
            ["location_id"],
            ["id"],
            ondelete="SET NULL",
        )
    for table_name in _CASCADE_TABLES:
        op.create_foreign_key(
            f"fk_{table_name}_location_id_locations",
            table_name,
            "locations",
            ["location_id"],
            ["id"],
            ondelete="CASCADE",
        )


def downgrade() -> None:
    for table_name in _CASCADE_TABLES:
        op.drop_constraint(
            f"fk_{table_name}_location_id_locations",
            table_name,
            type_="foreignkey",
        )
    for table_name in _SET_NULL_TABLES:
        op.drop_constraint(
            f"fk_{table_name}_location_id_locations",
            table_name,
            type_="foreignkey",
        )
