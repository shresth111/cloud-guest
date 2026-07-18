"""Add a real ``organizations.id`` ForeignKey to the ``organization_id``
columns already present on RBAC tables, now that the Organization domain
(Module 005) exists.

This is a pure ALTER-TABLE follow-up -- it does not touch ``0002_create_
rbac_tables``'s already-applied column/index definitions, only adds a
constraint on top of the existing nullable ``organization_id`` columns.
Nullable columns with no rows referencing a nonexistent organization pass
the constraint validation trivially on a fresh/empty table, and are
unaffected on a populated one as long as every existing ``organization_id``
value already corresponds to a real ``organizations.id`` row (true for any
environment where RBAC data was seeded before Organization data existed,
since those columns were always nullable and unpopulated until now).

Tables affected (constraint name matches ``Base.metadata``'s naming
convention, ``fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s``):

* ``roles.organization_id`` -- ON DELETE SET NULL (a global/custom role
  should not disappear if its owning organization is later hard-deleted).
* ``user_roles.organization_id`` -- ON DELETE SET NULL.
* ``organization_roles.organization_id`` -- ON DELETE CASCADE (a strict
  per-organization config row; already ``NOT NULL``).
* ``permission_overrides.organization_id`` -- ON DELETE SET NULL.
* ``audit_log_entries.organization_id`` -- ON DELETE SET NULL (preserve
  audit history even if the organization row is later removed).

``permission_scopes`` carries no ``organization_id`` column at all (only
``permission_id``/``scope_type``) and is intentionally not touched here.
``location_id``/``router_id``/``msp_id`` columns remain FK-less -- the
Location/Router domains still do not exist (see ``rbac/models.py``'s module
docstring).

Revision ID: 0004_add_organization_fk_to_rbac_tables
Revises: 0003_create_organization_tables
Create Date: 2026-07-18
"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "0004_add_organization_fk_to_rbac_tables"
down_revision = "0003_create_organization_tables"
branch_labels = None
depends_on = None

_SET_NULL_TABLES = (
    "roles",
    "user_roles",
    "permission_overrides",
    "audit_log_entries",
)
_CASCADE_TABLES = ("organization_roles",)


def upgrade() -> None:
    for table_name in _SET_NULL_TABLES:
        op.create_foreign_key(
            f"fk_{table_name}_organization_id_organizations",
            table_name,
            "organizations",
            ["organization_id"],
            ["id"],
            ondelete="SET NULL",
        )
    for table_name in _CASCADE_TABLES:
        op.create_foreign_key(
            f"fk_{table_name}_organization_id_organizations",
            table_name,
            "organizations",
            ["organization_id"],
            ["id"],
            ondelete="CASCADE",
        )


def downgrade() -> None:
    for table_name in _CASCADE_TABLES:
        op.drop_constraint(
            f"fk_{table_name}_organization_id_organizations",
            table_name,
            type_="foreignkey",
        )
    for table_name in _SET_NULL_TABLES:
        op.drop_constraint(
            f"fk_{table_name}_organization_id_organizations",
            table_name,
            type_="foreignkey",
        )
