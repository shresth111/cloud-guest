"""Add a real ``routers.id`` ForeignKey to the ``router_id`` columns already
present on RBAC tables, now that the Router domain (Module 008) exists.

This is a pure ALTER-TABLE follow-up -- it does not touch
``0002_create_rbac_tables``'s already-applied column/index definitions, only
adds a constraint on top of the existing ``router_id`` columns. Nullable
columns with no rows referencing a nonexistent router pass the constraint
validation trivially on a fresh/empty table, and are unaffected on a
populated one as long as every existing ``router_id`` value already
corresponds to a real ``routers.id`` row (true for any environment where
RBAC data was seeded before Router data existed, since those columns were
always nullable/FK-less and unpopulated until now).

Tables affected (constraint name matches ``Base.metadata``'s naming
convention, ``fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s``):

* ``user_roles.router_id`` -- ON DELETE SET NULL (a role assignment losing
  its router context is safer than being destroyed outright, mirroring
  ``user_roles.location_id``'s own ``SET NULL`` reasoning from migration
  ``0006``).
* ``permission_overrides.router_id`` -- ON DELETE SET NULL (same reasoning
  as ``user_roles``).

``audit_log_entries`` carries no ``router_id`` column at all (only
``organization_id``/``location_id``) and is not touched here. There is no
``RouterRole`` table (see ``app/domains/rbac/models.py``'s module docstring
and ``docs/router/ROUTER_ARCHITECTURE.md`` §7 for why), so no analogous
``CASCADE``-owning config table exists to update, unlike
``location_roles``/``organization_roles`` in the prior two FK follow-ups.
``msp_id`` remains FK-less -- the MSP domain still does not exist.

Revision ID: 0008_add_router_fk_to_rbac_tables
Revises: 0007_create_router_tables
Create Date: 2026-07-18
"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "0008_add_router_fk_to_rbac_tables"
down_revision = "0007_create_router_tables"
branch_labels = None
depends_on = None

_SET_NULL_TABLES = ("user_roles", "permission_overrides")


def upgrade() -> None:
    for table_name in _SET_NULL_TABLES:
        op.create_foreign_key(
            f"fk_{table_name}_router_id_routers",
            table_name,
            "routers",
            ["router_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    for table_name in _SET_NULL_TABLES:
        op.drop_constraint(
            f"fk_{table_name}_router_id_routers",
            table_name,
            type_="foreignkey",
        )
