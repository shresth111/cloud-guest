"""Create RBAC domain tables: permission_groups, permissions, permission_scopes,
roles, role_scopes, role_permissions, user_roles, permission_overrides,
organization_roles, location_roles, audit_log_entries.

Mirrors ``0001_create_auth_tables``'s conventions: every table gets the
``BaseModel`` column set (id, created_at, updated_at, soft-delete, audit,
version) plus its own base-model indexes, using the same
``_base_model_columns`` / ``_create_base_model_indexes`` helpers (duplicated
here, not imported, since Alembic migrations are meant to be self-contained
snapshots rather than depending on other migration modules).

Revision ID: 0002_create_rbac_tables
Revises: 0001_create_auth_tables
Create Date: 2026-07-18
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0002_create_rbac_tables"
down_revision = "0001_create_auth_tables"
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
    # -- permission_groups ---------------------------------------------------
    op.create_table(
        "permission_groups",
        *_base_model_columns(),
        sa.Column("key", sa.String(100), nullable=False),
        sa.Column("name", sa.String(150), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("key", name="uq_permission_groups_key"),
    )
    _create_base_model_indexes("permission_groups")
    op.create_index("ix_permission_groups_key", "permission_groups", ["key"])

    # -- permissions -----------------------------------------------------------
    op.create_table(
        "permissions",
        *_base_model_columns(),
        sa.Column("permission_group_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("key", sa.String(150), nullable=False),
        sa.Column("action", sa.String(30), nullable=False),
        sa.Column("name", sa.String(150), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.ForeignKeyConstraint(
            ["permission_group_id"],
            ["permission_groups.id"],
            name="fk_permissions_permission_group_id_permission_groups",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("key", name="uq_permissions_key"),
    )
    _create_base_model_indexes("permissions")
    op.create_index(
        "ix_permissions_permission_group_id", "permissions", ["permission_group_id"]
    )
    op.create_index("ix_permissions_key", "permissions", ["key"])
    op.create_index("ix_permissions_action", "permissions", ["action"])

    # -- permission_scopes -----------------------------------------------------
    op.create_table(
        "permission_scopes",
        *_base_model_columns(),
        sa.Column("permission_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scope_type", sa.String(20), nullable=False),
        sa.ForeignKeyConstraint(
            ["permission_id"],
            ["permissions.id"],
            name="fk_permission_scopes_permission_id_permissions",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "permission_id", "scope_type", name="uq_permission_scopes_permission_scope"
        ),
    )
    _create_base_model_indexes("permission_scopes")
    op.create_index(
        "ix_permission_scopes_permission_id", "permission_scopes", ["permission_id"]
    )

    # -- roles -------------------------------------------------------------------
    op.create_table(
        "roles",
        *_base_model_columns(),
        sa.Column("name", sa.String(150), nullable=False),
        sa.Column("slug", sa.String(150), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "is_system_role", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column(
            "is_template", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("scope_type", sa.String(20), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("parent_role_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["parent_role_id"],
            ["roles.id"],
            name="fk_roles_parent_role_id_roles",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint(
            "slug", "organization_id", name="uq_roles_slug_organization_id"
        ),
    )
    _create_base_model_indexes("roles")
    op.create_index("ix_roles_slug", "roles", ["slug"])
    op.create_index("ix_roles_scope_type", "roles", ["scope_type"])
    op.create_index("ix_roles_organization_id", "roles", ["organization_id"])
    op.create_index("ix_roles_parent_role_id", "roles", ["parent_role_id"])
    op.create_index("ix_roles_is_active", "roles", ["is_active"])
    op.create_index("ix_roles_is_system_role", "roles", ["is_system_role"])

    # -- role_scopes ---------------------------------------------------------
    op.create_table(
        "role_scopes",
        *_base_model_columns(),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scope_type", sa.String(20), nullable=False),
        sa.Column(
            "is_default", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name="fk_role_scopes_role_id_roles",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("role_id", "scope_type", name="uq_role_scopes_role_scope"),
    )
    _create_base_model_indexes("role_scopes")
    op.create_index("ix_role_scopes_role_id", "role_scopes", ["role_id"])

    # -- role_permissions ------------------------------------------------------
    op.create_table(
        "role_permissions",
        *_base_model_columns(),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("permission_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("granted_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name="fk_role_permissions_role_id_roles",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["permission_id"],
            ["permissions.id"],
            name="fk_role_permissions_permission_id_permissions",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "role_id", "permission_id", name="uq_role_permissions_role_permission"
        ),
    )
    _create_base_model_indexes("role_permissions")
    op.create_index("ix_role_permissions_role_id", "role_permissions", ["role_id"])
    op.create_index(
        "ix_role_permissions_permission_id", "role_permissions", ["permission_id"]
    )

    # -- user_roles --------------------------------------------------------------
    op.create_table(
        "user_roles",
        *_base_model_columns(),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scope_type", sa.String(20), nullable=False),
        sa.Column("msp_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("location_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("router_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("granted_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_user_roles_user_id_users",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name="fk_user_roles_role_id_roles",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("user_roles")
    op.create_index("ix_user_roles_user_id", "user_roles", ["user_id"])
    op.create_index("ix_user_roles_role_id", "user_roles", ["role_id"])
    op.create_index("ix_user_roles_organization_id", "user_roles", ["organization_id"])
    op.create_index("ix_user_roles_location_id", "user_roles", ["location_id"])
    op.create_index("ix_user_roles_router_id", "user_roles", ["router_id"])
    op.create_index("ix_user_roles_is_active", "user_roles", ["is_active"])
    op.create_index("ix_user_roles_expires_at", "user_roles", ["expires_at"])

    # -- permission_overrides --------------------------------------------------
    op.create_table(
        "permission_overrides",
        *_base_model_columns(),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("permission_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("effect", sa.String(10), nullable=False),
        sa.Column("scope_type", sa.String(20), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("location_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("router_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("granted_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_permission_overrides_user_id_users",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["permission_id"],
            ["permissions.id"],
            name="fk_permission_overrides_permission_id_permissions",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("permission_overrides")
    op.create_index(
        "ix_permission_overrides_user_id", "permission_overrides", ["user_id"]
    )
    op.create_index(
        "ix_permission_overrides_permission_id",
        "permission_overrides",
        ["permission_id"],
    )
    op.create_index(
        "ix_permission_overrides_is_active", "permission_overrides", ["is_active"]
    )

    # -- organization_roles ------------------------------------------------------
    op.create_table(
        "organization_roles",
        *_base_model_columns(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "is_default_for_new_members",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name="fk_organization_roles_role_id_roles",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "organization_id", "role_id", name="uq_organization_roles_org_role"
        ),
    )
    _create_base_model_indexes("organization_roles")
    op.create_index(
        "ix_organization_roles_organization_id",
        "organization_roles",
        ["organization_id"],
    )
    op.create_index("ix_organization_roles_role_id", "organization_roles", ["role_id"])

    # -- location_roles ------------------------------------------------------------
    op.create_table(
        "location_roles",
        *_base_model_columns(),
        sa.Column("location_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "is_default_for_new_members",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["roles.id"],
            name="fk_location_roles_role_id_roles",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "location_id", "role_id", name="uq_location_roles_location_role"
        ),
    )
    _create_base_model_indexes("location_roles")
    op.create_index("ix_location_roles_location_id", "location_roles", ["location_id"])
    op.create_index("ix_location_roles_role_id", "location_roles", ["role_id"])

    # -- audit_log_entries -----------------------------------------------------
    op.create_table(
        "audit_log_entries",
        *_base_model_columns(),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("entity_type", sa.String(50), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "metadata",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("location_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    _create_base_model_indexes("audit_log_entries")
    op.create_index(
        "ix_audit_log_entries_actor_user_id", "audit_log_entries", ["actor_user_id"]
    )
    op.create_index("ix_audit_log_entries_action", "audit_log_entries", ["action"])
    op.create_index(
        "ix_audit_log_entries_entity_type", "audit_log_entries", ["entity_type"]
    )
    op.create_index(
        "ix_audit_log_entries_entity_id", "audit_log_entries", ["entity_id"]
    )
    op.create_index(
        "ix_audit_log_entries_organization_id", "audit_log_entries", ["organization_id"]
    )


def downgrade() -> None:
    op.drop_index(
        "ix_audit_log_entries_organization_id", table_name="audit_log_entries"
    )
    op.drop_index("ix_audit_log_entries_entity_id", table_name="audit_log_entries")
    op.drop_index("ix_audit_log_entries_entity_type", table_name="audit_log_entries")
    op.drop_index("ix_audit_log_entries_action", table_name="audit_log_entries")
    op.drop_index("ix_audit_log_entries_actor_user_id", table_name="audit_log_entries")
    _drop_base_model_indexes("audit_log_entries")
    op.drop_table("audit_log_entries")

    op.drop_index("ix_location_roles_role_id", table_name="location_roles")
    op.drop_index("ix_location_roles_location_id", table_name="location_roles")
    _drop_base_model_indexes("location_roles")
    op.drop_table("location_roles")

    op.drop_index("ix_organization_roles_role_id", table_name="organization_roles")
    op.drop_index(
        "ix_organization_roles_organization_id", table_name="organization_roles"
    )
    _drop_base_model_indexes("organization_roles")
    op.drop_table("organization_roles")

    op.drop_index(
        "ix_permission_overrides_is_active", table_name="permission_overrides"
    )
    op.drop_index(
        "ix_permission_overrides_permission_id", table_name="permission_overrides"
    )
    op.drop_index("ix_permission_overrides_user_id", table_name="permission_overrides")
    _drop_base_model_indexes("permission_overrides")
    op.drop_table("permission_overrides")

    op.drop_index("ix_user_roles_expires_at", table_name="user_roles")
    op.drop_index("ix_user_roles_is_active", table_name="user_roles")
    op.drop_index("ix_user_roles_router_id", table_name="user_roles")
    op.drop_index("ix_user_roles_location_id", table_name="user_roles")
    op.drop_index("ix_user_roles_organization_id", table_name="user_roles")
    op.drop_index("ix_user_roles_role_id", table_name="user_roles")
    op.drop_index("ix_user_roles_user_id", table_name="user_roles")
    _drop_base_model_indexes("user_roles")
    op.drop_table("user_roles")

    op.drop_index("ix_role_permissions_permission_id", table_name="role_permissions")
    op.drop_index("ix_role_permissions_role_id", table_name="role_permissions")
    _drop_base_model_indexes("role_permissions")
    op.drop_table("role_permissions")

    op.drop_index("ix_role_scopes_role_id", table_name="role_scopes")
    _drop_base_model_indexes("role_scopes")
    op.drop_table("role_scopes")

    op.drop_index("ix_roles_is_system_role", table_name="roles")
    op.drop_index("ix_roles_is_active", table_name="roles")
    op.drop_index("ix_roles_parent_role_id", table_name="roles")
    op.drop_index("ix_roles_organization_id", table_name="roles")
    op.drop_index("ix_roles_scope_type", table_name="roles")
    op.drop_index("ix_roles_slug", table_name="roles")
    _drop_base_model_indexes("roles")
    op.drop_table("roles")

    op.drop_index("ix_permission_scopes_permission_id", table_name="permission_scopes")
    _drop_base_model_indexes("permission_scopes")
    op.drop_table("permission_scopes")

    op.drop_index("ix_permissions_action", table_name="permissions")
    op.drop_index("ix_permissions_key", table_name="permissions")
    op.drop_index("ix_permissions_permission_group_id", table_name="permissions")
    _drop_base_model_indexes("permissions")
    op.drop_table("permissions")

    op.drop_index("ix_permission_groups_key", table_name="permission_groups")
    _drop_base_model_indexes("permission_groups")
    op.drop_table("permission_groups")
