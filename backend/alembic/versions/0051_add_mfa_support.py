"""MFA/TOTP support: ``users.mfa_enabled``, ``user_mfa_credentials``,
``user_mfa_recovery_codes``.

See ``app.domains.auth.mfa``'s own module docstring for the full design
(pyotp TOTP, Fernet-encrypted secret under its own dedicated
``mfa_encryption_key`` -- never shared with ``router_encryption_key``).

* ``users.mfa_enabled`` -- ``NOT NULL`` boolean, ``server_default false``
  (every pre-existing row stays off; a user must explicitly enroll).
  Mirrors migration ``0047``'s identical ``data_masking_enabled`` addition
  (same table, same "additive boolean, real server_default" shape).
* ``user_mfa_credentials`` -- one row per enrolled user (1:1, unique
  ``user_id``); ``secret_encrypted`` is opaque ciphertext.
* ``user_mfa_recovery_codes`` -- single-use, SHA-256-hashed recovery
  codes.

No RBAC schema change.

Revision ID: 0051_add_mfa_support
Revises: 0050_create_api_keys_table
Create Date: 2026-07-21
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0051_add_mfa_support"
down_revision = "0050_create_api_keys_table"
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
    op.add_column(
        "users",
        sa.Column(
            "mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )

    op.create_table(
        "user_mfa_credentials",
        *_base_model_columns(),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("secret_encrypted", sa.Text(), nullable=False),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    _create_base_model_indexes("user_mfa_credentials")
    op.create_index(
        "ix_user_mfa_credentials_user_id",
        "user_mfa_credentials",
        ["user_id"],
        unique=True,
    )

    op.create_table(
        "user_mfa_recovery_codes",
        *_base_model_columns(),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("code_hash", sa.String(128), nullable=False, unique=True),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
    )
    _create_base_model_indexes("user_mfa_recovery_codes")
    op.create_index(
        "ix_user_mfa_recovery_codes_user_id", "user_mfa_recovery_codes", ["user_id"]
    )
    op.create_index(
        "ix_user_mfa_recovery_codes_used_at", "user_mfa_recovery_codes", ["used_at"]
    )


def downgrade() -> None:
    op.drop_index(
        "ix_user_mfa_recovery_codes_used_at", table_name="user_mfa_recovery_codes"
    )
    op.drop_index(
        "ix_user_mfa_recovery_codes_user_id", table_name="user_mfa_recovery_codes"
    )
    _drop_base_model_indexes("user_mfa_recovery_codes")
    op.drop_table("user_mfa_recovery_codes")

    op.drop_index(
        "ix_user_mfa_credentials_user_id", table_name="user_mfa_credentials"
    )
    _drop_base_model_indexes("user_mfa_credentials")
    op.drop_table("user_mfa_credentials")

    op.drop_column("users", "mfa_enabled")
