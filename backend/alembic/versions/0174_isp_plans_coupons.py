"""ISP Phase 2a (ADDENDUM_02): speed groups, packages, coupon batches,
subscribers, plan settings. Additive: seven new tables in the ISP partner
domain. FKs point into existing queue_profiles / voucher_plans /
voucher_batches / vouchers / guests, which are not altered. Rows this
feature creates in those existing tables (per ISP customer org) are left in
place on downgrade (manual cleanup SQL in ADDENDUM_02 §6).

Revision ID: 0174_isp_plans_coupons
Revises: 0173_isp_service_and_billing
Create Date: 2026-10-22
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0174_isp_plans_coupons"
down_revision = "0173_isp_service_and_billing"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "isp_plan_settings",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "default_validity_days", sa.Integer(), server_default="30", nullable=False
        ),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_plan_settings_isp_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_plan_settings")),
        sa.UniqueConstraint(
            "isp_organization_id", name=op.f("uq_isp_plan_settings_isp_organization_id")
        ),
    )
    op.create_index(
        op.f("ix_isp_plan_settings_created_at"),
        "isp_plan_settings",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_plan_settings_created_by"),
        "isp_plan_settings",
        ["created_by"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_plan_settings_deleted_at"),
        "isp_plan_settings",
        ["deleted_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_plan_settings_is_deleted"),
        "isp_plan_settings",
        ["is_deleted"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_plan_settings_updated_by"),
        "isp_plan_settings",
        ["updated_by"],
        unique=False,
    )
    op.create_table(
        "isp_speed_groups",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("download_kbps", sa.Integer(), nullable=False),
        sa.Column("upload_kbps", sa.Integer(), nullable=False),
        sa.Column("burst_download_kbps", sa.Integer(), nullable=True),
        sa.Column("burst_upload_kbps", sa.Integer(), nullable=True),
        sa.Column("burst_threshold_kbps", sa.Integer(), nullable=True),
        sa.Column("burst_time_seconds", sa.Integer(), nullable=True),
        sa.Column("priority", sa.SmallInteger(), server_default="8", nullable=False),
        sa.Column(
            "status", sa.String(length=10), server_default="active", nullable=False
        ),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_speed_groups_isp_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_speed_groups")),
    )
    op.create_index(
        op.f("ix_isp_speed_groups_created_at"),
        "isp_speed_groups",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_speed_groups_created_by"),
        "isp_speed_groups",
        ["created_by"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_speed_groups_deleted_at"),
        "isp_speed_groups",
        ["deleted_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_speed_groups_is_deleted"),
        "isp_speed_groups",
        ["is_deleted"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_speed_groups_updated_by"),
        "isp_speed_groups",
        ["updated_by"],
        unique=False,
    )
    op.create_index(
        "uq_isp_speed_groups_isp_name",
        "isp_speed_groups",
        ["isp_organization_id", sa.text("lower(name)")],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_table(
        "isp_packages",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column("speed_group_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=150), nullable=False),
        sa.Column("type", sa.String(length=10), nullable=False),
        sa.Column("validity_days", sa.Integer(), nullable=False),
        sa.Column("price_paise", sa.BigInteger(), nullable=False),
        sa.Column(
            "price_includes_gst",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column("data_cap_mb", sa.Integer(), nullable=True),
        sa.Column("max_devices", sa.SmallInteger(), server_default="1", nullable=False),
        sa.Column(
            "status", sa.String(length=10), server_default="active", nullable=False
        ),
        sa.Column(
            "needs_price", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_packages_isp_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["speed_group_id"],
            ["isp_speed_groups.id"],
            name=op.f("fk_isp_packages_speed_group_id_isp_speed_groups"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_packages")),
    )
    op.create_index(
        op.f("ix_isp_packages_created_at"), "isp_packages", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_isp_packages_created_by"), "isp_packages", ["created_by"], unique=False
    )
    op.create_index(
        op.f("ix_isp_packages_deleted_at"), "isp_packages", ["deleted_at"], unique=False
    )
    op.create_index(
        "ix_isp_packages_group", "isp_packages", ["speed_group_id"], unique=False
    )
    op.create_index(
        op.f("ix_isp_packages_is_deleted"), "isp_packages", ["is_deleted"], unique=False
    )
    op.create_index(
        op.f("ix_isp_packages_updated_by"), "isp_packages", ["updated_by"], unique=False
    )
    op.create_index(
        "uq_isp_packages_isp_name",
        "isp_packages",
        ["isp_organization_id", sa.text("lower(name)")],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_table(
        "isp_coupon_batches",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column("package_id", sa.UUID(), nullable=False),
        sa.Column("customer_organization_id", sa.UUID(), nullable=False),
        sa.Column("location_id", sa.UUID(), nullable=True),
        sa.Column("batch_seq", sa.Integer(), nullable=False),
        sa.Column("serial_prefix", sa.String(length=12), nullable=False),
        sa.Column("quantity", sa.Integer(), nullable=False),
        sa.Column("shelf_life_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["customer_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_coupon_batches_customer_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_coupon_batches_isp_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["location_id"],
            ["locations.id"],
            name=op.f("fk_isp_coupon_batches_location_id_locations"),
        ),
        sa.ForeignKeyConstraint(
            ["package_id"],
            ["isp_packages.id"],
            name=op.f("fk_isp_coupon_batches_package_id_isp_packages"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_coupon_batches")),
    )
    op.create_index(
        op.f("ix_isp_coupon_batches_created_at"),
        "isp_coupon_batches",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_coupon_batches_created_by"),
        "isp_coupon_batches",
        ["created_by"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_coupon_batches_deleted_at"),
        "isp_coupon_batches",
        ["deleted_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_coupon_batches_is_deleted"),
        "isp_coupon_batches",
        ["is_deleted"],
        unique=False,
    )
    op.create_index(
        "ix_isp_coupon_batches_isp_customer",
        "isp_coupon_batches",
        ["isp_organization_id", "customer_organization_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_coupon_batches_updated_by"),
        "isp_coupon_batches",
        ["updated_by"],
        unique=False,
    )
    op.create_index(
        "uq_isp_coupon_batches_seq",
        "isp_coupon_batches",
        ["isp_organization_id", "batch_seq"],
        unique=True,
    )
    op.create_table(
        "isp_package_materializations",
        sa.Column("package_id", sa.UUID(), nullable=False),
        sa.Column("customer_organization_id", sa.UUID(), nullable=False),
        sa.Column("queue_profile_id", sa.UUID(), nullable=False),
        sa.Column("voucher_plan_id", sa.UUID(), nullable=False),
        sa.Column(
            "group_profile_version", sa.Integer(), server_default="1", nullable=False
        ),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["customer_organization_id"],
            ["organizations.id"],
            name=op.f(
                "fk_isp_package_materializations_customer_organization_id_organizations"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["package_id"],
            ["isp_packages.id"],
            name=op.f("fk_isp_package_materializations_package_id_isp_packages"),
        ),
        sa.ForeignKeyConstraint(
            ["queue_profile_id"],
            ["queue_profiles.id"],
            name=op.f(
                "fk_isp_package_materializations_queue_profile_id_queue_profiles"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["voucher_plan_id"],
            ["voucher_plans.id"],
            name=op.f("fk_isp_package_materializations_voucher_plan_id_voucher_plans"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_package_materializations")),
    )
    op.create_index(
        op.f("ix_isp_package_materializations_created_at"),
        "isp_package_materializations",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_package_materializations_created_by"),
        "isp_package_materializations",
        ["created_by"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_package_materializations_deleted_at"),
        "isp_package_materializations",
        ["deleted_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_package_materializations_is_deleted"),
        "isp_package_materializations",
        ["is_deleted"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_package_materializations_updated_by"),
        "isp_package_materializations",
        ["updated_by"],
        unique=False,
    )
    op.create_index(
        "uq_isp_package_materializations_pkg_customer",
        "isp_package_materializations",
        ["package_id", "customer_organization_id"],
        unique=True,
    )
    op.create_table(
        "isp_coupon_batch_parts",
        sa.Column("coupon_batch_id", sa.UUID(), nullable=False),
        sa.Column("voucher_batch_id", sa.UUID(), nullable=False),
        sa.Column("part_index", sa.Integer(), nullable=False),
        sa.Column("quantity", sa.Integer(), nullable=False),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["coupon_batch_id"],
            ["isp_coupon_batches.id"],
            name=op.f("fk_isp_coupon_batch_parts_coupon_batch_id_isp_coupon_batches"),
        ),
        sa.ForeignKeyConstraint(
            ["voucher_batch_id"],
            ["voucher_batches.id"],
            name=op.f("fk_isp_coupon_batch_parts_voucher_batch_id_voucher_batches"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_coupon_batch_parts")),
        sa.UniqueConstraint(
            "voucher_batch_id", name=op.f("uq_isp_coupon_batch_parts_voucher_batch_id")
        ),
    )
    op.create_index(
        "ix_isp_coupon_batch_parts_batch",
        "isp_coupon_batch_parts",
        ["coupon_batch_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_coupon_batch_parts_created_at"),
        "isp_coupon_batch_parts",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_coupon_batch_parts_created_by"),
        "isp_coupon_batch_parts",
        ["created_by"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_coupon_batch_parts_deleted_at"),
        "isp_coupon_batch_parts",
        ["deleted_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_coupon_batch_parts_is_deleted"),
        "isp_coupon_batch_parts",
        ["is_deleted"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_coupon_batch_parts_updated_by"),
        "isp_coupon_batch_parts",
        ["updated_by"],
        unique=False,
    )
    op.create_table(
        "isp_subscribers",
        sa.Column("isp_organization_id", sa.UUID(), nullable=False),
        sa.Column("customer_organization_id", sa.UUID(), nullable=False),
        sa.Column("identifier", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=True),
        sa.Column("package_id", sa.UUID(), nullable=True),
        sa.Column("speed_group_id", sa.UUID(), nullable=True),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("source", sa.String(length=10), nullable=False),
        sa.Column("last_voucher_id", sa.UUID(), nullable=True),
        sa.Column("guest_id", sa.UUID(), nullable=True),
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.UUID(), nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["customer_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_subscribers_customer_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["guest_id"], ["guests.id"], name=op.f("fk_isp_subscribers_guest_id_guests")
        ),
        sa.ForeignKeyConstraint(
            ["isp_organization_id"],
            ["organizations.id"],
            name=op.f("fk_isp_subscribers_isp_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(
            ["last_voucher_id"],
            ["vouchers.id"],
            name=op.f("fk_isp_subscribers_last_voucher_id_vouchers"),
        ),
        sa.ForeignKeyConstraint(
            ["package_id"],
            ["isp_packages.id"],
            name=op.f("fk_isp_subscribers_package_id_isp_packages"),
        ),
        sa.ForeignKeyConstraint(
            ["speed_group_id"],
            ["isp_speed_groups.id"],
            name=op.f("fk_isp_subscribers_speed_group_id_isp_speed_groups"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_isp_subscribers")),
    )
    op.create_index(
        op.f("ix_isp_subscribers_created_at"),
        "isp_subscribers",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_subscribers_created_by"),
        "isp_subscribers",
        ["created_by"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_subscribers_deleted_at"),
        "isp_subscribers",
        ["deleted_at"],
        unique=False,
    )
    op.create_index(
        "ix_isp_subscribers_group", "isp_subscribers", ["speed_group_id"], unique=False
    )
    op.create_index(
        op.f("ix_isp_subscribers_is_deleted"),
        "isp_subscribers",
        ["is_deleted"],
        unique=False,
    )
    op.create_index(
        "ix_isp_subscribers_isp",
        "isp_subscribers",
        ["isp_organization_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_isp_subscribers_updated_by"),
        "isp_subscribers",
        ["updated_by"],
        unique=False,
    )
    op.create_index(
        "uq_isp_subscribers_customer_identifier",
        "isp_subscribers",
        ["customer_organization_id", "identifier"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )


def downgrade() -> None:
    for table in (
        "isp_subscribers",
        "isp_coupon_batch_parts",
        "isp_coupon_batches",
        "isp_package_materializations",
        "isp_packages",
        "isp_speed_groups",
        "isp_plan_settings",
    ):
        op.drop_table(table)
