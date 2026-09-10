"""captive_portal_configs: content_image_key for the per-venue pre-login picture.

The "Before sign-in: show a picture" content mode gained a real upload in
the Portal settings (previously the field was a URL the venue had to host
themselves -- see PortalPage.tsx). Uploaded bytes live in object storage,
so the config row needs the durable object key, mirroring
``app.domains.branding``'s own ``logo_key``/``background_image_key``
columns exactly (key + public proxy URL built per-request by the router,
never a bare browser-loadable URL stored here).

Additive and nullable: existing rows keep today's behaviour (no upload,
``content_image_key`` NULL, ``content_image_url`` still available for a
venue that types in an externally hosted link).

Revision ID: 0120_add_content_image_key_to_captive_portal_configs
Revises: 0119_add_idle_timeout_minutes_to_guest_sessions
Create Date: 2026-09-08
"""

import sqlalchemy as sa

from alembic import op

revision = "0120_add_content_image_key_to_captive_portal_configs"
down_revision = "0119_add_idle_timeout_minutes_to_guest_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "captive_portal_configs",
        sa.Column("content_image_key", sa.String(length=500), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("captive_portal_configs", "content_image_key")
