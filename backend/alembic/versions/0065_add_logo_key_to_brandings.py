"""Add logo_key to brandings for real, object-storage-backed portal/org
logo uploads (previously logo_url was a plain text column only -- an
admin had to paste an already-hosted image URL, there was no upload).

Mirrors 0063_add_background_image_to_brandings.py exactly: stores the
MinIO/S3 *object key* app.core.storage.S3ObjectStorage uploaded the logo
under, not a URL -- BrandingService resolves it to the stable
GET /branding/logo/raw proxy path on every read, the same pattern already
used for the login-screen background image.

Revision ID: 0065_add_logo_key_to_brandings
Revises: 0064_add_guest_hashed_password
Create Date: 2026-07-26
"""

import sqlalchemy as sa

from alembic import op

revision = "0065_add_logo_key_to_brandings"
down_revision = "0064_add_guest_hashed_password"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "brandings",
        sa.Column("logo_key", sa.String(1024), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("brandings", "logo_key")
