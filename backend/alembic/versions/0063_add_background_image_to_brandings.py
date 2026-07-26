"""Add background_image_key to brandings for the customer dashboard's
Background Image page (login-screen background, one per organization).

Stores the MinIO/S3 *object key* app.core.storage.S3ObjectStorage uploaded
the image under -- not a plain URL. The branding module's own docstring
already earmarked this ("Future S3/CloudFront ... a pre-signed upload
endpoint will write to S3 ... No upload implementation is included in this
module"); this migration is that upload landing, reusing the same object
storage app.domains.voucher/app.domains.analytics already write through.
``BrandingService`` resolves the key to a fresh presigned URL on every
``GET /branding`` call rather than storing a URL directly, since a
presigned URL itself expires -- the *key* is what's durable.

Revision ID: 0063_add_background_image_to_brandings
Revises: 0062_create_demo_requests_table
Create Date: 2026-07-26
"""

import sqlalchemy as sa

from alembic import op

revision = "0063_add_background_image_to_brandings"
down_revision = "0062_create_demo_requests_table"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "brandings",
        sa.Column("background_image_key", sa.String(1024), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("brandings", "background_image_key")
