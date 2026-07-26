"""Branding module for organization-specific visual identity.

Each organization gets its own Branding row defining company name, logo,
favicon, color scheme, and theme (light/dark). If no branding is configured,
the system returns a default platform branding.

Architecture notes:

* **Separate table, not JSONB:** unlike the lightweight branding stored
  inside ``Organization.settings["branding"]`` (app name/favicon/support
  email/custom domain), this module uses a dedicated ``brandings`` table
  with indexed columns — the brand data here is expected to be queried
  and updated frequently and independently of Organization settings.

* **Future S3/CloudFront:** ``logo_url`` and ``favicon_url`` are stored as
  plain text URL columns -- still true for those two, no upload
  implementation for them yet.

* **Background image is the one exception:** ``background_image_key``
  (the login-screen background) *is* a real upload, going through
  ``app.core.storage`` (the same MinIO/S3-compatible object storage
  ``app.domains.voucher``/``app.domains.analytics`` already write
  through). It stores the object *key*, not a URL -- the frontend fetches
  the actual bytes through ``GET /branding/background-image/raw``
  (``BrandingService.get_background_image_bytes``), a proxy through this
  API's own already-public port, rather than a direct object-storage
  link the object storage's own docker-network-only endpoint can't serve
  to a browser.

* **Default fallback:** every ``GET /api/branding`` endpoint returns
  non-null branding — either the organization's own row or the platform
  default. The frontend never receives null branding.
"""

import uuid

from sqlalchemy import ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class Branding(BaseModel):
    """Organization-specific visual branding configuration."""

    __tablename__ = "brandings"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        unique=True,
    )

    company_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    logo_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    favicon_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # Object storage key (not a URL) for the login-screen background image
    # -- see this module's docstring. Resolved to a presigned URL at read
    # time by BrandingService, never exposed to the frontend directly.
    background_image_key: Mapped[str | None] = mapped_column(
        String(1024), nullable=True
    )

    primary_color: Mapped[str | None] = mapped_column(String(50), nullable=True)
    secondary_color: Mapped[str | None] = mapped_column(String(50), nullable=True)
    accent_color: Mapped[str | None] = mapped_column(String(50), nullable=True)

    theme: Mapped[str | None] = mapped_column(
        String(20), nullable=True, default="light"
    )

    __table_args__ = (
        Index("ix_brandings_organization_id", "organization_id", unique=True),
    )


__all__ = ["Branding"]
