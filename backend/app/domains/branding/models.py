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
  plain text URL columns. When file upload is implemented in a future phase,
  a pre-signed upload endpoint will write to S3 and store the CloudFront URL
  here. No upload implementation is included in this module.

* **Default fallback:** every ``GET /api/branding`` endpoint returns
  non-null branding — either the organization's own row or the platform
  default. The frontend never receives null branding.
"""

import uuid

from app.database.base import BaseModel
from sqlalchemy import String, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column


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
