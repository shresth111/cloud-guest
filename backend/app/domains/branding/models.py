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

* **``favicon_url`` is still a plain text URL column** -- no upload
  implementation for it yet.

* **Background image and logo are real uploads:** ``background_image_key``
  (the login-screen background) and ``logo_key`` (the org/portal logo)
  both go through ``app.core.storage`` (the same MinIO/S3-compatible
  object storage ``app.domains.voucher``/``app.domains.analytics``
  already write through) -- storing the object *key*, not a URL. The
  frontend fetches the actual bytes through ``GET
  /branding/background-image/raw`` / ``GET /branding/logo/raw``
  (``BrandingService.get_background_image_bytes`` /
  ``get_logo_bytes``), a proxy through this API's own already-public
  port, rather than a direct object-storage link the object storage's
  own docker-network-only endpoint can't serve to a browser.
  ``logo_url`` (the plain text column) is kept as a fallback for an
  organization that has typed in an already-hosted URL instead of
  uploading a file -- ``BrandingService`` prefers ``logo_key`` when both
  are present.

* **Default fallback:** every ``GET /api/branding`` endpoint returns
  non-null branding — either the organization's own row or the platform
  default. The frontend never receives null branding.
"""

import uuid

from sqlalchemy import ForeignKey, Index, Integer, String
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

    # Measurements of the background image above, computed once at
    # upload by ``BrandingService``'s ``_process_background_image``
    # (captive-portal v7 design spec §1.4 C3/C5) and never edited by
    # hand. They live on ``brandings``, next to the image, because they
    # *describe the image* -- a second venue reusing the same org photo
    # measures identically, so per-venue storage would be duplication
    # that can go stale. (The per-venue half of the same feature,
    # ``background_focal_x``/``_y``, is on ``captive_portal_configs``
    # for the mirror-image reason: the same photo should crop
    # differently at different venues.)
    #
    # All three are 0-100 and all three are nullable, which is the
    # correct shape rather than a NOT NULL DEFAULT: "we have not
    # measured this image" is a real, distinguishable state -- every row
    # uploaded before v7, plus any upload that took the graceful
    # store-the-original fallback -- and it is not the same statement as
    # "this image measured 0" (a pure black photo). The frontend needs
    # to tell those apart to decide between C3's adaptive scrim and the
    # unconditional §1.3 floor, and a NOT NULL default would quietly
    # assert a measurement that was never taken.
    #
    # ``background_luminance``: mean luma of the whole image.
    # ``background_top_luminance``: mean luma of the top band the
    # headline sits over. ``background_entropy``: normalized histogram
    # entropy, the "busyness" measure C5's refusal rule reads to decide
    # whether the headline must drop onto the card.
    background_luminance: Mapped[int | None] = mapped_column(Integer, nullable=True)
    background_top_luminance: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    background_entropy: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Object storage key (not a URL) for an uploaded logo -- same pattern
    # as background_image_key. Takes priority over the plain-text
    # `logo_url` column when both are set (see this module's docstring).
    logo_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)

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
