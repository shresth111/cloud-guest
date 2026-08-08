"""SQLAlchemy ORM model for the URL Shortener domain.

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version columns) for the same reason every other domain does --
Alembic autogenerate, ``GenericRepository``, and cross-domain FKs all keep
working uniformly.

## Why ``organization_id``/``created_by_user_id`` are both nullable

A :class:`ShortLink` may be created from three distinct surfaces (see
``constants.ShortLinkSource``):

* The public, unauthenticated marketing-site tool -- no platform-user
  identity and no organization context exist at all for that caller, the
  same "guest-facing, no platform identity" posture
  ``app.domains.otp.models.OtpRequest.organization_id``/``location_id``
  already established. Both columns are ``NULL`` for a ``public_site`` row.
* The authenticated customer dashboard -- ``organization_id`` is always set
  (``CurrentOrganization``-resolved, tenant-scoped) and
  ``created_by_user_id`` is always set (the authenticated caller).
* The Master console -- platform-wide, not tied to any one organization;
  ``organization_id`` stays ``NULL`` the same way a ``public_site`` row's
  does, but ``created_by_user_id`` is set to the operator.

``organization_id is None`` is therefore this table's own "not scoped to
any one tenant" signal -- mirrors
``app.domains.voucher.models.VoucherPlan.organization_id``'s identical
nullable-means-platform-wide-or-anonymous posture, and is exactly what
``ShortLinkService``'s tenant-isolation checks (see that module's own
docstring) key off of.

## Why ``code`` is a plain, unique, plaintext column, not hashed

A short-link code is meant to be looked up by an anonymous visitor's
browser on every single click (``GET /s/{code}``) -- it is a public,
by-design-guessable-only-by-brute-force routing key, not a secret proving
anything about the holder (unlike an OTP code or a voucher's redemption
value). Hashing it would only add a lookup-time cost with no security
benefit, mirroring the "plaintext where hashing buys nothing" judgment call
``app.domains.voucher.models.Voucher``'s own module docstring documents at
length for the identical reason (a voucher code, too, is validated by "does
this string exist", not by proving possession of a secret).

## Why ``target_url`` is only ever validated, never fetched

See ``validators.validate_target_url``'s own docstring: this module stores
and redirects, and deliberately never makes a server-side request to
``target_url`` itself (no HEAD/GET pre-flight, no preview-image fetch) --
that would be a genuine SSRF vector (an attacker-controlled URL fetched by
this server's own network position). Validation is syntactic only (scheme
allow-list, hostname deny-list for obviously-internal targets), same
posture as the module brief.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import ShortLinkSource


class ShortLink(BaseModel):
    """A single shortened URL and its click-tracking state."""

    __tablename__ = "short_links"

    code: Mapped[str] = mapped_column(String(16), nullable=False, unique=True)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    source: Mapped[str] = mapped_column(
        String(20), default=ShortLinkSource.CUSTOMER.value, nullable=False
    )
    click_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_clicked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_short_links_code", "code", unique=True),
        Index("ix_short_links_organization_id", "organization_id"),
        Index("ix_short_links_created_by_user_id", "created_by_user_id"),
        Index("ix_short_links_source", "source"),
        Index("ix_short_links_is_active", "is_active"),
        Index("ix_short_links_expires_at", "expires_at"),
    )

    def is_expired(self, *, now: datetime) -> bool:
        return self.expires_at is not None and now > self.expires_at

    def is_resolvable(self, *, now: datetime) -> bool:
        """Whether ``GET /s/{code}`` should redirect through this link right
        now -- active, not (soft-)deleted, and not past its own
        ``expires_at``. Checked on read, not swept by a background job --
        mirrors ``app.domains.voucher.models.VoucherBatch
        .is_batch_expired``'s identical "lazy expiry" posture."""
        return self.is_active and not self.is_deleted and not self.is_expired(now=now)

    def __repr__(self) -> str:
        return f"<ShortLink(id={self.id}, code={self.code})>"


__all__ = ["ShortLink"]
