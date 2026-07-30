"""SQLAlchemy ORM model for the Captive Portal domain (BE-010 Part 3).

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version columns) for the same reason every other domain does --
Alembic autogenerate, ``GenericRepository``, and cross-domain FKs all keep
working uniformly.

One model: :class:`CaptivePortalConfig` -- the branding/content/enabled-
login-methods configuration for the guest WiFi login page a guest's device
is redirected to before getting internet access. This module is pure
configuration data plus a guest-facing "resolve the effective config" read
path (``service.CaptivePortalService.resolve_portal_config``) -- it does
**not** implement guest authentication itself (that is
``app.domains.otp``/``app.domains.voucher``, already built, and the future
``app.domains.guest`` module composes with all three).

## ``organization_id`` / ``location_id``: most-specific-wins resolution

Mirrors ``app.domains.router_provisioning.models.ConfigVariable``'s own
``ORGANIZATION``/``LOCATION`` scoping precedent, narrowed to just these two
tiers (this module has no router-level tier -- a captive portal's branding
is a business/site concern, not a per-device one):

* ``location_id IS NULL`` -- an **organization-level default** config, used
  by any location under that organization that has no config of its own.
  ``organization_id`` is always a real, non-nullable FK (a captive portal
  config always belongs to a tenant -- there is no "platform-wide, no
  organization" default the way OTP's nullable scope columns allow; mirrors
  ``app.domains.voucher.models.VoucherBatch.organization_id``'s identical
  non-nullable choice, see that module's ``FLOW.md`` §10 for the same
  reasoning applied here).
* ``location_id`` **non-null** -- a **location-specific override**.
  ``organization_id`` is still populated (denormalized from the location's
  own hierarchy, validated at creation time against the real
  ``LocationService`` -- see ``service.py``), purely so a location-scoped
  lookup never needs a join.

See ``service.CaptivePortalService.resolve_portal_config`` for the actual
most-specific-wins lookup (location override, else organization default,
else a raised ``CaptivePortalConfigNotConfiguredError`` -- there is no
hardcoded platform-wide fallback branding).

## ``is_default``: exactly one per organization, and only at the org tier

``is_default`` is only meaningful on an organization-level row
(``location_id IS NULL``) -- it marks *which* org-level config (an
organization may keep several, e.g. a draft being iterated on alongside a
currently-live one) is the one ``resolve_portal_config`` falls back to.
Setting ``is_default=True`` on a row with a non-null ``location_id`` is
rejected outright by ``validators.validate_default_scope`` -- a location
override's "is this the one used" question is already answered by
``is_active`` (see below), it has no separate "default among location
overrides" concept to express.

**Enforcement of "at most one ``is_default=True`` per organization" is
two-layered**, mirroring this codebase's established belt-and-suspenders
convention for a business invariant that matters (cf.
``OrganizationMember``'s active-membership partial unique index):

1. **Service-layer (the one that actually runs on every write):**
   ``CaptivePortalService._clear_existing_default`` looks up the
   organization's current default (if any) and flips it to
   ``is_default=False`` in the same call, *before* the new/updated row is
   persisted as the default -- so the invariant is actually maintained by
   normal application logic, not merely guarded against violation.
2. **Database partial unique index (the backstop):** a partial unique
   index on ``organization_id`` where ``location_id IS NULL AND
   is_default = true`` (see the migration) makes it structurally
   impossible for two org-level default rows to coexist even if the
   service-layer step above were ever bypassed (a direct script, a bug, a
   concurrent write race) -- a real ``IntegrityError`` at the database
   layer, not just an application-level promise.

## Content fields: inline text *or* external URL, never both

``terms_and_conditions_text``/``terms_and_conditions_url`` (and the
identical ``privacy_policy_text``/``privacy_policy_url`` pair) are two
nullable columns rather than one polymorphic field, so a captive portal's
frontend can render either "here is the text inline" or "link out to our
own hosted policy page" without needing to sniff whether a stored string is
a URL. ``validators.validate_single_content_source`` rejects only the case
where **both** are supplied at once for the same field (ambiguous: which
one should the frontend show?) -- it deliberately does **not** require
*exactly* one to always be set, so a config can be created/iterated on
before its legal text is finalized (see ``service.py``'s module docstring
for the full reasoning on this "at most one", not "exactly one", choice).

## Authentication method flags -- and the honest ``social_login`` boundary

``otp_sms_enabled``/``otp_email_enabled``/``voucher_enabled``/
``username_password_enabled``/``social_login_enabled`` are plain booleans
(not a JSONB bag) because they are a small, fixed, individually-meaningful
set this module's own guest-facing resolve response needs to expose
directly -- the same "explicit columns over JSONB when the shape is known
and small" judgment call ``app.domains.router_provisioning.models
.ConfigTemplate.is_system_template`` already documents.

**``social_login_enabled`` is a schema-only readiness flag, not a working
feature.** There is no real OAuth/social-login integration anywhere in this
codebase, and none is attempted here -- the same honest-boundary posture
``app.domains.otp``'s logging-only SMS/email "providers" already
establish for their own not-really-integrated dependency. Setting this
flag to ``True`` only changes what the guest-facing resolve response
*reports* as enabled; nothing in this module (or any other) actually
performs a social login. ``social_login_providers`` (JSONB, default
``[]``) is a forward-compatible extension point for a future integration
to list configured provider slugs (e.g. ``["google", "facebook"]``) --
today it is stored and returned verbatim, never interpreted or validated
against a real provider registry, because no such registry exists.
``username_password_enabled`` was originally the same kind of readiness
placeholder, written before the ``guest`` module existed to authenticate
against -- it no longer is. ``app.domains.guest.service.GuestService
.login_via_password``/``POST /guest/login/password`` is a real, working
login path today, and this flag genuinely gates it (see
``GuestService._resolve_and_validate_method``). It defaults to ``True``
-- the standard baseline every location gets (OTP once, then a saved
password from then on) -- mirroring
``app.domains.location.provisioning_service._resolve_login_methods``'s
identical always-on default for a freshly provisioned location; an admin
can still turn it off per location.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, Index, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import (
    DEFAULT_LANGUAGE,
    DEFAULT_PRIMARY_COLOR,
    DEFAULT_SECONDARY_COLOR,
    DEFAULT_THEME,
)
from .constants import DEFAULT_SUPPORTED_LANGUAGES as _DEFAULT_LANGS


def _default_supported_languages() -> list[str]:
    return list(_DEFAULT_LANGS)


class CaptivePortalConfig(BaseModel):
    """One captive-portal branding/content/login-methods configuration --
    either an organization-level default (``location_id IS NULL``) or a
    location-specific override. See module docstring for the full
    resolution-order, single-default-enforcement, and content-field write-up.
    """

    __tablename__ = "captive_portal_configs"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="CASCADE"),
        nullable=True,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Only meaningful when location_id IS NULL -- see module docstring.
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # -- branding --------------------------------------------------------------
    theme: Mapped[str] = mapped_column(
        String(20), default=DEFAULT_THEME.value, nullable=False
    )
    logo_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    background_image_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    primary_color: Mapped[str] = mapped_column(
        String(7), default=DEFAULT_PRIMARY_COLOR, nullable=False
    )
    secondary_color: Mapped[str] = mapped_column(
        String(7), default=DEFAULT_SECONDARY_COLOR, nullable=False
    )
    default_language: Mapped[str] = mapped_column(
        String(10), default=DEFAULT_LANGUAGE, nullable=False
    )
    supported_languages: Mapped[list[str]] = mapped_column(
        JSONB, default=_default_supported_languages, nullable=False
    )

    # -- content -----------------------------------------------------------------
    advertisement_banner_url: Mapped[str | None] = mapped_column(
        String(500), nullable=True
    )
    advertisement_banner_link: Mapped[str | None] = mapped_column(
        String(500), nullable=True
    )
    # Inline text OR external URL -- at most one set, never both. See module
    # docstring's "Content fields" section.
    terms_and_conditions_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    terms_and_conditions_url: Mapped[str | None] = mapped_column(
        String(500), nullable=True
    )
    privacy_policy_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    privacy_policy_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    splash_headline: Mapped[str | None] = mapped_column(String(200), nullable=True)
    splash_welcome_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Where a guest is sent after a successful login (e.g. back to the
    # business's own website) -- consumed by the future `guest` module,
    # never followed by this one.
    redirect_url: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # -- authentication method flags -----------------------------------------
    otp_sms_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    otp_email_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    voucher_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Real, working login-method gate -- see module docstring. Defaults
    # on: the standard "OTP once, then a saved password" baseline.
    username_password_enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    # Schema-only placeholder -- see module docstring. No real OAuth/
    # social-login integration exists anywhere in this codebase.
    social_login_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    social_login_providers: Mapped[list[str]] = mapped_column(
        JSONB, default=list, nullable=False
    )

    # -- business hours -----------------------------------------------------
    # Real, guest-facing effect (service.py's own resolve_portal_config
    # computes `is_open_now` from these at read time -- never stored/
    # cached, always evaluated against the current moment): when enabled
    # and the current time in `business_hours_timezone` falls outside the
    # matching day's open window, a guest hitting the portal sees a
    # "business is closed" screen instead of the sign-in card. Disabled
    # (False) leaves the portal open 24/7, unaffected by whatever schedule
    # is stored below -- exactly the previous, always-open behavior.
    business_hours_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    # IANA zone name (e.g. "Asia/Kolkata") -- the schedule's start/end
    # times are local to this zone, not UTC or the server's own zone.
    business_hours_timezone: Mapped[str] = mapped_column(
        String(64), default="UTC", nullable=False
    )
    # {"monday": {"open": true, "start": "09:00", "end": "18:00"}, ...} --
    # one entry per lowercase weekday name; a day with "open": false (or
    # missing entirely) is treated as closed all day. Validated by
    # validators.validate_business_hours_schedule before it's ever stored.
    business_hours_schedule: Mapped[dict] = mapped_column(
        JSONB, default=dict, nullable=False
    )
    # Shown on the guest-facing closed screen in place of the normal
    # sign-in card; a generic default is used when unset (see
    # renderers/service -- this domain has no renderer, the frontend
    # supplies the default copy).
    business_hours_closed_message: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    __table_args__ = (
        Index("ix_captive_portal_configs_organization_id", "organization_id"),
        Index("ix_captive_portal_configs_location_id", "location_id"),
        Index("ix_captive_portal_configs_is_active", "is_active"),
        Index("ix_captive_portal_configs_is_default", "is_default"),
        # Backstop for "at most one is_default=True org-level config" -- see
        # module docstring's two-layered enforcement write-up. Mirrors
        # app.domains.organization.models.OrganizationMember's identical
        # partial-unique-index convention (a plain Index(unique=True,
        # postgresql_where=...), not a UniqueConstraint).
        Index(
            "uq_captive_portal_configs_org_default",
            "organization_id",
            unique=True,
            postgresql_where=text("location_id IS NULL AND is_default = true"),
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<CaptivePortalConfig(id={self.id}, organization_id="
            f"{self.organization_id}, location_id={self.location_id}, "
            f"is_active={self.is_active}, is_default={self.is_default})>"
        )


__all__ = ["CaptivePortalConfig"]
