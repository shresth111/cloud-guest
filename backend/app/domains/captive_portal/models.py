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

``otp_sms_enabled``/``otp_email_enabled``/``otp_whatsapp_enabled``/
``voucher_enabled``/``username_password_enabled``/``social_login_enabled``
are plain booleans
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

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import (
    DEFAULT_BACKGROUND_FOCAL_X,
    DEFAULT_BACKGROUND_FOCAL_Y,
    DEFAULT_BACKGROUND_OVERLAY_STRENGTH,
    DEFAULT_GUEST_FONT_CHOICE,
    DEFAULT_LANGUAGE,
    DEFAULT_PORTAL_CONTENT_MODE,
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
    # Curated heading-font allowlist (v6 design spec §3.2) -- a plain
    # String, not a native PostgreSQL enum type, for the same reason
    # `theme` above is (see constants.py's module docstring): adding a 5th
    # curated face never requires an ALTER TYPE migration, only a new
    # additive GuestFontChoice member plus validators.validate_
    # guest_font_choice's allowlist. Governs the guest-facing heading layer
    # only (frontend's pg-display/pg-title/pg-subtitle) -- never body/UI
    # text. Validated server-side against GuestFontChoice's exact 4 values
    # in validators.validate_guest_font_choice -- deliberately never a
    # free-text field (spec §3.2/§6.1 item 2).
    guest_font_choice: Mapped[str] = mapped_column(
        String(20), default=DEFAULT_GUEST_FONT_CHOICE.value, nullable=False
    )
    # Guest-facing background scrim peak opacity, 0-100 (v6 design spec
    # §4.2) -- the structural, per-venue-tunable fix to a saga of three
    # sequential hardcoded single-engineer opacity guesses (see the spec's
    # §1.2/§4.1). Default 55 reproduces today's hardcoded 0.55 peak scrim
    # opacity exactly, so a venue with no explicit value set (every venue
    # migrated from before this field existed) renders pixel-identical to
    # previously-shipped output. Stored as the admin's literal chosen
    # integer across the full [0, 100] range -- the frontend's own
    # [15, 85] guardrail (spec §4.3's buildGuestBackdropScrim) is a
    # render-time clamp applied on read, never applied to what's stored
    # here, so the admin UI's slider always reflects the real saved value.
    # Validated server-side in validators.validate_background_overlay_
    # strength.
    background_overlay_strength: Mapped[int] = mapped_column(
        Integer, default=DEFAULT_BACKGROUND_OVERLAY_STRENGTH, nullable=False
    )
    # Per-venue background focal point as integer percentages of the
    # image's width/height (v7 design spec §1.4 C4). NOT NULL with
    # defaults 50/25 chosen to be exactly the frontend's current
    # hardcoded `background-position: center 25%`, so this is a
    # zero-rendered-change addition for every venue that already exists
    # -- the same discipline background_overlay_strength's default 55
    # follows above.
    #
    # On captive_portal_configs, not brandings, deliberately: an
    # organization's single uploaded photo is shared across its venues,
    # and the crop worth using differs per venue (a wide lobby shot may
    # want its left third at one site and its right at another). The
    # numbers that describe the *file* rather than the venue --
    # brandings.background_luminance / _top_luminance / _entropy, from
    # the same v7 pass -- live with the file for the same reason.
    #
    # Validated server-side in validators.validate_background_focal_point.
    background_focal_x: Mapped[int] = mapped_column(
        Integer, default=DEFAULT_BACKGROUND_FOCAL_X, nullable=False
    )
    background_focal_y: Mapped[int] = mapped_column(
        Integer, default=DEFAULT_BACKGROUND_FOCAL_Y, nullable=False
    )

    # Whether the guest-facing portal renders the "Powered by Wyfy Guest"
    # attribution (v7 design spec Part 3, P4). Turning it *off* is
    # white-label behaviour: the check lives in
    # service.CaptivePortalService.update_config, gated on
    # PlanFeatureKey.WHITE_LABEL, and fires only on the transition to
    # False -- turning the mark back on is always free, or a tenant who
    # downgraded would be stuck with a setting they could not revert.
    #
    # Deliberately NOT enforced through a RequireFeature router
    # dependency: that would gate the whole PUT, so a non-entitled tenant
    # could no longer change their logo or colours either. Equally
    # deliberately not enforced on resolve, which is unauthenticated --
    # a 402 there would break the portal outright for every non-entitled
    # tenant.
    #
    # NOT NULL default True because every row predating this column has
    # always rendered the mark, so True is the value meaning "unchanged"
    # -- the same test guest_font_choice's 'system' and
    # background_focal_x/y's 50/25 are chosen against. It is also the
    # only default that cannot leak revenue on deploy.
    powered_by_enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
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
    # never followed by this one. Also the destination for
    # ``content_mode == "redirect"`` (see below) -- one column, both
    # purposes, rather than a parallel field that could drift out of sync.
    redirect_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # The venue's own HTML for the page a guest sees *after* a successful
    # sign-in -- the post-login surface, which until now could only ever be
    # "bounce them at redirect_url" or "show the built-in success screen".
    #
    # Deliberately NOT a sixth ``content_mode`` value. ``content_mode``
    # below is the *pre*-login content step: what the portal presents
    # before/instead of the sign-in form. This is a different screen at a
    # different point in the journey, and folding it into that enum would
    # make "show a promo image before login" and "show my own page after
    # login" mutually exclusive, which they are not. It does follow that
    # enum's own stated convention exactly -- one column per surface, and
    # degrade gracefully when the column is empty.
    #
    # Nullable, and null/empty is load-bearing: it means "unchanged", i.e.
    # today's behaviour byte-for-byte (countdown to ``redirect_url`` if one
    # is set, the built-in success screen otherwise). No row that exists
    # when this column is added changes what any guest currently sees.
    #
    # ``post_login_html`` and ``redirect_url`` are not alternatives and do
    # not override one another: with both set, the venue's HTML renders
    # *and* the existing continue-to-URL affordance stays. Reconciling the
    # two on screen is the frontend's job; this layer's only obligation is
    # that both fields are always returned together, which
    # ``router._config_response`` satisfies for every endpoint at once.
    #
    # **Stored pre-sanitized, never sanitized on read.** What is in this
    # column has already been through
    # ``html_sanitizer.sanitize_post_login_html`` -- see that module for
    # why the write path is the right place and what the allowlist is. The
    # short version: this HTML is shown to a guest on the same origin that
    # handles their OTP code, its author is semi-trusted, and the
    # sandboxed-iframe renderer on the frontend is the primary control but
    # must not be the only one. A reader of this column may assume the
    # bytes are already safe; a *writer* must never assume that and must go
    # through the service layer.
    post_login_html: Mapped[str | None] = mapped_column(Text, nullable=True)

    # -- content mode --------------------------------------------------------
    # What the portal presents as its primary content before/instead of the
    # sign-in form -- see constants.PortalContentMode. A plain String (not a
    # PG enum), default "login" (the existing, unchanged sign-in-only render),
    # so migration 0098 backfilling every existing row to "login" is a pure
    # no-op on what any guest currently sees. Each non-login mode reads its
    # content from exactly one of the columns below (redirect reuses
    # redirect_url above); the frontend's PortalContentBlock renders it.
    content_mode: Mapped[str] = mapped_column(
        String(20), default=DEFAULT_PORTAL_CONTENT_MODE.value, nullable=False
    )
    # content_mode == "image"/"text"/"survey": an optional heading shown
    # above the content block. content_mode == "text": the body copy under
    # it. content_mode == "image": the foreground content image URL (the
    # promo/menu/event graphic itself -- distinct from background_image_url,
    # which is the backdrop the sign-in card floats over). All nullable: a
    # mode may be selected before its content is filled in (a draft), and the
    # frontend degrades gracefully to the sign-in card when the chosen mode's
    # source column is empty.
    content_heading: Mapped[str | None] = mapped_column(String(200), nullable=True)
    content_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_image_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # content_mode == "survey": the survey definition -- a small
    # JSON object ({"questions": [...], "submitLabel": "..."}), the same
    # "explicit column, JSONB when the shape is a self-contained document"
    # choice supported_languages/social_login_providers already make here.
    # The frontend (types/portal-runtime.ts PortalSurvey) owns the schema;
    # this column stores it verbatim.
    content_survey: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # -- authentication method flags -----------------------------------------
    otp_sms_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    otp_email_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    # Third real OTP delivery channel, additive alongside otp_sms_enabled/
    # otp_email_enabled -- see app.domains.otp.constants.OtpChannel.WHATSAPP
    # and app.domains.otp.service.TwilioWhatsAppProvider for the backing
    # delivery mechanism. Defaults off (unlike otp_sms_enabled): a real send
    # requires a Meta-approved WhatsApp Business template
    # (whatsapp_twilio_content_sid) most fresh deployments won't have
    # configured yet, so this never silently promises a channel that isn't
    # actually wired up for a given organization.
    otp_whatsapp_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    voucher_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Real, working login-method gate -- see module docstring. Defaults
    # on: the standard "OTP once, then a saved password" baseline.
    username_password_enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    # Real, working login-method gate for Portal PIN
    # (app.domains.guest.service.GuestService.login_via_pin /
    # POST /guest/login/pin) -- mirrors username_password_enabled's
    # identical shape one column above, checked the exact same way via
    # GuestService._require_method_enabled. Defaults off (unlike
    # username_password_enabled): a PIN is a materially weaker secret
    # (constants.PIN_LENGTH digits vs. a real password), so this is an
    # opt-in an operator turns on deliberately per location, not a
    # baseline every fresh deployment gets for free.
    pin_login_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
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
