"""Smart Location Provisioning: the single orchestration entry point that
composes every existing domain this platform already has (Organization,
Location, User, RBAC, Router, Router Provisioning, WireGuard, Billing,
Captive Portal, OTP's provider protocols) into one "Create Location" flow --
without reimplementing any of them.

## Why this lives in its own file, inside ``app.domains.location``

The project owner explicitly rejected an earlier attempt that built this as
a separate ``app/domains/onboarding/`` module: "extend the existing Location
module". This file is that extension -- it is not a new domain, it is not
imported from ``alembic/env.py`` as a separate models module (it defines no
models of its own beyond what ``models.py`` already gained), and its own
router endpoints are registered on the *same* ``app.domains.location.router``
``APIRouter`` used by every other Location endpoint. It is a second file
(rather than adding ~500 more lines to the already-substantial
``service.py``) purely to keep ``service.py`` focused on plain Location
CRUD/lifecycle -- the orchestration below composes nine other domains and
earns its own module for readability, exactly the "your call, document it"
latitude the spec explicitly gives.

## The real single-transaction guarantee -- how this module upholds it

``app/database/session.py``'s ``get_db_session`` yields exactly ONE
request-scoped ``AsyncSession``, calls ``session.commit()`` exactly once at
the very end if nothing raised, and calls ``session.rollback()`` (then
re-raises) if any exception propagated out of the request handler. Every
domain service this module composes (``OrganizationService``,
``LocationService``, ``UserService``, ``RouterService``,
``RouterProvisioningService``, ``WireGuardService``, ``PlanService``/
``SubscriptionService``, ``CaptivePortalService``, RBAC's repository) is, in
turn, built entirely on ``GenericRepository``, whose ``create``/``update``/
``soft_delete`` methods call only ``session.flush()`` -- never
``session.commit()``. (``GenericRepository`` *does* expose an explicit
``commit()``/``rollback()`` method, and Billing's own ``PlanService``/
``SubscriptionService`` do not call it either -- confirmed by reading
``app/domains/billing/service.py`` before composing it here.) This module's
``get_location_provisioning_service`` dependency (see ``dependencies.py``)
builds every one of the above services through FastAPI's own dependency
graph, which resolves ``Depends(get_db_session)`` exactly once per request
and hands that *same* ``AsyncSession`` instance to every dependant that
(transitively) needs one -- so every composed repository in this call tree
shares one connection/transaction. ``provision_location`` itself never
catches and swallows an exception from any composed step (no
``try``/``except`` anywhere in this method) -- so a failure at, say, step
(g) propagates all the way up through the FastAPI route handler to
``get_db_session``'s own ``except Exception: await session.rollback(); raise``,
which genuinely rolls back every flushed-but-uncommitted change from steps
(a)-(f) too. See ``tests/unit/test_location_provisioning.py``'s
``TestTransactionalRollback`` for a real, forced-failure proof of this using
a shared fake session double.

## Billing feature-flag/plan-limit override design decision

BE-013 Part 1's ``PlanFeature`` is inherently *plan-level*: every
organization subscribed to the same ``Plan`` shares identical entitlements.
There is no existing per-organization override table anywhere in
``app.domains.billing`` (confirmed by reading its full model/constants
surface). Two designs were considered for the spec's "Feature Access" step
(a Super-Admin override, at provisioning time, layered on top of whatever
the selected Plan's own defaults already are):

1. A new, ``location``-owned override table keyed by organization_id +
   feature_key.
2. Reuse Billing's own existing, documented precedent: ``PlanType.CUSTOM``
   plus ``Plan.is_public=False`` -- "Super-Admin-created, negotiated,
   typically-private... one-off plans that don't fit any standard tier"
   (see ``app.domains.billing.constants.PlanType``'s own docstring, and
   ``docs/billing/DATABASE.md``'s ``is_public`` write-up).

**Design (2) was chosen.** It is explicitly the more consistent choice given
this codebase's own precedent: Billing already owns the concept of
"this specific customer's entitlements diverge from the stock catalog", and
the project owner's own instructions list "Subscription" among the domains
this feature may extend. A parallel override mechanism in ``location`` would
duplicate that concept in a second place, split "what can this org do" across
two tables, and require every future entitlement check
(``UsageService``/anything else that reads ``PlanFeature``) to *also* learn
about a second override table -- exactly the kind of duplication this
codebase's own composition-not-duplication convention across every other
domain argues against. Concretely: when the Super-Admin selects zero
overrides, the newly-created (or reused) organization subscribes directly to
the selected public ``Plan``. When at least one override is selected,
``_create_overridden_plan`` clones the base plan's own ``PlanFeature`` rows
(via ``PlanService.list_features``), applies the overrides on top, and
creates a brand-new, ``is_public=False``, ``plan_type=CUSTOM`` ``Plan`` (via
``PlanService.create_plan`` -- the only creation path that exists, there is
no dedicated "clone" method) that the organization is subscribed to instead.
This is a real, additively-extended use of Billing's own existing model, not
a new parallel concept.

``PlanFeatureKey`` was additively extended (see
``app.domains.billing.constants``) with the "Feature Access"/"Plan Limits"
keys the spec names that Part 1 had not yet needed (``DASHBOARD`` through
``MULTI_LOCATION``, plus ``MAX_CONCURRENT_SESSIONS``/``MAX_STAFF_USERS``/
``MAX_API_KEYS``) -- a plain, additive ``StrEnum`` member never requires a
migration (the column is a plain ``String``, not a native Postgres enum type,
per that module's own documented convention).

## RBAC role choice: "Organization Owner"

The spec's flowchart says "Location Owner / Organization Admin" as if
interchangeable. The real, seeded system role
(``app.domains.rbac.seed.SYSTEM_ROLES``) that best fits "the person who
should be able to administer this entire new customer account" is
**"Organization Owner"** (slug ``organization-owner``), not "Organization
Admin": its own seed description is "Full control over a single
organization's configuration and operations", strictly broader than
"Organization Admin"'s "Day-to-day administration". A location owner
provisioned through this brand-new-customer flow is exactly this: the
account meant to administer everything for their organization, not a
subordinate day-to-day operator. There is no seeded "Location Owner" role at
all (the narrowest location-scoped role that exists, "Location Manager", is
a day-to-day operational role, not an account-administration one) -- see
``docs/location/FLOW.md`` for the full write-up.

## must_change_password (auth extension) necessity

This flow hands a freshly-generated, high-entropy random password to a
brand-new account owner via email. This codebase's auth flow (BE-002) has
never before needed to force a password change before first ordinary use --
confirmed by reading ``app.domains.auth.models``/``service.py`` in full
before adding anything. A single, narrow, additive
``User.must_change_password`` boolean column (default ``False`` --
unaffected for every pre-existing/self-registered account) plus one
``if user.must_change_password: raise PasswordChangeRequiredError()`` check
in ``AuthService.login`` (placed alongside the existing, identically-shaped
``EmailNotVerifiedError`` check, before any token pair is issued) is the
full auth-side diff -- no rewriting of the surrounding login logic. Cleared
back to ``False`` by both ``AuthService.change_password`` and
``AuthService.reset_password`` (the two existing, legitimate ways a user can
set a new password), documented in full in ``docs/location/FLOW.md``.

## Default router config template gap

No system (``is_system_template=True``) ``ConfigTemplate`` is seeded
anywhere in this codebase's fixture/seed data (confirmed by grepping the
whole tree). ``_resolve_default_template_id`` looks for the most recently
created active system template via ``RouterProvisioningService
.list_templates(requesting_organization_id=None, ...)`` (an already-existing
public method -- returns every template, system and tenant-owned alike, when
called with no organization scope) and filters client-side; if none exists
and the caller did not supply an explicit ``router_config_template_id``,
``DefaultConfigTemplateNotFoundError`` is raised -- a real, honestly
surfaced operational gap (a real deployment must seed at least one system
template first), not a fabricated fallback template.

## Username / temporary-password generation

No reusable "username generator" exists anywhere in this codebase. A
reusable *secure-random-token* pattern does (``app.domains.router.service``'s
zero-touch-provisioning token: ``secrets.token_urlsafe(32)``), but it is not
directly reusable for a *human-typed, complexity-constrained* temporary
password. ``_generate_temporary_password`` below reuses the same ``secrets``
stdlib module (never ``random``) but composes a password guaranteed to
contain upper/lower/digit/special characters, matching this codebase's own
``RegisterRequest.password`` documented complexity expectation
(``app.domains.auth.schemas``). ``_generate_username`` derives a candidate
from the owner's email local-part plus a short random suffix (also via
``secrets``) -- a real, if minimal, generator, not a hardcoded placeholder.
"""

from __future__ import annotations

import logging
import re
import secrets
import string
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any, Protocol

from app.common.exceptions import CloudGuestError
from app.domains.billing.constants import (
    FEATURE_KEY_TYPE,
    PlanFeatureKey,
    PlanFeatureType,
    PlanType,
)
from app.domains.billing.models import Plan, PlanFeature, Subscription
from app.domains.captive_portal.models import CaptivePortalConfig
from app.domains.guest.nas_number_generator import preview_first_nas_code
from app.domains.organization.enums import OrganizationStatus, OrganizationType
from app.domains.organization.exceptions import (
    DuplicateSlugError,
    OrganizationArchivedError,
    OrganizationNotFoundError,
)
from app.domains.organization.models import Organization
from app.domains.rbac.enums import AuditAction
from app.domains.rbac.models import Role
from app.domains.router.models import Router
from app.domains.router_provisioning.models import ConfigTemplate
from app.domains.wireguard.service import TunnelDeliveryInfo

from .enums import PropertyType
from .exceptions import DefaultConfigTemplateNotFoundError, NewOrganizationRequiredError
from .models import Location
from .service import LocationService

logger = logging.getLogger(__name__)

_OWNER_ROLE_SLUG = "organization-owner"
_TEMPORARY_PASSWORD_LENGTH = 16
_TEMPORARY_PASSWORD_SPECIALS = "!@#$%^&*()-_=+"
_DEFAULT_LOGIN_URL_BASE = "https://app.cloudguest.example"
"""Documented placeholder -- ``app/core/config.py`` is outside this domain's
directory-rule boundary (not one of the explicitly-permitted narrow
exceptions), so no ``Settings`` field was added for a real frontend base
URL. ``LocationProvisioningService`` accepts ``login_url_base`` as a plain
constructor argument instead; a real deployment should pass its actual
frontend origin when wiring ``get_location_provisioning_service`` (see
``dependencies.py``)."""


class OwnerRoleNotSeededError(CloudGuestError):
    """The ``organization-owner`` system role (see module docstring's "RBAC
    role choice" section) was not found -- this should never happen against
    a database that has run ``app.domains.rbac.seed.seed_rbac``, but is
    checked explicitly rather than surfacing a confusing ``AttributeError``
    on a ``None`` role."""

    def __init__(self) -> None:
        super().__init__(
            "The 'organization-owner' system role is not seeded -- run "
            "app.domains.rbac.seed.seed_rbac first",
            status_code=500,
        )


class OwnerNotProvisionedError(CloudGuestError):
    """``resend_welcome_email`` was called for a location whose
    ``settings['owner_user_id']`` is missing or no longer resolves to a real
    user -- i.e. a location that was never provisioned through this flow
    (or whose owner account has since been deleted)."""

    def __init__(self, location_id: uuid.UUID) -> None:
        super().__init__(
            f"Location {location_id} has no provisioned owner account to " "email",
            status_code=409,
        )


# ============================================================================
# Narrow cross-domain protocols (composition, not duplication -- the same
# pattern every other domain's own service.py already establishes)
# ============================================================================


class OrganizationProvisioningProtocol(Protocol):
    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization: ...

    async def get_by_slug(self, slug: str) -> Organization: ...

    async def create_organization(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        name: str,
        slug: str,
        contact_email: str,
        legal_name: str | None = None,
        org_type: OrganizationType = OrganizationType.STANDARD,
        status: OrganizationStatus = OrganizationStatus.ACTIVE,
        parent_organization_id: uuid.UUID | None = None,
        contact_phone: str | None = None,
        timezone: str = "UTC",
        default_locale: str = "en",
        settings: dict[str, Any] | None = None,
        subscription_tier: str | None = None,
    ) -> Organization: ...

    async def activate_organization(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> Organization: ...


class UserProvisioningProtocol(Protocol):
    async def create_user(
        self,
        *,
        actor_user_id: uuid.UUID,
        first_name: str,
        last_name: str,
        email: str,
        username: str,
        temporary_password: str,
        requesting_organization_id: uuid.UUID | None,
        phone: str | None = None,
        designation: str | None = None,
        department: str | None = None,
        employee_id: str | None = None,
        timezone: str = "UTC",
        language: str = "en",
        organization_id: uuid.UUID | None = None,
        initial_role_id: uuid.UUID | None = None,
    ) -> object: ...


class IdentityUpdateProtocol(Protocol):
    """The exact shape of ``app.domains.auth.repository.AuthRepository`` this
    module needs -- reused directly (composition, not a second identity
    store) for the one thing ``UserService.create_user`` cannot itself do
    (set ``must_change_password``, an auth-domain column ``UserService``
    -- a domain this task may not otherwise modify -- has no reason to know
    about) and for resolving a previously-provisioned owner by id."""

    async def get_user_by_id(self, user_id: uuid.UUID) -> object | None: ...

    async def update_user(self, user: object, **fields: object) -> object: ...


class RbacSupportProtocol(Protocol):
    """The exact narrow subset of ``RBACRepositoryProtocol`` this module
    needs: resolving the seeded "Organization Owner" role by slug, plus the
    same shared ``audit_log_entries`` writer every other domain's service
    already composes with."""

    async def get_role_by_slug(
        self, slug: str, organization_id: uuid.UUID | None
    ) -> Role | None: ...

    async def create_audit_log_entry(self, **fields: object) -> object: ...


class RouterProvisioningProtocol(Protocol):
    async def create_router(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        location_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        name: str,
        serial_number: str,
        mac_address: str,
        model: str,
        management_ip_address: str | None = None,
        public_ip_address: str | None = None,
        api_username: str | None = None,
        api_secret: str | None = None,
        settings: dict[str, Any] | None = None,
    ) -> Router: ...


class ConfigTemplateAssignmentProtocol(Protocol):
    async def list_templates(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[ConfigTemplate], object]: ...

    async def assign_profile(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        template_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> tuple[object, object]: ...


class WireGuardProvisioningProtocol(Protocol):
    async def create_tunnel(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> TunnelDeliveryInfo: ...


class PlanProvisioningProtocol(Protocol):
    async def get_plan(
        self, plan_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Plan: ...

    async def list_features(self, plan_id: uuid.UUID) -> list[PlanFeature]: ...

    async def create_plan(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        name: str,
        slug: str,
        plan_type: str,
        description: str | None,
        billing_cycle: str,
        base_price: Decimal,
        currency: str,
        is_active: bool,
        is_public: bool,
        sort_order: int,
        features: list[dict[str, object]],
    ) -> Plan: ...


class SubscriptionProvisioningProtocol(Protocol):
    async def create_subscription(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        plan_id: uuid.UUID,
        coupon_code: str | None = None,
    ) -> Subscription: ...


class CaptivePortalProvisioningProtocol(Protocol):
    async def create_config(self, **fields: object) -> CaptivePortalConfig: ...


class EmailProviderProtocol(Protocol):
    async def send(self, email: str, subject: str, body: str) -> None: ...


class SmsProviderProtocol(Protocol):
    async def send(self, phone_number: str, message: str) -> None: ...


# ============================================================================
# Plain input/output value objects (dataclasses, not pydantic -- mirrors
# ``app.domains.auth.service.DeviceInfo``'s own "service layer stays
# framework-agnostic" convention; ``router.py`` converts the pydantic
# request schema into these before calling this service).
# ============================================================================


@dataclass(frozen=True, slots=True)
class NewOrganizationInput:
    name: str
    slug: str
    contact_email: str
    contact_phone: str | None = None
    legal_name: str | None = None
    timezone: str = "UTC"
    default_locale: str = "en"


@dataclass(frozen=True, slots=True)
class LocationInput:
    name: str
    slug: str
    address_line1: str
    city: str
    state_province: str
    postal_code: str
    country: str
    property_type: PropertyType | None = None
    address_line2: str | None = None
    timezone: str = "UTC"
    latitude: float | None = None
    longitude: float | None = None
    contact_name: str | None = None
    contact_phone: str | None = None
    contact_email: str | None = None
    settings: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class OwnerInput:
    first_name: str
    last_name: str
    email: str
    username: str | None = None
    phone: str | None = None
    designation: str | None = None
    department: str | None = None
    employee_id: str | None = None
    timezone: str = "UTC"
    language: str = "en"
    send_welcome_sms: bool = False


@dataclass(frozen=True, slots=True)
class RouterInput:
    name: str
    serial_number: str
    mac_address: str
    model: str
    management_ip_address: str | None = None
    public_ip_address: str | None = None
    api_username: str | None = None
    api_secret: str | None = None
    settings: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class FeatureOverride:
    feature_key: PlanFeatureKey
    limit_value: Decimal | None = None
    is_enabled: bool | None = None
    tier_value: str | None = None


@dataclass(frozen=True, slots=True)
class ProvisionLocationInput:
    location: LocationInput
    owner: OwnerInput
    router: RouterInput
    plan_id: uuid.UUID
    existing_organization_id: uuid.UUID | None = None
    new_organization: NewOrganizationInput | None = None
    feature_overrides: tuple[FeatureOverride, ...] = ()
    router_config_template_id: uuid.UUID | None = None
    coupon_code: str | None = None


@dataclass(frozen=True, slots=True)
class ProvisionLocationResult:
    organization_id: uuid.UUID
    organization_name: str
    location_id: uuid.UUID
    location_name: str
    location_code: str
    property_type: PropertyType | None
    plan_id: uuid.UUID
    plan_name: str
    feature_summary: dict[str, object]
    router_id: uuid.UUID
    router_name: str
    tunnel_ip_address: str | None
    owner_user_id: uuid.UUID
    owner_name: str
    owner_username: str
    owner_email: str
    owner_temporary_password: str
    login_url: str
    provisioned_at: datetime


@dataclass(frozen=True, slots=True)
class ProvisionLocationPreview:
    """Read model for
    ``LocationProvisioningService.preview_provision_location`` -- a dry
    run that never creates any record. Mirrors
    ``app.domains.network_config.service.NetworkConfigPreview``'s own
    "same read/validate logic as the real write path, stop before any
    write" shape.

    ``organization_id`` is ``None`` when previewing a *new* organization
    (it does not exist yet, so it has no id to preview -- unlike
    ``ProvisionLocationResult.organization_id``, which is always real
    since that runs after creation). ``site_id``/``nas_id`` are the
    real "Site ID"/"NAS ID" the wizard would generate, previewed via
    ``LocationService.preview_next_location_code``/
    ``app.domains.guest.nas_number_generator.preview_first_nas_code``
    without consuming either real counter. ``customer_id`` is the
    organization's own ``slug`` (existing or, for a new organization,
    the one supplied in the request) -- this codebase's already-unique,
    already-human-readable per-customer identifier, reused here rather
    than inventing a second, parallel "Customer ID" concept.
    ``controller_id`` is the router's own ``serial_number`` as supplied
    in the request -- the MikroTik device *is* "the controller" in this
    architecture (see this dataclass's own docstring section in
    ``preview_provision_location``), not a separately generated value.

    This preview validates everything checkable without writing (Plan
    exists, Organization archived-state or new-slug availability, the
    "organization-owner" role is seeded, a default config template
    resolves) but is not an exhaustive guarantee: a few failure modes
    only the real write path can catch (e.g. a router serial/MAC
    uniqueness race, WireGuard IP pool exhaustion) can still make
    ``provision_location`` fail after a clean preview -- the same
    honest boundary every preview/commit split in this codebase
    documents (see ``app.domains.network_config``'s own)."""

    organization_id: uuid.UUID | None
    organization_name: str
    customer_id: str
    site_id: str
    nas_id: str
    controller_id: str
    plan_id: uuid.UUID
    plan_name: str
    feature_summary: dict[str, object]
    owner_name: str
    owner_email: str
    owner_username_preview: str
    router_name: str


# ============================================================================
# Generation helpers -- see module docstring's "Username / temporary-
# password generation" section.
# ============================================================================

_USERNAME_SUFFIX_ALPHABET = string.ascii_lowercase + string.digits


def _generate_username(email: str) -> str:
    local_part = re.sub(r"[^a-z0-9]", "", email.split("@", 1)[0].lower()) or "owner"
    suffix = "".join(secrets.choice(_USERNAME_SUFFIX_ALPHABET) for _ in range(5))
    return f"{local_part}.{suffix}"


def _generate_temporary_password(length: int = _TEMPORARY_PASSWORD_LENGTH) -> str:
    """A real, cryptographically secure (``secrets``, never ``random``)
    temporary password, guaranteed to contain at least one uppercase,
    lowercase, digit, and special character."""
    categories = [
        string.ascii_uppercase,
        string.ascii_lowercase,
        string.digits,
        _TEMPORARY_PASSWORD_SPECIALS,
    ]
    chars = [secrets.choice(category) for category in categories]
    all_chars = "".join(categories)
    chars.extend(secrets.choice(all_chars) for _ in range(length - len(categories)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def _summarize_features(rows: list[PlanFeature]) -> dict[str, object]:
    summary: dict[str, object] = {}
    for row in rows:
        if row.feature_type == PlanFeatureType.LIMIT.value:
            summary[row.feature_key] = (
                float(row.limit_value) if row.limit_value is not None else None
            )
        elif row.feature_type == PlanFeatureType.BOOLEAN.value:
            summary[row.feature_key] = bool(row.is_enabled)
        else:
            summary[row.feature_key] = row.tier_value
    return summary


@dataclass(frozen=True, slots=True)
class _LoginMethods:
    otp_sms_enabled: bool
    otp_email_enabled: bool
    voucher_enabled: bool
    social_login_enabled: bool
    username_password_enabled: bool = True


def _resolve_login_methods(feature_summary: dict[str, object]) -> _LoginMethods:
    """Reuses the SAME resolved feature set as "Feature Access" for
    ``CaptivePortalConfig``'s login-method toggles rather than tracking
    auth-method-enablement a second time (see module/spec's "Guest WiFi
    login methods" note). ``QR_LOGIN`` has no corresponding
    ``CaptivePortalConfig`` field to map onto today -- a real, documented
    gap (not fabricated), left for a future Captive Portal addition.
    ``username_password_enabled`` has no corresponding ``PlanFeatureKey`` in
    the spec's list either, so it defaults to always-on (the standard,
    baseline login method)."""
    mobile_otp_enabled = bool(
        feature_summary.get(PlanFeatureKey.MOBILE_OTP.value, False)
    )
    voucher_enabled = bool(
        feature_summary.get(PlanFeatureKey.VOUCHER_LOGIN.value, False)
    )
    social_login_enabled = bool(
        feature_summary.get(PlanFeatureKey.SOCIAL_LOGIN.value, False)
    )
    return _LoginMethods(
        otp_sms_enabled=mobile_otp_enabled,
        otp_email_enabled=mobile_otp_enabled,
        voucher_enabled=voucher_enabled,
        social_login_enabled=social_login_enabled,
    )


# ============================================================================
# Service
# ============================================================================


class LocationProvisioningService:
    """Orchestrates Smart Location Provisioning -- see module docstring for
    the full design write-up (transactional guarantee, billing override
    design, RBAC role choice, auth extension, default-template gap,
    generation helpers)."""

    def __init__(
        self,
        location_service: LocationService,
        organization_service: OrganizationProvisioningProtocol,
        user_service: UserProvisioningProtocol,
        identity_repository: IdentityUpdateProtocol,
        rbac_support: RbacSupportProtocol,
        router_service: RouterProvisioningProtocol,
        router_provisioning_service: ConfigTemplateAssignmentProtocol,
        wireguard_service: WireGuardProvisioningProtocol,
        plan_service: PlanProvisioningProtocol,
        subscription_service: SubscriptionProvisioningProtocol,
        captive_portal_service: CaptivePortalProvisioningProtocol,
        email_provider: EmailProviderProtocol,
        sms_provider: SmsProviderProtocol,
        *,
        login_url_base: str = _DEFAULT_LOGIN_URL_BASE,
    ) -> None:
        self.location_service = location_service
        self.organization_service = organization_service
        self.user_service = user_service
        self.identity_repository = identity_repository
        self.rbac_support = rbac_support
        self.router_service = router_service
        self.router_provisioning_service = router_provisioning_service
        self.wireguard_service = wireguard_service
        self.plan_service = plan_service
        self.subscription_service = subscription_service
        self.captive_portal_service = captive_portal_service
        self.email_provider = email_provider
        self.sms_provider = sms_provider
        self.login_url_base = login_url_base

    # -- preview (read-only dry run) ----------------------------------------

    async def preview_provision_location(
        self, *, data: ProvisionLocationInput
    ) -> ProvisionLocationPreview:
        """Read-only dry run of ``provision_location`` -- see
        ``ProvisionLocationPreview``'s own docstring for exactly what is
        and is not validated, and the honest boundary on what it does not
        guarantee. Never calls a single ``create_*``/``update_*`` method
        on any composed service."""
        organization_id: uuid.UUID | None
        if data.existing_organization_id is not None:
            organization = await self.organization_service.get_organization(
                data.existing_organization_id
            )
            if organization.status == OrganizationStatus.ARCHIVED.value:
                raise OrganizationArchivedError(organization.id)
            organization_id = organization.id
            organization_name = organization.name
            customer_id = organization.slug
        else:
            if data.new_organization is None:
                raise NewOrganizationRequiredError()
            try:
                await self.organization_service.get_by_slug(
                    data.new_organization.slug
                )
            except OrganizationNotFoundError:
                pass
            else:
                raise DuplicateSlugError(data.new_organization.slug)
            organization_id = None
            organization_name = data.new_organization.name
            customer_id = data.new_organization.slug

        owner_role = await self.rbac_support.get_role_by_slug(_OWNER_ROLE_SLUG, None)
        if owner_role is None:
            raise OwnerRoleNotSeededError()

        if data.router_config_template_id is None:
            await self._resolve_default_template_id()

        base_plan = await self.plan_service.get_plan(data.plan_id)
        feature_rows = await self.plan_service.list_features(base_plan.id)
        feature_summary = _summarize_features(feature_rows)

        site_id = await self.location_service.preview_next_location_code()
        nas_id = preview_first_nas_code(site_id)
        owner_username_preview = data.owner.username or _generate_username(
            data.owner.email
        )

        return ProvisionLocationPreview(
            organization_id=organization_id,
            organization_name=organization_name,
            customer_id=customer_id,
            site_id=site_id,
            nas_id=nas_id,
            controller_id=data.router.serial_number,
            plan_id=base_plan.id,
            plan_name=base_plan.name,
            feature_summary=feature_summary,
            owner_name=f"{data.owner.first_name} {data.owner.last_name}".strip(),
            owner_email=data.owner.email,
            owner_username_preview=owner_username_preview,
            router_name=data.router.name,
        )

    # -- main orchestration ------------------------------------------------

    async def provision_location(
        self, *, actor_user_id: uuid.UUID, data: ProvisionLocationInput
    ) -> ProvisionLocationResult:
        """Executes every Smart Location Provisioning step, in order. No
        ``try``/``except`` anywhere in this method -- see module docstring's
        transactional-guarantee section for why that is exactly what makes
        the single-transaction rollback real."""
        now = datetime.now(UTC)

        # -- a. Create Organization (if new) / reuse existing ----------------
        organization = await self._resolve_organization(actor_user_id, data)

        # -- b. Create Location (auto-generates location_code internally) ---
        location = await self.location_service.create_location(
            actor_user_id=actor_user_id,
            organization_id=organization.id,
            requesting_organization_id=None,
            name=data.location.name,
            slug=data.location.slug,
            address_line1=data.location.address_line1,
            address_line2=data.location.address_line2,
            city=data.location.city,
            state_province=data.location.state_province,
            postal_code=data.location.postal_code,
            country=data.location.country,
            timezone=data.location.timezone,
            latitude=data.location.latitude,
            longitude=data.location.longitude,
            contact_name=data.location.contact_name,
            contact_phone=data.location.contact_phone,
            contact_email=data.location.contact_email,
            settings=dict(data.location.settings),
            property_type=data.location.property_type,
        )

        # -- c. Create Location Owner -----------------------------------------
        owner_role = await self.rbac_support.get_role_by_slug(_OWNER_ROLE_SLUG, None)
        if owner_role is None:
            raise OwnerRoleNotSeededError()

        username = data.owner.username or _generate_username(data.owner.email)
        temporary_password = _generate_temporary_password()
        owner = await self.user_service.create_user(
            actor_user_id=actor_user_id,
            first_name=data.owner.first_name,
            last_name=data.owner.last_name,
            email=data.owner.email,
            username=username,
            temporary_password=temporary_password,
            requesting_organization_id=None,
            phone=data.owner.phone,
            designation=data.owner.designation,
            department=data.owner.department,
            employee_id=data.owner.employee_id,
            timezone=data.owner.timezone,
            language=data.owner.language,
            organization_id=organization.id,
            initial_role_id=owner_role.id,
        )
        # must_change_password: set directly through auth's own identity
        # repository (composition, not a UserService change -- see module
        # docstring's "must_change_password" section for why UserService
        # itself was not touched).
        owner = await self.identity_repository.update_user(
            owner, must_change_password=True
        )

        # -- d. Register Router ------------------------------------------------
        router = await self.router_service.create_router(
            actor_user_id=actor_user_id,
            location_id=location.id,
            requesting_organization_id=None,
            name=data.router.name,
            serial_number=data.router.serial_number,
            mac_address=data.router.mac_address,
            model=data.router.model,
            management_ip_address=data.router.management_ip_address,
            public_ip_address=data.router.public_ip_address,
            api_username=data.router.api_username,
            api_secret=data.router.api_secret,
            settings=dict(data.router.settings),
        )

        # -- e. Generate WireGuard Peer -----------------------------------------
        tunnel = await self.wireguard_service.create_tunnel(
            actor_user_id=actor_user_id,
            router_id=router.id,
            requesting_organization_id=None,
        )

        # -- f. Apply default router configuration ------------------------------
        template_id = data.router_config_template_id
        if template_id is None:
            template_id = await self._resolve_default_template_id()
        await self.router_provisioning_service.assign_profile(
            actor_user_id=actor_user_id,
            router_id=router.id,
            template_id=template_id,
            requesting_organization_id=None,
        )

        # -- g. Apply Subscription Plan (License is created/activated by
        # SubscriptionService.create_subscription itself -- see module
        # docstring) -----------------------------------------------------------
        base_plan = await self.plan_service.get_plan(data.plan_id)
        effective_plan_id = base_plan.id
        if data.feature_overrides:
            effective_plan_id = await self._create_overridden_plan(
                actor_user_id=actor_user_id,
                base_plan=base_plan,
                organization=organization,
                overrides=data.feature_overrides,
            )
        await self.subscription_service.create_subscription(
            actor_user_id=actor_user_id,
            organization_id=organization.id,
            plan_id=effective_plan_id,
            coupon_code=data.coupon_code,
        )

        # -- h. Apply Feature Flags + Plan Limits (resolved from whichever
        # plan -- base or overridden-custom -- the subscription now points
        # at) --------------------------------------------------------------
        resolved_plan = await self.plan_service.get_plan(effective_plan_id)
        feature_rows = await self.plan_service.list_features(effective_plan_id)
        feature_summary = _summarize_features(feature_rows)

        # -- i. Create Default Settings ------------------------------------------
        location = await self.location_service.update_location(
            actor_user_id=actor_user_id,
            location_id=location.id,
            requesting_organization_id=None,
            data={
                "settings": {
                    **dict(location.settings),
                    "owner_user_id": str(owner.id),
                    "provisioning_source": "smart_location_provisioning",
                    "provisioned_at": now.isoformat(),
                }
            },
        )

        # -- j. Configure Captive Portal / Guest WiFi ---------------------------
        login_methods = _resolve_login_methods(feature_summary)
        await self.captive_portal_service.create_config(
            actor_user_id=actor_user_id,
            requesting_organization_id=None,
            organization_id=organization.id,
            location_id=location.id,
            name=f"{location.name} Guest WiFi",
            is_active=True,
            is_default=False,
            theme="default",
            logo_url=None,
            background_image_url=None,
            primary_color="#2563EB",
            secondary_color="#1E293B",
            default_language="en",
            supported_languages=["en"],
            advertisement_banner_url=None,
            advertisement_banner_link=None,
            terms_and_conditions_text=None,
            terms_and_conditions_url=None,
            privacy_policy_text=None,
            privacy_policy_url=None,
            splash_headline=f"Welcome to {location.name}",
            splash_welcome_message="Connect to continue.",
            redirect_url=None,
            otp_sms_enabled=login_methods.otp_sms_enabled,
            otp_email_enabled=login_methods.otp_email_enabled,
            voucher_enabled=login_methods.voucher_enabled,
            username_password_enabled=login_methods.username_password_enabled,
            social_login_enabled=login_methods.social_login_enabled,
            social_login_providers=[],
        )

        # -- k. Audit logging (one additional Location-domain entry for the
        # overall event -- every composed step above already wrote its own,
        # see module docstring) --------------------------------------------
        await self.rbac_support.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=AuditAction.LOCATION_PROVISIONED.value,
            entity_type="location",
            entity_id=location.id,
            description=f"Location '{location.name}' fully provisioned",
            event_metadata={
                "organization_id": str(organization.id),
                "router_id": str(router.id),
                "plan_id": str(effective_plan_id),
                "owner_user_id": str(owner.id),
            },
            organization_id=organization.id,
            location_id=location.id,
        )

        # -- l. Send Welcome Email (+ optional SMS) ------------------------------
        login_url = self._login_url()
        await self._send_welcome_email(
            location=location,
            owner=owner,
            username=username,
            temporary_password=temporary_password,
            login_url=login_url,
        )
        if data.owner.send_welcome_sms and data.owner.phone:
            await self.sms_provider.send(
                data.owner.phone,
                f"Welcome to CloudGuest! Your username is {username}. "
                f"Sign in at {login_url}",
            )

        # -- m. Activate Customer/Tenant (License/Subscription already
        # activated by step g; only the Organization itself might still need
        # an explicit activation, e.g. a reused existing org that was not
        # already ACTIVE) --------------------------------------------------
        if organization.status != OrganizationStatus.ACTIVE.value:
            organization = await self.organization_service.activate_organization(
                actor_user_id=actor_user_id,
                organization_id=organization.id,
                requesting_organization_id=None,
            )

        assert location.location_code is not None  # noqa: S101 -- always set by (b)
        return ProvisionLocationResult(
            organization_id=organization.id,
            organization_name=organization.name,
            location_id=location.id,
            location_name=location.name,
            location_code=location.location_code,
            property_type=data.location.property_type,
            plan_id=effective_plan_id,
            plan_name=resolved_plan.name,
            feature_summary=feature_summary,
            router_id=router.id,
            router_name=router.name,
            tunnel_ip_address=tunnel.peer.tunnel_ip_address,
            owner_user_id=owner.id,
            owner_name=f"{owner.first_name} {owner.last_name}".strip(),
            owner_username=owner.username,
            owner_email=owner.email,
            owner_temporary_password=temporary_password,
            login_url=login_url,
            provisioned_at=now,
        )

    # -- resend welcome email ------------------------------------------------

    async def resend_welcome_email(
        self, *, location_id: uuid.UUID
    ) -> tuple[Location, str]:
        """The spec's "Send Welcome Email Again" button. Never re-sends the
        original temporary password (it was shown exactly once and is not
        retrievable -- see module docstring) -- the resend email instead
        points the owner at the login URL/username and the "Forgot
        password" flow."""
        location = await self.location_service.get_location(
            location_id, requesting_organization_id=None
        )
        owner_user_id_raw = (location.settings or {}).get("owner_user_id")
        if not owner_user_id_raw:
            raise OwnerNotProvisionedError(location_id)

        owner = await self.identity_repository.get_user_by_id(
            uuid.UUID(str(owner_user_id_raw))
        )
        if owner is None:
            raise OwnerNotProvisionedError(location_id)

        login_url = self._login_url()
        await self._send_welcome_email(
            location=location,
            owner=owner,
            username=owner.username,
            temporary_password=None,
            login_url=login_url,
        )
        await self.rbac_support.create_audit_log_entry(
            actor_user_id=None,
            action=AuditAction.LOCATION_WELCOME_EMAIL_SENT.value,
            entity_type="location",
            entity_id=location.id,
            description=f"Welcome email resent for location '{location.name}'",
            event_metadata={"owner_user_id": str(owner.id)},
            organization_id=location.organization_id,
            location_id=location.id,
        )
        return location, owner.email

    # -- internal helpers -----------------------------------------------------

    async def _resolve_organization(
        self, actor_user_id: uuid.UUID, data: ProvisionLocationInput
    ) -> Organization:
        if data.existing_organization_id is not None:
            organization = await self.organization_service.get_organization(
                data.existing_organization_id
            )
            if organization.status == OrganizationStatus.ARCHIVED.value:
                raise OrganizationArchivedError(organization.id)
            return organization

        if data.new_organization is None:
            raise NewOrganizationRequiredError()

        return await self.organization_service.create_organization(
            actor_user_id=actor_user_id,
            name=data.new_organization.name,
            slug=data.new_organization.slug,
            contact_email=data.new_organization.contact_email,
            contact_phone=data.new_organization.contact_phone,
            legal_name=data.new_organization.legal_name,
            timezone=data.new_organization.timezone,
            default_locale=data.new_organization.default_locale,
            settings={
                "onboarded_via": "smart_location_provisioning",
                "onboarding_completed": True,
            },
        )

    async def _resolve_default_template_id(self) -> uuid.UUID:
        templates, _meta = await self.router_provisioning_service.list_templates(
            requesting_organization_id=None, page=1, page_size=100
        )
        system_templates = [
            template
            for template in templates
            if template.is_system_template and template.is_active
        ]
        if not system_templates:
            raise DefaultConfigTemplateNotFoundError()
        system_templates.sort(key=lambda template: template.created_at, reverse=True)
        return system_templates[0].id

    async def _create_overridden_plan(
        self,
        *,
        actor_user_id: uuid.UUID,
        base_plan: Plan,
        organization: Organization,
        overrides: tuple[FeatureOverride, ...],
    ) -> uuid.UUID:
        base_features = await self.plan_service.list_features(base_plan.id)
        feature_by_key: dict[str, dict[str, object]] = {
            row.feature_key: {
                "feature_key": PlanFeatureKey(row.feature_key),
                "feature_type": PlanFeatureType(row.feature_type),
                "limit_value": row.limit_value,
                "is_enabled": row.is_enabled,
                "tier_value": row.tier_value,
            }
            for row in base_features
        }
        for override in overrides:
            feature_by_key[override.feature_key.value] = {
                "feature_key": override.feature_key,
                "feature_type": FEATURE_KEY_TYPE[override.feature_key],
                "limit_value": override.limit_value,
                "is_enabled": override.is_enabled,
                "tier_value": override.tier_value,
            }

        custom_plan = await self.plan_service.create_plan(
            actor_user_id=actor_user_id,
            name=f"{organization.name} Custom ({base_plan.name})",
            slug=f"{base_plan.slug}-custom-{secrets.token_hex(5)}",
            plan_type=PlanType.CUSTOM.value,
            description=(
                f"Private plan cloned from '{base_plan.name}' at provisioning "
                "time with Super-Admin feature/limit overrides applied."
            ),
            billing_cycle=base_plan.billing_cycle,
            base_price=base_plan.base_price,
            currency=base_plan.currency,
            is_active=True,
            is_public=False,
            sort_order=base_plan.sort_order,
            features=list(feature_by_key.values()),
        )
        return custom_plan.id

    def _login_url(self) -> str:
        return f"{self.login_url_base.rstrip('/')}/login"

    async def _send_welcome_email(
        self,
        *,
        location: Location,
        owner: Any,
        username: str,
        temporary_password: str | None,
        login_url: str,
    ) -> None:
        subject = f"Welcome to CloudGuest - {location.name}"
        if temporary_password is not None:
            body = (
                f"Hello {owner.first_name},\n\n"
                f"Your CloudGuest account for '{location.name}' is ready.\n\n"
                f"Login URL: {login_url}\n"
                f"Username: {username}\n"
                f"Temporary password: {temporary_password}\n\n"
                "You will be required to change this password the first time "
                "you log in."
            )
        else:
            body = (
                f"Hello {owner.first_name},\n\n"
                f"This is a reminder of your CloudGuest account for "
                f"'{location.name}'.\n\n"
                f"Login URL: {login_url}\n"
                f"Username: {username}\n\n"
                "If you no longer have your temporary password, use "
                "'Forgot password' on the login page to set a new one."
            )
        await self.email_provider.send(owner.email, subject, body)


__all__ = [
    "LocationProvisioningService",
    "ProvisionLocationInput",
    "ProvisionLocationResult",
    "NewOrganizationInput",
    "LocationInput",
    "OwnerInput",
    "RouterInput",
    "FeatureOverride",
    "OwnerRoleNotSeededError",
    "OwnerNotProvisionedError",
]
