"""Idempotent demo-data seeder for a populated CloudGuest customer dashboard.

Creates one self-contained DEMO tenant so ``demo.wyfyguest.com`` renders a
believable, populated customer dashboard for sales demos -- an organization,
an org-admin login, a few venues, online-looking routers, and ~30 days of
realistic guest traffic (sessions, byte usage, login history, router health
snapshots) so every analytics tile/chart/time-series has data behind it
instead of an empty state.

Seeds, in order (every step checks existence first -- safe to re-run):

1. RBAC system roles/permissions, via ``app.domains.rbac.seed.seed_rbac``
   (reused, not reimplemented, exactly as ``scripts/seed.py`` does). This is
   idempotent and guarantees the ``"organization-admin"`` system role the
   demo user is assigned actually exists, so this script has no hidden
   prerequisite beyond a migrated database.
2. One demo **Organization** -- name "Wyfy Demo", stable slug ``"wyfy-demo"``
   (the idempotency key).
3. One demo **admin user** -- ``demo@wyfyguest.com``, created verified/active
   straight through ``AuthRepository`` (not ``AuthService.register``) for the
   same reason ``scripts/seed.py`` documents: ``register`` is a public
   self-registration flow that leaves ``is_verified=False`` behind an email
   token, which a seeded login must never be gated on.
4. The demo user's ``"organization-admin"`` role assignment at
   ``ScopeType.ORGANIZATION``, scoped to the demo org's id -- so the demo
   login can only ever see the demo tenant, nothing else on the platform.
5. An active **OrganizationMember** row for the demo user (the "belongs to
   this org at all" record, distinct from the RBAC role -- see
   ``app.domains.organization.models``).
6. The platform's default system ``ConfigTemplate`` (reusing
   ``scripts.seed.ensure_default_system_template``), so location/router
   provisioning has the system template it resolves against.
7. Three **Locations** (a cafe, a hotel, a co-working space) with real
   ``location_code`` values generated through the same atomic counter the
   real ``LocationService.create_location`` uses.
8. Two **Routers** per location -- ``ONLINE``, recently seen, ``healthy``.
9. ~30 days of guest traffic: **Guests**, one **GuestDevice** each, several
   hundred **GuestSessions** spread across days/locations with varied volume
   and byte usage (a slice currently ``ACTIVE`` so "live sessions"/"active
   guests" tiles are non-zero), matching **GuestLoginHistory** rows (with a
   realistic minority of failures), and recent **RouterHealthSnapshot**
   readings for the router-health charts.

Step 9 is the only non-deterministic data (sessions/history/snapshots have no
natural unique business key). It is made idempotent at the batch level: if the
demo org already has any ``GuestSession`` row, the whole traffic-generation
step is skipped, so re-running never double-seeds. Every deterministic entity
(org, user, role, membership, locations, routers, guests, devices) is guarded
individually by its own stable key.

Run with (from the ``backend/`` directory, against a migrated database):

    python -m scripts.seed_demo

The demo login is ``demo@wyfyguest.com``. Its password is never accepted as a
bare CLI flag -- provide it via the ``CLOUDGUEST_DEMO_PASSWORD`` environment
variable, or omit it and you will be prompted (hidden input, via ``getpass``),
exactly as ``scripts/seed.py`` handles the Super Admin password.

Timestamps use ``datetime.now(UTC)`` -- consistent with the models
themselves, whose ``BaseModel`` timestamp defaults are literally
``lambda: datetime.now(UTC)`` (there is no separate app clock helper to defer
to).
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import os
import random
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from app.database.session import SessionLocal
from app.domains.auth.models import User
from app.domains.auth.password import PasswordManager
from app.domains.auth.repository import AuthRepository, AuthRepositoryProtocol

# Guest/Location/Organization/Router models are imported partly for direct use
# and -- like scripts/seed.py's own note -- partly so every model class is
# mapped into SQLAlchemy's shared declarative registry before any string-based
# ForeignKey (e.g. rbac.models.UserRole -> "organizations.id"/"locations.id"/
# "routers.id", or guest_sessions -> "routers.id"/"locations.id") resolves at
# flush time. A narrow script that imports only a slice of the app is exactly
# where an unresolved "could not find table" would otherwise surface.
from app.domains.guest.constants import (
    BYTES_PER_MB,
    DEFAULT_SESSION_TIMEOUT_MINUTES,
    GuestAuthMethod,
    GuestSessionStatus,
)
from app.domains.guest.models import (  # noqa: F401
    Guest,
    GuestDevice,
    GuestLoginHistory,
    GuestSession,
)
from app.domains.guest.repository import GuestRepository
from app.domains.location.enums import LocationStatus, PropertyType
from app.domains.location.models import Location  # noqa: F401
from app.domains.location.number_generator import generate_location_code
from app.domains.location.repository import (
    LocationCodeCounterRepository,
    LocationRepository,
)
from app.domains.organization.enums import MembershipStatus, OrganizationType
from app.domains.organization.models import Organization  # noqa: F401
from app.domains.organization.repository import OrganizationRepository
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.models import UserRole  # noqa: F401
from app.domains.rbac.repository import RBACRepository, RBACRepositoryProtocol
from app.domains.rbac.seed import seed_rbac
from app.domains.router.enums import RouterHealthStatus, RouterStatus
from app.domains.router.models import Router  # noqa: F401
from app.domains.router.repository import RouterRepository
from app.domains.router_provisioning.models import RouterHealthSnapshot  # noqa: F401
from app.domains.router_provisioning.repository import RouterProvisioningRepository

# Reused, not reimplemented -- the exact same default-system-template helper
# scripts/seed.py already ships (see its module docstring for why a fresh
# deployment's location/router provisioning breaks without it).
from scripts.seed import ensure_default_system_template

logger = logging.getLogger(__name__)

# -- stable idempotency keys -------------------------------------------------

DEMO_ORG_SLUG = "wyfy-demo"
DEMO_ORG_NAME = "Wyfy Demo"
DEMO_USER_EMAIL = "demo@wyfyguest.com"
DEMO_USER_USERNAME = "demo"
ORGANIZATION_ADMIN_ROLE_SLUG = "organization-admin"

# A fixed RNG seed so the generated traffic looks the same every time it is
# (re)seeded onto a fresh database -- reproducible demos, not random noise.
RANDOM_SEED = 20260829

TRAFFIC_DAYS = 30
GUEST_POOL_SIZE = 48

# Per-location, per-day session volume is drawn from this inclusive range,
# scaled down on weekends for the office/co-working venue so the trend chart
# has a believable weekly rhythm rather than a flat line.
SESSIONS_PER_LOCATION_PER_DAY = (3, 9)


@dataclass
class DemoLocationSpec:
    slug: str
    name: str
    property_type: PropertyType
    address_line1: str
    city: str
    state_province: str
    postal_code: str
    country: str
    timezone: str
    latitude: float
    longitude: float
    weekend_heavy: bool  # True -> busier on weekends (leisure venue)


DEMO_LOCATIONS: list[DemoLocationSpec] = [
    DemoLocationSpec(
        slug="brew-and-bytes-cafe",
        name="Brew & Bytes Cafe",
        property_type=PropertyType.CAFE,
        address_line1="12 Church Street",
        city="Bengaluru",
        state_province="Karnataka",
        postal_code="560001",
        country="IN",
        timezone="Asia/Kolkata",
        latitude=12.9756,
        longitude=77.6068,
        weekend_heavy=True,
    ),
    DemoLocationSpec(
        slug="grand-horizon-hotel",
        name="The Grand Horizon Hotel",
        property_type=PropertyType.HOTEL,
        address_line1="440 Marine Drive",
        city="Mumbai",
        state_province="Maharashtra",
        postal_code="400020",
        country="IN",
        timezone="Asia/Kolkata",
        latitude=18.9440,
        longitude=72.8230,
        weekend_heavy=True,
    ),
    DemoLocationSpec(
        slug="nexus-coworking-hub",
        name="Nexus Coworking Hub",
        property_type=PropertyType.COWORKING_SPACE,
        address_line1="Tower B, Cyber City",
        city="Gurugram",
        state_province="Haryana",
        postal_code="122002",
        country="IN",
        timezone="Asia/Kolkata",
        latitude=28.4949,
        longitude=77.0880,
        weekend_heavy=False,  # busiest on weekdays
    ),
]

ROUTERS_PER_LOCATION = 2
ROUTER_MODELS = ["hAP ac2", "RB4011iGS+", "hAP ax3", "CCR2004-16G-2S+"]
ROUTEROS_VERSION = "7.15.3"

# Weighted so OTP dominates (the platform's primary flow) but vouchers and
# password logins are still well-represented for the auth-method breakdown.
AUTH_METHOD_WEIGHTS: list[tuple[str, int]] = [
    (GuestAuthMethod.OTP_SMS.value, 52),
    (GuestAuthMethod.OTP_EMAIL.value, 16),
    (GuestAuthMethod.VOUCHER.value, 22),
    (GuestAuthMethod.USERNAME_PASSWORD.value, 10),
]

USER_AGENTS = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/125.0",
    "Mozilla/5.0 (Linux; Android 13; SM-S911B) AppleWebKit/537.36 Chrome/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0",
    "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15",
]
ACCEPT_LANGUAGES = ["en-IN,en;q=0.9", "en-US,en;q=0.8", "hi-IN,hi;q=0.9,en;q=0.7"]

# A minority of login attempts fail -- makes OTP success-rate / failure-reason
# analytics render something other than a perfect 100%.
LOGIN_FAILURE_REASONS = [
    "invalid_otp",
    "otp_expired",
    "voucher_not_found",
    "voucher_exhausted",
]

FIRST_NAMES = [
    "Aarav", "Diya", "Vivaan", "Ananya", "Aditya", "Ishaan", "Saanvi", "Kabir",
    "Myra", "Reyansh", "Anika", "Arjun", "Kiara", "Vihaan", "Prisha", "Advait",
    "Riya", "Rohan", "Sara", "Dhruv", "Aisha", "Karan", "Neha", "Rahul",
]
LAST_NAMES = [
    "Sharma", "Patel", "Reddy", "Nair", "Iyer", "Singh", "Gupta", "Mehta",
    "Rao", "Das", "Kapoor", "Bose",
]


@dataclass
class DemoSeedResult:
    organization_id: uuid.UUID
    organization_created: bool
    user_id: uuid.UUID
    user_created: bool
    role_assigned: bool
    membership_created: bool
    default_template_id: uuid.UUID
    locations_created: int = 0
    locations_total: int = 0
    routers_created: int = 0
    routers_total: int = 0
    guests_created: int = 0
    devices_created: int = 0
    sessions_created: int = 0
    active_sessions: int = 0
    login_history_created: int = 0
    health_snapshots_created: int = 0
    traffic_skipped_existing: bool = False
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Deterministic entities
# ---------------------------------------------------------------------------


async def ensure_demo_organization(
    org_repository: OrganizationRepository,
) -> tuple[Organization, bool]:
    existing = await org_repository.get_by_slug(DEMO_ORG_SLUG)
    if existing is not None:
        return existing, False
    org = await org_repository.create_organization(
        name=DEMO_ORG_NAME,
        slug=DEMO_ORG_SLUG,
        legal_name="Wyfy Guest Demo Pvt. Ltd.",
        org_type=OrganizationType.STANDARD.value,
        status="active",
        parent_organization_id=None,
        contact_email="hello@wyfyguest.com",
        contact_phone="+911140000000",
        timezone="Asia/Kolkata",
        default_locale="en",
        settings={"demo": True},
        subscription_tier="enterprise",
    )
    return org, True


async def ensure_demo_user(
    auth_repository: AuthRepositoryProtocol, *, password: str
) -> tuple[User, bool]:
    existing = await auth_repository.get_user_by_email(DEMO_USER_EMAIL)
    if existing is not None:
        return existing, False
    user = await auth_repository.create_user(
        first_name="Demo",
        last_name="Admin",
        email=DEMO_USER_EMAIL,
        username=DEMO_USER_USERNAME,
        password_hash=PasswordManager.hash(password),
        timezone="Asia/Kolkata",
        # Verified + active so the demo login works immediately -- see module
        # docstring for why AuthService.register would be wrong here.
        is_active=True,
        is_verified=True,
    )
    return user, True


async def ensure_org_admin_role_assignment(
    rbac_repository: RBACRepositoryProtocol,
    *,
    user_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> tuple[UserRole | None, bool]:
    """Assign the seeded ``organization-admin`` system role at
    ``ScopeType.ORGANIZATION``, scoped to the demo org, so the demo login is
    confined to the demo tenant. System roles carry ``organization_id IS
    NULL`` (see ``rbac.seed``), hence the ``None`` lookup key."""
    role = await rbac_repository.get_role_by_slug(ORGANIZATION_ADMIN_ROLE_SLUG, None)
    if role is None:
        return None, False
    existing_roles = await rbac_repository.get_active_user_roles(user_id)
    if any(
        r.role_id == role.id and r.organization_id == organization_id
        for r in existing_roles
    ):
        return None, False
    assignment = await rbac_repository.create_user_role(
        user_id=user_id,
        role_id=role.id,
        scope_type=ScopeType.ORGANIZATION.value,
        organization_id=organization_id,
        location_id=None,
        router_id=None,
        granted_at=datetime.now(UTC),
        granted_by=None,
        expires_at=None,
        is_active=True,
    )
    return assignment, True


async def ensure_org_membership(
    org_repository: OrganizationRepository,
    *,
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
) -> bool:
    existing = await org_repository.get_membership(organization_id, user_id)
    if existing is not None and existing.status == MembershipStatus.ACTIVE.value:
        return False
    now = datetime.now(UTC)
    await org_repository.create_membership(
        organization_id=organization_id,
        user_id=user_id,
        status=MembershipStatus.ACTIVE.value,
        invited_by_user_id=None,
        invited_at=now,
        joined_at=now,
        is_primary_contact=True,
    )
    return True


async def ensure_locations(
    location_repository: LocationRepository,
    code_counter: LocationCodeCounterRepository,
    *,
    organization_id: uuid.UUID,
    actor_user_id: uuid.UUID,
) -> tuple[list[Location], int]:
    locations: list[Location] = []
    created = 0
    for spec in DEMO_LOCATIONS:
        existing = await location_repository.get_by_slug(organization_id, spec.slug)
        if existing is not None:
            locations.append(existing)
            continue
        location_code = await generate_location_code(code_counter, at=datetime.now(UTC))
        location = await location_repository.create_location(
            organization_id=organization_id,
            name=spec.name,
            slug=spec.slug,
            status=LocationStatus.ACTIVE.value,
            property_type=spec.property_type.value,
            location_code=location_code,
            address_line1=spec.address_line1,
            address_line2=None,
            city=spec.city,
            state_province=spec.state_province,
            postal_code=spec.postal_code,
            country=spec.country,
            timezone=spec.timezone,
            latitude=spec.latitude,
            longitude=spec.longitude,
            contact_name="Front Desk",
            contact_phone="+919900000000",
            contact_email=f"{spec.slug}@wyfyguest.com",
            settings={"demo": True},
            created_by=actor_user_id,
        )
        locations.append(location)
        created += 1
    return locations, created


async def ensure_routers(
    router_repository: RouterRepository,
    *,
    organization_id: uuid.UUID,
    locations: list[Location],
    actor_user_id: uuid.UUID,
) -> tuple[dict[uuid.UUID, list[Router]], int]:
    """Two online-looking routers per location. Serial/MAC are deterministic
    (their unique columns are the idempotency keys)."""
    by_location: dict[uuid.UUID, list[Router]] = {}
    created = 0
    now = datetime.now(UTC)
    for loc_idx, location in enumerate(locations, start=1):
        routers: list[Router] = []
        for r_idx in range(1, ROUTERS_PER_LOCATION + 1):
            serial = f"WYFYDEMO-{loc_idx:02d}{r_idx:02d}-SN"
            mac = f"DE:70:{loc_idx:02X}:{r_idx:02X}:00:0{r_idx}"
            existing = await router_repository.get_by_serial_number(serial)
            if existing is not None:
                routers.append(existing)
                continue
            router = await router_repository.create_router(
                location_id=location.id,
                organization_id=organization_id,
                name=f"{location.name} AP {r_idx}",
                serial_number=serial,
                mac_address=mac,
                model=ROUTER_MODELS[(loc_idx + r_idx) % len(ROUTER_MODELS)],
                vendor="mikrotik",
                routeros_version=ROUTEROS_VERSION,
                # RFC1918, and outside the WireGuard tunnel network
                # (10.20.0.0/24) for as long as this stays under 20
                # locations. Three seeded demo routers once carried
                # management addresses inside that range, one of which was
                # a live router's real tunnel address -- check this if you
                # add entries to DEMO_LOCATIONS or the tunnel CIDR widens.
                management_ip_address=f"10.{loc_idx}.{r_idx}.1",
                # TEST-NET-2 (RFC 5737), reserved for documentation and
                # examples. This used to read ``49.36.{loc_idx}.{r_idx}``,
                # which is inside 49.32.0.0/12 -- real, currently-allocated
                # space belonging to Reliance Jio Infocomm (confirmed via
                # APNIC RDAP). Demo fixtures must never carry somebody
                # else's routable addresses: they show up in the dashboard
                # as this platform's own infrastructure, and anyone who
                # copies one out of a screenshot is looking at a stranger's
                # network. The other demo dataset in this database already
                # used 198.51.100.x correctly; this one did not.
                public_ip_address=f"198.51.100.{loc_idx * 10 + r_idx}",
                status=RouterStatus.ONLINE.value,
                last_seen_at=now - timedelta(minutes=random.randint(0, 4)),
                last_health_check_at=now - timedelta(minutes=random.randint(0, 4)),
                health_status=RouterHealthStatus.HEALTHY.value,
                snmp_enabled=True,
                settings={"demo": True},
                created_by=actor_user_id,
            )
            routers.append(router)
            created += 1
        by_location[location.id] = routers
    return by_location, created


# ---------------------------------------------------------------------------
# Volatile traffic (guests, sessions, login history, health snapshots)
# ---------------------------------------------------------------------------


async def _org_has_sessions(session, organization_id: uuid.UUID) -> bool:
    result = await session.execute(
        select(func.count())
        .select_from(GuestSession)
        .where(GuestSession.organization_id == organization_id)
    )
    return int(result.scalar_one()) > 0


async def ensure_guests(
    guest_repository: GuestRepository,
    *,
    organization_id: uuid.UUID,
    locations: list[Location],
    now: datetime,
) -> tuple[list[tuple[Guest, GuestDevice]], int, int]:
    """A pool of returning guests, one recognized device each. Idempotent by
    ``(organization_id, identifier)`` and globally-unique device MAC."""
    pairs: list[tuple[Guest, GuestDevice]] = []
    guests_created = 0
    devices_created = 0
    for i in range(GUEST_POOL_SIZE):
        identifier = f"+9190{00000 + i:07d}"
        first = FIRST_NAMES[i % len(FIRST_NAMES)]
        last = LAST_NAMES[(i // len(FIRST_NAMES)) % len(LAST_NAMES)]
        display_name = f"{first} {last}"
        email = f"{first.lower()}.{last.lower()}{i}@example.com"
        home_location = locations[i % len(locations)]
        first_seen = now - timedelta(days=random.randint(20, TRAFFIC_DAYS + 60))
        last_seen = now - timedelta(hours=random.randint(1, 24 * 5))

        guest = await guest_repository.get_guest_by_identifier(
            organization_id, identifier
        )
        if guest is None:
            guest = await guest_repository.create_guest(
                organization_id=organization_id,
                location_id=home_location.id,
                identifier=identifier,
                display_name=display_name,
                email=email,
                first_seen_at=first_seen,
                last_seen_at=last_seen,
                total_visit_count=random.randint(1, 40),
                is_blocked=False,
            )
            guests_created += 1

        # Deterministic, globally-unique, strictly-valid 17-char MAC.
        mac = f"AA:BB:CC:{(i >> 8) & 0xFF:02X}:{i & 0xFF:02X}:{(i * 7) & 0xFF:02X}"
        device = await guest_repository.get_device_by_mac(mac)
        if device is None:
            device = await guest_repository.create_device(
                guest_id=guest.id,
                mac_address=mac,
                device_name=random.choice(["iPhone", "Android", "Laptop", "iPad"]),
                first_seen_at=first_seen,
                last_seen_at=last_seen,
            )
            devices_created += 1
        pairs.append((guest, device))
    return pairs, guests_created, devices_created


def _client_ip() -> str:
    return f"100.64.{random.randint(0, 255)}.{random.randint(2, 254)}"


def _weighted_auth_method() -> str:
    population = [m for m, _ in AUTH_METHOD_WEIGHTS]
    weights = [w for _, w in AUTH_METHOD_WEIGHTS]
    return random.choices(population, weights=weights, k=1)[0]


def _sessions_for_day(spec: DemoLocationSpec, day: datetime) -> int:
    low, high = SESSIONS_PER_LOCATION_PER_DAY
    base = random.randint(low, high)
    is_weekend = day.weekday() >= 5
    if is_weekend and not spec.weekend_heavy:
        base = max(low, base - 3)  # quiet weekends at the office venue
    if is_weekend and spec.weekend_heavy:
        base = min(high + 2, base + 2)  # busy weekends at leisure venues
    return base


async def generate_traffic(
    session,
    guest_repository: GuestRepository,
    provisioning_repository: RouterProvisioningRepository,
    *,
    organization_id: uuid.UUID,
    locations: list[Location],
    routers_by_location: dict[uuid.UUID, list[Router]],
    guest_pairs: list[tuple[Guest, GuestDevice]],
    now: datetime,
    result: DemoSeedResult,
) -> None:
    for day_offset in range(TRAFFIC_DAYS, -1, -1):
        day = now - timedelta(days=day_offset)
        is_today = day_offset == 0
        for location, spec in zip(locations, DEMO_LOCATIONS, strict=True):
            routers = routers_by_location.get(location.id, [])
            if not routers:
                continue
            count = _sessions_for_day(spec, day)
            for _ in range(count):
                guest, device = random.choice(guest_pairs)
                router = random.choice(routers)
                auth_method = _weighted_auth_method()

                start_hour = random.randint(7, 22)
                started_at = day.replace(
                    hour=start_hour,
                    minute=random.randint(0, 59),
                    second=random.randint(0, 59),
                    microsecond=0,
                )
                duration_min = random.randint(8, 210)

                # A slice of "today" is still live -- drives the active-guests
                # / live-sessions tiles.
                make_active = is_today and random.random() < 0.5
                if make_active:
                    started_at = now - timedelta(minutes=random.randint(5, 150))
                    ended_at = None
                    status = GuestSessionStatus.ACTIVE.value
                    last_activity_at = now - timedelta(minutes=random.randint(0, 12))
                    disconnect_reason = None
                else:
                    ended_at = started_at + timedelta(minutes=duration_min)
                    if ended_at > now:
                        ended_at = now
                    # Mostly clean disconnects; a few timed-out or terminated.
                    roll = random.random()
                    if roll < 0.85:
                        status = GuestSessionStatus.DISCONNECTED.value
                        disconnect_reason = "guest_disconnected"
                    elif roll < 0.96:
                        status = GuestSessionStatus.EXPIRED.value
                        disconnect_reason = "session_timeout"
                    else:
                        status = GuestSessionStatus.TERMINATED.value
                        disconnect_reason = "admin_terminated"
                    last_activity_at = ended_at

                down_mb = random.randint(20, 2200)
                up_mb = random.randint(2, max(3, down_mb // 6))
                bytes_downloaded = down_mb * BYTES_PER_MB
                bytes_uploaded = up_mb * BYTES_PER_MB

                await guest_repository.create_session(
                    guest_id=guest.id,
                    device_id=device.id,
                    router_id=router.id,
                    location_id=location.id,
                    organization_id=organization_id,
                    auth_method=auth_method,
                    voucher_id=None,
                    status=status,
                    started_at=started_at,
                    ended_at=ended_at,
                    last_activity_at=last_activity_at,
                    ip_address=_client_ip(),
                    user_agent=random.choice(USER_AGENTS),
                    accept_language=random.choice(ACCEPT_LANGUAGES),
                    bytes_uploaded=bytes_uploaded,
                    bytes_downloaded=bytes_downloaded,
                    data_limit_mb=None,
                    session_timeout_minutes=DEFAULT_SESSION_TIMEOUT_MINUTES,
                    disconnect_reason=disconnect_reason,
                )
                result.sessions_created += 1
                if status == GuestSessionStatus.ACTIVE.value:
                    result.active_sessions += 1

                # A successful login-history row for every session created...
                await guest_repository.create_login_history(
                    guest_id=guest.id,
                    organization_id=organization_id,
                    location_id=location.id,
                    identifier=guest.identifier,
                    auth_method=auth_method,
                    success=True,
                    failure_reason=None,
                    attempted_at=started_at,
                    ip_address=_client_ip(),
                )
                result.login_history_created += 1

                # ...and a minority of failed attempts scattered in.
                if random.random() < 0.15:
                    failed_at = started_at - timedelta(minutes=random.randint(1, 4))
                    await guest_repository.create_login_history(
                        guest_id=None,
                        organization_id=organization_id,
                        location_id=location.id,
                        identifier=guest.identifier,
                        auth_method=auth_method,
                        success=False,
                        failure_reason=random.choice(LOGIN_FAILURE_REASONS),
                        attempted_at=failed_at,
                        ip_address=None,
                    )
                    result.login_history_created += 1

    # Recent router-health snapshots -- feeds the router-health time-series.
    for routers in routers_by_location.values():
        for router in routers:
            for h in range(8, -1, -1):
                recorded_at = now - timedelta(hours=h * 3)
                await provisioning_repository.create_health_snapshot(
                    router_id=router.id,
                    recorded_at=recorded_at,
                    health_status=RouterHealthStatus.HEALTHY.value,
                    cpu_usage_percent=round(random.uniform(4.0, 38.0), 1),
                    memory_usage_percent=round(random.uniform(22.0, 61.0), 1),
                    uptime_seconds=random.randint(3600 * 24 * 3, 3600 * 24 * 40),
                    connected_clients_count=random.randint(3, 45),
                    metrics_source="snmp",
                    interface_traffic_counters=None,
                )
                result.health_snapshots_created += 1


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


async def run_seed_demo(session, *, password: str) -> DemoSeedResult:
    """Run every demo-seed step against ``session``. Does not commit -- the
    CLI entrypoint owns the transaction boundary (one commit after every step
    succeeds), mirroring ``scripts/seed.py``."""
    random.seed(RANDOM_SEED)

    org_repository = OrganizationRepository(session)
    auth_repository = AuthRepository(session)
    rbac_repository = RBACRepository(session)
    location_repository = LocationRepository(session)
    code_counter = LocationCodeCounterRepository(session)
    router_repository = RouterRepository(session)
    guest_repository = GuestRepository(session)
    provisioning_repository = RouterProvisioningRepository(session)

    # 1. Idempotent RBAC seed -- guarantees the organization-admin role exists.
    await seed_rbac(session)

    # 2-3. Organization + demo user.
    org, org_created = await ensure_demo_organization(org_repository)
    user, user_created = await ensure_demo_user(auth_repository, password=password)

    # 4-5. Role assignment (org-scoped) + org membership.
    _assignment, role_assigned = await ensure_org_admin_role_assignment(
        rbac_repository, user_id=user.id, organization_id=org.id
    )
    membership_created = await ensure_org_membership(
        org_repository, organization_id=org.id, user_id=user.id
    )

    # 6. Default system config template (reused from scripts/seed).
    template, _template_created = await ensure_default_system_template(
        provisioning_repository, actor_user_id=user.id
    )

    result = DemoSeedResult(
        organization_id=org.id,
        organization_created=org_created,
        user_id=user.id,
        user_created=user_created,
        role_assigned=role_assigned,
        membership_created=membership_created,
        default_template_id=template.id,
    )
    if role_assigned is False and _assignment is None:
        role = await rbac_repository.get_role_by_slug(
            ORGANIZATION_ADMIN_ROLE_SLUG, None
        )
        if role is None:
            result.warnings.append(
                "organization-admin role not found even after seed_rbac -- "
                "demo user has NO org-admin role assignment."
            )

    # 7-8. Locations + routers.
    locations, locations_created = await ensure_locations(
        location_repository,
        code_counter,
        organization_id=org.id,
        actor_user_id=user.id,
    )
    result.locations_created = locations_created
    result.locations_total = len(locations)

    routers_by_location, routers_created = await ensure_routers(
        router_repository,
        organization_id=org.id,
        locations=locations,
        actor_user_id=user.id,
    )
    result.routers_created = routers_created
    result.routers_total = sum(len(r) for r in routers_by_location.values())

    # 9. Volatile traffic -- gated on "does the demo org already have any
    # session" so re-runs never double-seed hundreds of rows.
    if await _org_has_sessions(session, org.id):
        result.traffic_skipped_existing = True
        return result

    now = datetime.now(UTC)
    guest_pairs, guests_created, devices_created = await ensure_guests(
        guest_repository,
        organization_id=org.id,
        locations=locations,
        now=now,
    )
    result.guests_created = guests_created
    result.devices_created = devices_created

    await generate_traffic(
        session,
        guest_repository,
        provisioning_repository,
        organization_id=org.id,
        locations=locations,
        routers_by_location=routers_by_location,
        guest_pairs=guest_pairs,
        now=now,
        result=result,
    )
    return result


def _resolve_password() -> str:
    password = os.environ.get("CLOUDGUEST_DEMO_PASSWORD")
    if password:
        return password
    password = getpass.getpass("Demo user password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")
    return password


async def _main_async(password: str) -> None:
    async with SessionLocal() as session:
        result = await run_seed_demo(session, password=password)
        await session.commit()

    logger.info("seed_demo_completed", extra={"result": result})
    lines = [
        f"Demo organization: {result.organization_id} "
        f"({'created' if result.organization_created else 'already existed'})",
        f"Demo user: {DEMO_USER_EMAIL} -> {result.user_id} "
        f"({'created' if result.user_created else 'already existed'})",
        f"Org-admin role assignment: "
        f"{'created' if result.role_assigned else 'already held'}",
        f"Org membership: "
        f"{'created' if result.membership_created else 'already active'}",
        f"Default system template: {result.default_template_id}",
        f"Locations: {result.locations_total} total "
        f"(+{result.locations_created} new)",
        f"Routers: {result.routers_total} total (+{result.routers_created} new)",
    ]
    if result.traffic_skipped_existing:
        lines.append(
            "Guest traffic: SKIPPED -- demo org already has sessions "
            "(idempotent re-run)."
        )
    else:
        lines.append(
            f"Guests: +{result.guests_created}, Devices: +{result.devices_created}"
        )
        lines.append(
            f"Sessions: +{result.sessions_created} "
            f"({result.active_sessions} currently active)"
        )
        lines.append(f"Login history rows: +{result.login_history_created}")
        lines.append(f"Router health snapshots: +{result.health_snapshots_created}")
    for warning in result.warnings:
        lines.append(f"WARNING: {warning}")
    print("\n".join(lines))  # noqa: T201 -- CLI entrypoint output


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Seed a self-contained DEMO tenant (organization, org-admin login, "
            "locations, routers, and ~30 days of guest traffic) so the "
            "customer dashboard renders populated for sales demos. Safe to "
            "re-run."
        )
    )
    parser.parse_args(argv)
    password = _resolve_password()
    asyncio.run(_main_async(password))


if __name__ == "__main__":
    main()
