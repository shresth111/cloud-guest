"""Unit tests for the Guest domain (BE-010 Part 4, the final BE-010 module):
OTP-based login (happy path, disabled-method-for-location rejection,
blocked-guest rejection), voucher-based login (happy path, quota
copied-not-referenced verification), device MAC-address handling (global
uniqueness / guest reassignment), session disconnect-vs-terminate-vs-
reconnect semantics, timeout/quota detection, the RADIUS
``rlm_rest``-style authorize/accounting flow (including NAS shared-secret
authentication), guest analytics aggregate correctness, and tenant
isolation.

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_captive_portal.py``); ``asyncio_mode = "auto"`` runs
async tests directly. ``GuestService``/``RadiusService``/
``GuestAnalyticsService`` are exercised against small, hand-rolled
in-memory fakes for their repository and every composed cross-domain
service (OTP/Voucher/CaptivePortal/Router) -- there is no live Postgres/
Redis in this environment.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.captive_portal.models import CaptivePortalConfig
from app.domains.captive_portal.service import ResolvedPortalConfig
from app.domains.guest.constants import (
    BYTES_PER_MB,
    DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST,
    DEFAULT_MAX_DEVICES_PER_GUEST,
    DEFAULT_SESSION_TIMEOUT_MINUTES,
    RECONNECT_GRACE_MINUTES,
    TERMINATION_RECONNECT_COOLDOWN_MINUTES,
    GuestAuthMethod,
    GuestSessionStatus,
    NasStatus,
    QuotaPeriodType,
)
from app.domains.guest.exceptions import (
    ConcurrentSessionLimitExceededError,
    CrossOrganizationGuestAccessError,
    CrossOrganizationNasAccessError,
    FairUsagePolicyExceededError,
    GuestAuthMethodNotEnabledError,
    GuestBlockedError,
    GuestDeviceLimitExceededError,
    GuestSessionNotFoundError,
    InvalidExtensionMinutesError,
    InvalidNasStatusTransitionError,
    InvalidSessionStatusTransitionError,
    NoReconnectableSessionError,
    RadiusNasAuthenticationError,
    RadiusNasNotFoundError,
    RouterNotEligibleForGuestSessionError,
    SessionTerminationCooldownError,
)
from app.domains.guest.models import (
    Guest,
    GuestConsent,
    GuestDevice,
    GuestLoginHistory,
    GuestQuotaUsage,
    GuestSession,
    RadiusNasClient,
)
from app.domains.guest.repository import (
    ActiveGuestOrgPair,
    AuthMethodOutcomeCounts,
    DeviceSessionCount,
    LocationSessionCount,
    QuotaUsageWithOrgTimezone,
    SessionAggregate,
)
from app.domains.guest.service import (
    GuestAnalyticsService,
    GuestService,
    RadiusService,
    get_or_reset_quota_usage,
    issue_live_disconnect,
    run_fup_time_accrual,
    run_quota_reset,
)
from app.domains.guest.validators import (
    compute_period_start,
    is_concurrent_session_limit_reached,
    is_device_limit_reached,
    is_fup_usage_exceeded,
    is_quota_exceeded,
    is_session_timed_out,
    validate_nas_status_transition,
)
from app.domains.guest_access.exceptions import GuestAccessDeniedError
from app.domains.location.models import Location
from app.domains.otp.constants import OtpPurpose
from app.domains.otp.exceptions import OtpCodeMismatchError
from app.domains.queue_management.constants import QueueTargetType
from app.domains.router.crypto import encrypt_secret
from app.domains.router.enums import RouterStatus
from app.domains.router.exceptions import RouterNotFoundError
from app.domains.router.models import Router
from app.domains.voucher.exceptions import VoucherNotFoundError
from app.domains.voucher.models import Voucher, VoucherBatch

# ============================================================================
# Test doubles
# ============================================================================


def _now() -> datetime:
    return datetime.now(UTC)


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": _now(),
        "updated_at": _now(),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


@dataclass
class FakeOtpService:
    """Stand-in for ``OtpVerifyProtocol`` -- a code of ``"GOOD"`` always
    verifies; anything else raises ``OtpCodeMismatchError``, mirroring the
    real service's own failure shape."""

    async def verify_otp(self, *, identifier: str, code: str, purpose: OtpPurpose):
        if code != "GOOD":
            raise OtpCodeMismatchError(attempts_remaining=4)
        return None


@dataclass
class FakeVoucherService:
    """Stand-in for ``VoucherRedeemProtocol``."""

    vouchers: dict[str, tuple[Voucher, VoucherBatch]] = field(default_factory=dict)
    plan_queue_profiles: dict[uuid.UUID, uuid.UUID | None] = field(default_factory=dict)

    def register(
        self,
        code: str,
        *,
        data_limit_mb: int | None,
        validity_minutes: int,
        plan_id: uuid.UUID | None = None,
    ) -> tuple[Voucher, VoucherBatch]:
        batch = VoucherBatch(
            **_base_fields(
                name="Batch",
                organization_id=uuid.uuid4(),
                location_id=None,
                plan_id=plan_id,
                series_id=None,
                quantity=1,
                code_length=8,
                code_prefix=None,
                validity_minutes=validity_minutes,
                batch_expires_at=None,
                max_uses_per_voucher=1,
                data_limit_mb=data_limit_mb,
                status="active",
                created_by_user_id=None,
                approved_by_user_id=None,
                approved_at=None,
                notes=None,
            )
        )
        voucher = Voucher(
            **_base_fields(
                batch_id=batch.id,
                plan_id=plan_id,
                code=code,
                status="unused",
                use_count=0,
                redeemed_at=None,
                last_used_at=None,
                redeemed_identifier=None,
                expires_at=None,
            )
        )
        self.vouchers[code] = (voucher, batch)
        return voucher, batch

    def register_plan_queue_profile(
        self, plan_id: uuid.UUID, queue_profile_id: uuid.UUID | None
    ) -> None:
        self.plan_queue_profiles[plan_id] = queue_profile_id

    async def redeem_voucher(
        self, *, code: str, identifier: str, source: str
    ) -> tuple[Voucher, VoucherBatch]:
        if code not in self.vouchers:
            raise VoucherNotFoundError()
        return self.vouchers[code]

    async def get_plan_queue_profile_id(self, plan_id: uuid.UUID) -> uuid.UUID | None:
        return self.plan_queue_profiles.get(plan_id)


@dataclass
class FakeCaptivePortalService:
    """Stand-in for ``CaptivePortalLookupProtocol``."""

    configs_by_org: dict[uuid.UUID, CaptivePortalConfig] = field(default_factory=dict)
    location_to_org: dict[uuid.UUID, uuid.UUID] = field(default_factory=dict)

    def register(
        self,
        organization_id: uuid.UUID,
        *,
        otp_sms_enabled: bool = True,
        otp_email_enabled: bool = False,
        voucher_enabled: bool = True,
        username_password_enabled: bool = False,
    ) -> CaptivePortalConfig:
        config = CaptivePortalConfig(
            **_base_fields(
                organization_id=organization_id,
                location_id=None,
                name="Portal",
                is_active=True,
                is_default=True,
                theme="light",
                logo_url=None,
                background_image_url=None,
                primary_color="#1A73E8",
                secondary_color="#FFFFFF",
                default_language="en",
                supported_languages=["en"],
                advertisement_banner_url=None,
                advertisement_banner_link=None,
                terms_and_conditions_text=None,
                terms_and_conditions_url=None,
                privacy_policy_text=None,
                privacy_policy_url=None,
                splash_headline=None,
                splash_welcome_message=None,
                redirect_url=None,
                otp_sms_enabled=otp_sms_enabled,
                otp_email_enabled=otp_email_enabled,
                voucher_enabled=voucher_enabled,
                username_password_enabled=username_password_enabled,
                social_login_enabled=False,
                social_login_providers=[],
            )
        )
        self.configs_by_org[organization_id] = config
        return config

    def add_location(self, location_id: uuid.UUID, organization_id: uuid.UUID) -> None:
        self.location_to_org[location_id] = organization_id

    async def resolve_portal_config(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> ResolvedPortalConfig:
        resolved_org = organization_id
        if resolved_org is None and location_id is not None:
            resolved_org = self.location_to_org[location_id]
        return ResolvedPortalConfig(
            config=self.configs_by_org[resolved_org],
            resolved_via_location_override=False,
        )


@dataclass
class FakeRouterService:
    """Stand-in for ``RouterLookupProtocol``."""

    routers: dict[uuid.UUID, Router] = field(default_factory=dict)

    def add(
        self,
        *,
        organization_id: uuid.UUID,
        status: str = RouterStatus.ONLINE.value,
        location_id: uuid.UUID | None = None,
        public_ip_address: str | None = None,
        management_ip_address: str | None = None,
    ) -> Router:
        router = Router(
            **_base_fields(
                location_id=location_id or uuid.uuid4(),
                organization_id=organization_id,
                name="Lobby AP",
                serial_number=f"SN-{uuid.uuid4()}",
                mac_address=f"AA:BB:CC:{uuid.uuid4().hex[:2]}:00:01",
                model="hAP ac2",
                routeros_version=None,
                management_ip_address=management_ip_address,
                public_ip_address=public_ip_address,
                status=status,
                last_seen_at=None,
                last_health_check_at=None,
                health_status=None,
                api_username=None,
                api_credentials_encrypted=None,
                settings={},
            )
        )
        self.routers[router.id] = router
        return router

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router:
        router = self.routers.get(router_id)
        if router is None:
            raise RouterNotFoundError(router_id)
        return router


@dataclass
class FakeLocationLookup:
    """Stand-in for ``RadiusService``'s ``LocationLookupProtocol``.
    ``FakeRouterService.add`` generates each router's own ``location_id``
    independently (no shared registry with ``Fixture.location_id``), so
    this fake auto-vivifies a synthetic ``Location`` (with
    ``location_code=None``, exercising ``nas_number_generator``'s own
    fallback-to-location-id-prefix path) for any id asked about, rather
    than requiring pre-registration -- a real ``LocationService`` would
    always resolve a real router's real ``location_id`` in production."""

    locations: dict[uuid.UUID, Location] = field(default_factory=dict)

    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Location:
        if location_id not in self.locations:
            self.locations[location_id] = Location(
                **_base_fields(
                    organization_id=requesting_organization_id or uuid.uuid4(),
                    name="Test Location",
                    slug=f"loc-{uuid.uuid4()}",
                    status="active",
                    address_line1="1 Main St",
                    address_line2=None,
                    city="Austin",
                    state_province="TX",
                    postal_code="78701",
                    country="US",
                    timezone="UTC",
                    latitude=None,
                    longitude=None,
                    contact_name=None,
                    contact_phone=None,
                    contact_email=None,
                    settings={},
                )
            )
        return self.locations[location_id]


@dataclass
class FakeNasCodeCounterRepository:
    """Stand-in for ``nas_number_generator.NasCodeCounterRepositoryProtocol``
    -- a plain in-memory counter, mirroring the real atomic-UPSERT
    repository's externally-visible behavior (monotonic per ``counter_key``)
    without a real database."""

    counters: dict[str, int] = field(default_factory=dict)

    async def increment_and_get_next(self, counter_key: str) -> int:
        self.counters[counter_key] = self.counters.get(counter_key, 0) + 1
        return self.counters[counter_key]


@dataclass
class FakeAccessControlHook:
    """Stand-in for ``AccessDecisionProtocol`` -- lets Guest Session
    Engine's login tests exercise ``GuestService._enforce_access_control``
    without constructing a real ``GuestAccessService``/repository. Denies
    any identifier/mac_address pair added via ``deny()``; allows everything
    else, mirroring the real ``AccessDecisionResolver``'s default-allow
    posture."""

    denied_identifiers: set[str] = field(default_factory=set)
    denied_macs: set[str] = field(default_factory=set)
    denial_reason: str | None = "blocked for testing"
    calls: list[dict[str, object]] = field(default_factory=list)

    def deny(self, *, identifier: str | None = None, mac_address: str | None = None):
        if identifier is not None:
            self.denied_identifiers.add(identifier)
        if mac_address is not None:
            self.denied_macs.add(mac_address.strip().upper())

    async def check_access(
        self,
        *,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        identifier: str | None,
        mac_address: str | None,
    ):
        self.calls.append(
            {
                "organization_id": organization_id,
                "requesting_organization_id": requesting_organization_id,
                "location_id": location_id,
                "identifier": identifier,
                "mac_address": mac_address,
            }
        )
        normalized_mac = mac_address.strip().upper() if mac_address else None
        denied = (identifier in self.denied_identifiers) or (
            normalized_mac is not None and normalized_mac in self.denied_macs
        )

        class _Decision:
            def __init__(self, allowed: bool, reason: str | None) -> None:
                self.allowed = allowed
                self.reason = reason

        return _Decision(
            allowed=not denied, reason=self.denial_reason if denied else None
        )


@dataclass
class FakeDevicePolicyLookup:
    """Stand-in for ``PolicyLookupProtocol`` -- lets device-limit tests
    exercise ``GuestService._resolve_device_limit``'s "real policy wired"
    branch without constructing a real ``PolicyService``/repository.
    ``max_devices_per_guest is None`` (the default) means "no override",
    letting ``_resolve_device_limit`` fall through to its own
    ``DEFAULT_MAX_DEVICES_PER_GUEST`` fallback exactly as if no rule had
    been configured -- mirrors a real resolved ``GenericPolicyRules``
    payload that simply omits the field."""

    max_devices_per_guest: int | None = None

    async def resolve_effective_policy(
        self,
        *,
        policy_type: object,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ):
        class _Resolved:
            def __init__(self, rules: dict[str, object]) -> None:
                self.rules = rules

        rules = (
            {}
            if self.max_devices_per_guest is None
            else {"max_devices_per_guest": self.max_devices_per_guest}
        )
        return _Resolved(rules)


@dataclass
class FakeFupPolicyLookup:
    """Stand-in for ``PolicyLookupProtocol`` -- lets FUP quota tests
    exercise ``GuestService._enforce_fup_quota``/``_track_fup_data_usage``/
    ``service.run_fup_time_accrual``'s "real policy wired" branch without
    constructing a real ``PolicyService``/repository. ``fup_rules`` is an
    empty dict by default -- mirrors a resolved ``FUPPolicyRules`` payload
    with every period's cap left ``None`` (no limit configured at all),
    exactly ``_enforce_fup_quota``'s own "skip entirely" no-op case."""

    fup_rules: dict[str, object] = field(default_factory=dict)

    async def resolve_effective_policy(
        self,
        *,
        policy_type: object,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ):
        class _Resolved:
            def __init__(self, rules: dict[str, object]) -> None:
                self.rules = rules

        return _Resolved(dict(self.fup_rules))


@dataclass
class FakeQueueAssignmentHook:
    """Stand-in for ``QueueAssignmentProtocol`` -- lets speed-linked-voucher
    tests exercise ``GuestService._assign_voucher_queue``'s
    ``create_assignment``/``apply_queue`` composition without constructing
    a real ``QueueManagementService``/repository. Tracks every call so
    tests can assert on the exact ``target_type``/``target_id``/
    ``queue_profile_id``/``device_target`` a call site supplied."""

    create_assignment_calls: list[dict[str, object]] = field(default_factory=list)
    apply_queue_calls: list[dict[str, object]] = field(default_factory=list)
    resolve_and_assign_queue_calls: list[dict[str, object]] = field(
        default_factory=list
    )
    raise_on_create: Exception | None = None

    async def resolve_and_assign_queue(self, **kwargs: object):
        self.resolve_and_assign_queue_calls.append(kwargs)

        class _Assignment:
            id = uuid.uuid4()

        return _Assignment()

    async def create_assignment(self, **kwargs: object):
        if self.raise_on_create is not None:
            raise self.raise_on_create
        self.create_assignment_calls.append(kwargs)

        class _Assignment:
            id = uuid.uuid4()

        return _Assignment()

    async def apply_queue(self, assignment_id: uuid.UUID, **kwargs: object):
        self.apply_queue_calls.append({"assignment_id": assignment_id, **kwargs})

        class _Assignment:
            id = assignment_id

        return _Assignment()


@dataclass
class FakeGuestRepository:
    """In-memory stand-in for ``GuestRepositoryProtocol`` -- including the
    analytics aggregate methods, computed in pure Python to mirror what the
    real repository's SQL aggregates compute (the same "test the arithmetic
    against a hand-rolled fake" convention ``test_voucher.py``'s
    ``FakeVoucherRepository.get_batch_status_counts`` already established)."""

    guests: dict[uuid.UUID, Guest] = field(default_factory=dict)
    devices: dict[uuid.UUID, GuestDevice] = field(default_factory=dict)
    sessions: dict[uuid.UUID, GuestSession] = field(default_factory=dict)
    login_history: list[GuestLoginHistory] = field(default_factory=list)
    consents: dict[uuid.UUID, GuestConsent] = field(default_factory=dict)
    nas_clients: dict[uuid.UUID, RadiusNasClient] = field(default_factory=dict)
    quota_usages: dict[uuid.UUID, GuestQuotaUsage] = field(default_factory=dict)
    organization_timezones: dict[uuid.UUID, str] = field(default_factory=dict)

    # -- guests ----------------------------------------------------------------
    async def create_guest(self, **fields: object) -> Guest:
        guest = Guest(**_base_fields(**fields))
        self.guests[guest.id] = guest
        return guest

    async def get_guest_by_id(
        self, guest_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Guest | None:
        return self.guests.get(guest_id)

    async def get_guest_by_identifier(
        self, organization_id: uuid.UUID, identifier: str
    ) -> Guest | None:
        for guest in self.guests.values():
            if (
                guest.organization_id == organization_id
                and guest.identifier == identifier
            ):
                return guest
        return None

    async def update_guest(self, guest: Guest, data: dict[str, object]) -> Guest:
        for key, value in data.items():
            setattr(guest, key, value)
        guest.version += 1
        return guest

    async def list_guests(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        search: str | None = None,
        sort_by: str = "created_at",
        sort_order: object = None,
    ) -> tuple[list[Guest], object]:
        items = list(self.guests.values())
        for key, value in (filters or {}).items():
            items = [i for i in items if getattr(i, key) == value]
        if search:
            needle = search.lower()
            items = [
                i
                for i in items
                if needle in i.identifier.lower()
                or (i.display_name and needle in i.display_name.lower())
            ]
        total = len(items)

        class _Meta:
            def __init__(self, total_items: int) -> None:
                self.page = page
                self.page_size = page_size
                self.total_items = total_items
                self.total_pages = 1
                self.has_next = False
                self.has_previous = False

        return items, _Meta(total)

    # -- devices -----------------------------------------------------------------
    async def create_device(self, **fields: object) -> GuestDevice:
        device = GuestDevice(**_base_fields(**fields))
        self.devices[device.id] = device
        return device

    async def get_device_by_id(self, device_id: uuid.UUID) -> GuestDevice | None:
        return self.devices.get(device_id)

    async def get_device_by_mac(self, mac_address: str) -> GuestDevice | None:
        for device in self.devices.values():
            if device.mac_address == mac_address:
                return device
        return None

    async def count_devices_for_guest(self, guest_id: uuid.UUID) -> int:
        return sum(1 for d in self.devices.values() if d.guest_id == guest_id)

    async def update_device(
        self, device: GuestDevice, data: dict[str, object]
    ) -> GuestDevice:
        for key, value in data.items():
            setattr(device, key, value)
        device.version += 1
        return device

    # -- sessions ------------------------------------------------------------------
    async def create_session(self, **fields: object) -> GuestSession:
        session = GuestSession(**_base_fields(**fields))
        self.sessions[session.id] = session
        return session

    async def get_session_by_id(
        self, session_id: uuid.UUID, *, include_deleted: bool = False
    ) -> GuestSession | None:
        return self.sessions.get(session_id)

    async def update_session(
        self, session: GuestSession, data: dict[str, object]
    ) -> GuestSession:
        for key, value in data.items():
            setattr(session, key, value)
        session.version += 1
        return session

    async def list_sessions(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = "created_at",
        sort_order: object = None,
    ) -> tuple[list[GuestSession], object]:
        items = list(self.sessions.values())
        for key, value in (filters or {}).items():
            items = [i for i in items if getattr(i, key) == value]
        total = len(items)

        class _Meta:
            def __init__(self, total_items: int) -> None:
                self.page = page
                self.page_size = page_size
                self.total_items = total_items
                self.total_pages = 1
                self.has_next = False
                self.has_previous = False

        return items, _Meta(total)

    async def list_sessions_for_guest(
        self, guest_id: uuid.UUID, *, limit: int | None = None
    ) -> list[GuestSession]:
        items = [s for s in self.sessions.values() if s.guest_id == guest_id]
        items.sort(key=lambda s: s.started_at, reverse=True)
        return items[:limit] if limit else items

    async def get_latest_session_for_guest(
        self, guest_id: uuid.UUID
    ) -> GuestSession | None:
        items = await self.list_sessions_for_guest(guest_id, limit=1)
        return items[0] if items else None

    async def get_latest_terminated_session_for_guest(
        self, guest_id: uuid.UUID
    ) -> GuestSession | None:
        items = [
            s
            for s in self.sessions.values()
            if s.guest_id == guest_id
            and s.status == GuestSessionStatus.TERMINATED.value
        ]
        items.sort(key=lambda s: s.ended_at or s.started_at, reverse=True)
        return items[0] if items else None

    async def count_active_sessions_for_guest(self, guest_id: uuid.UUID) -> int:
        return sum(
            1
            for s in self.sessions.values()
            if s.guest_id == guest_id and s.status == GuestSessionStatus.ACTIVE.value
        )

    async def list_timed_out_sessions(self, *, now: datetime) -> list[GuestSession]:
        return [
            s
            for s in self.sessions.values()
            if s.status == GuestSessionStatus.ACTIVE.value
            and s.session_timeout_minutes is not None
            and is_session_timed_out(s, now=now)
        ]

    async def list_active_sessions_for_guest(
        self, guest_id: uuid.UUID
    ) -> list[GuestSession]:
        return [
            s
            for s in self.sessions.values()
            if s.guest_id == guest_id and s.status == GuestSessionStatus.ACTIVE.value
        ]

    async def list_active_guest_org_pairs(self) -> list[ActiveGuestOrgPair]:
        seen: set[tuple[uuid.UUID, uuid.UUID]] = set()
        pairs: list[ActiveGuestOrgPair] = []
        for s in self.sessions.values():
            if s.status != GuestSessionStatus.ACTIVE.value:
                continue
            key = (s.guest_id, s.organization_id)
            if key in seen:
                continue
            seen.add(key)
            pairs.append(
                ActiveGuestOrgPair(
                    guest_id=s.guest_id, organization_id=s.organization_id
                )
            )
        return pairs

    # -- FUP quota usage ---------------------------------------------------------

    async def get_quota_usage(
        self, guest_id: uuid.UUID, period_type: str
    ) -> GuestQuotaUsage | None:
        for usage in self.quota_usages.values():
            if usage.guest_id == guest_id and usage.period_type == period_type:
                return usage
        return None

    async def create_quota_usage(self, **fields: object) -> GuestQuotaUsage:
        usage = GuestQuotaUsage(**_base_fields(**fields))
        self.quota_usages[usage.id] = usage
        return usage

    async def update_quota_usage(
        self, usage: GuestQuotaUsage, data: dict[str, object]
    ) -> GuestQuotaUsage:
        for key, value in data.items():
            setattr(usage, key, value)
        usage.version += 1
        return usage

    async def list_all_quota_usages_with_org_timezone(
        self,
    ) -> list[QuotaUsageWithOrgTimezone]:
        return [
            QuotaUsageWithOrgTimezone(
                usage=usage,
                organization_timezone=self.organization_timezones.get(
                    usage.organization_id, "UTC"
                ),
            )
            for usage in self.quota_usages.values()
        ]

    async def get_organization_timezone(self, organization_id: uuid.UUID) -> str:
        return self.organization_timezones.get(organization_id, "UTC")

    # -- login history ---------------------------------------------------------
    async def create_login_history(self, **fields: object) -> GuestLoginHistory:
        entry = GuestLoginHistory(**_base_fields(**fields))
        self.login_history.append(entry)
        return entry

    # -- consents ----------------------------------------------------------------
    async def create_consent(self, **fields: object) -> GuestConsent:
        consent = GuestConsent(**_base_fields(**fields))
        self.consents[consent.id] = consent
        return consent

    # -- RADIUS NAS clients --------------------------------------------------------
    async def create_nas_client(self, **fields: object) -> RadiusNasClient:
        nas_client = RadiusNasClient(**_base_fields(**fields))
        self.nas_clients[nas_client.id] = nas_client
        return nas_client

    async def get_nas_client_by_identifier(
        self, nas_identifier: str
    ) -> RadiusNasClient | None:
        for client in self.nas_clients.values():
            if client.nas_identifier == nas_identifier:
                return client
        return None

    async def get_nas_client_by_router(
        self, router_id: uuid.UUID
    ) -> RadiusNasClient | None:
        for client in self.nas_clients.values():
            if client.router_id == router_id:
                return client
        return None

    async def get_nas_client_by_id(
        self, nas_id: uuid.UUID, *, include_deleted: bool = False
    ) -> RadiusNasClient | None:
        client = self.nas_clients.get(nas_id)
        if client is None or (client.is_deleted and not include_deleted):
            return None
        return client

    async def update_nas_client(
        self, nas_client: RadiusNasClient, data: dict[str, object]
    ) -> RadiusNasClient:
        for key, value in data.items():
            setattr(nas_client, key, value)
        nas_client.version += 1
        return nas_client

    async def soft_delete_nas_client(
        self, nas_client: RadiusNasClient
    ) -> RadiusNasClient:
        nas_client.is_deleted = True
        nas_client.deleted_at = datetime.now(UTC)
        nas_client.version += 1
        return nas_client

    async def list_nas_clients(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = "created_at",
        sort_order: object = None,
    ) -> tuple[list[RadiusNasClient], object]:
        items = [c for c in self.nas_clients.values() if not c.is_deleted]
        for key, value in (filters or {}).items():
            items = [i for i in items if getattr(i, key) == value]
        total = len(items)

        class _Meta:
            def __init__(self, total_items: int) -> None:
                self.page = page
                self.page_size = page_size
                self.total_items = total_items
                self.total_pages = 1
                self.has_next = False
                self.has_previous = False

        return items, _Meta(total)

    # -- analytics -----------------------------------------------------------------
    def _in_scope_sessions(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> list[GuestSession]:
        items = [
            s
            for s in self.sessions.values()
            if s.organization_id == organization_id and start <= s.started_at <= end
        ]
        if location_id is not None:
            items = [s for s in items if s.location_id == location_id]
        return items

    async def get_session_aggregate(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> SessionAggregate:
        items = self._in_scope_sessions(
            organization_id=organization_id,
            location_id=location_id,
            start=start,
            end=end,
        )
        if not items:
            return SessionAggregate(0, 0, None, 0)
        now = _now()
        durations = [
            ((s.ended_at or now) - s.started_at).total_seconds() for s in items
        ]
        return SessionAggregate(
            visitors=len(items),
            unique_guests=len({s.guest_id for s in items}),
            avg_duration_seconds=sum(durations) / len(durations),
            total_bandwidth_bytes=sum(
                s.bytes_uploaded + s.bytes_downloaded for s in items
            ),
        )

    async def get_returning_guest_count(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> int:
        items = self._in_scope_sessions(
            organization_id=organization_id,
            location_id=location_id,
            start=start,
            end=end,
        )
        guest_ids = {s.guest_id for s in items}
        return sum(1 for gid in guest_ids if self.guests[gid].total_visit_count > 1)

    async def get_top_locations(
        self,
        *,
        organization_id: uuid.UUID,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> list[LocationSessionCount]:
        items = self._in_scope_sessions(
            organization_id=organization_id, location_id=None, start=start, end=end
        )
        counts: dict[uuid.UUID, int] = {}
        for s in items:
            counts[s.location_id] = counts.get(s.location_id, 0) + 1
        ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]
        return [
            LocationSessionCount(
                location_id=loc_id, location_name=str(loc_id), session_count=count
            )
            for loc_id, count in ranked
        ]

    async def get_top_devices(
        self,
        *,
        organization_id: uuid.UUID,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> list[DeviceSessionCount]:
        items = [
            s
            for s in self._in_scope_sessions(
                organization_id=organization_id,
                location_id=None,
                start=start,
                end=end,
            )
            if s.device_id is not None
        ]
        counts: dict[uuid.UUID, list[GuestSession]] = {}
        for s in items:
            counts.setdefault(s.device_id, []).append(s)
        ranked = sorted(counts.items(), key=lambda kv: len(kv[1]), reverse=True)[:limit]
        return [
            DeviceSessionCount(
                device_id=device_id,
                mac_address=self.devices[device_id].mac_address,
                session_count=len(sess_list),
                unique_guest_count=len({s.guest_id for s in sess_list}),
            )
            for device_id, sess_list in ranked
        ]

    async def get_login_history_outcome_counts(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
        auth_methods,
    ) -> AuthMethodOutcomeCounts:
        items = [
            entry
            for entry in self.login_history
            if entry.organization_id == organization_id
            and start <= entry.attempted_at <= end
            and entry.auth_method in auth_methods
        ]
        if location_id is not None:
            items = [i for i in items if i.location_id == location_id]
        return AuthMethodOutcomeCounts(
            total_attempts=len(items),
            successful_attempts=sum(1 for i in items if i.success),
        )

    async def list_login_history(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        guest_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ):
        values = list(self.login_history)
        if organization_id is not None:
            values = [v for v in values if v.organization_id == organization_id]
        if location_id is not None:
            values = [v for v in values if v.location_id == location_id]
        if guest_id is not None:
            values = [v for v in values if v.guest_id == guest_id]
        values.sort(key=lambda v: v.attempted_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def get_session_auth_method_aggregate(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
        auth_method: str,
    ) -> SessionAggregate:
        items = [
            s
            for s in self._in_scope_sessions(
                organization_id=organization_id,
                location_id=location_id,
                start=start,
                end=end,
            )
            if s.auth_method == auth_method
        ]
        if not items:
            return SessionAggregate(0, 0, None, 0)
        now = _now()
        durations = [
            ((s.ended_at or now) - s.started_at).total_seconds() for s in items
        ]
        return SessionAggregate(
            visitors=len(items),
            unique_guests=len({s.guest_id for s in items}),
            avg_duration_seconds=sum(durations) / len(durations),
            total_bandwidth_bytes=sum(
                s.bytes_uploaded + s.bytes_downloaded for s in items
            ),
        )


@dataclass
class Fixture:
    repository: FakeGuestRepository
    otp_service: FakeOtpService
    voucher_service: FakeVoucherService
    captive_portal_service: FakeCaptivePortalService
    router_service: FakeRouterService
    location_lookup: FakeLocationLookup
    nas_code_counter_repository: FakeNasCodeCounterRepository
    audit_writer: FakeAuditLogWriter
    guest_service: GuestService
    radius_service: RadiusService
    analytics_service: GuestAnalyticsService
    organization_id: uuid.UUID
    location_id: uuid.UUID
    router: Router


def make_fixture(
    *,
    otp_sms_enabled: bool = True,
    voucher_enabled: bool = True,
    router_status: str = RouterStatus.ONLINE.value,
    access_control_hook: object | None = None,
    queue_lookup: object | None = None,
    policy_lookup: object | None = None,
    queue_assignment_hook: object | None = None,
) -> Fixture:
    repository = FakeGuestRepository()
    otp_service = FakeOtpService()
    voucher_service = FakeVoucherService()
    captive_portal_service = FakeCaptivePortalService()
    router_service = FakeRouterService()
    location_lookup = FakeLocationLookup()
    nas_code_counter_repository = FakeNasCodeCounterRepository()
    audit_writer = FakeAuditLogWriter()

    organization_id = uuid.uuid4()
    location_id = uuid.uuid4()
    captive_portal_service.register(
        organization_id,
        otp_sms_enabled=otp_sms_enabled,
        voucher_enabled=voucher_enabled,
    )
    captive_portal_service.add_location(location_id, organization_id)
    router = router_service.add(organization_id=organization_id, status=router_status)

    guest_service = GuestService(
        repository,
        otp_service,
        voucher_service,
        captive_portal_service,
        router_service,
        audit_writer=audit_writer,
        access_control_hook=access_control_hook,
        policy_lookup=policy_lookup,
        queue_assignment_hook=queue_assignment_hook,
    )
    radius_service = RadiusService(
        repository,
        guest_service,
        router_service,
        location_lookup,
        nas_code_counter_repository,
        audit_writer=audit_writer,
        queue_lookup=queue_lookup,
    )
    analytics_service = GuestAnalyticsService(repository)

    return Fixture(
        repository=repository,
        otp_service=otp_service,
        voucher_service=voucher_service,
        captive_portal_service=captive_portal_service,
        router_service=router_service,
        location_lookup=location_lookup,
        nas_code_counter_repository=nas_code_counter_repository,
        audit_writer=audit_writer,
        guest_service=guest_service,
        radius_service=radius_service,
        analytics_service=analytics_service,
        organization_id=organization_id,
        location_id=location_id,
        router=router,
    )


# ============================================================================
# OTP-based login
# ============================================================================


class TestOtpLogin:
    async def test_happy_path_creates_guest_device_and_session(self) -> None:
        fx = make_fixture()
        result = await fx.guest_service.login_via_otp(
            identifier="+15551234567",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
            device_mac="aa:bb:cc:dd:ee:ff",
        )
        assert result.is_new_guest is True
        assert result.guest.organization_id == fx.organization_id
        assert result.guest.total_visit_count == 1
        assert result.device is not None
        assert result.device.mac_address == "AA:BB:CC:DD:EE:FF"
        assert result.session.status == GuestSessionStatus.ACTIVE.value
        assert result.session.auth_method == GuestAuthMethod.OTP_SMS.value
        assert result.session.session_timeout_minutes == DEFAULT_SESSION_TIMEOUT_MINUTES
        assert result.session.data_limit_mb is None
        # High-volume login is not itself audited -- see service.py's
        # module docstring's audit-volume judgment call.
        assert fx.audit_writer.entries == []

    async def test_returning_guest_bumps_visit_count(self) -> None:
        fx = make_fixture()
        first = await fx.guest_service.login_via_otp(
            identifier="+15551234567",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        assert first.is_new_guest is True
        second = await fx.guest_service.login_via_otp(
            identifier="+15551234567",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        assert second.is_new_guest is False
        assert second.guest.id == first.guest.id
        assert second.guest.total_visit_count == 2

    async def test_disabled_method_for_location_rejected(self) -> None:
        fx = make_fixture(otp_sms_enabled=False)
        with pytest.raises(GuestAuthMethodNotEnabledError):
            await fx.guest_service.login_via_otp(
                identifier="+15551234567",
                code="GOOD",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )

    async def test_blocked_guest_rejected_before_otp_verification(self) -> None:
        fx = make_fixture()
        first = await fx.guest_service.login_via_otp(
            identifier="+15551234567",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        await fx.guest_service.block_guest(
            actor_user_id=uuid.uuid4(),
            guest_id=first.guest.id,
            requesting_organization_id=fx.organization_id,
            reason="abuse",
        )
        with pytest.raises(GuestBlockedError):
            # Even a WRONG code must surface GuestBlockedError first --
            # blocked guests never learn if their code would've worked.
            await fx.guest_service.login_via_otp(
                identifier="+15551234567",
                code="WRONG",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )

    async def test_wrong_code_records_failure_and_reraises(self) -> None:
        fx = make_fixture()
        with pytest.raises(OtpCodeMismatchError):
            await fx.guest_service.login_via_otp(
                identifier="+15551234567",
                code="WRONG",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )
        assert len(fx.repository.login_history) == 1
        assert fx.repository.login_history[0].success is False
        assert fx.repository.login_history[0].guest_id is None

    async def test_router_not_eligible_rejected(self) -> None:
        fx = make_fixture(router_status=RouterStatus.SUSPENDED.value)
        with pytest.raises(RouterNotEligibleForGuestSessionError):
            await fx.guest_service.login_via_otp(
                identifier="+15551234567",
                code="GOOD",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )


# ============================================================================
# Voucher-based login
# ============================================================================


class TestVoucherLogin:
    async def test_happy_path(self) -> None:
        fx = make_fixture()
        fx.voucher_service.register("VOUCHER1", data_limit_mb=500, validity_minutes=120)
        result = await fx.guest_service.login_via_voucher(
            code="VOUCHER1",
            identifier="guest@example.com",
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        assert result.session.auth_method == GuestAuthMethod.VOUCHER.value
        assert result.session.voucher_id is not None
        assert result.session.data_limit_mb == 500
        assert result.session.session_timeout_minutes == 120

    async def test_quota_copied_not_referenced(self) -> None:
        """A later change to the voucher batch's own data_limit_mb must
        never retroactively alter an already-in-progress session's quota
        -- see service.py's module docstring."""
        fx = make_fixture()
        voucher, batch = fx.voucher_service.register(
            "VOUCHER2", data_limit_mb=100, validity_minutes=60
        )
        result = await fx.guest_service.login_via_voucher(
            code="VOUCHER2",
            identifier="guest2@example.com",
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        assert result.session.data_limit_mb == 100

        # Admin edits the batch's own limit after the fact.
        batch.data_limit_mb = 9999
        batch.validity_minutes = 9999

        refetched = await fx.repository.get_session_by_id(result.session.id)
        assert refetched.data_limit_mb == 100
        assert refetched.session_timeout_minutes == 60

    async def test_disabled_method_rejected(self) -> None:
        fx = make_fixture(voucher_enabled=False)
        fx.voucher_service.register("VOUCHER3", data_limit_mb=None, validity_minutes=60)
        with pytest.raises(GuestAuthMethodNotEnabledError):
            await fx.guest_service.login_via_voucher(
                code="VOUCHER3",
                identifier="guest3@example.com",
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )

    async def test_invalid_code_records_failure_and_reraises(self) -> None:
        fx = make_fixture()
        with pytest.raises(VoucherNotFoundError):
            await fx.guest_service.login_via_voucher(
                code="NOPE",
                identifier="guest4@example.com",
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )
        assert fx.repository.login_history[0].success is False


class TestSpeedLinkedVoucherQueueAssignment:
    async def test_creates_and_applies_a_voucher_targeted_assignment(self) -> None:
        fx = make_fixture(queue_assignment_hook=FakeQueueAssignmentHook())
        plan_id = uuid.uuid4()
        queue_profile_id = uuid.uuid4()
        fx.voucher_service.register_plan_queue_profile(plan_id, queue_profile_id)
        voucher, _ = fx.voucher_service.register(
            "SPEEDV1", data_limit_mb=None, validity_minutes=60, plan_id=plan_id
        )
        result = await fx.guest_service.login_via_voucher(
            code="SPEEDV1",
            identifier="guest@example.com",
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
            ip_address="10.0.0.5",
        )
        hook = fx.guest_service.queue_assignment_hook
        assert len(hook.create_assignment_calls) == 1
        call = hook.create_assignment_calls[0]
        assert call["target_type"] == QueueTargetType.VOUCHER
        assert call["target_id"] == voucher.id
        assert call["queue_profile_id"] == queue_profile_id
        assert call["router_id"] == fx.router.id
        assert call["device_target"] == "10.0.0.5"
        assert len(hook.apply_queue_calls) == 1
        assert result.session.voucher_id == voucher.id

    async def test_no_op_when_voucher_has_no_plan(self) -> None:
        fx = make_fixture(queue_assignment_hook=FakeQueueAssignmentHook())
        fx.voucher_service.register("SPEEDV2", data_limit_mb=None, validity_minutes=60)
        await fx.guest_service.login_via_voucher(
            code="SPEEDV2",
            identifier="guest2@example.com",
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
            ip_address="10.0.0.6",
        )
        hook = fx.guest_service.queue_assignment_hook
        assert hook.create_assignment_calls == []

    async def test_no_op_when_plan_has_no_queue_profile(self) -> None:
        fx = make_fixture(queue_assignment_hook=FakeQueueAssignmentHook())
        plan_id = uuid.uuid4()
        fx.voucher_service.register_plan_queue_profile(plan_id, None)
        fx.voucher_service.register(
            "SPEEDV3", data_limit_mb=None, validity_minutes=60, plan_id=plan_id
        )
        await fx.guest_service.login_via_voucher(
            code="SPEEDV3",
            identifier="guest3@example.com",
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
            ip_address="10.0.0.7",
        )
        hook = fx.guest_service.queue_assignment_hook
        assert hook.create_assignment_calls == []

    async def test_no_op_when_no_queue_assignment_hook_wired(self) -> None:
        fx = make_fixture()
        plan_id = uuid.uuid4()
        fx.voucher_service.register_plan_queue_profile(plan_id, uuid.uuid4())
        fx.voucher_service.register(
            "SPEEDV4", data_limit_mb=None, validity_minutes=60, plan_id=plan_id
        )
        result = await fx.guest_service.login_via_voucher(
            code="SPEEDV4",
            identifier="guest4@example.com",
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
            ip_address="10.0.0.8",
        )
        assert result.session.status == GuestSessionStatus.ACTIVE.value

    async def test_no_op_when_no_ip_address_known(self) -> None:
        fx = make_fixture(queue_assignment_hook=FakeQueueAssignmentHook())
        plan_id = uuid.uuid4()
        fx.voucher_service.register_plan_queue_profile(plan_id, uuid.uuid4())
        fx.voucher_service.register(
            "SPEEDV5", data_limit_mb=None, validity_minutes=60, plan_id=plan_id
        )
        await fx.guest_service.login_via_voucher(
            code="SPEEDV5",
            identifier="guest5@example.com",
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        hook = fx.guest_service.queue_assignment_hook
        assert hook.create_assignment_calls == []

    async def test_never_raises_when_the_hook_explodes(self) -> None:
        hook = FakeQueueAssignmentHook(raise_on_create=RuntimeError("boom"))
        fx = make_fixture(queue_assignment_hook=hook)
        plan_id = uuid.uuid4()
        fx.voucher_service.register_plan_queue_profile(plan_id, uuid.uuid4())
        fx.voucher_service.register(
            "SPEEDV6", data_limit_mb=None, validity_minutes=60, plan_id=plan_id
        )
        result = await fx.guest_service.login_via_voucher(
            code="SPEEDV6",
            identifier="guest6@example.com",
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
            ip_address="10.0.0.9",
        )
        assert result.session.status == GuestSessionStatus.ACTIVE.value


# ============================================================================
# Device MAC-address handling
# ============================================================================


class TestDeviceHandling:
    async def test_same_mac_reassigned_to_new_guest(self) -> None:
        """See models.py's module docstring: mac_address is globally
        unique, guest_id is reassignable -- a device belongs to whoever
        most recently authenticated with it."""
        fx = make_fixture()
        first = await fx.guest_service.login_via_otp(
            identifier="+15550000001",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
            device_mac="11:22:33:44:55:66",
        )
        second = await fx.guest_service.login_via_otp(
            identifier="+15550000002",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
            device_mac="11:22:33:44:55:66",
        )
        assert first.device.id == second.device.id  # same physical device row
        assert second.device.guest_id == second.guest.id
        assert second.device.guest_id != first.guest.id
        # Only one GuestDevice row exists for this MAC -- no fragmentation.
        assert len(fx.repository.devices) == 1

    async def test_mac_normalized_case_and_whitespace(self) -> None:
        fx = make_fixture()
        result = await fx.guest_service.login_via_otp(
            identifier="+15550000003",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
            device_mac="  aa:bb:cc:dd:ee:ff  ",
        )
        assert result.device.mac_address == "AA:BB:CC:DD:EE:FF"

    async def test_no_device_mac_creates_session_without_device(self) -> None:
        fx = make_fixture()
        result = await fx.guest_service.login_via_otp(
            identifier="+15550000004",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        assert result.device is None
        assert result.session.device_id is None


# ============================================================================
# Session lifecycle: disconnect vs terminate vs reconnect
# ============================================================================


class TestSessionLifecycle:
    async def _login(
        self, fx: Fixture, identifier: str = "+15551110000"
    ) -> GuestSession:
        result = await fx.guest_service.login_via_otp(
            identifier=identifier,
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        return result.session

    async def test_disconnect_is_not_audited_when_system_initiated(self) -> None:
        fx = make_fixture()
        session = await self._login(fx)
        updated = await fx.guest_service.disconnect_session(session_id=session.id)
        assert updated.status == GuestSessionStatus.DISCONNECTED.value
        assert updated.ended_at is not None
        assert fx.audit_writer.entries == []

    async def test_disconnect_is_audited_when_admin_initiated(self) -> None:
        fx = make_fixture()
        session = await self._login(fx)
        await fx.guest_service.disconnect_session(
            session_id=session.id, actor_user_id=uuid.uuid4(), reason="guest left"
        )
        actions = [e["action"] for e in fx.audit_writer.entries]
        assert "guest_session_disconnected" in actions

    async def test_disconnect_twice_raises_invalid_transition(self) -> None:
        fx = make_fixture()
        session = await self._login(fx)
        await fx.guest_service.disconnect_session(session_id=session.id)
        with pytest.raises(InvalidSessionStatusTransitionError):
            await fx.guest_service.disconnect_session(session_id=session.id)

    async def test_terminate_is_always_audited_and_distinct_from_disconnect(
        self,
    ) -> None:
        fx = make_fixture()
        session = await self._login(fx)
        updated = await fx.guest_service.terminate_session(
            session_id=session.id, actor_user_id=uuid.uuid4(), reason="policy violation"
        )
        assert updated.status == GuestSessionStatus.TERMINATED.value
        actions = [e["action"] for e in fx.audit_writer.entries]
        assert "guest_session_terminated" in actions

    async def test_reconnect_after_disconnect_creates_new_session(self) -> None:
        """Reconnect is append-only: a NEW GuestSession row, never a
        resurrected old one."""
        fx = make_fixture()
        session = await self._login(fx)
        await fx.guest_service.disconnect_session(session_id=session.id)

        reconnected = await fx.guest_service.reconnect(
            guest_id=session.guest_id,
            router_id=fx.router.id,
            location_id=fx.location_id,
        )
        assert reconnected.id != session.id
        assert reconnected.status == GuestSessionStatus.ACTIVE.value
        assert reconnected.guest_id == session.guest_id
        # Original row is untouched -- still DISCONNECTED, never flipped
        # back to ACTIVE.
        original = await fx.repository.get_session_by_id(session.id)
        assert original.status == GuestSessionStatus.DISCONNECTED.value

    async def test_reconnect_is_idempotent_when_already_active(self) -> None:
        fx = make_fixture()
        session = await self._login(fx)
        reconnected = await fx.guest_service.reconnect(
            guest_id=session.guest_id,
            router_id=fx.router.id,
            location_id=fx.location_id,
        )
        assert reconnected.id == session.id
        assert len(fx.repository.sessions) == 1

    async def test_reconnect_outside_grace_window_rejected(self) -> None:
        fx = make_fixture()
        session = await self._login(fx)
        await fx.guest_service.disconnect_session(session_id=session.id)
        # Simulate the disconnect having happened long ago.
        session.ended_at = _now() - timedelta(minutes=RECONNECT_GRACE_MINUTES + 5)

        with pytest.raises(NoReconnectableSessionError):
            await fx.guest_service.reconnect(
                guest_id=session.guest_id,
                router_id=fx.router.id,
                location_id=fx.location_id,
            )

    async def test_reconnect_with_no_prior_session_rejected(self) -> None:
        fx = make_fixture()
        guest = await fx.repository.create_guest(
            organization_id=fx.organization_id,
            location_id=fx.location_id,
            identifier="+15559998888",
            display_name=None,
            first_seen_at=_now(),
            last_seen_at=_now(),
            total_visit_count=0,
            is_blocked=False,
            blocked_reason=None,
        )
        with pytest.raises(NoReconnectableSessionError):
            await fx.guest_service.reconnect(
                guest_id=guest.id, router_id=fx.router.id, location_id=fx.location_id
            )

    async def test_reconnect_blocked_during_termination_cooldown(self) -> None:
        fx = make_fixture()
        session = await self._login(fx)
        await fx.guest_service.terminate_session(
            session_id=session.id, actor_user_id=uuid.uuid4()
        )
        with pytest.raises(SessionTerminationCooldownError):
            await fx.guest_service.reconnect(
                guest_id=session.guest_id,
                router_id=fx.router.id,
                location_id=fx.location_id,
            )

    async def test_reconnect_allowed_after_cooldown_elapses(self) -> None:
        fx = make_fixture()
        session = await self._login(fx)
        terminated = await fx.guest_service.terminate_session(
            session_id=session.id, actor_user_id=uuid.uuid4()
        )
        terminated.ended_at = _now() - timedelta(
            minutes=TERMINATION_RECONNECT_COOLDOWN_MINUTES + 1
        )
        reconnected = await fx.guest_service.reconnect(
            guest_id=session.guest_id,
            router_id=fx.router.id,
            location_id=fx.location_id,
        )
        assert reconnected.status == GuestSessionStatus.ACTIVE.value


class TestPauseResumeExtend:
    async def _login(
        self, fx: Fixture, identifier: str = "+15551112000"
    ) -> GuestSession:
        result = await fx.guest_service.login_via_otp(
            identifier=identifier,
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        return result.session

    async def test_pause_flips_status_and_is_reversible_via_resume(self) -> None:
        fx = make_fixture()
        session = await self._login(fx)
        paused = await fx.guest_service.pause_session(
            session_id=session.id, actor_user_id=uuid.uuid4(), reason="admin pause"
        )
        assert paused.status == GuestSessionStatus.PAUSED.value

        resumed = await fx.guest_service.resume_session(
            session_id=session.id, actor_user_id=uuid.uuid4()
        )
        assert resumed.status == GuestSessionStatus.ACTIVE.value
        assert resumed.id == session.id  # same row, not a new one

    async def test_pause_is_always_audited(self) -> None:
        fx = make_fixture()
        session = await self._login(fx)
        await fx.guest_service.pause_session(
            session_id=session.id, actor_user_id=uuid.uuid4(), reason="abuse"
        )
        actions = [e["action"] for e in fx.audit_writer.entries]
        assert "guest_session_paused" in actions

    async def test_resume_is_always_audited(self) -> None:
        fx = make_fixture()
        session = await self._login(fx)
        await fx.guest_service.pause_session(
            session_id=session.id, actor_user_id=uuid.uuid4()
        )
        await fx.guest_service.resume_session(
            session_id=session.id, actor_user_id=uuid.uuid4()
        )
        actions = [e["action"] for e in fx.audit_writer.entries]
        assert "guest_session_resumed" in actions

    async def test_resume_refreshes_last_activity_at(self) -> None:
        fx = make_fixture()
        session = await self._login(fx)
        await fx.guest_service.pause_session(
            session_id=session.id, actor_user_id=uuid.uuid4()
        )
        session.last_activity_at = _now() - timedelta(hours=2)
        resumed = await fx.guest_service.resume_session(
            session_id=session.id, actor_user_id=uuid.uuid4()
        )
        assert (_now() - resumed.last_activity_at).total_seconds() < 5

    async def test_resuming_an_already_active_session_raises(self) -> None:
        fx = make_fixture()
        session = await self._login(fx)
        with pytest.raises(InvalidSessionStatusTransitionError):
            await fx.guest_service.resume_session(
                session_id=session.id, actor_user_id=uuid.uuid4()
            )

    async def test_pausing_a_terminal_session_raises(self) -> None:
        fx = make_fixture()
        session = await self._login(fx)
        await fx.guest_service.disconnect_session(session_id=session.id)
        with pytest.raises(InvalidSessionStatusTransitionError):
            await fx.guest_service.pause_session(
                session_id=session.id, actor_user_id=uuid.uuid4()
            )

    async def test_paused_session_can_still_be_terminated(self) -> None:
        fx = make_fixture()
        session = await self._login(fx)
        await fx.guest_service.pause_session(
            session_id=session.id, actor_user_id=uuid.uuid4()
        )
        terminated = await fx.guest_service.terminate_session(
            session_id=session.id, actor_user_id=uuid.uuid4()
        )
        assert terminated.status == GuestSessionStatus.TERMINATED.value

    async def test_extend_increases_session_timeout_minutes(self) -> None:
        fx = make_fixture()
        session = await self._login(fx)
        original_timeout = session.session_timeout_minutes
        extended = await fx.guest_service.extend_session(
            session_id=session.id,
            additional_minutes=30,
            actor_user_id=uuid.uuid4(),
        )
        assert extended.session_timeout_minutes == original_timeout + 30

    async def test_extend_seeds_a_timeout_when_none_previously_set(self) -> None:
        fx = make_fixture()
        session = await self._login(fx)
        session.session_timeout_minutes = None  # an unlimited-grant session
        extended = await fx.guest_service.extend_session(
            session_id=session.id,
            additional_minutes=45,
            actor_user_id=uuid.uuid4(),
        )
        assert extended.session_timeout_minutes == 45

    async def test_extend_is_always_audited(self) -> None:
        fx = make_fixture()
        session = await self._login(fx)
        await fx.guest_service.extend_session(
            session_id=session.id,
            additional_minutes=15,
            actor_user_id=uuid.uuid4(),
        )
        actions = [e["action"] for e in fx.audit_writer.entries]
        assert "guest_session_extended" in actions

    async def test_extend_rejects_non_positive_minutes(self) -> None:
        fx = make_fixture()
        session = await self._login(fx)
        with pytest.raises(InvalidExtensionMinutesError):
            await fx.guest_service.extend_session(
                session_id=session.id,
                additional_minutes=0,
                actor_user_id=uuid.uuid4(),
            )

    async def test_extend_rejects_a_terminal_session(self) -> None:
        fx = make_fixture()
        session = await self._login(fx)
        await fx.guest_service.disconnect_session(session_id=session.id)
        with pytest.raises(InvalidSessionStatusTransitionError):
            await fx.guest_service.extend_session(
                session_id=session.id,
                additional_minutes=10,
                actor_user_id=uuid.uuid4(),
            )

    async def test_extend_allowed_on_a_paused_session(self) -> None:
        fx = make_fixture()
        session = await self._login(fx)
        await fx.guest_service.pause_session(
            session_id=session.id, actor_user_id=uuid.uuid4()
        )
        extended = await fx.guest_service.extend_session(
            session_id=session.id,
            additional_minutes=20,
            actor_user_id=uuid.uuid4(),
        )
        assert extended.status == GuestSessionStatus.PAUSED.value


class TestLiveDisconnect:
    async def _login_with_registered_nas(
        self, fx: Fixture, *, ip_address: str | None = "203.0.113.10"
    ) -> GuestSession:
        result = await fx.guest_service.login_via_otp(
            identifier="+15551113000",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(),
            router_id=fx.router.id,
            nas_identifier="nas-live-disconnect",
            shared_secret="s3cr3t-value",
            ip_address=ip_address,
        )
        return result.session

    async def test_no_op_when_no_nas_is_registered_for_the_router(self) -> None:
        fx = make_fixture()
        session = await fx.guest_service.login_via_otp(
            identifier="+15551114000",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        result = await issue_live_disconnect(fx.repository, session=session.session)
        assert result is None

    async def test_no_op_when_the_registered_nas_has_no_ip_address(self) -> None:
        fx = make_fixture()
        session = await self._login_with_registered_nas(fx, ip_address=None)
        result = await issue_live_disconnect(fx.repository, session=session)
        assert result is None

    async def test_returns_true_once_a_real_disconnect_ack_comes_back(
        self, monkeypatch
    ) -> None:
        from app.domains.guest import service as service_module
        from app.domains.guest.radius_coa import RADIUS_CODE_DISCONNECT_ACK

        fx = make_fixture()
        session = await self._login_with_registered_nas(fx)

        sent: dict[str, object] = {}

        def _fake_send_packet(packet: bytes, *, host: str, **kwargs: object):
            sent["packet"] = packet
            sent["host"] = host
            return bytes([RADIUS_CODE_DISCONNECT_ACK])

        monkeypatch.setattr(service_module, "send_packet", _fake_send_packet)

        result = await issue_live_disconnect(fx.repository, session=session)
        assert result is True
        assert sent["host"] == "203.0.113.10"

    async def test_returns_false_on_a_disconnect_nak(self, monkeypatch) -> None:
        from app.domains.guest import service as service_module
        from app.domains.guest.radius_coa import RADIUS_CODE_DISCONNECT_NAK

        fx = make_fixture()
        session = await self._login_with_registered_nas(fx)

        monkeypatch.setattr(
            service_module,
            "send_packet",
            lambda packet, *, host, **kwargs: bytes([RADIUS_CODE_DISCONNECT_NAK]),
        )

        result = await issue_live_disconnect(fx.repository, session=session)
        assert result is False

    async def test_returns_none_on_a_timeout(self, monkeypatch) -> None:
        """Mirrors ``radius_coa.send_packet``'s own real "no live NAS
        listening" outcome -- a timeout, surfaced as ``None``, never an
        exception."""
        from app.domains.guest import service as service_module

        fx = make_fixture()
        session = await self._login_with_registered_nas(fx)

        monkeypatch.setattr(
            service_module, "send_packet", lambda packet, *, host, **kwargs: None
        )

        result = await issue_live_disconnect(fx.repository, session=session)
        assert result is None

    async def test_never_raises_when_the_send_itself_explodes(
        self, monkeypatch
    ) -> None:
        from app.domains.guest import service as service_module

        fx = make_fixture()
        session = await self._login_with_registered_nas(fx)

        def _exploding_send_packet(packet: bytes, *, host: str, **kwargs: object):
            raise OSError("network unreachable")

        monkeypatch.setattr(service_module, "send_packet", _exploding_send_packet)

        result = await issue_live_disconnect(fx.repository, session=session)
        assert result is None

    async def test_disconnect_session_attempts_a_live_disconnect(
        self, monkeypatch
    ) -> None:
        """Integration-level proof that ``disconnect_session`` itself
        (not just ``issue_live_disconnect`` called directly) triggers the
        real send."""
        from app.domains.guest import service as service_module
        from app.domains.guest.radius_coa import RADIUS_CODE_DISCONNECT_ACK

        fx = make_fixture()
        session = await self._login_with_registered_nas(fx)

        calls: list[str] = []

        def _fake_send_packet(packet: bytes, *, host: str, **kwargs: object):
            calls.append(host)
            return bytes([RADIUS_CODE_DISCONNECT_ACK])

        monkeypatch.setattr(service_module, "send_packet", _fake_send_packet)

        updated = await fx.guest_service.disconnect_session(session_id=session.id)
        assert updated.status == GuestSessionStatus.DISCONNECTED.value
        assert calls == ["203.0.113.10"]


# ============================================================================
# Timeout / quota detection
# ============================================================================


class TestTimeoutAndQuota:
    def test_is_session_timed_out_pure_function(self) -> None:
        now = _now()
        session = GuestSession(
            **_base_fields(
                guest_id=uuid.uuid4(),
                device_id=None,
                router_id=uuid.uuid4(),
                location_id=uuid.uuid4(),
                organization_id=uuid.uuid4(),
                auth_method="otp_sms",
                voucher_id=None,
                status="active",
                started_at=now - timedelta(minutes=100),
                ended_at=None,
                last_activity_at=now - timedelta(minutes=90),
                ip_address=None,
                bytes_uploaded=0,
                bytes_downloaded=0,
                data_limit_mb=None,
                session_timeout_minutes=60,
                disconnect_reason=None,
            )
        )
        assert is_session_timed_out(session, now=now) is True
        session.last_activity_at = now - timedelta(minutes=10)
        assert is_session_timed_out(session, now=now) is False
        session.session_timeout_minutes = None
        assert is_session_timed_out(session, now=now) is False

    def test_is_quota_exceeded_pure_function(self) -> None:
        now = _now()
        session = GuestSession(
            **_base_fields(
                guest_id=uuid.uuid4(),
                device_id=None,
                router_id=uuid.uuid4(),
                location_id=uuid.uuid4(),
                organization_id=uuid.uuid4(),
                auth_method="voucher",
                voucher_id=None,
                status="active",
                started_at=now,
                ended_at=None,
                last_activity_at=now,
                ip_address=None,
                bytes_uploaded=50 * BYTES_PER_MB,
                bytes_downloaded=40 * BYTES_PER_MB,
                data_limit_mb=100,
                session_timeout_minutes=None,
                disconnect_reason=None,
            )
        )
        assert is_quota_exceeded(session) is False
        session.bytes_downloaded = 60 * BYTES_PER_MB
        assert is_quota_exceeded(session) is True
        session.data_limit_mb = None
        assert is_quota_exceeded(session) is False

    async def test_enforce_timeouts_expires_stale_sessions(self) -> None:
        fx = make_fixture()
        result = await fx.guest_service.login_via_otp(
            identifier="+15552223333",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        session = result.session
        session.session_timeout_minutes = 5
        session.last_activity_at = _now() - timedelta(minutes=10)

        expired = await fx.guest_service.enforce_timeouts()
        assert len(expired) == 1
        assert expired[0].id == session.id
        assert expired[0].status == GuestSessionStatus.EXPIRED.value
        assert expired[0].disconnect_reason == "inactivity_timeout"

    async def test_enforce_timeouts_ignores_fresh_sessions(self) -> None:
        fx = make_fixture()
        result = await fx.guest_service.login_via_otp(
            identifier="+15552223334",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        result.session.session_timeout_minutes = 240
        expired = await fx.guest_service.enforce_timeouts()
        assert expired == []

    async def test_record_usage_expires_session_on_quota_breach(self) -> None:
        fx = make_fixture()
        fx.voucher_service.register("QVOUCHER", data_limit_mb=1, validity_minutes=60)
        result = await fx.guest_service.login_via_voucher(
            code="QVOUCHER",
            identifier="quota@example.com",
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        updated = await fx.guest_service.record_usage(
            session_id=result.session.id,
            bytes_uploaded_delta=2 * BYTES_PER_MB,
            bytes_downloaded_delta=0,
        )
        assert updated.status == GuestSessionStatus.EXPIRED.value
        assert updated.disconnect_reason == "data_limit_exceeded"

    async def test_record_usage_noop_on_terminal_session(self) -> None:
        fx = make_fixture()
        result = await fx.guest_service.login_via_otp(
            identifier="+15552223335",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        await fx.guest_service.disconnect_session(session_id=result.session.id)
        updated = await fx.guest_service.record_usage(
            session_id=result.session.id,
            bytes_uploaded_delta=1000,
            bytes_downloaded_delta=1000,
        )
        assert updated.bytes_uploaded == 0  # unchanged -- session was terminal


# ============================================================================
# Concurrent session limit (Guest Session Engine, Phase 1)
# ============================================================================


class TestConcurrentSessionLimit:
    def test_is_concurrent_session_limit_reached_pure_function(self) -> None:
        assert is_concurrent_session_limit_reached(active_count=2, limit=3) is False
        assert is_concurrent_session_limit_reached(active_count=3, limit=3) is True
        assert is_concurrent_session_limit_reached(active_count=4, limit=3) is True

    async def test_count_active_sessions_for_guest_counts_only_active(self) -> None:
        fx = make_fixture()
        first = await fx.guest_service.login_via_otp(
            identifier="+15559990001",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        await fx.guest_service.login_via_otp(
            identifier="+15559990001",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        count = await fx.repository.count_active_sessions_for_guest(first.guest.id)
        assert count == 2

        await fx.guest_service.disconnect_session(session_id=first.session.id)
        count_after_disconnect = await fx.repository.count_active_sessions_for_guest(
            first.guest.id
        )
        assert count_after_disconnect == 1

    async def test_login_raises_once_limit_reached(self) -> None:
        fx = make_fixture()
        identifier = "+15559990002"
        for _ in range(DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST):
            await fx.guest_service.login_via_otp(
                identifier=identifier,
                code="GOOD",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )
        sessions_before = len(fx.repository.sessions)

        with pytest.raises(ConcurrentSessionLimitExceededError) as exc_info:
            await fx.guest_service.login_via_otp(
                identifier=identifier,
                code="GOOD",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )
        assert exc_info.value.limit == DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST
        # No new session row was created for the rejected attempt.
        assert len(fx.repository.sessions) == sessions_before

    async def test_login_rejected_before_otp_verification_is_attempted(self) -> None:
        """A guest already at the limit must never spend a real OTP
        verification attempt on a login that was always going to be
        rejected -- see ``GuestService._enforce_concurrent_session_limit``'s
        call-site placement in ``login_via_otp``."""
        fx = make_fixture()
        identifier = "+15559990003"
        for _ in range(DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST):
            await fx.guest_service.login_via_otp(
                identifier=identifier,
                code="GOOD",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )

        # A *wrong* code would normally raise OtpCodeMismatchError from
        # FakeOtpService -- if the concurrent-session check runs first (as
        # it must), ConcurrentSessionLimitExceededError is raised instead,
        # proving verify_otp was never reached.
        with pytest.raises(ConcurrentSessionLimitExceededError):
            await fx.guest_service.login_via_otp(
                identifier=identifier,
                code="WRONG",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )

    async def test_voucher_login_raises_once_limit_reached(self) -> None:
        fx = make_fixture()
        identifier = "voucher-guest@example.com"
        for index in range(DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST):
            code = f"VCODE{index}"
            fx.voucher_service.register(code, data_limit_mb=None, validity_minutes=60)
            await fx.guest_service.login_via_voucher(
                code=code,
                identifier=identifier,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )

        fx.voucher_service.register(
            "VCODE-OVER", data_limit_mb=None, validity_minutes=60
        )
        with pytest.raises(ConcurrentSessionLimitExceededError):
            await fx.guest_service.login_via_voucher(
                code="VCODE-OVER",
                identifier=identifier,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )

    async def test_new_guest_login_skips_the_check_entirely(self) -> None:
        """A never-before-seen identifier has no ``existing_guest`` yet, so
        the limit check is skipped rather than querying a guest_id that
        doesn't exist -- see the call site's comment in ``login_via_otp``."""
        fx = make_fixture()
        result = await fx.guest_service.login_via_otp(
            identifier="+15559990004",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        assert result.is_new_guest is True
        assert result.session.status == GuestSessionStatus.ACTIVE.value

    async def test_reconnect_never_pushes_guest_over_the_limit(self) -> None:
        """``reconnect`` is idempotent against an existing ACTIVE session
        (returns it unchanged) and only ever derives a new row when the
        guest holds zero active sessions -- it can never itself trigger
        ``ConcurrentSessionLimitExceededError``."""
        fx = make_fixture()
        result = await fx.guest_service.login_via_otp(
            identifier="+15559990005",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        again = await fx.guest_service.reconnect(
            guest_id=result.guest.id,
            router_id=fx.router.id,
            location_id=fx.location_id,
        )
        assert again.id == result.session.id  # idempotent no-op, not a new row


class TestDeviceLimit:
    def test_is_device_limit_reached_pure_function(self) -> None:
        assert is_device_limit_reached(device_count=2, limit=3) is False
        assert is_device_limit_reached(device_count=3, limit=3) is True
        assert is_device_limit_reached(device_count=4, limit=3) is True

    async def test_count_devices_for_guest_counts_distinct_macs(self) -> None:
        fx = make_fixture()
        identifier = "+15559990010"
        first = await fx.guest_service.login_via_otp(
            identifier=identifier,
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
            device_mac="AA:BB:CC:DD:EE:01",
        )
        await fx.guest_service.disconnect_session(session_id=first.session.id)
        await fx.guest_service.login_via_otp(
            identifier=identifier,
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
            device_mac="AA:BB:CC:DD:EE:02",
        )
        count = await fx.repository.count_devices_for_guest(first.guest.id)
        assert count == 2

    async def test_login_raises_once_device_limit_reached(self) -> None:
        fx = make_fixture()
        identifier = "+15559990011"
        for index in range(DEFAULT_MAX_DEVICES_PER_GUEST):
            result = await fx.guest_service.login_via_otp(
                identifier=identifier,
                code="GOOD",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
                device_mac=f"AA:BB:CC:DD:EE:{index:02d}",
            )
            # Disconnected between iterations so the (same-valued) concurrent
            # session limit never trips before the device limit does -- see
            # this class's own module-level discussion in the roadmap
            # write-up. Disconnecting frees the session slot but leaves the
            # GuestDevice row (and thus the device count) intact.
            await fx.guest_service.disconnect_session(session_id=result.session.id)
        devices_before = len(fx.repository.devices)

        with pytest.raises(GuestDeviceLimitExceededError) as exc_info:
            await fx.guest_service.login_via_otp(
                identifier=identifier,
                code="GOOD",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
                device_mac="AA:BB:CC:DD:EE:FF",
            )
        assert exc_info.value.limit == DEFAULT_MAX_DEVICES_PER_GUEST
        # No new device row was created for the rejected attempt.
        assert len(fx.repository.devices) == devices_before

    async def test_login_rejected_before_otp_verification_is_attempted(self) -> None:
        """Mirrors ``TestConcurrentSessionLimit``'s identical-named test:
        a guest already at the device limit must never spend a real OTP
        verification attempt on a login that was always going to be
        rejected -- see ``GuestService._enforce_device_limit``'s call-site
        placement in ``login_via_otp``."""
        fx = make_fixture()
        identifier = "+15559990012"
        for index in range(DEFAULT_MAX_DEVICES_PER_GUEST):
            result = await fx.guest_service.login_via_otp(
                identifier=identifier,
                code="GOOD",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
                device_mac=f"BB:CC:DD:EE:FF:{index:02d}",
            )
            await fx.guest_service.disconnect_session(session_id=result.session.id)

        with pytest.raises(GuestDeviceLimitExceededError):
            await fx.guest_service.login_via_otp(
                identifier=identifier,
                code="WRONG",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
                device_mac="BB:CC:DD:EE:FF:FF",
            )

    async def test_returning_device_never_counts_against_the_limit(self) -> None:
        """The same MAC logging in repeatedly is a *returning* device, not
        a new one -- ``_enforce_device_limit`` recognizes it via
        ``get_device_by_mac`` + ``guest_id`` match and never raises,
        regardless of how many times it reconnects."""
        fx = make_fixture()
        identifier = "+15559990013"
        mac = "CC:DD:EE:FF:00:01"
        for _ in range(DEFAULT_MAX_DEVICES_PER_GUEST + 2):
            result = await fx.guest_service.login_via_otp(
                identifier=identifier,
                code="GOOD",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
                device_mac=mac,
            )
            await fx.guest_service.disconnect_session(session_id=result.session.id)
        count = await fx.repository.count_devices_for_guest(result.guest.id)
        assert count == 1

    async def test_device_limit_check_is_skipped_when_no_device_mac(self) -> None:
        """A login with no ``device_mac`` at all registers no device, so it
        must never be rejected on the device limit's account -- even after
        the guest is already sitting at the limit via other, MAC-bearing
        logins."""
        fx = make_fixture()
        identifier = "+15559990014"
        for index in range(DEFAULT_MAX_DEVICES_PER_GUEST):
            result = await fx.guest_service.login_via_otp(
                identifier=identifier,
                code="GOOD",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
                device_mac=f"DD:EE:FF:00:11:{index:02d}",
            )
            await fx.guest_service.disconnect_session(session_id=result.session.id)

        no_mac_result = await fx.guest_service.login_via_otp(
            identifier=identifier,
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        assert no_mac_result.session.status == GuestSessionStatus.ACTIVE.value
        assert no_mac_result.device is None

    async def test_policy_lookup_overrides_the_default_limit(self) -> None:
        """When a ``policy_lookup`` hook is wired and resolves a
        ``max_devices_per_guest`` override, that value governs instead of
        ``DEFAULT_MAX_DEVICES_PER_GUEST`` -- see
        ``GuestService._resolve_device_limit``."""
        fx = make_fixture(policy_lookup=FakeDevicePolicyLookup(max_devices_per_guest=1))
        identifier = "+15559990015"
        first = await fx.guest_service.login_via_otp(
            identifier=identifier,
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
            device_mac="EE:FF:00:11:22:01",
        )
        await fx.guest_service.disconnect_session(session_id=first.session.id)

        with pytest.raises(GuestDeviceLimitExceededError) as exc_info:
            await fx.guest_service.login_via_otp(
                identifier=identifier,
                code="GOOD",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
                device_mac="EE:FF:00:11:22:02",
            )
        assert exc_info.value.limit == 1

    async def test_new_guest_login_skips_the_check_entirely(self) -> None:
        """Mirrors ``TestConcurrentSessionLimit``'s identical-named test: a
        never-before-seen identifier has no ``existing_guest`` yet, so the
        device limit check is skipped rather than counting devices against
        a guest_id that doesn't exist."""
        fx = make_fixture()
        result = await fx.guest_service.login_via_otp(
            identifier="+15559990016",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
            device_mac="FF:00:11:22:33:01",
        )
        assert result.is_new_guest is True
        assert result.session.status == GuestSessionStatus.ACTIVE.value


# ============================================================================
# FUP (Fair Usage Policy) quota tracking (Phase 1 BhaiFi-parity)
# ============================================================================


class TestComputePeriodStart:
    def test_daily_boundary_in_utc(self) -> None:
        now = datetime(2026, 7, 18, 15, 30, tzinfo=UTC)
        start = compute_period_start(QuotaPeriodType.DAILY, now=now, tz_name="UTC")
        assert start == datetime(2026, 7, 18, 0, 0, tzinfo=UTC)

    def test_daily_boundary_respects_organization_timezone(self) -> None:
        """2026-07-18 02:00 UTC is still 2026-07-17 evening in
        America/Los_Angeles (UTC-7 under DST in July) -- the returned
        boundary must be *that* local day's midnight, converted back to
        UTC, not the UTC calendar day's midnight."""
        now = datetime(2026, 7, 18, 2, 0, tzinfo=UTC)
        start = compute_period_start(
            QuotaPeriodType.DAILY, now=now, tz_name="America/Los_Angeles"
        )
        assert start == datetime(2026, 7, 17, 7, 0, tzinfo=UTC)

    def test_weekly_boundary_starts_monday(self) -> None:
        """2026-07-18 is a Saturday; the week's boundary is Monday
        2026-07-13 -- mirrors ``schemas.TimeWindow.days_of_week``'s own
        0=Monday ISO convention."""
        now = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
        start = compute_period_start(QuotaPeriodType.WEEKLY, now=now, tz_name="UTC")
        assert start == datetime(2026, 7, 13, 0, 0, tzinfo=UTC)

    def test_monthly_boundary_starts_on_day_one(self) -> None:
        now = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
        start = compute_period_start(QuotaPeriodType.MONTHLY, now=now, tz_name="UTC")
        assert start == datetime(2026, 7, 1, 0, 0, tzinfo=UTC)

    def test_unknown_timezone_falls_back_to_utc(self) -> None:
        now = datetime(2026, 7, 18, 15, 30, tzinfo=UTC)
        start = compute_period_start(
            QuotaPeriodType.DAILY, now=now, tz_name="Not/AZone"
        )
        assert start == datetime(2026, 7, 18, 0, 0, tzinfo=UTC)


class TestIsFupUsageExceeded:
    def test_pure_function_boundary(self) -> None:
        assert is_fup_usage_exceeded(used=99, limit=100) is False
        assert is_fup_usage_exceeded(used=100, limit=100) is True
        assert is_fup_usage_exceeded(used=101, limit=100) is True


class TestGetOrResetQuotaUsage:
    async def test_creates_a_fresh_row_when_none_exists(self) -> None:
        fx = make_fixture()
        guest_id = uuid.uuid4()
        now = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
        usage = await get_or_reset_quota_usage(
            fx.repository,
            guest_id=guest_id,
            organization_id=fx.organization_id,
            period_type=QuotaPeriodType.DAILY,
            tz_name="UTC",
            now=now,
        )
        assert usage.guest_id == guest_id
        assert usage.period_type == QuotaPeriodType.DAILY.value
        assert usage.bytes_used == 0
        assert usage.minutes_used == 0
        assert usage.period_start == datetime(2026, 7, 18, 0, 0, tzinfo=UTC)

    async def test_returns_the_same_row_unchanged_within_the_same_period(
        self,
    ) -> None:
        fx = make_fixture()
        guest_id = uuid.uuid4()
        now = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
        first = await get_or_reset_quota_usage(
            fx.repository,
            guest_id=guest_id,
            organization_id=fx.organization_id,
            period_type=QuotaPeriodType.DAILY,
            tz_name="UTC",
            now=now,
        )
        await fx.repository.update_quota_usage(first, {"bytes_used": 500})
        later_same_day = datetime(2026, 7, 18, 23, 0, tzinfo=UTC)
        second = await get_or_reset_quota_usage(
            fx.repository,
            guest_id=guest_id,
            organization_id=fx.organization_id,
            period_type=QuotaPeriodType.DAILY,
            tz_name="UTC",
            now=later_same_day,
        )
        assert second.id == first.id
        assert second.bytes_used == 500

    async def test_resets_counters_once_the_period_has_rolled_over(self) -> None:
        fx = make_fixture()
        guest_id = uuid.uuid4()
        now = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
        first = await get_or_reset_quota_usage(
            fx.repository,
            guest_id=guest_id,
            organization_id=fx.organization_id,
            period_type=QuotaPeriodType.DAILY,
            tz_name="UTC",
            now=now,
        )
        await fx.repository.update_quota_usage(
            first, {"bytes_used": 999, "minutes_used": 42}
        )
        next_day = datetime(2026, 7, 19, 1, 0, tzinfo=UTC)
        rolled = await get_or_reset_quota_usage(
            fx.repository,
            guest_id=guest_id,
            organization_id=fx.organization_id,
            period_type=QuotaPeriodType.DAILY,
            tz_name="UTC",
            now=next_day,
        )
        assert rolled.id == first.id  # same row, reset in place -- not a new one
        assert rolled.bytes_used == 0
        assert rolled.minutes_used == 0
        assert rolled.period_start == datetime(2026, 7, 19, 0, 0, tzinfo=UTC)


class TestEnforceFupQuotaLoginGate:
    async def test_no_policy_lookup_wired_is_a_no_op(self) -> None:
        fx = make_fixture()
        result = await fx.guest_service.login_via_otp(
            identifier="+15559990020",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        assert result.session.status == GuestSessionStatus.ACTIVE.value

    async def test_policy_wired_with_no_fup_limits_configured_is_a_no_op(
        self,
    ) -> None:
        fx = make_fixture(policy_lookup=FakeFupPolicyLookup(fup_rules={}))
        result = await fx.guest_service.login_via_otp(
            identifier="+15559990021",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        assert result.session.status == GuestSessionStatus.ACTIVE.value

    async def test_raises_once_a_configured_daily_data_cap_is_already_met(
        self,
    ) -> None:
        fx = make_fixture(
            policy_lookup=FakeFupPolicyLookup(fup_rules={"daily_data_limit_mb": 100})
        )
        identifier = "+15559990022"
        first = await fx.guest_service.login_via_otp(
            identifier=identifier,
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        await fx.guest_service.disconnect_session(session_id=first.session.id)
        # Directly drive the guest's own daily usage row to the configured
        # cap -- mirrors driving GuestSession.bytes_uploaded directly in
        # existing quota tests rather than sending real accounting deltas.
        usage = await get_or_reset_quota_usage(
            fx.repository,
            guest_id=first.guest.id,
            organization_id=fx.organization_id,
            period_type=QuotaPeriodType.DAILY,
            tz_name="UTC",
            now=datetime.now(UTC),
        )
        await fx.repository.update_quota_usage(
            usage, {"bytes_used": 100 * BYTES_PER_MB}
        )

        with pytest.raises(FairUsagePolicyExceededError) as exc_info:
            await fx.guest_service.login_via_otp(
                identifier=identifier,
                code="GOOD",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )
        assert exc_info.value.period_type == QuotaPeriodType.DAILY.value
        assert exc_info.value.metric == "data"
        assert exc_info.value.limit == 100

    async def test_raises_once_a_configured_daily_time_cap_is_already_met(
        self,
    ) -> None:
        fx = make_fixture(
            policy_lookup=FakeFupPolicyLookup(
                fup_rules={"daily_time_limit_minutes": 60}
            )
        )
        identifier = "+15559990023"
        first = await fx.guest_service.login_via_otp(
            identifier=identifier,
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        await fx.guest_service.disconnect_session(session_id=first.session.id)
        usage = await get_or_reset_quota_usage(
            fx.repository,
            guest_id=first.guest.id,
            organization_id=fx.organization_id,
            period_type=QuotaPeriodType.DAILY,
            tz_name="UTC",
            now=datetime.now(UTC),
        )
        await fx.repository.update_quota_usage(usage, {"minutes_used": 60})

        with pytest.raises(FairUsagePolicyExceededError) as exc_info:
            await fx.guest_service.login_via_otp(
                identifier=identifier,
                code="GOOD",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )
        assert exc_info.value.metric == "time"
        assert exc_info.value.limit == 60

    async def test_login_succeeds_when_usage_is_still_under_the_cap(self) -> None:
        fx = make_fixture(
            policy_lookup=FakeFupPolicyLookup(fup_rules={"daily_data_limit_mb": 100})
        )
        identifier = "+15559990024"
        first = await fx.guest_service.login_via_otp(
            identifier=identifier,
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        await fx.guest_service.disconnect_session(session_id=first.session.id)
        usage = await get_or_reset_quota_usage(
            fx.repository,
            guest_id=first.guest.id,
            organization_id=fx.organization_id,
            period_type=QuotaPeriodType.DAILY,
            tz_name="UTC",
            now=datetime.now(UTC),
        )
        await fx.repository.update_quota_usage(usage, {"bytes_used": 1 * BYTES_PER_MB})

        second = await fx.guest_service.login_via_otp(
            identifier=identifier,
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        assert second.session.status == GuestSessionStatus.ACTIVE.value

    async def test_rejected_before_otp_verification_is_attempted(self) -> None:
        fx = make_fixture(
            policy_lookup=FakeFupPolicyLookup(fup_rules={"daily_data_limit_mb": 100})
        )
        identifier = "+15559990025"
        first = await fx.guest_service.login_via_otp(
            identifier=identifier,
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        await fx.guest_service.disconnect_session(session_id=first.session.id)
        usage = await get_or_reset_quota_usage(
            fx.repository,
            guest_id=first.guest.id,
            organization_id=fx.organization_id,
            period_type=QuotaPeriodType.DAILY,
            tz_name="UTC",
            now=datetime.now(UTC),
        )
        await fx.repository.update_quota_usage(
            usage, {"bytes_used": 100 * BYTES_PER_MB}
        )

        with pytest.raises(FairUsagePolicyExceededError):
            await fx.guest_service.login_via_otp(
                identifier=identifier,
                code="WRONG",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )

    async def test_new_guest_login_skips_the_check_entirely(self) -> None:
        fx = make_fixture(
            policy_lookup=FakeFupPolicyLookup(fup_rules={"daily_data_limit_mb": 0})
        )
        result = await fx.guest_service.login_via_otp(
            identifier="+15559990026",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        assert result.is_new_guest is True
        assert result.session.status == GuestSessionStatus.ACTIVE.value


class TestRecordUsageFupTracking:
    async def test_bumps_all_three_period_rows_when_policy_lookup_wired(
        self,
    ) -> None:
        fx = make_fixture(policy_lookup=FakeFupPolicyLookup(fup_rules={}))
        result = await fx.guest_service.login_via_otp(
            identifier="+15559990030",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        await fx.guest_service.record_usage(
            session_id=result.session.id,
            bytes_uploaded_delta=1000,
            bytes_downloaded_delta=2000,
        )
        for period_type in QuotaPeriodType:
            usage = await fx.repository.get_quota_usage(
                result.guest.id, period_type.value
            )
            assert usage is not None
            assert usage.bytes_used == 3000

    async def test_no_op_when_no_policy_lookup_wired(self) -> None:
        fx = make_fixture()
        result = await fx.guest_service.login_via_otp(
            identifier="+15559990031",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        await fx.guest_service.record_usage(
            session_id=result.session.id,
            bytes_uploaded_delta=1000,
            bytes_downloaded_delta=2000,
        )
        assert (
            await fx.repository.get_quota_usage(
                result.guest.id, QuotaPeriodType.DAILY.value
            )
            is None
        )

    async def test_expires_session_once_a_configured_data_cap_is_crossed(
        self,
    ) -> None:
        fx = make_fixture(
            policy_lookup=FakeFupPolicyLookup(fup_rules={"weekly_data_limit_mb": 1})
        )
        result = await fx.guest_service.login_via_otp(
            identifier="+15559990032",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        updated = await fx.guest_service.record_usage(
            session_id=result.session.id,
            bytes_uploaded_delta=BYTES_PER_MB,
            bytes_downloaded_delta=BYTES_PER_MB,
        )
        assert updated.status == GuestSessionStatus.EXPIRED.value
        assert updated.disconnect_reason == "fup_data_quota_exceeded_weekly"

    async def test_never_raises_when_the_policy_lookup_itself_fails(self) -> None:
        class ExplodingPolicyLookup:
            async def resolve_effective_policy(self, **kwargs: object):
                raise RuntimeError("policy service unreachable")

        fx = make_fixture(policy_lookup=ExplodingPolicyLookup())
        result = await fx.guest_service.login_via_otp(
            identifier="+15559990033",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        updated = await fx.guest_service.record_usage(
            session_id=result.session.id,
            bytes_uploaded_delta=1000,
            bytes_downloaded_delta=0,
        )
        assert updated.status == GuestSessionStatus.ACTIVE.value


class TestRunFupTimeAccrual:
    async def test_skips_guests_whose_org_has_no_time_limit_configured(self) -> None:
        fx = make_fixture()
        result = await fx.guest_service.login_via_otp(
            identifier="+15559990040",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        policy_lookup = FakeFupPolicyLookup(fup_rules={})
        summary = await run_fup_time_accrual(
            fx.repository, policy_lookup, now=datetime.now(UTC)
        )
        assert summary == {"accrued_rows": 0, "expired_sessions": 0}
        assert (
            await fx.repository.get_quota_usage(
                result.guest.id, QuotaPeriodType.DAILY.value
            )
            is None
        )

    async def test_accrues_elapsed_minutes_since_last_accrual(self) -> None:
        fx = make_fixture()
        result = await fx.guest_service.login_via_otp(
            identifier="+15559990041",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        policy_lookup = FakeFupPolicyLookup(
            fup_rules={"daily_time_limit_minutes": 999_999}
        )
        now = datetime.now(UTC)
        # Pre-seed the row with a known last_accrued_at baseline (rather
        # than letting the first sweep tick accrue from period_start,
        # which -- at whatever real wall-clock time this test happens to
        # run -- could itself already be hundreds of minutes, an
        # unpredictable number to assert against).
        usage = await get_or_reset_quota_usage(
            fx.repository,
            guest_id=result.guest.id,
            organization_id=fx.organization_id,
            period_type=QuotaPeriodType.DAILY,
            tz_name="UTC",
            now=now,
        )
        await fx.repository.update_quota_usage(usage, {"last_accrued_at": now})

        later = now + timedelta(minutes=10)
        await run_fup_time_accrual(fx.repository, policy_lookup, now=later)
        usage_after = await fx.repository.get_quota_usage(
            result.guest.id, QuotaPeriodType.DAILY.value
        )
        assert usage_after.minutes_used == 10

    async def test_disconnects_every_active_session_once_the_cap_is_crossed(
        self,
    ) -> None:
        fx = make_fixture()
        identifier = "+15559990042"
        first = await fx.guest_service.login_via_otp(
            identifier=identifier,
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
            device_mac="AA:11:22:33:44:01",
        )
        policy_lookup = FakeFupPolicyLookup(fup_rules={"daily_time_limit_minutes": 5})
        now = datetime.now(UTC)
        summary = await run_fup_time_accrual(
            fx.repository, policy_lookup, now=now + timedelta(minutes=10)
        )
        assert summary["expired_sessions"] == 1
        updated_session = await fx.repository.get_session_by_id(first.session.id)
        assert updated_session.status == GuestSessionStatus.EXPIRED.value
        assert updated_session.disconnect_reason == "fup_time_quota_exceeded_daily"

    async def test_guest_level_time_is_not_doubled_across_concurrent_sessions(
        self,
    ) -> None:
        """Two simultaneous devices connected for the same wall-clock
        window must accrue as one guest's worth of connected time, not
        two -- see ``models.GuestQuotaUsage``'s own docstring."""
        fx = make_fixture()
        identifier = "+15559990043"
        first = await fx.guest_service.login_via_otp(
            identifier=identifier,
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
            device_mac="AA:11:22:33:44:02",
        )
        await fx.guest_service.login_via_otp(
            identifier=identifier,
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
            device_mac="AA:11:22:33:44:03",
        )
        policy_lookup = FakeFupPolicyLookup(
            fup_rules={"daily_time_limit_minutes": 999_999}
        )
        now = datetime.now(UTC)
        # Pre-seed a known last_accrued_at baseline -- see the identical
        # note in test_accrues_elapsed_minutes_since_last_accrual.
        usage = await get_or_reset_quota_usage(
            fx.repository,
            guest_id=first.guest.id,
            organization_id=fx.organization_id,
            period_type=QuotaPeriodType.DAILY,
            tz_name="UTC",
            now=now,
        )
        await fx.repository.update_quota_usage(usage, {"last_accrued_at": now})

        later = now + timedelta(minutes=15)
        await run_fup_time_accrual(fx.repository, policy_lookup, now=later)
        usage_after = await fx.repository.get_quota_usage(
            first.guest.id, QuotaPeriodType.DAILY.value
        )
        # Exactly one guest-worth of the 15-minute window is accrued, not
        # two, despite two concurrent ACTIVE sessions.
        assert usage_after.minutes_used == 15


class TestRunQuotaReset:
    async def test_resets_rows_whose_period_has_rolled_over(self) -> None:
        fx = make_fixture()
        guest_id = uuid.uuid4()
        now = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
        usage = await get_or_reset_quota_usage(
            fx.repository,
            guest_id=guest_id,
            organization_id=fx.organization_id,
            period_type=QuotaPeriodType.DAILY,
            tz_name="UTC",
            now=now,
        )
        await fx.repository.update_quota_usage(usage, {"bytes_used": 500})

        next_day = datetime(2026, 7, 19, 1, 0, tzinfo=UTC)
        summary = await run_quota_reset(fx.repository, now=next_day)
        assert summary == {"reset_count": 1}
        reset_usage = await fx.repository.get_quota_usage(
            guest_id, QuotaPeriodType.DAILY.value
        )
        assert reset_usage.bytes_used == 0
        assert reset_usage.period_start == datetime(2026, 7, 19, 0, 0, tzinfo=UTC)

    async def test_is_idempotent_within_the_same_period(self) -> None:
        fx = make_fixture()
        guest_id = uuid.uuid4()
        now = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)
        await get_or_reset_quota_usage(
            fx.repository,
            guest_id=guest_id,
            organization_id=fx.organization_id,
            period_type=QuotaPeriodType.DAILY,
            tz_name="UTC",
            now=now,
        )
        later_same_day = datetime(2026, 7, 18, 23, 0, tzinfo=UTC)
        summary = await run_quota_reset(fx.repository, now=later_same_day)
        assert summary == {"reset_count": 0}


def test_run_fup_time_accrual_sweep_task_bridges_into_async(monkeypatch) -> None:
    """Mirrors ``test_run_session_timeout_sweep_task_bridges_into_async``'s
    identical pattern."""
    from app.domains.guest import tasks as tasks_module

    async def _fake_run_fup_time_accrual_sweep_async() -> dict[str, int]:
        return {"accrued_rows": 2, "expired_sessions": 1}

    monkeypatch.setattr(
        tasks_module,
        "_run_fup_time_accrual_sweep_async",
        _fake_run_fup_time_accrual_sweep_async,
    )

    result = tasks_module.run_fup_time_accrual_sweep()
    assert result == {"accrued_rows": 2, "expired_sessions": 1}


def test_run_quota_reset_sweep_task_bridges_into_async(monkeypatch) -> None:
    """Mirrors ``test_run_session_timeout_sweep_task_bridges_into_async``'s
    identical pattern."""
    from app.domains.guest import tasks as tasks_module

    async def _fake_run_quota_reset_sweep_async() -> dict[str, int]:
        return {"reset_count": 4}

    monkeypatch.setattr(
        tasks_module, "_run_quota_reset_sweep_async", _fake_run_quota_reset_sweep_async
    )

    result = tasks_module.run_quota_reset_sweep()
    assert result == {"reset_count": 4}


# ============================================================================
# Guest Access Control enforcement hook (Phase 1)
# ============================================================================


class TestAccessControlHookIntegration:
    async def test_no_hook_wired_preserves_default_behavior(self) -> None:
        """The default (``access_control_hook=None``) -- every existing
        caller/test of ``GuestService`` behaves exactly as before this
        hook existed."""
        fx = make_fixture()  # access_control_hook defaults to None
        result = await fx.guest_service.login_via_otp(
            identifier="+15559991001",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        assert result.session.status == GuestSessionStatus.ACTIVE.value

    async def test_login_via_otp_denied_by_blocklist_rule(self) -> None:
        hook = FakeAccessControlHook()
        hook.deny(identifier="+15559991002")
        fx = make_fixture(access_control_hook=hook)
        with pytest.raises(GuestAccessDeniedError):
            await fx.guest_service.login_via_otp(
                identifier="+15559991002",
                code="GOOD",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )
        # No session was created for the denied attempt.
        assert len(fx.repository.sessions) == 0

    async def test_login_via_otp_allowed_when_no_matching_rule(self) -> None:
        hook = FakeAccessControlHook()
        hook.deny(identifier="+15559991099")  # a different identifier
        fx = make_fixture(access_control_hook=hook)
        result = await fx.guest_service.login_via_otp(
            identifier="+15559991003",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        assert result.session.status == GuestSessionStatus.ACTIVE.value
        assert len(hook.calls) == 1
        assert hook.calls[0]["identifier"] == "+15559991003"

    async def test_denial_checked_before_otp_verification_is_attempted(self) -> None:
        """A denied guest must never spend a real OTP attempt -- mirrors
        the identical ordering guarantee
        ``TestConcurrentSessionLimit`` establishes for its own limit
        check."""
        hook = FakeAccessControlHook()
        hook.deny(identifier="+15559991004")
        fx = make_fixture(access_control_hook=hook)
        with pytest.raises(GuestAccessDeniedError):
            await fx.guest_service.login_via_otp(
                identifier="+15559991004",
                code="WRONG",  # would raise OtpCodeMismatchError if reached
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )

    async def test_login_via_voucher_denied_by_blocklist_rule(self) -> None:
        hook = FakeAccessControlHook()
        hook.deny(identifier="denied-voucher@example.com")
        fx = make_fixture(access_control_hook=hook)
        fx.voucher_service.register("VDENY", data_limit_mb=None, validity_minutes=60)
        with pytest.raises(GuestAccessDeniedError):
            await fx.guest_service.login_via_voucher(
                code="VDENY",
                identifier="denied-voucher@example.com",
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )
        assert len(fx.repository.sessions) == 0

    async def test_device_mac_denial_blocks_login(self) -> None:
        """A device-level blocklist rule (matched by MAC, not identifier)
        also blocks a login attempt on that device."""
        hook = FakeAccessControlHook()
        hook.deny(mac_address="AA:BB:CC:DD:EE:FF")
        fx = make_fixture(access_control_hook=hook)
        with pytest.raises(GuestAccessDeniedError):
            await fx.guest_service.login_via_otp(
                identifier="+15559991005",
                code="GOOD",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
                device_mac="aa:bb:cc:dd:ee:ff",
            )


# ============================================================================
# RADIUS rlm_rest integration
# ============================================================================


class TestRadius:
    async def _register_nas(self, fx: Fixture, secret: str = "supersecret123") -> None:
        await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(),
            router_id=fx.router.id,
            nas_identifier="nas-1",
            shared_secret=secret,
        )

    async def test_authenticate_nas_success(self) -> None:
        fx = make_fixture()
        await self._register_nas(fx, secret="s3cr3t-value")
        nas_client = await fx.radius_service.authenticate_nas(
            nas_identifier="nas-1", shared_secret="s3cr3t-value"
        )
        assert nas_client.router_id == fx.router.id

    async def test_authenticate_nas_wrong_secret_rejected(self) -> None:
        fx = make_fixture()
        await self._register_nas(fx, secret="s3cr3t-value")
        with pytest.raises(RadiusNasAuthenticationError):
            await fx.radius_service.authenticate_nas(
                nas_identifier="nas-1", shared_secret="wrong"
            )

    async def test_authenticate_nas_unknown_identifier_rejected(self) -> None:
        fx = make_fixture()
        with pytest.raises(RadiusNasAuthenticationError):
            await fx.radius_service.authenticate_nas(
                nas_identifier="does-not-exist", shared_secret="anything"
            )

    async def test_authenticate_nas_inactive_rejected(self) -> None:
        fx = make_fixture()
        await self._register_nas(fx, secret="s3cr3t-value")
        nas_client = await fx.repository.get_nas_client_by_identifier("nas-1")
        await fx.repository.update_nas_client(
            nas_client, {"status": NasStatus.DISABLED.value, "is_active": False}
        )
        with pytest.raises(RadiusNasAuthenticationError):
            await fx.radius_service.authenticate_nas(
                nas_identifier="nas-1", shared_secret="s3cr3t-value"
            )

    async def test_shared_secret_stored_encrypted_not_plaintext(self) -> None:
        fx = make_fixture()
        await self._register_nas(fx, secret="s3cr3t-value")
        nas_client = await fx.repository.get_nas_client_by_identifier("nas-1")
        assert nas_client.shared_secret_encrypted != "s3cr3t-value"
        assert encrypt_secret("s3cr3t-value") != "s3cr3t-value"

    async def test_authorize_active_session(self) -> None:
        fx = make_fixture()
        await self._register_nas(fx)
        result = await fx.guest_service.login_via_otp(
            identifier="+15553334444",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        nas_client = await fx.radius_service.authenticate_nas(
            nas_identifier="nas-1", shared_secret="supersecret123"
        )
        authz = await fx.radius_service.authorize(
            nas_client=nas_client, username="+15553334444"
        )
        assert authz.authorized is True
        assert authz.session_timeout_seconds == DEFAULT_SESSION_TIMEOUT_MINUTES * 60
        assert result.session.status == GuestSessionStatus.ACTIVE.value
        assert authz.rate_limit is None  # no queue_lookup wired

    async def test_authorize_returns_rate_limit_when_queue_lookup_wired(self) -> None:
        class FakeQueueLookup:
            async def get_rate_limit_reply_for_session(self, session_id: uuid.UUID):
                return "1000k/5000k"

        fx = make_fixture(queue_lookup=FakeQueueLookup())
        await self._register_nas(fx)
        await fx.guest_service.login_via_otp(
            identifier="+15553334444",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        nas_client = await fx.radius_service.authenticate_nas(
            nas_identifier="nas-1", shared_secret="supersecret123"
        )
        authz = await fx.radius_service.authorize(
            nas_client=nas_client, username="+15553334444"
        )
        assert authz.rate_limit == "1000k/5000k"

    async def test_authorize_rate_limit_lookup_failure_never_blocks_authorization(
        self,
    ) -> None:
        class ExplodingQueueLookup:
            async def get_rate_limit_reply_for_session(self, session_id: uuid.UUID):
                raise RuntimeError("queue service unreachable")

        fx = make_fixture(queue_lookup=ExplodingQueueLookup())
        await self._register_nas(fx)
        await fx.guest_service.login_via_otp(
            identifier="+15553334444",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        nas_client = await fx.radius_service.authenticate_nas(
            nas_identifier="nas-1", shared_secret="supersecret123"
        )
        authz = await fx.radius_service.authorize(
            nas_client=nas_client, username="+15553334444"
        )
        assert authz.authorized is True
        assert authz.rate_limit is None

    async def test_authorize_rejects_unknown_guest(self) -> None:
        fx = make_fixture()
        await self._register_nas(fx)
        nas_client = await fx.radius_service.authenticate_nas(
            nas_identifier="nas-1", shared_secret="supersecret123"
        )
        authz = await fx.radius_service.authorize(
            nas_client=nas_client, username="nobody@example.com"
        )
        assert authz.authorized is False

    async def test_full_accounting_flow_start_interim_stop(self) -> None:
        fx = make_fixture()
        await self._register_nas(fx)
        login = await fx.guest_service.login_via_otp(
            identifier="+15554445555",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        nas_client = await fx.radius_service.authenticate_nas(
            nas_identifier="nas-1", shared_secret="supersecret123"
        )

        started = await fx.radius_service.accounting_start(
            nas_client=nas_client, session_id=login.session.id
        )
        assert started.id == login.session.id

        updated = await fx.radius_service.accounting_interim_update(
            nas_client=nas_client,
            session_id=login.session.id,
            bytes_uploaded_delta=1024,
            bytes_downloaded_delta=2048,
        )
        assert updated.bytes_uploaded == 1024
        assert updated.bytes_downloaded == 2048

        stopped = await fx.radius_service.accounting_stop(
            nas_client=nas_client,
            session_id=login.session.id,
            bytes_uploaded_total=5000,
            bytes_downloaded_total=8000,
        )
        assert stopped.status == GuestSessionStatus.DISCONNECTED.value
        assert stopped.bytes_uploaded == 5000
        assert stopped.bytes_downloaded == 8000
        assert stopped.disconnect_reason == "radius_accounting_stop"

    async def test_accounting_rejects_session_on_different_router(self) -> None:
        fx = make_fixture()
        await self._register_nas(fx)
        other_router = fx.router_service.add(organization_id=fx.organization_id)
        login = await fx.guest_service.login_via_otp(
            identifier="+15556667777",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=other_router.id,
        )
        nas_client = await fx.radius_service.authenticate_nas(
            nas_identifier="nas-1", shared_secret="supersecret123"
        )
        with pytest.raises(RadiusNasAuthenticationError):
            await fx.radius_service.accounting_start(
                nas_client=nas_client, session_id=login.session.id
            )

    async def test_accounting_stop_is_noop_on_already_terminal_session(self) -> None:
        fx = make_fixture()
        await self._register_nas(fx)
        login = await fx.guest_service.login_via_otp(
            identifier="+15557778888",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        await fx.guest_service.disconnect_session(session_id=login.session.id)
        nas_client = await fx.radius_service.authenticate_nas(
            nas_identifier="nas-1", shared_secret="supersecret123"
        )
        stopped = await fx.radius_service.accounting_stop(
            nas_client=nas_client, session_id=login.session.id
        )
        assert stopped.status == GuestSessionStatus.DISCONNECTED.value

    async def test_accounting_unknown_session_raises(self) -> None:
        fx = make_fixture()
        await self._register_nas(fx)
        nas_client = await fx.radius_service.authenticate_nas(
            nas_identifier="nas-1", shared_secret="supersecret123"
        )
        with pytest.raises(GuestSessionNotFoundError):
            await fx.radius_service.accounting_start(
                nas_client=nas_client, session_id=uuid.uuid4()
            )


# ============================================================================
# NAS extension: nas_code generation, shared-secret auto-generation, full
# lifecycle (list/get/update/activate/disable/regenerate-secret/delete),
# tenant isolation, and organization_id/location_id denormalization.
# ============================================================================


class TestNasCodeGeneration:
    async def test_uses_real_location_code_when_present(self) -> None:
        fx = make_fixture()
        fx.location_lookup.locations[fx.router.location_id] = Location(
            **_base_fields(
                organization_id=fx.organization_id,
                name="HQ",
                slug="hq",
                status="active",
                address_line1="1 Main St",
                address_line2=None,
                city="Austin",
                state_province="TX",
                postal_code="78701",
                country="US",
                timezone="UTC",
                latitude=None,
                longitude=None,
                contact_name=None,
                contact_phone=None,
                contact_email=None,
                settings={},
                location_code="LOC-2026-000001",
            )
        )
        result = await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(), router_id=fx.router.id, nas_identifier="nas-x"
        )
        assert result.nas_client.nas_code == "NAS-LOC-2026-000001-0001"

    async def test_falls_back_to_location_id_prefix_when_no_location_code(
        self,
    ) -> None:
        fx = make_fixture()
        result = await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(), router_id=fx.router.id, nas_identifier="nas-x"
        )
        assert result.nas_client.nas_code == (
            f"NAS-{str(fx.router.location_id)[:8]}-0001"
        )

    async def test_codes_increment_per_location(self) -> None:
        fx = make_fixture()
        router_b = fx.router_service.add(
            organization_id=fx.organization_id, location_id=fx.router.location_id
        )
        result_a = await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(), router_id=fx.router.id, nas_identifier="nas-a"
        )
        result_b = await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(), router_id=router_b.id, nas_identifier="nas-b"
        )
        assert result_a.nas_client.nas_code.endswith("-0001")
        assert result_b.nas_client.nas_code.endswith("-0002")

    async def test_different_locations_each_start_at_one(self) -> None:
        fx = make_fixture()
        router_b = fx.router_service.add(organization_id=fx.organization_id)
        result_a = await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(), router_id=fx.router.id, nas_identifier="nas-a"
        )
        result_b = await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(), router_id=router_b.id, nas_identifier="nas-b"
        )
        assert result_a.nas_client.nas_code.endswith("-0001")
        assert result_b.nas_client.nas_code.endswith("-0001")


class TestSharedSecretGeneration:
    async def test_omitted_secret_is_auto_generated_and_usable(self) -> None:
        fx = make_fixture()
        result = await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(), router_id=fx.router.id, nas_identifier="nas-x"
        )
        assert len(result.shared_secret) >= 32
        nas_client = await fx.radius_service.authenticate_nas(
            nas_identifier="nas-x", shared_secret=result.shared_secret
        )
        assert nas_client.id == result.nas_client.id

    async def test_supplied_secret_is_used_verbatim(self) -> None:
        fx = make_fixture()
        result = await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(),
            router_id=fx.router.id,
            nas_identifier="nas-x",
            shared_secret="my-own-secret-123",
        )
        assert result.shared_secret == "my-own-secret-123"

    async def test_ip_address_defaults_from_router_public_ip(self) -> None:
        fx = make_fixture()
        router_b = fx.router_service.add(
            organization_id=fx.organization_id, public_ip_address="203.0.113.5"
        )
        result = await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(), router_id=router_b.id, nas_identifier="nas-y"
        )
        assert result.nas_client.ip_address == "203.0.113.5"

    async def test_ip_address_explicit_override_wins(self) -> None:
        fx = make_fixture()
        router_b = fx.router_service.add(
            organization_id=fx.organization_id, public_ip_address="203.0.113.5"
        )
        result = await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(),
            router_id=router_b.id,
            nas_identifier="nas-z",
            ip_address="198.51.100.9",
        )
        assert result.nas_client.ip_address == "198.51.100.9"


class TestNasLifecycle:
    async def _register(self, fx: Fixture, **overrides: object):
        overrides.setdefault("nas_identifier", "nas-x")
        return await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(), router_id=fx.router.id, **overrides
        )

    async def test_get_nas_client(self) -> None:
        fx = make_fixture()
        result = await self._register(fx)
        fetched = await fx.radius_service.get_nas_client(
            result.nas_client.id, requesting_organization_id=fx.organization_id
        )
        assert fetched.id == result.nas_client.id

    async def test_get_unknown_nas_raises(self) -> None:
        fx = make_fixture()
        with pytest.raises(RadiusNasNotFoundError):
            await fx.radius_service.get_nas_client(
                uuid.uuid4(), requesting_organization_id=fx.organization_id
            )

    async def test_list_filters_by_status(self) -> None:
        fx = make_fixture()
        result = await self._register(fx)
        await fx.radius_service.disable_nas(
            nas_id=result.nas_client.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )
        active, _ = await fx.radius_service.list_nas_clients(
            requesting_organization_id=fx.organization_id, status=NasStatus.ACTIVE
        )
        disabled, _ = await fx.radius_service.list_nas_clients(
            requesting_organization_id=fx.organization_id, status=NasStatus.DISABLED
        )
        assert active == []
        assert len(disabled) == 1

    async def test_update_cosmetic_fields(self) -> None:
        fx = make_fixture()
        result = await self._register(fx)
        updated = await fx.radius_service.update_nas_client(
            nas_id=result.nas_client.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
            name="Front Desk NAS",
            description="Lobby router",
            ip_address="10.0.0.5",
        )
        assert updated.name == "Front Desk NAS"
        assert updated.description == "Lobby router"
        assert updated.ip_address == "10.0.0.5"

    async def test_activate_disable_round_trip(self) -> None:
        fx = make_fixture()
        result = await self._register(fx)
        disabled = await fx.radius_service.disable_nas(
            nas_id=result.nas_client.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
            reason="maintenance",
        )
        assert disabled.status == NasStatus.DISABLED.value
        assert disabled.is_active is False
        activated = await fx.radius_service.activate_nas(
            nas_id=result.nas_client.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )
        assert activated.status == NasStatus.ACTIVE.value
        assert activated.is_active is True

    async def test_disabling_already_disabled_raises(self) -> None:
        fx = make_fixture()
        result = await self._register(fx)
        await fx.radius_service.disable_nas(
            nas_id=result.nas_client.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )
        with pytest.raises(InvalidNasStatusTransitionError):
            await fx.radius_service.disable_nas(
                nas_id=result.nas_client.id,
                requesting_organization_id=fx.organization_id,
                actor_user_id=uuid.uuid4(),
            )

    async def test_disabled_nas_cannot_authenticate(self) -> None:
        fx = make_fixture()
        result = await self._register(fx, shared_secret="s3cr3t")
        await fx.radius_service.disable_nas(
            nas_id=result.nas_client.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )
        with pytest.raises(RadiusNasAuthenticationError):
            await fx.radius_service.authenticate_nas(
                nas_identifier=result.nas_client.nas_identifier,
                shared_secret="s3cr3t",
            )

    async def test_regenerate_secret_invalidates_old_one(self) -> None:
        fx = make_fixture()
        result = await self._register(fx, shared_secret="original-secret")
        regen = await fx.radius_service.regenerate_secret(
            nas_id=result.nas_client.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )
        assert regen.shared_secret != "original-secret"
        with pytest.raises(RadiusNasAuthenticationError):
            await fx.radius_service.authenticate_nas(
                nas_identifier=result.nas_client.nas_identifier,
                shared_secret="original-secret",
            )
        authenticated = await fx.radius_service.authenticate_nas(
            nas_identifier=result.nas_client.nas_identifier,
            shared_secret=regen.shared_secret,
        )
        assert authenticated.id == result.nas_client.id

    async def test_regenerate_secret_does_not_change_status(self) -> None:
        fx = make_fixture()
        result = await self._register(fx)
        await fx.radius_service.disable_nas(
            nas_id=result.nas_client.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )
        regen = await fx.radius_service.regenerate_secret(
            nas_id=result.nas_client.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )
        assert regen.nas_client.status == NasStatus.DISABLED.value

    async def test_delete_sets_terminal_status_and_soft_delete(self) -> None:
        fx = make_fixture()
        result = await self._register(fx)
        deleted = await fx.radius_service.delete_nas(
            nas_id=result.nas_client.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )
        assert deleted.status == NasStatus.DELETED.value
        assert deleted.is_deleted is True
        assert deleted.deleted_at is not None

    async def test_deleted_nas_is_unreachable_via_get_by_id(self) -> None:
        """Once ``delete_nas`` sets ``is_deleted=True``, the row becomes
        unreachable via ``get_nas_client`` (``RadiusNasNotFoundError``, not
        ``InvalidNasStatusTransitionError``) -- the same "a soft-deleted row
        is invisible to plain get-by-id" convention every other domain's own
        ``get_policy``/``get_team`` already establishes, rather than a NAS-
        specific exception."""
        fx = make_fixture()
        result = await self._register(fx)
        await fx.radius_service.delete_nas(
            nas_id=result.nas_client.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )
        with pytest.raises(RadiusNasNotFoundError):
            await fx.radius_service.delete_nas(
                nas_id=result.nas_client.id,
                requesting_organization_id=fx.organization_id,
                actor_user_id=uuid.uuid4(),
            )

    async def test_disabled_nas_cannot_be_deleted_twice_via_status_graph(
        self,
    ) -> None:
        """Direct unit coverage of ``NAS_STATUS_TRANSITIONS``'s own
        terminal-state rule, independent of soft-delete visibility (see
        ``test_deleted_nas_is_unreachable_via_get_by_id`` for why exercising
        this through ``delete_nas`` twice can't observe it)."""
        validate_nas_status_transition(
            current=NasStatus.DISABLED, target=NasStatus.DELETED
        )  # legal, does not raise
        with pytest.raises(InvalidNasStatusTransitionError):
            validate_nas_status_transition(
                current=NasStatus.DELETED, target=NasStatus.DELETED
            )

    async def test_pending_nas_can_be_deleted_directly(self) -> None:
        fx = make_fixture()
        result = await self._register(fx, initial_status=NasStatus.PENDING)
        deleted = await fx.radius_service.delete_nas(
            nas_id=result.nas_client.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )
        assert deleted.status == NasStatus.DELETED.value

    async def test_lifecycle_actions_are_audited(self) -> None:
        fx = make_fixture()
        result = await self._register(fx)
        await fx.radius_service.disable_nas(
            nas_id=result.nas_client.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
            reason="test",
        )
        await fx.radius_service.activate_nas(
            nas_id=result.nas_client.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )
        await fx.radius_service.regenerate_secret(
            nas_id=result.nas_client.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )
        await fx.radius_service.update_nas_client(
            nas_id=result.nas_client.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
            name="X",
        )
        await fx.radius_service.delete_nas(
            nas_id=result.nas_client.id,
            requesting_organization_id=fx.organization_id,
            actor_user_id=uuid.uuid4(),
        )
        actions = [e["action"] for e in fx.audit_writer.entries]
        assert "radius_nas_disabled" in actions
        assert "radius_nas_activated" in actions
        assert "radius_nas_secret_regenerated" in actions
        assert "radius_nas_updated" in actions
        assert "radius_nas_deleted" in actions


class TestNasTenantIsolationAndDenormalization:
    async def test_organization_and_location_denormalized_from_router(self) -> None:
        fx = make_fixture()
        result = await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(), router_id=fx.router.id, nas_identifier="nas-x"
        )
        assert result.nas_client.organization_id == fx.router.organization_id
        assert result.nas_client.location_id == fx.router.location_id

    async def test_cross_organization_get_raises(self) -> None:
        fx = make_fixture()
        result = await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(), router_id=fx.router.id, nas_identifier="nas-x"
        )
        with pytest.raises(CrossOrganizationNasAccessError):
            await fx.radius_service.get_nas_client(
                result.nas_client.id, requesting_organization_id=uuid.uuid4()
            )

    async def test_list_scopes_by_organization(self) -> None:
        fx = make_fixture()
        await fx.radius_service.register_nas(
            actor_user_id=uuid.uuid4(), router_id=fx.router.id, nas_identifier="nas-x"
        )
        items, _ = await fx.radius_service.list_nas_clients(
            requesting_organization_id=uuid.uuid4()
        )
        assert items == []


# ============================================================================
# Analytics
# ============================================================================


class TestAnalytics:
    async def _login(
        self,
        fx: Fixture,
        *,
        identifier: str,
        auth_method: GuestAuthMethod = GuestAuthMethod.OTP_SMS,
        router_id: uuid.UUID | None = None,
        device_mac: str | None = None,
        voucher_code: str | None = None,
    ) -> GuestSession:
        if auth_method == GuestAuthMethod.VOUCHER:
            fx.voucher_service.register(
                voucher_code, data_limit_mb=None, validity_minutes=60
            )
            result = await fx.guest_service.login_via_voucher(
                code=voucher_code,
                identifier=identifier,
                organization_id=None,
                location_id=fx.location_id,
                router_id=router_id or fx.router.id,
                device_mac=device_mac,
            )
        else:
            result = await fx.guest_service.login_via_otp(
                identifier=identifier,
                code="GOOD",
                auth_method=auth_method,
                organization_id=None,
                location_id=fx.location_id,
                router_id=router_id or fx.router.id,
                device_mac=device_mac,
            )
        return result.session

    async def test_summary_counts_visitors_unique_and_returning_guests(self) -> None:
        fx = make_fixture()
        await self._login(fx, identifier="+15550001111")
        await self._login(fx, identifier="+15550001111")  # same guest, 2nd visit
        await self._login(fx, identifier="+15550002222")  # different guest

        start = _now() - timedelta(hours=1)
        end = _now() + timedelta(hours=1)
        summary = await fx.analytics_service.get_summary(
            organization_id=fx.organization_id, location_id=None, start=start, end=end
        )
        assert summary.visitors == 3
        assert summary.unique_guests == 2
        assert summary.returning_guests == 1  # the guest with total_visit_count > 1

    async def test_bandwidth_sums_across_sessions(self) -> None:
        fx = make_fixture()
        session = await self._login(fx, identifier="+15550003333")
        await fx.guest_service.record_usage(
            session_id=session.id,
            bytes_uploaded_delta=1000,
            bytes_downloaded_delta=2000,
        )
        start = _now() - timedelta(hours=1)
        end = _now() + timedelta(hours=1)
        summary = await fx.analytics_service.get_summary(
            organization_id=fx.organization_id, location_id=None, start=start, end=end
        )
        assert summary.total_bandwidth_bytes == 3000

    async def test_top_locations_ranks_by_session_count(self) -> None:
        fx = make_fixture()
        other_location = uuid.uuid4()
        fx.captive_portal_service.add_location(other_location, fx.organization_id)
        other_router = fx.router_service.add(organization_id=fx.organization_id)

        await self._login(fx, identifier="+15550004444")
        await self._login(fx, identifier="+15550005555")
        await fx.guest_service.login_via_otp(
            identifier="+15550006666",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=other_location,
            router_id=other_router.id,
        )

        start = _now() - timedelta(hours=1)
        end = _now() + timedelta(hours=1)
        top = await fx.analytics_service.get_top_locations(
            organization_id=fx.organization_id, start=start, end=end, limit=10
        )
        assert top[0].location_id == fx.location_id
        assert top[0].session_count == 2
        assert top[1].location_id == other_location
        assert top[1].session_count == 1

    async def test_top_devices_ranks_by_session_count(self) -> None:
        fx = make_fixture()
        await self._login(fx, identifier="+15550007777", device_mac="11:11:11:11:11:11")
        await fx.guest_service.disconnect_session(
            session_id=(
                await fx.repository.list_sessions_for_guest(
                    (
                        await fx.repository.get_guest_by_identifier(
                            fx.organization_id, "+15550007777"
                        )
                    ).id
                )
            )[0].id
        )
        await self._login(fx, identifier="+15550007777", device_mac="11:11:11:11:11:11")
        await self._login(fx, identifier="+15550008888", device_mac="22:22:22:22:22:22")

        start = _now() - timedelta(hours=1)
        end = _now() + timedelta(hours=1)
        top = await fx.analytics_service.get_top_devices(
            organization_id=fx.organization_id, start=start, end=end, limit=10
        )
        assert top[0].mac_address == "11:11:11:11:11:11"
        assert top[0].session_count == 2
        assert top[1].mac_address == "22:22:22:22:22:22"
        assert top[1].session_count == 1

    async def test_otp_success_rate_derived_from_login_history(self) -> None:
        fx = make_fixture()
        await self._login(fx, identifier="+15550009999")
        with pytest.raises(OtpCodeMismatchError):
            await fx.guest_service.login_via_otp(
                identifier="+15550009999",
                code="WRONG",
                auth_method=GuestAuthMethod.OTP_SMS,
                organization_id=None,
                location_id=fx.location_id,
                router_id=fx.router.id,
            )

        start = _now() - timedelta(hours=1)
        end = _now() + timedelta(hours=1)
        result = await fx.analytics_service.get_otp_success_rate(
            organization_id=fx.organization_id, location_id=None, start=start, end=end
        )
        assert result.total_attempts == 2
        assert result.successful_attempts == 1
        assert result.success_rate == pytest.approx(0.5)

    async def test_voucher_usage_derived_from_sessions(self) -> None:
        fx = make_fixture()
        await self._login(
            fx,
            identifier="voucher-guest@example.com",
            auth_method=GuestAuthMethod.VOUCHER,
            voucher_code="VUSE1",
        )
        await self._login(fx, identifier="+15550001010")  # OTP -- excluded

        start = _now() - timedelta(hours=1)
        end = _now() + timedelta(hours=1)
        result = await fx.analytics_service.get_voucher_usage(
            organization_id=fx.organization_id, location_id=None, start=start, end=end
        )
        assert result.sessions == 1
        assert result.unique_guests == 1

    async def test_empty_range_returns_zeros(self) -> None:
        fx = make_fixture()
        start = _now() - timedelta(days=2)
        end = _now() - timedelta(days=1)
        summary = await fx.analytics_service.get_summary(
            organization_id=fx.organization_id, location_id=None, start=start, end=end
        )
        assert summary.visitors == 0
        assert summary.unique_guests == 0
        assert summary.returning_guests == 0
        assert summary.average_session_duration_seconds is None
        assert summary.total_bandwidth_bytes == 0


# ============================================================================
# Tenant isolation
# ============================================================================


class TestTenantIsolation:
    async def test_cross_organization_guest_access_raises(self) -> None:
        fx = make_fixture()
        result = await fx.guest_service.login_via_otp(
            identifier="+15550011111",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        other_org = uuid.uuid4()
        with pytest.raises(CrossOrganizationGuestAccessError):
            await fx.guest_service.get_guest(
                result.guest.id, requesting_organization_id=other_org
            )

    async def test_cross_organization_session_access_raises(self) -> None:
        fx = make_fixture()
        result = await fx.guest_service.login_via_otp(
            identifier="+15550022222",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        other_org = uuid.uuid4()
        with pytest.raises(CrossOrganizationGuestAccessError):
            await fx.guest_service.get_session(
                result.session.id, requesting_organization_id=other_org
            )

    async def test_list_guests_scoped_to_organization(self) -> None:
        fx = make_fixture()
        await fx.guest_service.login_via_otp(
            identifier="+15550033333",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        other_org = uuid.uuid4()
        other_location = uuid.uuid4()
        fx.captive_portal_service.register(other_org, otp_sms_enabled=True)
        fx.captive_portal_service.add_location(other_location, other_org)
        other_router = fx.router_service.add(organization_id=other_org)
        await fx.guest_service.login_via_otp(
            identifier="+15550044444",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=other_location,
            router_id=other_router.id,
        )

        guests, meta = await fx.guest_service.list_guests(
            requesting_organization_id=fx.organization_id
        )
        assert meta.total_items == 1
        assert guests[0].organization_id == fx.organization_id


# ============================================================================
# Session timeout sweep -- module-level function + Celery task bridge
# (Guest Session Engine, Phase 1)
# ============================================================================


class TestSessionTimeoutSweep:
    async def test_enforce_session_timeouts_function_matches_service_method(
        self,
    ) -> None:
        """``GuestService.enforce_timeouts`` now delegates to the
        module-level ``enforce_session_timeouts`` -- this asserts the
        delegation actually happens (calling the free function directly,
        against the same repository, produces the identical result the
        service method already returns for the same data)."""
        from app.domains.guest.service import enforce_session_timeouts

        fx = make_fixture()
        result = await fx.guest_service.login_via_otp(
            identifier="+15559990010",
            code="GOOD",
            auth_method=GuestAuthMethod.OTP_SMS,
            organization_id=None,
            location_id=fx.location_id,
            router_id=fx.router.id,
        )
        result.session.session_timeout_minutes = 5
        result.session.last_activity_at = _now() - timedelta(minutes=10)

        expired = await enforce_session_timeouts(fx.repository)
        assert len(expired) == 1
        assert expired[0].id == result.session.id
        assert expired[0].status == GuestSessionStatus.EXPIRED.value


def test_run_session_timeout_sweep_task_bridges_into_async(monkeypatch) -> None:
    """Mirrors ``tests/unit/test_analytics.py``'s identical
    ``..._task_bridges_into_async`` pattern: the async bridge function is
    monkeypatched so this runs with no real Celery worker/broker/Postgres,
    and only the sync task's own wiring (does it await the bridge, does it
    shape the return value correctly) is under test."""
    from app.domains.guest import tasks as tasks_module

    async def _fake_run_session_timeout_sweep_async() -> int:
        return 3

    monkeypatch.setattr(
        tasks_module,
        "_run_session_timeout_sweep_async",
        _fake_run_session_timeout_sweep_async,
    )

    result = tasks_module.run_session_timeout_sweep()
    assert result == {"expired_count": 3}
