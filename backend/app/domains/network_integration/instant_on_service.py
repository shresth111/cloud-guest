"""Read side of the Aruba Instant On integration: what the dashboards get.

## The one rule: never stale data as current, never zeros as a fallback

Every answer carries ``source: "instant_on"`` and ``as_of`` (when the data
was read from Instant On). When the data cannot be vouched for, the answer
is ``status: "unavailable"`` with a ``unavailable_reason`` and **no items at
all** -- ``items`` is ``null``, not ``[]``, because an empty list reads as
"zero clients", which is a claim. The reasons:

* ``not_configured`` -- no Instant On site for this venue (or, on the
  customer route, not switched on for customers, or not the caller's venue:
  the three are indistinguishable on purpose);
* ``polling_disabled`` -- the global switch or the venue's poll flag is off;
* ``never_polled`` -- configured, but no read has happened yet;
* ``poll_failed`` -- the most recent read of this kind failed, even if an
  older good read exists (its time is still given as ``last_success_at``);
* ``stale`` -- the last read succeeded but is older than
  ``instant_on_stale_after_polls`` of its own poll periods (the poller has
  stopped, the worker is down...).

## Tenancy

Customer reads name a location and nothing else. The site is resolved by a
query carrying the caller's organization *and* that location
(``InstantOnRepository.get_site_for_location``), then the caller's
location confinement is applied to the row's own location -- the pattern
``NetworkIntegrationService._resolve_location_controller`` uses, so the
path-id-vs-header-org defect class cannot occur: there is no id in the
request that is read before it is scoped. Master reads are keyed on a
fleet ``router_id`` behind ``ScopeType.GLOBAL``.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from app.core.config import Settings, get_settings
from app.domains.rbac.location_scope import LocationScope, enforce_entity_location

from .exceptions import (
    CrossLocationNetworkIntegrationAccessError,
    InstantOnSiteNotConfigurableError,
)
from .instant_on_repository import InstantOnRepositoryProtocol
from .models import InstantOnSite, InstantOnSnapshot
from .providers.aruba_instant_on_client import validate_site_id

__all__ = [
    "CUSTOMER_KINDS",
    "GuestMacLookup",
    "GuestRepositoryMacLookup",
    "InstantOnKind",
    "InstantOnReadService",
    "InstantOnSiteNotConfigurableError",
    "InstantOnView",
    "build_view",
    "poll_period_seconds",
]

SOURCE = "instant_on"


class InstantOnKind(StrEnum):
    ACCESS_POINTS = "access_points"
    CLIENTS = "clients"
    SSIDS = "ssids"
    ALERTS = "alerts"
    HEALTH = "health"
    CLIENT_USAGE = "client_usage"


CUSTOMER_KINDS = frozenset(
    {
        InstantOnKind.ACCESS_POINTS,
        InstantOnKind.CLIENTS,
        InstantOnKind.SSIDS,
        InstantOnKind.ALERTS,
    }
)


def poll_period_seconds(kind: str, settings: Settings) -> int:
    if kind in (InstantOnKind.ACCESS_POINTS, InstantOnKind.CLIENTS):
        return settings.instant_on_fast_poll_seconds
    if kind == InstantOnKind.CLIENT_USAGE:
        return settings.instant_on_usage_poll_seconds
    return settings.instant_on_health_poll_seconds


@dataclass(frozen=True, slots=True)
class InstantOnView:
    kind: str
    status: str  # ok | unavailable
    unavailable_reason: str | None
    as_of: datetime | None
    last_success_at: datetime | None
    stale_after_seconds: int
    items: list[dict[str, Any]] | None
    # Master-only detail; the customer schema does not carry these.
    error_code: str | None = None
    api_state: str | None = None
    source: str = SOURCE


def build_view(
    *,
    kind: str,
    site: InstantOnSite | None,
    snapshot: InstantOnSnapshot | None,
    now: datetime,
    settings: Settings,
) -> InstantOnView:
    """Pure: decide whether a snapshot may be served as current."""
    stale_after = (
        poll_period_seconds(kind, settings) * settings.instant_on_stale_after_polls
    )

    def unavailable(reason: str, **extra: Any) -> InstantOnView:
        return InstantOnView(
            kind=kind,
            status="unavailable",
            unavailable_reason=reason,
            as_of=None,
            last_success_at=snapshot.fetched_at if snapshot is not None else None,
            stale_after_seconds=stale_after,
            items=None,
            api_state=site.api_state if site is not None else None,
            **extra,
        )

    if site is None:
        return InstantOnView(
            kind=kind,
            status="unavailable",
            unavailable_reason="not_configured",
            as_of=None,
            last_success_at=None,
            stale_after_seconds=stale_after,
            items=None,
        )
    if not settings.instant_on_poller_enabled or not site.poll_enabled:
        return unavailable("polling_disabled")
    if snapshot is None or snapshot.last_attempt_at is None:
        return unavailable("never_polled")
    if not snapshot.last_attempt_ok:
        return unavailable("poll_failed", error_code=snapshot.error_code)
    if snapshot.fetched_at is None or not isinstance(snapshot.payload, list):
        return unavailable("never_polled")
    if now - snapshot.fetched_at > timedelta(seconds=stale_after):
        return unavailable("stale")
    return InstantOnView(
        kind=kind,
        status="ok",
        unavailable_reason=None,
        as_of=snapshot.fetched_at,
        last_success_at=snapshot.fetched_at,
        stale_after_seconds=stale_after,
        items=[dict(item) for item in snapshot.payload],
        api_state=site.api_state,
    )


class GuestMacLookup(Protocol):
    """MACs (``AA:BB:CC:DD:EE:FF``) of guests with an ACTIVE RADIUS session
    on this fleet router. RADIUS stays the source of truth for guests; this
    only lets a client row say "this is a signed-in guest"."""

    async def active_guest_macs(
        self, *, router_id: uuid.UUID, organization_id: uuid.UUID
    ) -> set[str]: ...


class GuestRepositoryMacLookup:
    """:class:`GuestMacLookup` over ``GuestRepository`` -- the same two reads
    the Omada usage sweep uses, org-scoped on the device side."""

    def __init__(self, guest_repository: Any) -> None:
        self._guest_repository = guest_repository

    async def active_guest_macs(
        self, *, router_id: uuid.UUID, organization_id: uuid.UUID
    ) -> set[str]:
        sessions = await self._guest_repository.list_active_sessions_for_router(
            router_id
        )
        device_ids = [s.device_id for s in sessions if s.device_id is not None]
        if not device_ids:
            return set()
        devices = await self._guest_repository.list_devices_for_session_ids(
            device_ids=device_ids, organization_id=organization_id
        )
        macs: set[str] = set()
        for device in devices:
            hex_only = "".join(
                ch
                for ch in str(device.mac_address or "").upper()
                if ch in "0123456789ABCDEF"
            )
            if len(hex_only) == 12:
                macs.add(":".join(hex_only[i : i + 2] for i in range(0, 12, 2)))
        return macs


class RouterLookup(Protocol):
    async def get_router(self, router_id: uuid.UUID) -> Any: ...


def _utcnow() -> datetime:
    return datetime.now(UTC)


class InstantOnReadService:
    def __init__(
        self,
        repository: InstantOnRepositoryProtocol,
        *,
        caller_location_scope: LocationScope = None,
        guest_mac_lookup: GuestMacLookup | None = None,
        audit_writer: Any | None = None,
        settings: Settings | None = None,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self.repository = repository
        self.caller_location_scope = caller_location_scope
        self.guest_mac_lookup = guest_mac_lookup
        self.audit_writer = audit_writer
        self.settings = settings or get_settings()
        self.clock = clock

    # -- customer --------------------------------------------------------

    async def customer_view(
        self,
        *,
        location_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        kind: InstantOnKind,
    ) -> InstantOnView:
        if kind not in CUSTOMER_KINDS:
            raise ValueError(f"{kind} is not a customer kind")
        site = (
            await self.repository.get_site_for_location(
                location_id=location_id, organization_id=organization_id
            )
            if organization_id is not None
            else None
        )
        if site is not None:
            # Location confinement for site-scoped staff, applied to the row
            # the org-scoped query returned.
            enforce_entity_location(
                entity_location_id=site.location_id,
                caller_location_scope=self.caller_location_scope,
                error=CrossLocationNetworkIntegrationAccessError(),
            )
        if site is None or not site.customer_visible:
            return build_view(
                kind=kind,
                site=None,
                snapshot=None,
                now=self.clock(),
                settings=self.settings,
            )
        view = await self._view(site, kind)
        # Customers get the reason, not Instant On's error text or our
        # internal API state.
        return InstantOnView(
            kind=view.kind,
            status=view.status,
            unavailable_reason=view.unavailable_reason,
            as_of=view.as_of,
            last_success_at=view.last_success_at,
            stale_after_seconds=view.stale_after_seconds,
            items=view.items,
        )

    # -- Master ----------------------------------------------------------

    async def platform_view(
        self, *, router_id: uuid.UUID, kind: InstantOnKind
    ) -> InstantOnView:
        site = await self.repository.get_site_for_router(router_id)
        if site is None:
            return build_view(
                kind=kind,
                site=None,
                snapshot=None,
                now=self.clock(),
                settings=self.settings,
            )
        return await self._view(site, kind)

    async def platform_list_sites(self, *, limit: int = 500) -> list[InstantOnSite]:
        return await self.repository.list_sites(limit=limit)

    async def configure_site(
        self,
        *,
        router_id: uuid.UUID,
        site_id: str,
        site_name: str | None,
        poll_enabled: bool,
        customer_visible: bool,
        router_lookup: RouterLookup,
        actor_user_id: uuid.UUID | None = None,
    ) -> InstantOnSite:
        """Map a NAS-only fleet router to its Instant On site. Writes only
        to this platform's database. Organization and location are copied
        from the router row, never taken from the request."""
        from app.domains.router.vendor_capabilities import is_nas_only

        try:
            clean_site_id = validate_site_id(site_id)
        except ValueError:
            raise InstantOnSiteNotConfigurableError("invalid_site_id") from None
        router = await router_lookup.get_router(router_id)
        if not is_nas_only(router):
            raise InstantOnSiteNotConfigurableError("not_nas_only_vendor")
        if getattr(router, "location_id", None) is None:
            raise InstantOnSiteNotConfigurableError("no_location")
        data = {
            "site_id": clean_site_id,
            "site_name": site_name,
            "poll_enabled": poll_enabled,
            "customer_visible": customer_visible,
            "organization_id": router.organization_id,
            "location_id": router.location_id,
        }
        existing = await self.repository.get_site_for_router(router_id)
        if existing is None:
            site = await self.repository.create_site({"router_id": router_id, **data})
            await self._audit(site, actor_user_id=actor_user_id, created=True)
            return site
        if existing.site_id != clean_site_id:
            # A different site: the previous one's state says nothing about
            # this one.
            data.update(
                api_state="never_polled",
                last_success_at=None,
                last_error_code=None,
                last_error_message=None,
                last_error_at=None,
                consecutive_failures=0,
                backoff_until=None,
            )
        site = await self.repository.update_site(existing, data)
        await self._audit(site, actor_user_id=actor_user_id, created=False)
        return site

    async def site_in_use(self, site_id: str) -> InstantOnSite | None:
        """The live mapping (on a live router) for this Instant On site id, or
        ``None``. A malformed id is ``invalid_site_id``, the same refusal
        ``configure_site`` gives."""
        try:
            clean_site_id = validate_site_id(site_id)
        except ValueError:
            raise InstantOnSiteNotConfigurableError("invalid_site_id") from None
        return await self.repository.get_live_site_by_site_id(clean_site_id)

    async def release_sites_for_router(
        self, router_id: uuid.UUID, *, actor_user_id: uuid.UUID | None = None
    ) -> int:
        """Soft-delete the router's site mapping when the router is
        decommissioned, audited. Returns how many were released."""
        sites = await self.repository.soft_delete_sites_for_router(router_id)
        for site in sites:
            if self.audit_writer is not None:
                await self.audit_writer.create_audit_log_entry(
                    actor_user_id=actor_user_id,
                    action="instant_on_site.delete",
                    entity_type="instant_on_site",
                    entity_id=site.id,
                    description=(
                        "Instant On site mapping removed with its fleet device"
                    ),
                    organization_id=site.organization_id,
                    location_id=site.location_id,
                    event_metadata={
                        "router_id": str(site.router_id),
                        "site_id": site.site_id,
                    },
                )
        return len(sites)

    async def _audit(
        self, site: InstantOnSite, *, actor_user_id: uuid.UUID | None, created: bool
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action="instant_on_site.create" if created else "instant_on_site.update",
            entity_type="instant_on_site",
            entity_id=site.id,
            description=(
                f"Instant On site {'mapped' if created else 'updated'}: "
                f"polling {'on' if site.poll_enabled else 'off'}, customer "
                f"view {'on' if site.customer_visible else 'off'}"
            ),
            organization_id=site.organization_id,
            location_id=site.location_id,
            event_metadata={
                "router_id": str(site.router_id),
                "site_id": site.site_id,
                "poll_enabled": site.poll_enabled,
                "customer_visible": site.customer_visible,
            },
        )

    # -- shared ----------------------------------------------------------

    async def _view(self, site: InstantOnSite, kind: InstantOnKind) -> InstantOnView:
        snapshots = await self.repository.get_snapshots(site)
        view = build_view(
            kind=kind,
            site=site,
            snapshot=snapshots.get(kind.value),
            now=self.clock(),
            settings=self.settings,
        )
        if (
            view.status == "ok"
            and kind == InstantOnKind.CLIENTS
            and self.guest_mac_lookup is not None
            and view.items is not None
        ):
            macs = await self.guest_mac_lookup.active_guest_macs(
                router_id=site.router_id, organization_id=site.organization_id
            )
            for item in view.items:
                item["is_signed_in_guest"] = item.get("mac") in macs
        return view
