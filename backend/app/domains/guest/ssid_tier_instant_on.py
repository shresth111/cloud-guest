"""Speed tiers by WiFi network -> Aruba Instant On: push each mapped SSID's
per-client speed cap through the cloud-control client (cloud-guest #348), or,
when that path is closed, say exactly what the owner sets by hand.

Nothing here talks to Instant On directly. The client, its token machinery,
its tenant-scoped site resolution (``resolve_control_target``) and its
read-back-after-write rule all belong to
``app.domains.network_integration.instant_on_control`` /
``providers.aruba_instant_on_control``; this module only maps SSID names to
Instant On network ids and calls ``set_guest_network_rate_limit`` once per
SSID. It is imported lazily so a build without the cloud-control client still
answers (with the manual steps).

Gates, ALL required for a write:
* ``Settings.instant_on_ssid_tier_push_enabled`` (this feature, OFF by default);
* the cloud-control gates (global flag, router allowlist, write account ARN,
  an ``instant_on_sites`` row) -- ``resolve_control_target`` returns ``None``
  unless every one is set;
* ``dry_run=False`` from a Master caller (the route pins GLOBAL scope), or
  from the venue's own customer through :func:`customer_apply_ssid_tier_speeds`,
  which additionally requires the cloud-control router to be a NAS-only
  (Aruba Instant On) router at that venue.

Two answers, two audiences. The Master payload (``SsidSyncResult.as_dict``)
carries ``manual_steps`` -- what ops set by hand in the vendor's app. The
customer answer (:class:`CustomerSpeedStatus`) never does: the customer
dashboard must not send an owner to another vendor's app (owner rule
2026-11-07), so it gets a neutral ``applied`` / ``pending`` /
``not_applicable`` status and neutral reason codes only.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

from app.core.config import Settings

from .ssid_tier_service import instant_on_manual_steps
from .ssid_tiers import SsidTierRule, ssid_key

logger = logging.getLogger(__name__)


class SyncStatus:
    MANUAL = "manual"  # cloud path closed: here are the steps
    PREVIEW = "preview"  # dry run: what would change
    APPLIED = "applied"  # every mapped SSID written and read back
    PARTIAL = "partial"  # some SSIDs failed or are missing in Instant On
    FAILED = "failed"


class SyncReason:
    PUSH_DISABLED = "ssid_tier_push_disabled"
    CLOUD_CONTROL_UNAVAILABLE = "cloud_control_not_in_this_build"
    CLOUD_CONTROL_NOT_ENABLED = "cloud_control_not_enabled"
    NO_TIERS = "no_ssid_tiers"
    NOT_NAS_ONLY = "not_nas_only_router"


@dataclass(slots=True)
class SsidSyncItem:
    ssid: str
    download_mbps: int | None
    upload_mbps: int | None
    network_id: str | None = None
    status: str = "pending"  # preview | applied | unchanged | missing | failed
    before_download_mbps: int | None = None
    before_upload_mbps: int | None = None
    message: str | None = None
    #: Neutral machine code for ``failed`` items (the ``message`` is the
    #: Master's prose): ``network_has_other_limit`` | ``apply_failed``.
    reason: str | None = None


@dataclass(slots=True)
class SsidSyncResult:
    status: str
    reason: str | None = None
    manual_steps: list[str] = field(default_factory=list)
    items: list[SsidSyncItem] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _control_module() -> Any | None:
    try:
        from app.domains.network_integration import instant_on_control
    except ImportError:
        return None
    if not hasattr(instant_on_control, "resolve_control_target"):
        return None
    return instant_on_control


async def _list_networks(client: Any, site_id: str) -> list[dict[str, Any]]:
    """Every network of the site (``GET networksSummary``). Uses the client's
    public ``list_networks`` when it has one, else its own transport."""
    lister = getattr(client, "list_networks", None)
    if lister is not None:
        return list(await lister(site_id))
    from app.domains.network_integration.providers import (
        aruba_instant_on_control as provider,
    )

    payload = await client._call("GET", site_id, "networksSummary")  # noqa: SLF001
    return provider._elements(payload, "networksSummary")  # noqa: SLF001


def match_network_ids(
    rules: Sequence[SsidTierRule], networks: Sequence[dict[str, Any]]
) -> dict[str, str | None]:
    """SSID -> Instant On network id, by exact name first, then
    case-insensitively. ``None`` = no such network on the site (the owner has
    not created it yet)."""
    by_name: dict[str, str] = {}
    by_key: dict[str, str] = {}
    for network in networks:
        name = network.get("networkName")
        nid = network.get("id")
        if not isinstance(name, str) or not nid:
            continue
        by_name.setdefault(name, str(nid))
        by_key.setdefault(ssid_key(name), str(nid))
    return {
        rule.ssid: by_name.get(rule.ssid) or by_key.get(ssid_key(rule.ssid))
        for rule in rules
    }


async def sync_ssid_tiers_to_instant_on(
    db: Any,
    *,
    organization_id: uuid.UUID,
    location_id: uuid.UUID,
    rules: Sequence[SsidTierRule],
    dry_run: bool,
    settings: Settings,
    client_factory: Any = None,
    target_check: Callable[[Any], Awaitable[bool]] | None = None,
) -> SsidSyncResult:
    """Preview or apply. ``client_factory(target)`` is an async context
    manager yielding a control client; the default builds the live one.
    Tests pass a fake. ``target_check(target)``, when given, must answer
    True for the resolved cloud-control target or nothing is read or
    written (the customer path uses it to require a NAS-only router)."""
    manual = instant_on_manual_steps(rules)
    if not rules:
        return SsidSyncResult(SyncStatus.MANUAL, SyncReason.NO_TIERS, manual)
    if not settings.instant_on_ssid_tier_push_enabled:
        return SsidSyncResult(SyncStatus.MANUAL, SyncReason.PUSH_DISABLED, manual)
    control = _control_module()
    if control is None:
        return SsidSyncResult(
            SyncStatus.MANUAL, SyncReason.CLOUD_CONTROL_UNAVAILABLE, manual
        )
    target = await control.resolve_control_target(
        db,
        organization_id=organization_id,
        location_id=location_id,
        settings=settings,
    )
    if target is None:
        return SsidSyncResult(
            SyncStatus.MANUAL, SyncReason.CLOUD_CONTROL_NOT_ENABLED, manual
        )
    if target_check is not None and not await target_check(target):
        return SsidSyncResult(SyncStatus.MANUAL, SyncReason.NOT_NAS_ONLY, manual)

    if client_factory is None:
        client_factory = _live_client_factory(control, settings)

    items = [SsidSyncItem(r.ssid, r.download_mbps, r.upload_mbps) for r in rules]
    try:
        async with client_factory(target) as client:
            networks = await _list_networks(client, target.site_id)
            ids = match_network_ids(rules, networks)
            for item in items:
                item.network_id = ids.get(item.ssid)
                if item.network_id is None:
                    item.status = "missing"
                    item.message = (
                        f"No WiFi network named {item.ssid!r} on this Instant On "
                        "site yet. Create it first (Networks > Add > Wireless, "
                        "Guest, Open, Show guest portal ON)."
                    )
                    continue
                try:
                    before = await client.get_guest_network_rate_limit(
                        target.site_id, item.network_id
                    )
                    item.before_download_mbps = before.download_mbps
                    item.before_upload_mbps = before.upload_mbps
                    # Before "unchanged" and "preview": a sync forces per-client
                    # mode, and equal-looking numbers are not the same limit.
                    if before.other_mode_limit:
                        item.status = "failed"
                        item.reason = "network_has_other_limit"
                        item.message = (
                            "This network has a network-wide limit set in the "
                            "Instant On app. Change it there, then sync again."
                        )
                        continue
                    if (
                        before.download_mbps == item.download_mbps
                        and before.upload_mbps == item.upload_mbps
                    ):
                        item.status = "unchanged"
                        continue
                    if dry_run:
                        item.status = "preview"
                        continue
                    await client.set_guest_network_rate_limit(
                        target.site_id,
                        item.network_id,
                        download_mbps=item.download_mbps,
                        upload_mbps=item.upload_mbps,
                    )
                    item.status = "applied"
                except Exception as exc:  # noqa: BLE001 -- reported per SSID
                    item.status = "failed"
                    item.reason = "apply_failed"
                    item.message = str(exc)[:300]
    except Exception as exc:  # noqa: BLE001 -- token/site failure: whole sync
        logger.warning(
            "ssid_tier_instant_on_sync_failed",
            extra={"location_id": str(location_id), "error": str(exc)[:300]},
        )
        return SsidSyncResult(SyncStatus.FAILED, type(exc).__name__, manual, items)

    bad = [i for i in items if i.status in ("missing", "failed")]
    if dry_run:
        status = SyncStatus.PREVIEW
    elif bad:
        status = SyncStatus.PARTIAL
    else:
        status = SyncStatus.APPLIED
    logger.info(
        "ssid_tier_instant_on_sync",
        extra={
            "location_id": str(location_id),
            "status": status,
            "dry_run": dry_run,
            "items": [(i.ssid, i.status) for i in items],
        },
    )
    return SsidSyncResult(status, None, manual, items)


# ---------------------------------------------------------------------------
# Customer answer: neutral status, never vendor-app steps
# ---------------------------------------------------------------------------


class CustomerSpeedState:
    APPLIED = "applied"  # every mapped SSID's speed is live on the network
    PENDING = "pending"  # saved; not (all) live on the network yet
    NOT_APPLICABLE = "not_applicable"  # no tiers, or not a NAS-only venue


class CustomerSpeedReason:
    NO_TIERS = "no_ssid_tiers"
    NOT_SUPPORTED = "not_supported_at_this_venue"
    PUSH_OFF = "push_off"  # instant_on_ssid_tier_push_enabled is off
    #: Cloud control is not in this build, switched off, or not allowed for
    #: this venue's router (allowlist / write account).
    CLOUD_CONTROL_OFF = "cloud_control_off"
    #: Genuinely not configured yet: cloud control is on, but this venue has
    #: no Instant On site mapping.
    AWAITING_SETUP = "awaiting_setup"
    #: Gates open, but no recent live check is cached; POST apply-speeds
    #: (``dry_run: true``) runs one.
    NOT_CHECKED = "not_checked"
    NOT_YET_APPLIED = "not_yet_applied"
    NOT_ALL_APPLIED = "not_all_applied"
    APPLY_FAILED = "apply_failed"
    NETWORK_NOT_FOUND = "network_not_found"
    NETWORK_HAS_OTHER_LIMIT = "network_has_other_limit"


@dataclass(slots=True)
class CustomerSpeedItem:
    ssid: str
    download_mbps: int | None
    upload_mbps: int | None
    status: str  # applied | pending
    reason: str | None = None


@dataclass(slots=True)
class CustomerSpeedStatus:
    """What the customer dashboard may show. Deliberately has no prose and
    no ``manual_steps`` field: nothing here can tell an owner to go to
    another vendor's app."""

    status: str
    reason: str | None = None
    cloud_apply_available: bool = False
    items: list[CustomerSpeedItem] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


_APPLIED_ITEM = frozenset({"applied", "unchanged"})


def _customer_item(item: SsidSyncItem) -> CustomerSpeedItem:
    if item.status in _APPLIED_ITEM:
        return CustomerSpeedItem(
            item.ssid, item.download_mbps, item.upload_mbps, CustomerSpeedState.APPLIED
        )
    if item.status == "missing":
        reason = CustomerSpeedReason.NETWORK_NOT_FOUND
    elif item.status == "failed":
        reason = item.reason or CustomerSpeedReason.APPLY_FAILED
    else:  # preview | pending
        reason = CustomerSpeedReason.NOT_YET_APPLIED
    return CustomerSpeedItem(
        item.ssid,
        item.download_mbps,
        item.upload_mbps,
        CustomerSpeedState.PENDING,
        reason,
    )


def customer_speed_status(result: SsidSyncResult) -> CustomerSpeedStatus:
    """Map the Master's sync result onto the customer's neutral status.
    ``manual_steps`` and per-item ``message`` are dropped on purpose."""
    if result.status == SyncStatus.MANUAL:
        if result.reason == SyncReason.NO_TIERS:
            return CustomerSpeedStatus(
                CustomerSpeedState.NOT_APPLICABLE, CustomerSpeedReason.NO_TIERS
            )
        if result.reason == SyncReason.NOT_NAS_ONLY:
            return CustomerSpeedStatus(
                CustomerSpeedState.NOT_APPLICABLE, CustomerSpeedReason.NOT_SUPPORTED
            )
        if result.reason == SyncReason.PUSH_DISABLED:
            return CustomerSpeedStatus(
                CustomerSpeedState.PENDING, CustomerSpeedReason.PUSH_OFF
            )
        # CLOUD_CONTROL_UNAVAILABLE / CLOUD_CONTROL_NOT_ENABLED. The caller
        # refines NOT_ENABLED into AWAITING_SETUP when no site is mapped.
        return CustomerSpeedStatus(
            CustomerSpeedState.PENDING, CustomerSpeedReason.CLOUD_CONTROL_OFF
        )
    items = [_customer_item(i) for i in result.items]
    if result.status == SyncStatus.FAILED:
        return CustomerSpeedStatus(
            CustomerSpeedState.PENDING,
            CustomerSpeedReason.APPLY_FAILED,
            True,
            [
                CustomerSpeedItem(
                    i.ssid,
                    i.download_mbps,
                    i.upload_mbps,
                    CustomerSpeedState.PENDING,
                    CustomerSpeedReason.APPLY_FAILED,
                )
                for i in items
            ],
        )
    if items and all(i.status == CustomerSpeedState.APPLIED for i in items):
        return CustomerSpeedStatus(CustomerSpeedState.APPLIED, None, True, items)
    reason = (
        CustomerSpeedReason.NOT_YET_APPLIED
        if result.status == SyncStatus.PREVIEW
        else CustomerSpeedReason.NOT_ALL_APPLIED
    )
    return CustomerSpeedStatus(CustomerSpeedState.PENDING, reason, True, items)


async def nas_only_router_at(
    db: Any,
    *,
    organization_id: uuid.UUID,
    location_id: uuid.UUID,
    router_id: uuid.UUID | None = None,
) -> bool:
    """True when a live NAS-only (Aruba Instant On) router of this
    organization is at this location -- and, with ``router_id``, when THAT
    router is one. Tenant-scoped in the WHERE clause."""
    from sqlalchemy import select

    from app.domains.router.models import Router
    from app.domains.router.vendor_capabilities import NAS_ONLY_VENDORS

    statement = select(Router.id).where(
        Router.organization_id == organization_id,
        Router.location_id == location_id,
        Router.is_deleted.is_(False),
        Router.vendor.in_(sorted(NAS_ONLY_VENDORS)),
    )
    if router_id is not None:
        statement = statement.where(Router.id == router_id)
    return (await db.execute(statement.limit(1))).scalars().first() is not None


async def instant_on_site_mapped(
    db: Any, *, organization_id: uuid.UUID, location_id: uuid.UUID
) -> bool:
    """True when this venue has a live Instant On site mapping (the Master
    has set it up). Tenant-scoped in the WHERE clause."""
    from sqlalchemy import select

    from app.domains.network_integration.models import InstantOnSite

    statement = select(InstantOnSite.id).where(
        InstantOnSite.organization_id == organization_id,
        InstantOnSite.location_id == location_id,
        InstantOnSite.is_deleted.is_(False),
    )
    return (await db.execute(statement.limit(1))).scalars().first() is not None


async def _no_target_reason(
    db: Any, *, organization_id: uuid.UUID, location_id: uuid.UUID, settings: Any
) -> str:
    """Why no cloud-control target resolved: switched off / not allowed
    (``cloud_control_off``) or genuinely not configured (``awaiting_setup``)."""
    if not getattr(settings, "instant_on_cloud_control_enabled", False):
        return CustomerSpeedReason.CLOUD_CONTROL_OFF
    if not await instant_on_site_mapped(
        db, organization_id=organization_id, location_id=location_id
    ):
        return CustomerSpeedReason.AWAITING_SETUP
    return CustomerSpeedReason.CLOUD_CONTROL_OFF


def rules_fingerprint(rules: Sequence[SsidTierRule]) -> str:
    """Changes whenever the saved SSID -> speed mapping changes, so a cached
    check never vouches for speeds it did not see."""
    import hashlib
    import json

    material = sorted((ssid_key(r.ssid), r.download_mbps, r.upload_mbps) for r in rules)
    return hashlib.sha256(json.dumps(material).encode()).hexdigest()[:32]


#: How long a live check answers the customer GET/PUT.
SPEED_STATUS_CACHE_TTL_SECONDS = 300


class SpeedStatusCache:
    """The last live check per location, in Redis, short TTL.

    Written only by POST apply-speeds (the one customer path that talks to
    Instant On); read by GET/PUT, which never talk to Instant On. Every
    Redis failure is a miss (read) or a no-op (write), never an error."""

    def __init__(
        self, redis: Any, *, ttl_seconds: int = SPEED_STATUS_CACHE_TTL_SECONDS
    ) -> None:
        self.redis = redis
        self.ttl_seconds = ttl_seconds

    @staticmethod
    def key(location_id: uuid.UUID) -> str:
        return f"ssid_tier:speed_status:{location_id}"

    async def get(
        self, location_id: uuid.UUID, fingerprint: str
    ) -> CustomerSpeedStatus | None:
        import json

        try:
            raw = await self.redis.get(self.key(location_id))
            if raw is None:
                return None
            payload = json.loads(raw)
            if payload.get("fp") != fingerprint:
                return None
            data = payload["status"]
            return CustomerSpeedStatus(
                status=data["status"],
                reason=data.get("reason"),
                cloud_apply_available=bool(data.get("cloud_apply_available")),
                items=[CustomerSpeedItem(**i) for i in data.get("items") or []],
            )
        except Exception as exc:  # noqa: BLE001 -- a cache miss, never an error
            logger.warning(
                "ssid_tier_speed_status_cache_read_failed",
                extra={"location_id": str(location_id), "error": str(exc)[:200]},
            )
            return None

    async def set(
        self,
        location_id: uuid.UUID,
        fingerprint: str,
        status: CustomerSpeedStatus,
    ) -> None:
        import json

        try:
            await self.redis.set(
                self.key(location_id),
                json.dumps({"fp": fingerprint, "status": status.as_dict()}),
                ex=self.ttl_seconds,
            )
        except Exception as exc:  # noqa: BLE001 -- best effort
            logger.warning(
                "ssid_tier_speed_status_cache_write_failed",
                extra={"location_id": str(location_id), "error": str(exc)[:200]},
            )


async def _venue_gate(
    db: Any,
    *,
    organization_id: uuid.UUID,
    location_id: uuid.UUID,
    rules: Sequence[SsidTierRule],
) -> CustomerSpeedStatus | None:
    """``not_applicable`` for no tiers or a venue without a NAS-only router
    (every MikroTik / Omada venue), else ``None``."""
    if not rules:
        return CustomerSpeedStatus(
            CustomerSpeedState.NOT_APPLICABLE, CustomerSpeedReason.NO_TIERS
        )
    if not await nas_only_router_at(
        db, organization_id=organization_id, location_id=location_id
    ):
        return CustomerSpeedStatus(
            CustomerSpeedState.NOT_APPLICABLE, CustomerSpeedReason.NOT_SUPPORTED
        )
    return None


async def customer_cached_speed_status(
    db: Any,
    *,
    organization_id: uuid.UUID,
    location_id: uuid.UUID,
    rules: Sequence[SsidTierRule],
    settings: Settings,
    cache: SpeedStatusCache | None,
) -> CustomerSpeedStatus:
    """The customer GET/PUT answer. Never constructs an Instant On client
    and never calls Instant On: gates are evaluated from settings and the
    database, and ``applied`` / per-SSID detail only ever comes from the
    last live check POST apply-speeds cached (``not_checked`` otherwise)."""
    closed = await _venue_gate(
        db, organization_id=organization_id, location_id=location_id, rules=rules
    )
    if closed is not None:
        return closed
    if not settings.instant_on_ssid_tier_push_enabled:
        return CustomerSpeedStatus(
            CustomerSpeedState.PENDING, CustomerSpeedReason.PUSH_OFF
        )
    control = _control_module()
    if control is None:
        return CustomerSpeedStatus(
            CustomerSpeedState.PENDING, CustomerSpeedReason.CLOUD_CONTROL_OFF
        )
    target = await control.resolve_control_target(
        db,
        organization_id=organization_id,
        location_id=location_id,
        settings=settings,
    )
    if target is None:
        return CustomerSpeedStatus(
            CustomerSpeedState.PENDING,
            await _no_target_reason(
                db,
                organization_id=organization_id,
                location_id=location_id,
                settings=settings,
            ),
        )
    router_id = getattr(target, "router_id", None)
    if router_id is None or not await nas_only_router_at(
        db,
        organization_id=organization_id,
        location_id=location_id,
        router_id=router_id,
    ):
        return CustomerSpeedStatus(
            CustomerSpeedState.NOT_APPLICABLE, CustomerSpeedReason.NOT_SUPPORTED
        )
    if cache is not None:
        cached = await cache.get(location_id, rules_fingerprint(rules))
        if cached is not None:
            return cached
    return CustomerSpeedStatus(
        CustomerSpeedState.PENDING, CustomerSpeedReason.NOT_CHECKED, True
    )


async def customer_apply_ssid_tier_speeds(
    db: Any,
    *,
    organization_id: uuid.UUID,
    location_id: uuid.UUID,
    rules: Sequence[SsidTierRule],
    dry_run: bool,
    settings: Settings,
    client_factory: Any = None,
    cache: SpeedStatusCache | None = None,
) -> CustomerSpeedStatus:
    """The customer's path to the same sync the Master runs -- and the only
    customer path that talks to Instant On.

    Only ever acts at a NAS-only venue whose cloud-control router is itself
    NAS-only: any other venue (MikroTik, Omada, anything else) answers
    ``not_applicable`` before a single Instant On read, so their behaviour
    is untouched. ``dry_run=True`` is a read-only check. A live answer
    (preview or apply) is stored in ``cache`` for the GET/PUT to serve."""
    closed = await _venue_gate(
        db, organization_id=organization_id, location_id=location_id, rules=rules
    )
    if closed is not None:
        return closed

    async def _target_is_nas_only(target: Any) -> bool:
        router_id = getattr(target, "router_id", None)
        if router_id is None:
            return False
        return await nas_only_router_at(
            db,
            organization_id=organization_id,
            location_id=location_id,
            router_id=router_id,
        )

    result = await sync_ssid_tiers_to_instant_on(
        db,
        organization_id=organization_id,
        location_id=location_id,
        rules=rules,
        dry_run=dry_run,
        settings=settings,
        client_factory=client_factory,
        target_check=_target_is_nas_only,
    )
    status_ = customer_speed_status(result)
    if result.reason == SyncReason.CLOUD_CONTROL_NOT_ENABLED:
        status_.reason = await _no_target_reason(
            db,
            organization_id=organization_id,
            location_id=location_id,
            settings=settings,
        )
    if status_.cloud_apply_available and cache is not None:
        await cache.set(location_id, rules_fingerprint(rules), status_)
    return status_


def _live_client_factory(control: Any, settings: Settings) -> Any:
    from contextlib import asynccontextmanager

    import httpx

    @asynccontextmanager
    async def factory(target: Any):  # noqa: ANN202
        async with httpx.AsyncClient(
            timeout=settings.instant_on_http_timeout_seconds
        ) as http:
            yield control.build_live_control_client(
                http, settings, secret_arn=target.secret_arn
            )

    return factory


__all__ = [
    "CustomerSpeedItem",
    "CustomerSpeedReason",
    "CustomerSpeedState",
    "CustomerSpeedStatus",
    "SsidSyncItem",
    "SsidSyncResult",
    "SyncReason",
    "SyncStatus",
    "SPEED_STATUS_CACHE_TTL_SECONDS",
    "SpeedStatusCache",
    "customer_apply_ssid_tier_speeds",
    "customer_cached_speed_status",
    "customer_speed_status",
    "match_network_ids",
    "instant_on_site_mapped",
    "nas_only_router_at",
    "rules_fingerprint",
    "sync_ssid_tiers_to_instant_on",
]
