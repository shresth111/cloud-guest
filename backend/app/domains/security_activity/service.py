"""Security activity: the hourly read-only counter collector, and the view
the customer dashboard reads.

## The collector never writes to a router

``SecurityCounterCollector.collect_for_router`` opens exactly one RouterOS
API connection, through ``ReadOnlyDeviceReader`` -- a class whose whole
public surface is ``print``-style reads of an allowlist of paths, so a write
cannot be expressed against it -- reads ``/ip/firewall/filter`` and
``/ip/firewall/nat`` in that one session, and closes it. Everything it
records goes to ``security_counter_samples``.

## Deltas, and the first read

The first time a rule is seen there is nothing to diff against, and its
cumulative counter may hold weeks of history. That read is stored as a
baseline with a delta of zero: attributing the whole history to the current
hour would make "last 24 hours" a lie on day one. A counter that went *down*
restarted (reboot, rule re-created), and the new total is then the delta --
everything counted since the restart.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from wyfy_device_gateway.contract import DeviceCredentials, DeviceVendor
from wyfy_device_gateway.read_only_reader import ReadOnlyDeviceReader

from app.core.logging import get_logger
from app.domains.router.crypto import decrypt_secret

from .classify import (
    PROTECTION_LABELS,
    CounterReading,
    Protection,
    classify_counter_rows,
    protection_sentence,
)
from .repository import (
    CloudflareScope,
    LocationFilter,
    SecurityActivityRepository,
)

logger = get_logger(__name__)

__all__ = [
    "ACTIVITY_WINDOWS",
    "CollectionSummary",
    "SecurityActivityService",
    "SecurityCounterCollector",
    "hour_bucket",
]

#: Sections the collector reads -- both plain prints, one connection.
COUNTER_SECTIONS: tuple[str, ...] = ("firewall_filter", "firewall_nat")
#: A short API timeout: this is background telemetry, and a slow router must
#: cost its own leaf task seconds, not a worker slot for a minute.
COLLECTOR_TIMEOUT_SECONDS = 8

ACTIVITY_WINDOWS: dict[str, timedelta] = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
}

#: Router-counter protections in display order. Device blocks and
#: Cloudflare are appended by the view from their own sources.
_ROUTER_PROTECTIONS: tuple[Protection, ...] = (
    Protection.WEBSITE_BLOCK,
    Protection.ADDRESS_BLOCK,
    Protection.PRIVATE_NETWORK,
    Protection.GUEST_ISOLATION,
    Protection.ACCESS_RULE,
    Protection.FLOOD_LIMIT,
    Protection.DNS_BYPASS,
    Protection.VPN_BLOCK,
    Protection.DNS_REDIRECT,
)

COUNTER_SEMANTICS = (
    "Counts come from the hit counters on your router's own protection rules, "
    "read every hour. They count blocked network packets: one blocked "
    "connection attempt is usually one to three packets. Blocked websites are "
    "counted on secure (HTTPS) visits; a router keeps no count of blocked "
    "website lookups, so the real number of attempts is higher, not lower."
)


def hour_bucket(moment: datetime) -> datetime:
    return moment.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


@dataclass(frozen=True, slots=True)
class CollectionSummary:
    router_id: str
    status: Literal["ok", "skipped", "unreachable"]
    rules_seen: int = 0
    baselined: int = 0
    packets_added: int = 0
    detail: str | None = None
    readings: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "router_id": self.router_id,
            "status": self.status,
            "rules_seen": self.rules_seen,
            "baselined": self.baselined,
            "packets_added": self.packets_added,
            "detail": self.detail,
        }


ReaderFactory = Callable[[DeviceCredentials], Any]


class SecurityCounterCollector:
    def __init__(
        self,
        repository: SecurityActivityRepository,
        *,
        reader_factory: ReaderFactory = ReadOnlyDeviceReader,
        decrypt: Callable[[Any], str | None] = decrypt_secret,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._repository = repository
        self._reader_factory = reader_factory
        self._decrypt = decrypt
        self._clock = clock

    async def collect_for_router(self, router_id: uuid.UUID) -> CollectionSummary:
        target = await self._repository.get_collection_target(router_id)
        if target is None or not target.host or not target.api_username:
            return CollectionSummary(
                str(router_id), "skipped", detail="no RouterOS API credentials"
            )
        secret = self._decrypt(target.api_credentials_encrypted)
        if not secret:
            return CollectionSummary(
                str(router_id), "skipped", detail="API secret could not be decrypted"
            )
        reader = self._reader_factory(
            DeviceCredentials(
                vendor=DeviceVendor.MIKROTIK,
                host=target.host,
                username=target.api_username,
                secret=secret,
                timeout_seconds=COLLECTOR_TIMEOUT_SECONDS,
            )
        )
        try:
            capture = await reader.read_all(list(COUNTER_SECTIONS))
        except Exception as exc:  # noqa: BLE001 -- an unreachable router is a gap, not a failure
            logger.info(
                "security_counters_router_unreachable",
                extra={"router_id": str(router_id), "error": str(exc)[:300]},
            )
            return CollectionSummary(
                str(router_id), "unreachable", detail=str(exc)[:300]
            )
        if capture.errors:
            logger.info(
                "security_counters_section_errors",
                extra={"router_id": str(router_id), "errors": capture.errors},
            )
        readings = classify_counter_rows(
            capture.sections.get("firewall_filter", []),
            capture.sections.get("firewall_nat", []),
        )
        labels = await self._resolve_labels(target.organization_id, readings)
        previous = await self._repository.latest_samples(router_id)
        now = self._clock()
        bucket = hour_bucket(now)
        baselined = 0
        added = 0
        shown: list[dict[str, Any]] = []
        for reading in readings:
            prior = previous.get(reading.rule_key)
            if prior is None:
                packets_delta, bytes_delta = 0, 0
                baselined += 1
            elif reading.packets >= prior.packets_total:
                packets_delta = reading.packets - prior.packets_total
                bytes_delta = max(0, reading.bytes - prior.bytes_total)
            else:
                # Counter restarted: everything it holds is new since then.
                packets_delta, bytes_delta = reading.packets, reading.bytes
            label = labels.get(reading.ref_id or "", reading.label)
            await self._repository.upsert_sample(
                organization_id=target.organization_id,
                location_id=target.location_id,
                router_id=router_id,
                protection=reading.protection.value,
                rule_key=reading.rule_key,
                label=label,
                bucket_start=bucket,
                sampled_at=now,
                packets_total=reading.packets,
                bytes_total=reading.bytes,
                packets_delta=packets_delta,
                bytes_delta=bytes_delta,
            )
            added += packets_delta
            shown.append(
                {
                    "protection": reading.protection.value,
                    "label": label,
                    "packets_total": reading.packets,
                    "packets_delta": packets_delta,
                    "baseline": prior is None,
                }
            )
        return CollectionSummary(
            str(router_id),
            "ok",
            rules_seen=len(readings),
            baselined=baselined,
            packets_added=added,
            readings=shown,
        )

    async def _resolve_labels(
        self, organization_id: uuid.UUID, readings: list[CounterReading]
    ) -> dict[str, str]:
        fw = [
            r.ref_id
            for r in readings
            if r.ref_id
            and r.protection in (Protection.PRIVATE_NETWORK, Protection.ACCESS_RULE)
        ]
        cf = [
            r.ref_id
            for r in readings
            if r.ref_id and r.protection is Protection.WEBSITE_BLOCK
        ]
        if not fw and not cf:
            return {}
        return await self._repository.rule_names(
            organization_id=organization_id,
            firewall_rule_ids=fw,
            content_filter_rule_ids=cf,
        )


# ============================================================================
# The view
# ============================================================================


CloudflareCounter = Callable[[list[str], datetime, datetime], Any]

_ACTION_TEXT: dict[str, str] = {
    "firewall_rule_created": "added a firewall rule",
    "firewall_rule_updated": "changed a firewall rule",
    "firewall_rule_deleted": "removed a firewall rule",
    "firewall_rules_pushed": "applied firewall rules to a router",
    "firewall_flood_limit_changed": "changed the connection flood limit",
    "content_filter_rule_created": "blocked a website or address",
    "content_filter_rule_updated": "changed a website block",
    "content_filter_rule_deleted": "removed a website block",
    "dns_filtering_policy_updated": "changed website category filtering",
    "dns_filtering_enabled": "turned on website category filtering",
    "dns_filtering_disabled": "turned off website category filtering",
    "dns_filtering_bypass_hardening_changed": "changed filter bypass protection",
    "guest_access_rule_created": "added a guest access rule",
    "guest_access_rule_deleted": "removed a guest access rule",
    "guest_access_rules_imported": "imported guest access rules",
    "connected_device_blocked": "blocked a device",
    "connected_device_unblocked": "unblocked a device",
    "mac_authorization_entry_created": "added a trusted device",
    "mac_authorization_entry_updated": "changed a trusted device",
    "mac_authorization_entry_deleted": "removed a trusted device",
}


class SecurityActivityService:
    def __init__(
        self,
        repository: SecurityActivityRepository,
        *,
        cloudflare_counter: CloudflareCounter | None = None,
        cloudflare_unavailable_reason: str | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._repository = repository
        self._cloudflare_counter = cloudflare_counter
        self._cloudflare_unavailable_reason = cloudflare_unavailable_reason
        self._clock = clock

    async def build(
        self,
        *,
        organization_id: uuid.UUID,
        location: LocationFilter,
        window: str,
    ) -> dict[str, Any]:
        now = self._clock()
        span = ACTIVITY_WINDOWS[window]
        since = now - span
        # Buckets are hour-aligned; include the partial hour at the start.
        bucket_since = hour_bucket(since)

        totals = {
            t.protection: t
            for t in await self._repository.protection_totals(
                organization_id=organization_id, location=location, since=bucket_since
            )
        }
        rules = await self._repository.top_rules(
            organization_id=organization_id, location=location, since=bucket_since
        )
        routers_total = await self._repository.agent_managed_router_count(
            organization_id=organization_id, location=location
        )
        protections: list[dict[str, Any]] = []
        for protection in _ROUTER_PROTECTIONS:
            total = totals.get(protection.value)
            if total is None:
                # No rule of this kind was read on any router in scope during
                # the window: either the protection is not switched on, or no
                # reading has happened yet. Not a zero.
                continue
            protections.append(
                {
                    "key": protection.value,
                    "label": PROTECTION_LABELS[protection],
                    "count": total.packets,
                    "available": True,
                    "unavailable_reason": None,
                    "sentence": protection_sentence(protection, total.packets),
                    "source": "router",
                    "routers_reporting": total.routers,
                    "routers_total": routers_total,
                    "last_read_at": total.last_sampled_at,
                    "top_rules": [
                        {"label": r.label, "count": r.packets}
                        for r in rules
                        if r.protection == protection.value
                    ][:5],
                }
            )

        active_blocks, newly_blocked = await self._repository.device_block_counts(
            organization_id=organization_id, location=location, since=since
        )
        protections.append(
            {
                "key": Protection.DEVICE_BLOCK.value,
                "label": PROTECTION_LABELS[Protection.DEVICE_BLOCK],
                "count": active_blocks,
                "available": True,
                "unavailable_reason": None,
                "sentence": protection_sentence(Protection.DEVICE_BLOCK, active_blocks)
                + (
                    f" {newly_blocked} were blocked on a router in this period."
                    if newly_blocked
                    else ""
                ),
                "source": "records",
                "routers_reporting": None,
                "routers_total": routers_total,
                "last_read_at": now,
                "top_rules": [],
            }
        )

        cloudflare = await self._cloudflare_entry(
            organization_id=organization_id, location=location, since=since, now=now
        )
        if cloudflare is not None:
            protections.append(cloudflare)

        changes = await self._repository.recent_staff_changes(
            organization_id=organization_id, location=location, since=since
        )
        return {
            "window": window,
            "since": since,
            "until": now,
            "protections": protections,
            "staff_changes": [
                {
                    "at": c.at,
                    "action": c.action,
                    "summary": (
                        f"{c.actor_name or 'Someone on your team'} "
                        f"{_ACTION_TEXT.get(c.action, c.action.replace('_', ' '))}."
                    ),
                    "description": c.description,
                }
                for c in changes
            ],
            "routers_total": routers_total,
            "semantics": COUNTER_SEMANTICS,
            "generated_at": now,
        }

    async def _cloudflare_entry(
        self,
        *,
        organization_id: uuid.UUID,
        location: LocationFilter,
        since: datetime,
        now: datetime,
    ) -> dict[str, Any] | None:
        scope: CloudflareScope = await self._repository.cloudflare_scope(
            organization_id=organization_id, location=location
        )
        if scope.routers_filtering == 0:
            return None  # category filtering is not on here; nothing to report

        def unavailable(reason: str) -> dict[str, Any]:
            return {
                "key": Protection.CLOUDFLARE_DNS.value,
                "label": PROTECTION_LABELS[Protection.CLOUDFLARE_DNS],
                "count": None,
                "available": False,
                "unavailable_reason": reason,
                "sentence": None,
                "source": "cloudflare",
                "routers_reporting": None,
                "routers_total": scope.routers_filtering,
                "last_read_at": None,
                "top_rules": [],
            }

        if self._cloudflare_counter is None:
            return unavailable(
                self._cloudflare_unavailable_reason
                or "Cloudflare is not connected on this platform."
            )
        if not scope.exclusive_location_ids:
            return unavailable(
                "Your category filter settings are shared with other venues on "
                "Cloudflare, so Cloudflare cannot tell us which blocked lookups "
                "were yours."
            )
        try:
            counts = await self._cloudflare_counter(
                scope.exclusive_location_ids, since, now
            )
        except Exception as exc:  # noqa: BLE001 -- a third-party read degrades, never fails the page
            message = str(getattr(exc, "message", exc))
            logger.warning(
                "security_activity_cloudflare_unavailable",
                extra={"error": message[:300]},
            )
            return unavailable(
                "Cloudflare did not return blocked-lookup counts. The platform's "
                "Cloudflare token needs read access to account analytics."
                if "auth" in message.lower() or "permission" in message.lower()
                else "Cloudflare did not return blocked-lookup counts right now."
            )
        total = sum(counts.get(loc, 0) for loc in scope.exclusive_location_ids)
        entry = unavailable("")
        entry.update(
            {
                "count": total,
                "available": True,
                "unavailable_reason": (
                    "Some of your routers share filter settings with other venues "
                    "and are not included."
                    if scope.shared_location_ids
                    else None
                ),
                "sentence": protection_sentence(Protection.CLOUDFLARE_DNS, total),
                "last_read_at": now,
            }
        )
        return entry
