"""Auto-learn a NAS-only venue's public egress address from its guests.

## The problem

FreeRADIUS chooses a client -- and so the shared secret and the
``%{client:shortname}`` that ``CurrentNas`` maps to a NAS row -- by the
Access-Request's SOURCE address, before it decodes anything. A packet from
an address with no ``client{}`` stanza is dropped without a reply, which the
access point reports as a timeout.

An Aruba Instant On venue is a NAS keyed on its public NAT address
(``register_public_radius_nas``). Measured 2026-10-03 on the AP21: that
address is not stable. The same venue's guests reached the portal from
103.84.202.195 and, an hour later, from 111.223.3.241 -- and the hub logged
``Ignoring request ... from unknown client 111.223.3.241`` four times, five
seconds apart, as the AP retried and gave up.

## The signal

When an unauthenticated guest joins the SSID, the AP redirects the browser
to our portal and appends ``apmac``, ``nas-id`` and friends. That page load,
and every API call the portal makes, leaves the venue through the SAME NAT
as the AP's own RADIUS packets. So the portal fires one hint
(``POST /guest/portal/nas-egress-hint``) carrying the ``routerId`` from its
own URL plus the AP-appended ``apmac`` / ``nas-id``, and this module reads
the request's real client address (``trusted_client_ip``).

The portal page loads well before the AP sends its Access-Request (the
guest still has to type and verify an OTP), and the AP retries every 5 s;
adding a stanza costs one ``freeradius -CX`` (~50 ms) plus a restart (~3 s
on staging, measured 2026-10-03). So the stanza lands first.

## What is learned, and what it can never do

* A learned address is ADDED beside the operator-registered one -- one more
  ``client{}`` stanza with the same secret and shortname (see
  ``radius_agent.add_client``'s ``additional_addresses``). It never
  replaces the registered address, so a forged hint cannot move a venue
  away from its working address.
* Only an ``aruba_instant_on`` fleet row with an ACTIVE NAS learns, and only
  when the hint's ``nas-id`` equals that NAS's identifier and its ``apmac``
  matches the device's recorded MAC (when one is recorded). Both are
  plausibility filters, not authentication: both appear in a URL every
  guest at the venue can read.
* Only a literal, public, global-unicast address outside the WireGuard
  range is learned (``validate_controller_nas_address``): never private,
  CGNAT, loopback or link-local.
* An address any other NAS uses (registered or learned) is refused: two
  stanzas for one source address would make FreeRADIUS refuse its config,
  and two venues cannot share a source anyway.
* At most ``nas_egress_max_new_per_hour`` new addresses per NAS per hour,
  at most ``nas_egress_max_addresses`` held at once (least recently seen
  evicted at the cap), and an address unseen for ``nas_egress_ttl_days``
  days is removed -- except the most recently seen one, which is kept
  however old it is, because "the venue's guests have not been back" is
  not evidence that the venue moved.

## Abuse ceiling

Anyone who can read a venue's portal URL can send a hint from their own
address. What that buys them: their address becomes an accepted RADIUS
SOURCE for that one NAS. They still need the 32-character shared secret to
produce a valid Message-Authenticator (every stanza requires one), so they
can neither authenticate nor forge accounting; FreeRADIUS discards their
packets as it would a wrong-secret packet from the venue itself. The cost
they can impose is bounded by the limits above: a few hub restarts per NAS
per hour, and evicting learned (never registered) addresses. Nothing about a
guest is stored -- see ``RadiusNasLearnedAddress``.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from sqlalchemy import delete, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.guest.constants import NasStatus
from app.domains.guest.models import RadiusNasClient, RadiusNasLearnedAddress
from app.domains.guest.radius_bridge import (
    RadiusBridgePushError,
    RadiusClientAddressRejected,
    push_nas_address_set,
    validate_controller_nas_address,
)
from app.domains.router.crypto import decrypt_secret
from app.domains.router.vendor_capabilities import ARUBA_INSTANT_ON_VENDOR

logger = logging.getLogger(__name__)

#: ``RadiusNasLearnedAddress.source`` for an address learned from the portal.
SOURCE_PORTAL_HINT = "portal_hint"

#: A repeat sighting refreshes ``last_seen_at`` at most this often: a busy
#: venue's every page load must not be a database write.
REFRESH_INTERVAL = timedelta(minutes=10)

_MAC_RE = re.compile(r"^[0-9a-f]{12}$")


class LearnOutcome(StrEnum):
    """Why a hint did or did not change anything. Logged, never returned to
    the (unauthenticated) caller."""

    DISABLED = "disabled"
    NO_CLIENT_ADDRESS = "no_client_address"
    NOT_PUBLIC = "not_public"
    UNKNOWN_ROUTER = "unknown_router"
    NOT_ARUBA = "not_aruba_instant_on"
    NO_ACTIVE_NAS = "no_active_nas"
    NAS_ID_MISMATCH = "nas_id_mismatch"
    AP_MAC_MISMATCH = "ap_mac_mismatch"
    PRIMARY = "registered_address"
    REFRESHED = "refreshed"
    LEARNED = "learned"
    LEARNED_UNCONFIRMED = "learned_hub_unconfirmed"
    RATE_LIMITED = "rate_limited"
    ADDRESS_IN_USE = "address_in_use_by_another_nas"
    PUSH_FAILED = "push_failed"


@dataclass(frozen=True)
class EgressHint:
    router_id: uuid.UUID
    client_ip: str | None
    nas_id: str | None
    ap_mac: str | None
    source: str = SOURCE_PORTAL_HINT


@dataclass(frozen=True)
class EgressPolicy:
    enabled: bool
    ttl: timedelta
    max_addresses: int
    max_new_per_hour: int

    @classmethod
    def from_settings(cls, settings: Any) -> EgressPolicy:
        return cls(
            enabled=bool(settings.nas_egress_learning_enabled),
            ttl=timedelta(days=int(settings.nas_egress_ttl_days)),
            max_addresses=int(settings.nas_egress_max_addresses),
            max_new_per_hour=int(settings.nas_egress_max_new_per_hour),
        )


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def _parse_cidrs(raw: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    out = []
    for part in (raw or "").split(","):
        part = part.strip()
        if part:
            try:
                out.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                logger.warning(
                    "nas_egress_bad_trusted_proxy_cidr", extra={"cidr": part}
                )
    return out


def trusted_client_ip(
    *, peer: str | None, headers: Any, trusted_proxy_cidrs: str
) -> str | None:
    """The address the request really came from.

    uvicorn here trusts forwarded headers only from a literal 127.0.0.1
    (``--forwarded-allow-ips``), but the host nginx reaches the api container
    through the Docker bridge, so ``request.client.host`` is the bridge
    gateway (172.18.0.1 on staging, measured 2026-10-03) for every request.

    nginx sets ``X-Real-IP $remote_addr`` -- it OVERWRITES whatever a client
    sent -- so that header is believed, but only when the direct peer is a
    trusted proxy. ``X-Forwarded-For`` is ``$proxy_add_x_forwarded_for``,
    which APPENDS: its leftmost entries are whatever the client typed, so
    only its rightmost entry (the one nginx added) is ever used, and only as
    a fallback.
    """
    if not peer:
        return None
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return None
    if not any(peer_ip in net for net in _parse_cidrs(trusted_proxy_cidrs)):
        return str(peer_ip)
    real = (headers.get("x-real-ip") or "").strip()
    if not real:
        forwarded = (headers.get("x-forwarded-for") or "").split(",")
        real = forwarded[-1].strip() if forwarded else ""
    if not real:
        return None
    try:
        return str(ipaddress.ip_address(real))
    except ValueError:
        return None


def canonical_mac(raw: str | None) -> str | None:
    """``AA:BB:CC:DD:EE:FF`` from any of the usual spellings, else None."""
    if not raw:
        return None
    hexed = re.sub(r"[^0-9a-fA-F]", "", raw).lower()
    if not _MAC_RE.match(hexed):
        return None
    return ":".join(hexed[i : i + 2] for i in range(0, 12, 2)).upper()


def learnable_address(raw: str | None) -> str | None:
    """The address if it may ever be a learned NAS source, else None."""
    if not raw:
        return None
    try:
        return validate_controller_nas_address(raw)
    except RadiusClientAddressRejected:
        return None


def active_rows(
    rows: Sequence[RadiusNasLearnedAddress], *, now: datetime, ttl: timedelta
) -> tuple[list[RadiusNasLearnedAddress], list[RadiusNasLearnedAddress]]:
    """``(keep, expired)``. Expired = unseen for ``ttl``, except the single
    most recently seen row, which is always kept."""
    if not rows:
        return [], []
    newest = max(rows, key=lambda r: r.last_seen_at)
    keep, expired = [], []
    for row in rows:
        if row is not newest and row.last_seen_at < now - ttl:
            expired.append(row)
        else:
            keep.append(row)
    return keep, expired


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


class LearnedAddressStore(Protocol):
    async def get_router(self, router_id: uuid.UUID) -> Any | None: ...
    async def get_nas_for_router(self, router_id: uuid.UUID) -> Any | None: ...
    async def lock_nas(self, nas_client_id: uuid.UUID) -> None: ...
    async def list_for_nas(
        self, nas_client_id: uuid.UUID
    ) -> list[RadiusNasLearnedAddress]: ...
    async def address_used_elsewhere(
        self, address: str, nas_client_id: uuid.UUID
    ) -> bool: ...
    async def add(
        self,
        *,
        nas_client_id: uuid.UUID,
        router_id: uuid.UUID,
        address: str,
        source: str,
        now: datetime,
    ) -> RadiusNasLearnedAddress: ...
    async def delete_rows(self, rows: Sequence[RadiusNasLearnedAddress]) -> None: ...
    async def nas_ids_with_learned(self) -> list[uuid.UUID]: ...
    async def learned_by_other_router(
        self, address: str, router_id: uuid.UUID
    ) -> bool: ...
    async def get_nas(self, nas_client_id: uuid.UUID) -> Any | None: ...
    async def flush(self) -> None: ...


class SqlLearnedAddressStore:
    """Postgres-backed store. ``lock_nas`` takes a transaction-scoped
    advisory lock, so two hints for one NAS compute and push its address set
    one after the other -- never two pushes with different sets racing to
    be the last write on the hub."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_router(self, router_id: uuid.UUID) -> Any | None:
        from app.domains.router.models import Router

        result = await self.session.execute(
            select(Router).where(Router.id == router_id, Router.is_deleted.is_(False))
        )
        return result.scalar_one_or_none()

    async def get_nas_for_router(self, router_id: uuid.UUID) -> Any | None:
        result = await self.session.execute(
            select(RadiusNasClient).where(
                RadiusNasClient.router_id == router_id,
                RadiusNasClient.is_deleted.is_(False),
            )
        )
        return result.scalar_one_or_none()

    async def get_nas(self, nas_client_id: uuid.UUID) -> Any | None:
        result = await self.session.execute(
            select(RadiusNasClient).where(
                RadiusNasClient.id == nas_client_id,
                RadiusNasClient.is_deleted.is_(False),
            )
        )
        return result.scalar_one_or_none()

    async def lock_nas(self, nas_client_id: uuid.UUID) -> None:
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
            {"key": f"nas_egress:{nas_client_id}"},
        )

    async def list_for_nas(
        self, nas_client_id: uuid.UUID
    ) -> list[RadiusNasLearnedAddress]:
        result = await self.session.execute(
            select(RadiusNasLearnedAddress)
            .where(RadiusNasLearnedAddress.nas_client_id == nas_client_id)
            .order_by(RadiusNasLearnedAddress.last_seen_at.desc())
        )
        return list(result.scalars().all())

    async def address_used_elsewhere(
        self, address: str, nas_client_id: uuid.UUID
    ) -> bool:
        registered = await self.session.execute(
            select(func.count())
            .select_from(RadiusNasClient)
            .where(
                RadiusNasClient.id != nas_client_id,
                RadiusNasClient.is_deleted.is_(False),
                or_(
                    RadiusNasClient.ip_address == address,
                    RadiusNasClient.hub_client_synced_ip == address,
                ),
            )
        )
        if registered.scalar_one():
            return True
        learned = await self.session.execute(
            select(func.count())
            .select_from(RadiusNasLearnedAddress)
            .where(
                RadiusNasLearnedAddress.nas_client_id != nas_client_id,
                RadiusNasLearnedAddress.ip_address == address,
            )
        )
        return bool(learned.scalar_one())

    async def add(
        self,
        *,
        nas_client_id: uuid.UUID,
        router_id: uuid.UUID,
        address: str,
        source: str,
        now: datetime,
    ) -> RadiusNasLearnedAddress:
        row = RadiusNasLearnedAddress(
            nas_client_id=nas_client_id,
            router_id=router_id,
            ip_address=address,
            source=source,
            first_seen_at=now,
            last_seen_at=now,
            hit_count=1,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def delete_rows(self, rows: Sequence[RadiusNasLearnedAddress]) -> None:
        ids = [r.id for r in rows]
        if ids:
            await self.session.execute(
                delete(RadiusNasLearnedAddress).where(
                    RadiusNasLearnedAddress.id.in_(ids)
                )
            )

    async def nas_ids_with_learned(self) -> list[uuid.UUID]:
        result = await self.session.execute(
            select(RadiusNasLearnedAddress.nas_client_id).distinct()
        )
        return list(result.scalars().all())

    async def learned_by_other_router(self, address: str, router_id: uuid.UUID) -> bool:
        result = await self.session.execute(
            select(func.count())
            .select_from(RadiusNasLearnedAddress)
            .where(
                RadiusNasLearnedAddress.router_id != router_id,
                RadiusNasLearnedAddress.ip_address == address,
            )
        )
        return bool(result.scalar_one())

    async def flush(self) -> None:
        await self.session.flush()


# ---------------------------------------------------------------------------
# The learner
# ---------------------------------------------------------------------------

PushAddressSet = Callable[..., Awaitable[list[str] | None]]


class NasEgressLearner:
    def __init__(
        self,
        store: LearnedAddressStore,
        policy: EgressPolicy,
        *,
        push: PushAddressSet | None = None,
        decrypt: Callable[[str], str] = decrypt_secret,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.store = store
        self.policy = policy
        self._push = push
        self._decrypt = decrypt
        self._clock = clock

    async def _push_set(self, **kwargs: Any) -> list[str] | None:
        # Resolved at call time so tests can monkeypatch the module function.
        push = self._push or push_nas_address_set
        return await push(**kwargs)

    # -- the learn path ------------------------------------------------------

    async def learn(self, hint: EgressHint) -> LearnOutcome:
        outcome = await self._learn(hint)
        logger.info(
            "nas_egress_hint",
            extra={
                "router_id": str(hint.router_id),
                "client_ip": hint.client_ip,
                "outcome": outcome.value,
            },
        )
        return outcome

    async def _learn(self, hint: EgressHint) -> LearnOutcome:
        if not self.policy.enabled:
            return LearnOutcome.DISABLED
        if not hint.client_ip:
            return LearnOutcome.NO_CLIENT_ADDRESS
        address = learnable_address(hint.client_ip)
        if address is None:
            return LearnOutcome.NOT_PUBLIC

        router = await self.store.get_router(hint.router_id)
        if router is None:
            return LearnOutcome.UNKNOWN_ROUTER
        # Vendor-gated to Aruba Instant On, not to "NAS-only" in general: a
        # MikroTik or Omada NAS is keyed on an address this platform knows,
        # and must behave exactly as before.
        if str(router.vendor) != ARUBA_INSTANT_ON_VENDOR:
            return LearnOutcome.NOT_ARUBA
        nas = await self.store.get_nas_for_router(router.id)
        if nas is None or str(nas.status) != NasStatus.ACTIVE.value:
            return LearnOutcome.NO_ACTIVE_NAS
        if (hint.nas_id or "").strip() != nas.nas_identifier:
            return LearnOutcome.NAS_ID_MISMATCH
        recorded_mac = canonical_mac(getattr(router, "mac_address", None))
        hinted_mac = canonical_mac(hint.ap_mac)
        if hinted_mac is None or (recorded_mac and hinted_mac != recorded_mac):
            return LearnOutcome.AP_MAC_MISMATCH

        primary = nas.hub_client_synced_ip or nas.ip_address
        if address == primary:
            return LearnOutcome.PRIMARY

        await self.store.lock_nas(nas.id)
        now = self._clock()
        rows = await self.store.list_for_nas(nas.id)
        existing = next((r for r in rows if r.ip_address == address), None)
        if existing is not None:
            return await self._refresh(nas, rows, existing, now)

        recent = [r for r in rows if r.first_seen_at > now - timedelta(hours=1)]
        if len(recent) >= self.policy.max_new_per_hour:
            logger.warning(
                "nas_egress_rate_limited",
                extra={"nas_identifier": nas.nas_identifier, "client_ip": address},
            )
            return LearnOutcome.RATE_LIMITED
        if await self.store.address_used_elsewhere(address, nas.id):
            logger.warning(
                "nas_egress_address_in_use",
                extra={"nas_identifier": nas.nas_identifier, "client_ip": address},
            )
            return LearnOutcome.ADDRESS_IN_USE

        new_row = await self.store.add(
            nas_client_id=nas.id,
            router_id=router.id,
            address=address,
            source=hint.source,
            now=now,
        )
        rows = [new_row, *rows]
        keep, drop = active_rows(rows, now=now, ttl=self.policy.ttl)
        # Make room at the cap: least recently seen first, never the new one.
        keep.sort(key=lambda r: r.last_seen_at, reverse=True)
        while len(keep) > self.policy.max_addresses:
            drop.append(keep.pop())
        await self.store.delete_rows(drop)

        confirmed = await self._sync(nas, keep, now)
        if confirmed is None:
            return LearnOutcome.PUSH_FAILED
        if address not in confirmed:
            return LearnOutcome.LEARNED_UNCONFIRMED
        logger.warning(
            # WARNING, not INFO: a new RADIUS source address for a venue is
            # an operator-visible security event, worth an alert rule.
            "nas_egress_learned",
            extra={
                "nas_identifier": nas.nas_identifier,
                "client_ip": address,
                "addresses": [primary, *[r.ip_address for r in keep]],
                "evicted": [r.ip_address for r in drop],
            },
        )
        return LearnOutcome.LEARNED

    async def _refresh(
        self,
        nas: Any,
        rows: list[RadiusNasLearnedAddress],
        row: RadiusNasLearnedAddress,
        now: datetime,
    ) -> LearnOutcome:
        if row.last_seen_at > now - REFRESH_INTERVAL and row.hub_confirmed_at:
            return LearnOutcome.REFRESHED
        row.last_seen_at = now
        row.hit_count = (row.hit_count or 0) + 1
        await self.store.flush()
        if row.hub_confirmed_at is None:
            # The earlier push failed or met an old agent: try again, at most
            # once per REFRESH_INTERVAL per address (the throttle above).
            keep, drop = active_rows(rows, now=now, ttl=self.policy.ttl)
            await self.store.delete_rows(drop)
            confirmed = await self._sync(nas, keep, now)
            if confirmed is None:
                return LearnOutcome.PUSH_FAILED
            if row.ip_address not in confirmed:
                return LearnOutcome.LEARNED_UNCONFIRMED
            return LearnOutcome.LEARNED
        return LearnOutcome.REFRESHED

    # -- hub sync -----------------------------------------------------------

    async def _sync(
        self, nas: Any, keep: Sequence[RadiusNasLearnedAddress], now: datetime
    ) -> list[str] | None:
        """Push the NAS's whole set (registered + ``keep``). Returns the
        addresses the hub confirmed, ``[]`` for an agent that predates the
        multi-address protocol, ``None`` when the push failed."""
        primary = nas.hub_client_synced_ip or nas.ip_address
        if not primary:
            return None
        try:
            confirmed = await self._push_set(
                primary_ip=primary,
                additional_addresses=[r.ip_address for r in keep],
                nas_identifier=nas.nas_identifier,
                secret=self._decrypt(nas.shared_secret_encrypted),
            )
        except (RadiusBridgePushError, RadiusClientAddressRejected) as exc:
            logger.warning(
                "nas_egress_push_failed",
                extra={
                    "nas_identifier": nas.nas_identifier,
                    "detail": getattr(exc, "detail", str(exc)),
                },
            )
            return None
        if confirmed is None:
            logger.warning(
                "nas_egress_agent_lacks_multi_address",
                extra={"nas_identifier": nas.nas_identifier},
            )
            confirmed = []
        mark_confirmed(keep, confirmed, now)
        await self.store.flush()
        return confirmed

    async def sync_nas(self, nas: Any) -> list[str] | None:
        """Re-push one NAS's set after pruning expired rows (operator remove,
        daily prune)."""
        await self.store.lock_nas(nas.id)
        now = self._clock()
        rows = await self.store.list_for_nas(nas.id)
        keep, drop = active_rows(rows, now=now, ttl=self.policy.ttl)
        await self.store.delete_rows(drop)
        return await self._sync(nas, keep, now)

    async def remove(self, nas: Any, address: str) -> bool:
        """Operator removal of one learned address, then re-push."""
        await self.store.lock_nas(nas.id)
        rows = await self.store.list_for_nas(nas.id)
        doomed = [r for r in rows if r.ip_address == address]
        if not doomed:
            return False
        await self.store.delete_rows(doomed)
        keep = [r for r in rows if r.ip_address != address]
        confirmed = await self._sync(nas, keep, self._clock())
        if confirmed is None:
            raise RadiusBridgePushError(
                "The RADIUS server bridge did not confirm the new address set",
                transport=False,
                status_code=None,
            )
        return True

    async def prune_all(self) -> dict[str, int]:
        """Daily: drop expired learned addresses everywhere and re-push only
        the NAS whose set actually changed."""
        pruned = 0
        pushed = 0
        now = self._clock()
        for nas_id in await self.store.nas_ids_with_learned():
            nas = await self.store.get_nas(nas_id)
            rows = await self.store.list_for_nas(nas_id)
            _keep, expired = active_rows(rows, now=now, ttl=self.policy.ttl)
            if not expired:
                continue
            if nas is None:
                await self.store.delete_rows(rows)
                continue
            pruned += len(expired)
            if await self.sync_nas(nas) is not None:
                pushed += 1
            logger.info(
                "nas_egress_pruned",
                extra={
                    "nas_identifier": nas.nas_identifier,
                    "expired": [r.ip_address for r in expired],
                },
            )
        return {"pruned": pruned, "pushed": pushed}

    async def learned_addresses_for_push(
        self, nas: Any, *, primary_ip: str
    ) -> list[str]:
        """The learned addresses a rotation/re-registration must carry over
        so it does not silently drop them from the hub. A learned row equal
        to the (new) registered address is dropped: it has been promoted."""
        if not self.policy.enabled:
            return []
        rows = await self.store.list_for_nas(nas.id)
        keep, expired = active_rows(rows, now=self._clock(), ttl=self.policy.ttl)
        promoted = [r for r in keep if r.ip_address == primary_ip]
        await self.store.delete_rows([*expired, *promoted])
        return [r.ip_address for r in keep if r.ip_address != primary_ip]

    async def record_confirmed(self, nas: Any, confirmed: Sequence[str] | None) -> None:
        rows = await self.store.list_for_nas(nas.id)
        mark_confirmed(rows, confirmed or [], self._clock())
        await self.store.flush()

    async def learned_elsewhere(self, address: str, router_id: uuid.UUID) -> bool:
        return await self.store.learned_by_other_router(address, router_id)


def mark_confirmed(
    rows: Sequence[RadiusNasLearnedAddress], confirmed: Sequence[str], now: datetime
) -> None:
    hub = set(confirmed)
    for row in rows:
        row.hub_confirmed_at = now if row.ip_address in hub else None


def learner_for_session(session: AsyncSession, settings: Any) -> NasEgressLearner:
    return NasEgressLearner(
        SqlLearnedAddressStore(session), EgressPolicy.from_settings(settings)
    )


def learner_for_radius_service(service: Any, settings: Any) -> NasEgressLearner | None:
    """The learner behind a ``RadiusService``'s own session, or None when the
    service has no real repository session (unit-test fakes) or the feature
    is off -- in which case callers keep their pre-learning behaviour."""
    if not getattr(settings, "nas_egress_learning_enabled", False):
        return None
    session = getattr(getattr(service, "repository", None), "session", None)
    if not isinstance(session, AsyncSession):
        return None
    return learner_for_session(session, settings)


__all__ = [
    "EgressHint",
    "EgressPolicy",
    "LearnOutcome",
    "NasEgressLearner",
    "SOURCE_PORTAL_HINT",
    "SqlLearnedAddressStore",
    "active_rows",
    "canonical_mac",
    "learnable_address",
    "learner_for_radius_service",
    "learner_for_session",
    "trusted_client_ip",
]
