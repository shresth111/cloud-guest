"""Aruba Instant On: more than one access point per site.

One Instant On SITE is one Wyfy location and ONE NAS-only fleet ``Router``
(the NAS-Identifier owner). Every AP in the site sends that NAS-Identifier
and its own MAC at the front of ``Called-Station-Id``. The shared listener
used to accept only the router's own ``mac_address``, so a guest on AP #2
was refused with ``ap_mac_mismatch``.

This module owns ``aruba_access_points``:

* :class:`ArubaAccessPointRepository` -- the table, on the caller's session.
* :class:`DbArubaApRegistry` -- what ``aruba_shared.resolve_shared_nas``
  asks: which MACs are approved for a router, plus two best-effort writes
  (record an unknown MAC as ``pending``; stamp an approved AP's
  ``last_seen_at``). The unknown-MAC write uses a session of its own and
  commits it, because the refused request's own transaction is rolled back.
* :func:`sync_from_instant_on_inventory` -- the poller's upsert of the
  owner's own Instant On inventory as ``approved`` rows.
* :func:`set_session_ap` -- the only writer of ``guest_sessions.ap_mac``.

Nothing here is reachable from a MikroTik or Omada NAS: the resolver only
calls the registry after it has proved the NAS row is an
``aruba_instant_on`` router.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .models import ArubaAccessPoint, ArubaAccessPointSource, ArubaAccessPointStatus

logger = logging.getLogger(__name__)

__all__ = [
    "AP_SEEN_WRITE_INTERVAL",
    "MAX_PENDING_PER_ROUTER",
    "ApSessionStats",
    "ArubaAccessPointRepository",
    "ArubaAccessPointService",
    "AP_ONLINE_WINDOW",
    "DbArubaApRegistry",
    "set_session_ap",
    "ssid_from_called_station_id",
    "sync_from_instant_on_inventory",
]

#: ``last_seen_at`` is stamped at most this often per AP: one RADIUS packet
#: must not mean one UPDATE.
AP_SEEN_WRITE_INTERVAL = timedelta(seconds=60)

#: A router never accumulates more than this many un-reviewed MACs. A
#: request reaching the resolver already carried the hub-only backend
#: secret, so this is a bound on a misbehaving site, not on the internet.
MAX_PENDING_PER_ROUTER = 20


def _now() -> datetime:
    return datetime.now(UTC)


def ssid_from_called_station_id(raw: str | None) -> str | None:
    """The SSID after the AP MAC in ``Called-Station-Id`` (RFC 3580 s3.20's
    ``AA-BB-CC-DD-EE-FF:SSID``), or None when there is none."""
    from app.domains.guest.aruba_shared import _MAC_PREFIX_RE

    if not raw:
        return None
    match = _MAC_PREFIX_RE.match(raw)
    if match is None:
        return None
    rest = raw[match.end() :]
    if not rest.startswith(":"):
        return None
    ssid = rest[1:].strip()
    return ssid[:64] or None


def _clean_serial(raw: str | None) -> str | None:
    if not raw:
        return None
    cleaned = "".join(ch for ch in raw.strip() if ch.isalnum() or ch in "-_.")
    return cleaned[:128] or None


@dataclass(frozen=True)
class ApSessionStats:
    clients_now: int = 0
    sessions_today: int = 0
    download_bytes_today: int = 0
    upload_bytes_today: int = 0
    last_activity_at: datetime | None = None


class ArubaAccessPointRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # -- reads -------------------------------------------------------------

    async def approved_macs(self, router_id: uuid.UUID) -> set[str]:
        rows = await self.session.execute(
            select(ArubaAccessPoint.mac).where(
                ArubaAccessPoint.router_id == router_id,
                ArubaAccessPoint.status == ArubaAccessPointStatus.APPROVED.value,
                ArubaAccessPoint.is_deleted.is_(False),
            )
        )
        return {mac for (mac,) in rows.all()}

    async def list_for_router(self, router_id: uuid.UUID) -> list[ArubaAccessPoint]:
        rows = await self.session.execute(
            select(ArubaAccessPoint)
            .where(
                ArubaAccessPoint.router_id == router_id,
                ArubaAccessPoint.is_deleted.is_(False),
            )
            .order_by(ArubaAccessPoint.created_at)
        )
        return list(rows.scalars().all())

    async def get_for_router(
        self, router_id: uuid.UUID, ap_id: uuid.UUID
    ) -> ArubaAccessPoint | None:
        rows = await self.session.execute(
            select(ArubaAccessPoint).where(
                ArubaAccessPoint.id == ap_id,
                ArubaAccessPoint.router_id == router_id,
                ArubaAccessPoint.is_deleted.is_(False),
            )
        )
        return rows.scalar_one_or_none()

    async def get_by_mac(
        self, router_id: uuid.UUID, mac: str
    ) -> ArubaAccessPoint | None:
        rows = await self.session.execute(
            select(ArubaAccessPoint).where(
                ArubaAccessPoint.router_id == router_id,
                ArubaAccessPoint.mac == mac,
                ArubaAccessPoint.is_deleted.is_(False),
            )
        )
        return rows.scalar_one_or_none()

    async def count_pending(self, router_id: uuid.UUID) -> int:
        rows = await self.session.execute(
            select(func.count())
            .select_from(ArubaAccessPoint)
            .where(
                ArubaAccessPoint.router_id == router_id,
                ArubaAccessPoint.status == ArubaAccessPointStatus.PENDING.value,
                ArubaAccessPoint.is_deleted.is_(False),
            )
        )
        return int(rows.scalar_one())

    async def list_approved_for_location(
        self, *, organization_id: uuid.UUID, location_id: uuid.UUID
    ) -> list[ArubaAccessPoint]:
        """Customer read: the tenant AND the venue are both in the WHERE."""
        rows = await self.session.execute(
            select(ArubaAccessPoint)
            .where(
                ArubaAccessPoint.organization_id == organization_id,
                ArubaAccessPoint.location_id == location_id,
                ArubaAccessPoint.status == ArubaAccessPointStatus.APPROVED.value,
                ArubaAccessPoint.is_deleted.is_(False),
            )
            .order_by(ArubaAccessPoint.created_at)
        )
        return list(rows.scalars().all())

    async def names_for(
        self, pairs: Iterable[tuple[uuid.UUID, str]]
    ) -> dict[tuple[uuid.UUID, str], str]:
        """``(router_id, mac) -> name`` for approved, named APs. One query."""
        wanted = list(dict.fromkeys(pairs))
        if not wanted:
            return {}
        router_ids = {rid for rid, _ in wanted}
        macs = {mac for _, mac in wanted}
        rows = await self.session.execute(
            select(
                ArubaAccessPoint.router_id, ArubaAccessPoint.mac, ArubaAccessPoint.name
            ).where(
                ArubaAccessPoint.router_id.in_(router_ids),
                ArubaAccessPoint.mac.in_(macs),
                ArubaAccessPoint.is_deleted.is_(False),
            )
        )
        wanted_set = set(wanted)
        return {
            (rid, mac): name
            for rid, mac, name in rows.all()
            if name and (rid, mac) in wanted_set
        }

    async def session_stats(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        router_ids: Sequence[uuid.UUID],
        since: datetime,
    ) -> tuple[dict[tuple[uuid.UUID, str], ApSessionStats], int]:
        """Per ``(router_id, ap_mac)``: ACTIVE sessions now, sessions started
        since ``since``, bytes of sessions started since ``since`` or still
        active, and the latest ``last_activity_at`` (refreshed by every
        accounting packet). Plus the count of ACTIVE sessions at these
        routers with no AP recorded (accounted before ``ap_mac`` existed).

        Organization and location are in the WHERE as well as the router
        ids, so a router id from elsewhere can never widen the read."""
        from app.domains.guest.constants import GuestSessionStatus
        from app.domains.guest.models import GuestSession

        if not router_ids:
            return {}, 0
        active = GuestSessionStatus.ACTIVE.value
        is_active = GuestSession.status == active
        started_today = GuestSession.started_at >= since
        in_window = or_(is_active, started_today)
        base = and_(
            GuestSession.organization_id == organization_id,
            GuestSession.location_id == location_id,
            GuestSession.router_id.in_(list(router_ids)),
            GuestSession.is_deleted.is_(False),
        )
        rows = await self.session.execute(
            select(
                GuestSession.router_id,
                GuestSession.ap_mac,
                func.count().filter(is_active),
                func.count().filter(started_today),
                func.coalesce(
                    func.sum(GuestSession.bytes_downloaded).filter(in_window), 0
                ),
                func.coalesce(
                    func.sum(GuestSession.bytes_uploaded).filter(in_window), 0
                ),
                func.max(GuestSession.last_activity_at),
            )
            .where(base, GuestSession.ap_mac.is_not(None), in_window)
            .group_by(GuestSession.router_id, GuestSession.ap_mac)
        )
        stats = {
            (rid, mac): ApSessionStats(
                clients_now=int(now_n or 0),
                sessions_today=int(today_n or 0),
                download_bytes_today=int(down or 0),
                upload_bytes_today=int(up or 0),
                last_activity_at=last,
            )
            for rid, mac, now_n, today_n, down, up, last in rows.all()
        }
        unattributed = await self.session.execute(
            select(func.count())
            .select_from(GuestSession)
            .where(base, GuestSession.ap_mac.is_(None), is_active)
        )
        return stats, int(unattributed.scalar_one())

    # -- writes ------------------------------------------------------------

    async def create(self, data: dict[str, Any]) -> ArubaAccessPoint:
        ap = ArubaAccessPoint(**data)
        self.session.add(ap)
        await self.session.flush()
        await self.session.refresh(ap)
        return ap

    async def update(
        self, ap: ArubaAccessPoint, data: dict[str, Any]
    ) -> ArubaAccessPoint:
        for key, value in data.items():
            setattr(ap, key, value)
        await self.session.flush()
        await self.session.refresh(ap)
        return ap

    async def soft_delete(self, ap: ArubaAccessPoint) -> None:
        ap.is_deleted = True
        ap.deleted_at = _now()
        await self.session.flush()

    async def touch_seen(
        self, router_id: uuid.UUID, mac: str, *, now: datetime
    ) -> None:
        """Stamp ``last_seen_at`` unless it was stamped within
        :data:`AP_SEEN_WRITE_INTERVAL`. A conditional UPDATE, so a busy AP
        costs one no-op statement per packet, not a row write."""
        await self.session.execute(
            update(ArubaAccessPoint)
            .where(
                ArubaAccessPoint.router_id == router_id,
                ArubaAccessPoint.mac == mac,
                ArubaAccessPoint.is_deleted.is_(False),
                or_(
                    ArubaAccessPoint.last_seen_at.is_(None),
                    ArubaAccessPoint.last_seen_at < now - AP_SEEN_WRITE_INTERVAL,
                ),
            )
            .values(last_seen_at=now)
            .execution_options(synchronize_session=False)
        )


# ---------------------------------------------------------------------------
# What the shared listener's resolver asks
# ---------------------------------------------------------------------------


class DbArubaApRegistry:
    """``aruba_shared.ApRegistry`` over the database. Every method that
    writes is best-effort: a registry failure must never turn a RADIUS
    decision the resolver has already made into a different one."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        session_factory: Callable[[], Any] | None = None,
        clock: Callable[[], datetime] = _now,
        serial_hint: str | None = None,
    ) -> None:
        self.repository = ArubaAccessPointRepository(session)
        # The packet's Aruba-Location-Id (the AP serial on Instant On), kept
        # on a NEW pending row to help Master match it to the inventory.
        # Sender-controlled like the MAC: display only, never trusted.
        self.serial_hint = _clean_serial(serial_hint)
        self.session_factory = session_factory
        self.clock = clock

    async def approved_macs(self, router_id: uuid.UUID) -> set[str]:
        return await self.repository.approved_macs(router_id)

    async def touch(self, router_id: uuid.UUID, mac: str) -> None:
        try:
            await self.repository.touch_seen(router_id, mac, now=self.clock())
        except Exception:  # noqa: BLE001 -- see class docstring
            logger.warning(
                "aruba_ap_touch_failed",
                extra={"router_id": str(router_id), "ap_mac": mac},
            )

    async def record_unknown(self, router: Any, mac: str) -> None:
        """Record a refused AP MAC as ``pending``/``discovered`` for Master
        to review, or refresh the ``last_seen_at`` of a row that already
        exists (pending or rejected). Never approves. On its own session,
        committed, because the caller's transaction is about to be rolled
        back with the refusal."""
        factory = self.session_factory
        if factory is None:
            from app.database.session import SessionLocal

            factory = SessionLocal
        now = self.clock()
        try:
            async with factory() as session:
                repo = ArubaAccessPointRepository(session)
                existing = await repo.get_by_mac(router.id, mac)
                if existing is not None:
                    await repo.touch_seen(router.id, mac, now=now)
                elif await repo.count_pending(router.id) < MAX_PENDING_PER_ROUTER:
                    await repo.create(
                        {
                            "organization_id": router.organization_id,
                            "location_id": router.location_id,
                            "router_id": router.id,
                            "mac": mac,
                            "source": ArubaAccessPointSource.DISCOVERED.value,
                            "status": ArubaAccessPointStatus.PENDING.value,
                            "serial": self.serial_hint,
                            "first_seen_at": now,
                            "last_seen_at": now,
                        }
                    )
                    logger.warning(
                        "aruba_ap_discovered_pending",
                        extra={"router_id": str(router.id), "ap_mac": mac},
                    )
                await session.commit()
        except IntegrityError:
            # A concurrent packet from the same AP inserted it first.
            pass
        except Exception:  # noqa: BLE001 -- see class docstring
            logger.warning(
                "aruba_ap_record_unknown_failed",
                extra={"router_id": str(getattr(router, "id", "")), "ap_mac": mac},
            )


# ---------------------------------------------------------------------------
# guest_sessions.ap_mac -- written only from the shared Aruba listener
# ---------------------------------------------------------------------------


async def set_session_ap(
    session: AsyncSession,
    *,
    guest_session_id: uuid.UUID,
    ap_mac: str,
    ap_ssid: str | None,
) -> None:
    """Record the AP (and SSID) a session was last reported from. A
    conditional UPDATE: a guest who stays on one AP costs no row write.

    ``ap_ssid=None`` keeps the recorded SSID: a real Instant On AP sends the
    SSID (VSA ``Aruba-Essid-Name``) on Access-Request / Start only, never on
    Interim or Stop, and its Called-Station-Id carries no ``:SSID`` suffix
    (measured 2026-10-03), so an Interim must not erase what Start wrote."""
    from app.domains.guest.models import GuestSession

    changed = GuestSession.ap_mac.is_distinct_from(ap_mac)
    values: dict[str, Any] = {"ap_mac": ap_mac}
    if ap_ssid is not None:
        changed = or_(changed, GuestSession.ap_ssid.is_distinct_from(ap_ssid))
        values["ap_ssid"] = ap_ssid
    await session.execute(
        update(GuestSession)
        .where(GuestSession.id == guest_session_id, changed)
        .values(**values)
        .execution_options(synchronize_session=False)
    )


# ---------------------------------------------------------------------------
# The poller: the owner's Instant On inventory
# ---------------------------------------------------------------------------


async def sync_from_instant_on_inventory(
    session: AsyncSession,
    *,
    site: Any,
    access_points: Sequence[dict[str, Any]],
    now: datetime,
) -> int:
    """Upsert the APs Instant On lists for this site as ``approved`` rows of
    the site's router (``site.router_id`` -- the mapping Master made). The
    inventory is the owner's own account data, so it may approve; a MAC
    Master has REJECTED stays rejected. Name/serial/model are refreshed on
    every row the inventory names. Returns the number of rows written."""
    from app.domains.guest.aruba_shared import canonical_mac, is_placeholder_mac

    repo = ArubaAccessPointRepository(session)
    written = 0
    for record in access_points:
        mac = canonical_mac(record.get("mac"))
        if mac is None or is_placeholder_mac(mac):
            continue
        details = {
            k: v
            for k, v in (
                ("name", record.get("name")),
                ("serial", record.get("serial_number")),
                ("model", record.get("model")),
            )
            if v
        }
        existing = await repo.get_by_mac(site.router_id, mac)
        if existing is None:
            await repo.create(
                {
                    "organization_id": site.organization_id,
                    "location_id": site.location_id,
                    "router_id": site.router_id,
                    "mac": mac,
                    "source": ArubaAccessPointSource.INSTANT_ON.value,
                    "status": ArubaAccessPointStatus.APPROVED.value,
                    "first_seen_at": now,
                    **details,
                }
            )
            written += 1
            continue
        changes: dict[str, Any] = {
            k: v for k, v in details.items() if getattr(existing, k) != v
        }
        if existing.status == ArubaAccessPointStatus.PENDING.value:
            changes["status"] = ArubaAccessPointStatus.APPROVED.value
            changes["source"] = ArubaAccessPointSource.INSTANT_ON.value
        if changes:
            await repo.update(existing, changes)
            written += 1
    return written


# ---------------------------------------------------------------------------
# Service: Master registry + the customer per-AP read
# ---------------------------------------------------------------------------

#: An AP whose last RADIUS evidence is newer than this reads ``online``.
#: Interims arrive every ~306 s (measured 2026-10-03), so 15 minutes is
#: about three missed interims.
AP_ONLINE_WINDOW = timedelta(minutes=15)


def _primary_record(router: Any) -> dict[str, Any] | None:
    from app.domains.guest.aruba_shared import recorded_ap_mac

    mac = recorded_ap_mac(router)
    if mac is None:
        return None
    return {
        "id": None,
        "router_id": router.id,
        "mac": mac,
        "name": getattr(router, "name", None),
        "source": ArubaAccessPointSource.PRIMARY.value,
        "status": ArubaAccessPointStatus.APPROVED.value,
        "is_primary": True,
    }


def _record(ap: ArubaAccessPoint, primary_mac: str | None) -> dict[str, Any]:
    return {
        "id": ap.id,
        "router_id": ap.router_id,
        "mac": ap.mac,
        "name": ap.name,
        "serial": ap.serial,
        "model": ap.model,
        "source": ap.source,
        "status": ap.status,
        "is_primary": ap.mac == primary_mac,
        "first_seen_at": ap.first_seen_at,
        "last_seen_at": ap.last_seen_at,
    }


class ArubaAccessPointService:
    def __init__(
        self,
        session: AsyncSession,
        *,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self.session = session
        self.repository = ArubaAccessPointRepository(session)
        self.clock = clock

    # -- Master ------------------------------------------------------------

    @staticmethod
    def _require_aruba(router: Any) -> None:
        from app.domains.router.vendor_capabilities import is_nas_only

        from .exceptions import ArubaAccessPointInvalidError

        if not is_nas_only(router):
            raise ArubaAccessPointInvalidError("not_nas_only_vendor")
        if getattr(router, "location_id", None) is None:
            raise ArubaAccessPointInvalidError("no_location")

    async def list_registry(self, router: Any) -> list[dict[str, Any]]:
        from app.domains.guest.aruba_shared import recorded_ap_mac

        self._require_aruba(router)
        primary_mac = recorded_ap_mac(router)
        rows = await self.repository.list_for_router(router.id)
        records = [_record(ap, primary_mac) for ap in rows]
        primary = _primary_record(router)
        if primary is not None and all(r["mac"] != primary["mac"] for r in records):
            records.insert(0, primary)
        return records

    async def add(
        self, router: Any, *, mac: str, name: str | None, actor_user_id: uuid.UUID
    ) -> dict[str, Any]:
        from app.domains.guest.aruba_shared import (
            canonical_mac,
            is_placeholder_mac,
            recorded_ap_mac,
        )

        from .exceptions import ArubaAccessPointInvalidError

        self._require_aruba(router)
        canonical = canonical_mac(mac)
        if canonical is None or is_placeholder_mac(canonical):
            raise ArubaAccessPointInvalidError("invalid_mac")
        primary_mac = recorded_ap_mac(router)
        existing = await self.repository.get_by_mac(router.id, canonical)
        if existing is not None:
            if existing.status == ArubaAccessPointStatus.APPROVED.value:
                raise ArubaAccessPointInvalidError("duplicate_mac")
            # A pending/rejected sighting Master now adds by hand: approve it.
            ap = await self.repository.update(
                existing,
                {
                    "status": ArubaAccessPointStatus.APPROVED.value,
                    "name": name or existing.name,
                    "updated_by": actor_user_id,
                },
            )
            return _record(ap, primary_mac)
        ap = await self.repository.create(
            {
                "organization_id": router.organization_id,
                "location_id": router.location_id,
                "router_id": router.id,
                "mac": canonical,
                "name": name,
                "source": (
                    ArubaAccessPointSource.PRIMARY.value
                    if canonical == primary_mac
                    else ArubaAccessPointSource.MANUAL.value
                ),
                "status": ArubaAccessPointStatus.APPROVED.value,
                "created_by": actor_user_id,
            }
        )
        return _record(ap, primary_mac)

    async def update(
        self,
        router: Any,
        ap_id: uuid.UUID,
        *,
        status: str | None,
        name: str | None,
        actor_user_id: uuid.UUID,
    ) -> dict[str, Any]:
        from app.domains.guest.aruba_shared import recorded_ap_mac

        from .exceptions import (
            ArubaAccessPointInvalidError,
            ArubaAccessPointNotFoundError,
        )

        self._require_aruba(router)
        ap = await self.repository.get_for_router(router.id, ap_id)
        if ap is None:
            raise ArubaAccessPointNotFoundError()
        primary_mac = recorded_ap_mac(router)
        changes: dict[str, Any] = {"updated_by": actor_user_id}
        if status is not None and status != ap.status:
            if ap.mac == primary_mac:
                # The router's own MAC is accepted by the resolver whatever
                # this row says; a "rejected" here would be a fake control.
                raise ArubaAccessPointInvalidError("primary_ap")
            changes["status"] = status
        if name is not None:
            changes["name"] = name or None
        ap = await self.repository.update(ap, changes)
        return _record(ap, primary_mac)

    async def delete(self, router: Any, ap_id: uuid.UUID) -> None:
        from app.domains.guest.aruba_shared import recorded_ap_mac

        from .exceptions import (
            ArubaAccessPointInvalidError,
            ArubaAccessPointNotFoundError,
        )

        self._require_aruba(router)
        ap = await self.repository.get_for_router(router.id, ap_id)
        if ap is None:
            raise ArubaAccessPointNotFoundError()
        if ap.mac == recorded_ap_mac(router):
            raise ArubaAccessPointInvalidError("primary_ap")
        await self.repository.soft_delete(ap)

    # -- Customer ----------------------------------------------------------

    async def _aruba_routers_at(
        self, *, organization_id: uuid.UUID, location_id: uuid.UUID
    ) -> list[Any]:
        from app.domains.router.models import Router
        from app.domains.router.vendor_capabilities import NAS_ONLY_VENDORS

        rows = await self.session.execute(
            select(Router).where(
                Router.organization_id == organization_id,
                Router.location_id == location_id,
                Router.vendor.in_(NAS_ONLY_VENDORS),
                Router.is_deleted.is_(False),
            )
        )
        return list(rows.scalars().all())

    async def location_access_points(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID,
        tz_offset_minutes: int = 0,
        instant_on_items: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """The customer per-AP view. ``organization_id`` is the caller's
        CurrentOrganization and goes into every WHERE; ``None`` (a platform
        caller who selected no organization) answers not-applicable rather
        than reading across tenants."""
        now = self.clock()
        local_now = now + timedelta(minutes=tz_offset_minutes)
        day_start = (
            local_now.replace(hour=0, minute=0, second=0, microsecond=0)
            - timedelta(minutes=tz_offset_minutes)
        )
        body: dict[str, Any] = {
            "location_id": location_id,
            "applicable": False,
            "as_of": now,
            "day_start": day_start,
            "online_window_seconds": int(AP_ONLINE_WINDOW.total_seconds()),
            "unattributed_clients_now": 0,
            "items": [],
        }
        if organization_id is None:
            return body
        routers = await self._aruba_routers_at(
            organization_id=organization_id, location_id=location_id
        )
        if not routers:
            return body
        body["applicable"] = True

        rows = await self.repository.list_approved_for_location(
            organization_id=organization_id, location_id=location_id
        )
        router_ids = {r.id for r in routers}
        records: list[dict[str, Any]] = []
        for router in routers:
            from app.domains.guest.aruba_shared import recorded_ap_mac

            primary_mac = recorded_ap_mac(router)
            mine = [
                _record(ap, primary_mac) for ap in rows if ap.router_id == router.id
            ]
            primary = _primary_record(router)
            if primary is not None and all(r["mac"] != primary["mac"] for r in mine):
                mine.insert(0, primary)
            records.extend(mine)
        # Rows of a router no longer at this location never show here.
        records = [r for r in records if r["router_id"] in router_ids]

        stats, unattributed = await self.repository.session_stats(
            organization_id=organization_id,
            location_id=location_id,
            router_ids=sorted(router_ids, key=str),
            since=day_start,
        )
        body["unattributed_clients_now"] = unattributed

        io_by_mac: dict[str, dict[str, Any]] = {}
        if instant_on_items:
            from app.domains.guest.aruba_shared import canonical_mac

            for item in instant_on_items:
                mac = canonical_mac(item.get("mac"))
                if mac:
                    io_by_mac[mac] = item

        items = []
        for rec in records:
            st = stats.get((rec["router_id"], rec["mac"]), ApSessionStats())
            seen = [t for t in (rec.get("last_seen_at"), st.last_activity_at) if t]
            last_seen = max(seen) if seen else None
            io = io_by_mac.get(rec["mac"])
            io_status = io.get("status") if io else None
            if last_seen is not None and now - last_seen <= AP_ONLINE_WINDOW:
                status, source = "online", "radius"
            elif io_status == "online":
                status, source = "online", "instant_on"
            else:
                status, source = "no_recent_activity", None
            items.append(
                {
                    "id": rec["id"],
                    "name": rec.get("name") or (io.get("name") if io else None),
                    "mac": rec["mac"],
                    "model": rec.get("model") or (io.get("model") if io else None),
                    "serial": rec.get("serial")
                    or (io.get("serial_number") if io else None),
                    "is_primary": rec["is_primary"],
                    "clients_now": st.clients_now,
                    "sessions_today": st.sessions_today,
                    "download_bytes_today": st.download_bytes_today,
                    "upload_bytes_today": st.upload_bytes_today,
                    "last_seen_at": last_seen,
                    "status": status,
                    "status_source": source,
                    "instant_on_status": io_status,
                }
            )
        body["items"] = items
        return body
