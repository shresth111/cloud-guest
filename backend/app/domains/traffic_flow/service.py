"""Traffic flow: ingestion, the Master overview, and the device config path.

Three services over one repository, all Master-only:

* :class:`TrafficFlowIngestService` -- one hub window in, rows out.
* :class:`TrafficFlowOverviewService` -- last N minutes per router, with an
  honest state for every router instead of an empty table.
* :class:`TrafficFlowDeviceService` -- preview the rendered lines, and
  apply/disable over 8728 with read-back (``dry_run`` by default).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from fastapi import status
from sqlalchemy import and_, delete, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.exceptions import CloudGuestError
from app.core.config import Settings
from app.core.logging import get_logger
from app.domains.guest.models import GuestSession
from app.domains.location.models import Location
from app.domains.organization.models import Organization
from app.domains.router.models import Router
from app.domains.wireguard.constants import PeerStatus
from app.domains.wireguard.models import WireGuardPeer, WireGuardServer

from .constants import (
    STALE_AFTER_SECONDS,
    WINDOW_SECONDS,
    RouterFlowState,
    TrafficFlowSource,
)
from .ingest import (
    attribute_talkers,
    reduce_window,
    top_destinations,
    top_talkers,
)
from .models import TrafficFlowIngestState, TrafficFlowWindow
from .routeros import (
    TrafficFlowTarget,
    desired_config,
    disabled_config,
    render_traffic_flow_lines,
    routeros_major_version,
    traffic_flow_target_for,
)

logger = get_logger(__name__)

__all__ = [
    "TrafficFlowDeviceService",
    "TrafficFlowError",
    "TrafficFlowIngestService",
    "TrafficFlowOverviewService",
    "TrafficFlowRepository",
    "traffic_flow_target_for",
]

#: Entries shown per list in the overview.
OVERVIEW_TOP_N = 10


class TrafficFlowError(CloudGuestError):
    def __init__(self, message: str, *, code: str, status_code: int) -> None:
        super().__init__(message, status_code=status_code, data={"code": code})
        self.code = code


# ---------------------------------------------------------------------------
# repository
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExporterRouter:
    router_id: uuid.UUID
    organization_id: uuid.UUID | None
    location_id: uuid.UUID | None


class TrafficFlowRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def exporter_router_map(self) -> dict[str, ExporterRouter]:
        """Tunnel address -> router, for every non-revoked peer. A tunnel
        address is unique per hub; the fleet has one hub."""
        stmt = (
            select(
                WireGuardPeer.tunnel_ip_address,
                Router.id,
                Router.organization_id,
                Router.location_id,
            )
            .join(Router, Router.id == WireGuardPeer.router_id)
            .where(WireGuardPeer.status != PeerStatus.REVOKED.value)
            .where(Router.is_deleted.is_(False))
        )
        rows = (await self.session.execute(stmt)).all()
        return {
            str(ip): ExporterRouter(router_id=rid, organization_id=org, location_id=loc)
            for ip, rid, org, loc in rows
        }

    async def sessions_by_ip(
        self,
        router_id: uuid.UUID,
        ips: Iterable[str],
        *,
        start: datetime,
        end: datetime,
    ) -> dict[str, list[uuid.UUID]]:
        wanted = sorted(set(ips))
        if not wanted:
            return {}
        stmt = select(GuestSession.ip_address, GuestSession.id).where(
            GuestSession.router_id == router_id,
            GuestSession.ip_address.in_(wanted),
            GuestSession.started_at < end,
            or_(GuestSession.ended_at.is_(None), GuestSession.ended_at >= start),
            GuestSession.is_deleted.is_(False),
        )
        out: dict[str, list[uuid.UUID]] = {}
        for ip, session_id in (await self.session.execute(stmt)).all():
            out.setdefault(str(ip), []).append(session_id)
        return out

    async def insert_window(self, values: Mapping[str, Any]) -> bool:
        """ON CONFLICT DO NOTHING on (router, source, window_start). Returns
        whether a row was written."""
        stmt = (
            pg_insert(TrafficFlowWindow)
            .values(id=uuid.uuid4(), **values)
            .on_conflict_do_nothing(constraint="uq_traffic_flow_windows_router_window")
            .returning(TrafficFlowWindow.id)
        )
        result = await self.session.execute(stmt)
        return result.first() is not None

    async def delete_windows_before(self, cutoff: datetime, *, limit: int) -> int:
        """Retention: delete at most ``limit`` windows older than ``cutoff``
        (bounded, so the sweep never holds a long lock on the shared box)."""
        ids = (
            select(TrafficFlowWindow.id)
            .where(TrafficFlowWindow.window_start < cutoff)
            .limit(limit)
            .scalar_subquery()
        )
        result = await self.session.execute(
            delete(TrafficFlowWindow).where(TrafficFlowWindow.id.in_(ids))
        )
        return int(result.rowcount or 0)

    async def get_state(self) -> TrafficFlowIngestState:
        state = await self.session.get(TrafficFlowIngestState, 1)
        if state is None:
            state = TrafficFlowIngestState(id=1, unknown_exporters=[])
            self.session.add(state)
        return state

    async def windows_since(self, since: datetime) -> list[TrafficFlowWindow]:
        stmt = (
            select(TrafficFlowWindow)
            .where(TrafficFlowWindow.window_start >= since)
            .order_by(TrafficFlowWindow.window_start)
        )
        return list((await self.session.execute(stmt)).scalars().all())

    async def router_labels(
        self, router_ids: Iterable[uuid.UUID]
    ) -> dict[uuid.UUID, dict[str, Any]]:
        ids = list(set(router_ids))
        if not ids:
            return {}
        stmt = (
            select(
                Router.id,
                Router.name,
                Router.vendor,
                Location.name,
                Organization.name,
            )
            .outerjoin(Location, Location.id == Router.location_id)
            .outerjoin(Organization, Organization.id == Router.organization_id)
            .where(Router.id.in_(ids))
        )
        return {
            rid: {
                "router_name": rname,
                "vendor": vendor,
                "location_name": lname,
                "organization_name": oname,
            }
            for rid, rname, vendor, lname, oname in (
                await self.session.execute(stmt)
            ).all()
        }

    async def peer_and_server(
        self, router_id: uuid.UUID
    ) -> tuple[WireGuardPeer | None, WireGuardServer | None]:
        peer = (
            await self.session.execute(
                select(WireGuardPeer).where(
                    and_(
                        WireGuardPeer.router_id == router_id,
                        WireGuardPeer.status != PeerStatus.REVOKED.value,
                    )
                )
            )
        ).scalar_one_or_none()
        if peer is None:
            return None, None
        server = await self.session.get(WireGuardServer, peer.server_id)
        return peer, server


# ---------------------------------------------------------------------------
# ingest
# ---------------------------------------------------------------------------


@dataclass
class WindowIngestSummary:
    window_start: datetime
    exporters: int = 0
    written: int = 0
    duplicates: int = 0
    unknown_exporters: tuple[str, ...] = ()
    rows_rejected: int = 0


class TrafficFlowIngestService:
    def __init__(self, repository: TrafficFlowRepository) -> None:
        self.repository = repository

    async def ingest_window(
        self,
        *,
        window_start: datetime,
        window_seconds: int,
        rows: Iterable[Mapping[str, Any]],
        exporter_map: Mapping[str, ExporterRouter] | None = None,
    ) -> WindowIngestSummary:
        if exporter_map is None:
            exporter_map = await self.repository.exporter_router_map()
        window_end = window_start + timedelta(seconds=window_seconds)
        summary = WindowIngestSummary(window_start=window_start)
        unknown: list[str] = []
        for exporter, reduced in reduce_window(rows).items():
            summary.exporters += 1
            summary.rows_rejected += reduced.rows_rejected
            router = exporter_map.get(exporter)
            if router is None:
                unknown.append(exporter)
                continue
            sessions = await self.repository.sessions_by_ip(
                router.router_id,
                reduced.talkers.keys(),
                start=window_start,
                end=window_end,
            )
            attribution = attribute_talkers(reduced.talkers.keys(), sessions)
            talkers, other_talkers = top_talkers(reduced, attribution)
            destinations, other_destinations = top_destinations(reduced)
            written = await self.repository.insert_window(
                {
                    "router_id": router.router_id,
                    "organization_id": router.organization_id,
                    "location_id": router.location_id,
                    "source": TrafficFlowSource.MIKROTIK_IPFIX.value,
                    "window_start": window_start,
                    "window_seconds": window_seconds,
                    "exporter_address": exporter,
                    "bytes_total": reduced.bytes_total,
                    "packets_total": reduced.packets_total,
                    "flows_total": reduced.flows_total,
                    "bytes_internal": reduced.bytes_internal,
                    "bytes_unclassified": reduced.bytes_unclassified,
                    "bytes_other_talkers": other_talkers,
                    "bytes_other_destinations": other_destinations,
                    "talker_count": len(reduced.talkers),
                    "destination_count": len(reduced.destinations),
                    "top_talkers": talkers,
                    "top_destinations": destinations,
                    "received_at": datetime.now(UTC),
                }
            )
            if written:
                summary.written += 1
            else:
                summary.duplicates += 1
        summary.unknown_exporters = tuple(sorted(unknown))
        return summary


# ---------------------------------------------------------------------------
# overview
# ---------------------------------------------------------------------------


def _merge_windows(windows: list[TrafficFlowWindow]) -> dict[str, Any]:
    """Sum stored per-window top-N lists. Approximate by construction: an
    address that was just outside the top N in every window is missed --
    the response says so (``approximate: true``)."""
    talkers: dict[str, dict[str, Any]] = {}
    destinations: dict[str, dict[str, Any]] = {}
    totals = {
        "bytes_total": 0,
        "flows_total": 0,
        "bytes_internal": 0,
        "bytes_unclassified": 0,
    }
    for window in windows:
        for key in totals:
            totals[key] += int(getattr(window, key) or 0)
        for entry in window.top_talkers or []:
            ip = str(entry.get("ip"))
            merged = talkers.setdefault(
                ip,
                {
                    "ip": ip,
                    "bytes_up": 0,
                    "bytes_down": 0,
                    "flows": 0,
                    "sessions": set(),
                    "matches": set(),
                },
            )
            merged["bytes_up"] += int(entry.get("bytes_up") or 0)
            merged["bytes_down"] += int(entry.get("bytes_down") or 0)
            merged["flows"] += int(entry.get("flows") or 0)
            merged["matches"].add(str(entry.get("match") or "none"))
            if entry.get("guest_session_id"):
                merged["sessions"].add(str(entry["guest_session_id"]))
        for entry in window.top_destinations or []:
            ip = str(entry.get("ip"))
            merged_dest = destinations.setdefault(
                ip, {"ip": ip, "bytes": 0, "flows": 0}
            )
            merged_dest["bytes"] += int(entry.get("bytes") or 0)
            merged_dest["flows"] += int(entry.get("flows") or 0)

    talker_list: list[dict[str, Any]] = []
    for merged in talkers.values():
        sessions = sorted(merged.pop("sessions"))
        matches = merged.pop("matches")
        if len(sessions) == 1 and matches == {"session"}:
            merged["match"], merged["guest_session_id"] = "session", sessions[0]
        elif sessions or "ambiguous" in matches:
            # The IP belonged to different sessions across the period.
            merged["match"], merged["guest_session_id"] = "ambiguous", None
        else:
            merged["match"], merged["guest_session_id"] = "none", None
        talker_list.append(merged)
    talker_list.sort(key=lambda t: (-(t["bytes_up"] + t["bytes_down"]), t["ip"]))
    dest_list = sorted(destinations.values(), key=lambda d: (-d["bytes"], d["ip"]))
    return {
        **totals,
        "talkers": talker_list[:OVERVIEW_TOP_N],
        "destinations": dest_list[:OVERVIEW_TOP_N],
    }


class TrafficFlowOverviewService:
    def __init__(
        self,
        repository: TrafficFlowRepository,
        settings: Settings,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.repository = repository
        self.settings = settings
        self.now = now

    async def overview(self, *, minutes: int) -> dict[str, Any]:
        now = self.now()
        since = now - timedelta(minutes=minutes)
        windows = await self.repository.windows_since(since)
        state = await self.repository.get_state()
        allowlist = self.settings.traffic_flow_router_id_set

        by_router: dict[uuid.UUID, list[TrafficFlowWindow]] = {}
        for window in windows:
            by_router.setdefault(window.router_id, []).append(window)
        router_ids = set(by_router) | set(allowlist)
        labels = await self.repository.router_labels(router_ids)

        pull_failed = state.last_pull_ok is False
        routers: list[dict[str, Any]] = []
        for router_id in sorted(router_ids, key=str):
            router_windows = by_router.get(router_id, [])
            newest = max((w.window_start for w in router_windows), default=None)
            allowlisted = router_id in allowlist
            if not self.settings.traffic_flow_enabled:
                router_state = RouterFlowState.DISABLED
            elif router_windows and not allowlisted:
                router_state = RouterFlowState.NOT_ALLOWLISTED
            elif pull_failed:
                router_state = RouterFlowState.COLLECTOR_UNREACHABLE
            elif newest is None:
                router_state = RouterFlowState.NO_WINDOWS
            elif (
                now - (newest + timedelta(seconds=WINDOW_SECONDS))
            ).total_seconds() > (STALE_AFTER_SECONDS):
                router_state = RouterFlowState.STALE
            else:
                router_state = RouterFlowState.OK
            label = labels.get(router_id, {})
            routers.append(
                {
                    "router_id": str(router_id),
                    "router_name": label.get("router_name"),
                    "vendor": label.get("vendor"),
                    "location_name": label.get("location_name"),
                    "organization_name": label.get("organization_name"),
                    "allowlisted": allowlisted,
                    "state": router_state.value,
                    "windows": len(router_windows),
                    "newest_window_start": newest.isoformat() if newest else None,
                    "source": TrafficFlowSource.MIKROTIK_IPFIX.value,
                    "approximate": True,
                    **_merge_windows(router_windows),
                }
            )
        return {
            "enabled": self.settings.traffic_flow_enabled,
            "agent_configured": bool(
                self.settings.traffic_flow_agent_url
                and self.settings.traffic_flow_agent_secret
            ),
            "period_minutes": minutes,
            "generated_at": now.isoformat(),
            "window_seconds": WINDOW_SECONDS,
            "last_pull_at": state.last_pull_at.isoformat()
            if state.last_pull_at
            else None,
            "last_pull_ok": state.last_pull_ok,
            "last_error": state.last_error,
            "last_window_start": (
                state.last_window_start.isoformat() if state.last_window_start else None
            ),
            "unknown_exporters": list(state.unknown_exporters or []),
            "routers": routers,
        }


# ---------------------------------------------------------------------------
# device config path
# ---------------------------------------------------------------------------


class _Adapter(Protocol):
    async def read_traffic_flow(self, creds: Any, *, marker: str) -> Any: ...

    async def apply_traffic_flow(self, creds: Any, config: Any) -> Any: ...


class RouterLookup(Protocol):
    async def get_router(self, router_id: uuid.UUID) -> Router: ...

    def get_decrypted_api_secret(self, router: Router) -> str | None: ...


class AuditWriter(Protocol):
    async def create_audit_log_entry(self, **kwargs: Any) -> Any: ...


def _state_dict(state: Any) -> dict[str, Any]:
    return {
        "routeros_version": state.routeros_version,
        "settings": dict(state.settings),
        "ipfix": dict(state.ipfix),
        "targets": [dict(t) for t in state.targets],
        "foreign_targets": state.foreign_targets,
    }


class TrafficFlowDeviceService:
    def __init__(
        self,
        repository: TrafficFlowRepository,
        router_lookup: RouterLookup,
        settings: Settings,
        *,
        adapter_factory: Callable[[], _Adapter],
        credentials_factory: Callable[[Router, str], Any],
        audit_writer: AuditWriter | None = None,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.settings = settings
        self.adapter_factory = adapter_factory
        self.credentials_factory = credentials_factory
        self.audit_writer = audit_writer

    def _blockers(self, router: Router, target: TrafficFlowTarget | None) -> list[str]:
        reasons: list[str] = []
        if not self.settings.traffic_flow_enabled:
            reasons.append("CLOUDGUEST_TRAFFIC_FLOW_ENABLED is off")
        if router.id not in self.settings.traffic_flow_router_id_set:
            reasons.append("router is not in CLOUDGUEST_TRAFFIC_FLOW_ROUTER_IDS")
        if (router.vendor or "").lower() != "mikrotik":
            reasons.append(
                f"vendor {router.vendor!r} does not export flows (MikroTik only)"
            )
        if target is None:
            reasons.append(
                "router has no WireGuard tunnel; the collector is reached over it"
            )
        major = routeros_major_version(router.routeros_version)
        if major is not None and major != 7:
            reasons.append(
                f"RouterOS 7 required (router reports {router.routeros_version})"
            )
        return reasons

    async def preview(self, router_id: uuid.UUID) -> dict[str, Any]:
        router = await self.router_lookup.get_router(router_id)
        peer, server = await self.repository.peer_and_server(router.id)
        target = traffic_flow_target_for(peer, server, self.settings)
        lines: list[str] = []
        if target is not None:
            lines = render_traffic_flow_lines(
                desired_config(target), routeros_version=router.routeros_version
            )
        blockers = self._blockers(router, target)
        return {
            "router_id": str(router.id),
            "eligible": not blockers,
            "blockers": blockers,
            "collector_address": target.collector_address if target else None,
            "collector_port": target.collector_port if target else None,
            "source_address": target.source_address if target else None,
            "routeros_version": router.routeros_version,
            "lines": lines,
        }

    async def apply(
        self,
        router_id: uuid.UUID,
        *,
        enabled: bool,
        dry_run: bool,
        actor_user_id: uuid.UUID | None,
    ) -> dict[str, Any]:
        from wyfy_device_gateway.mikrotik_adapter import MikroTikDeviceError
        from wyfy_device_gateway.mikrotik_traffic_flow import (
            TrafficFlowRefusal,
            diff_traffic_flow,
            plan_traffic_flow,
        )

        router = await self.router_lookup.get_router(router_id)
        peer, server = await self.repository.peer_and_server(router.id)
        target = traffic_flow_target_for(peer, server, self.settings)
        blockers = self._blockers(router, target)
        if not enabled:
            # Turning export OFF needs no tunnel and must work for a router
            # that has since left the allowlist.
            blockers = [
                b for b in blockers if "WireGuard" not in b and "ROUTER_IDS" not in b
            ]
        if blockers:
            raise TrafficFlowError(
                "; ".join(blockers),
                code="TRAFFIC_FLOW_NOT_ELIGIBLE",
                status_code=status.HTTP_409_CONFLICT,
            )
        config = desired_config(target) if enabled and target else disabled_config()
        secret = self.router_lookup.get_decrypted_api_secret(router)
        host = router.management_ip_address or router.public_ip_address
        if not host or not router.api_username or not secret:
            raise TrafficFlowError(
                "router has no API credentials on record",
                code="TRAFFIC_FLOW_NO_CREDENTIALS",
                status_code=status.HTTP_409_CONFLICT,
            )
        creds = self.credentials_factory(router, secret)
        adapter = self.adapter_factory()
        try:
            if dry_run:
                state = await adapter.read_traffic_flow(creds, marker=config.marker)
                plan = plan_traffic_flow(state, config)
                return {
                    "router_id": str(router.id),
                    "dry_run": True,
                    "enabled": enabled,
                    "planned_writes": [
                        f"{op} /{'/'.join(path)} "
                        + " ".join(f"{k}={v}" for k, v in fields.items())
                        for op, path, fields in plan
                    ],
                    "differences": list(diff_traffic_flow(state, config)),
                    "before": _state_dict(state),
                }
            result = await adapter.apply_traffic_flow(creds, config)
        except TrafficFlowRefusal as exc:
            raise TrafficFlowError(
                exc.detail, code=exc.code, status_code=status.HTTP_409_CONFLICT
            ) from exc
        except MikroTikDeviceError as exc:
            raise TrafficFlowError(
                f"router did not answer the traffic-flow "
                f"{'read' if dry_run else 'write'}: {exc}",
                code="TRAFFIC_FLOW_DEVICE_ERROR",
                status_code=status.HTTP_502_BAD_GATEWAY,
            ) from exc

        if self.audit_writer is not None and result.writes:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action="traffic_flow_applied",
                entity_type="router",
                entity_id=router.id,
                description=(
                    f"Traffic flow export {'enabled' if enabled else 'disabled'} "
                    f"on router {router.id}: {len(result.writes)} write(s), read-back "
                    f"{'matches' if result.matches else 'MISMATCH'}"
                ),
                organization_id=router.organization_id,
            )
        logger.info(
            "traffic_flow_applied",
            extra={
                "router_id": str(router.id),
                "enabled": enabled,
                "writes": len(result.writes),
                "matches": result.matches,
            },
        )
        return {
            "router_id": str(router.id),
            "dry_run": False,
            "enabled": enabled,
            "writes": list(result.writes),
            "matches": result.matches,
            "mismatches": list(result.mismatches),
            "before": _state_dict(result.before),
            "after": _state_dict(result.after),
        }
