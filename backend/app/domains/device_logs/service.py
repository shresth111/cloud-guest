"""Device Logs business logic: ingest (parse -> attribute -> mask -> store),
the Master viewer, per-router status, and apply/remove of remote logging on
a MikroTik with read-back.

Honesty rules this module keeps:

* A router that was configured but has never been heard from is
  ``awaiting_first_message`` -- unknown -- not "no events".
* Attribution is by source tunnel IP only. An IP that matches no router, or
  more than one, is stored unattributed; the ``wyfy-`` tag never attributes
  on its own.
* A write is only "verified" when the read-back from the device matched.

Firewall logging (``WYFY-FW``) rides on remote logging: rate-limited log rows
above Wyfy's own forward drops (gateway ``mikrotik_firewall_logging``). The
per-router intent lives on ``router_remote_logging``; the rows are on the
router only while that intent, remote logging and the platform switch are all
on. Every write of them holds the router's forward-chain lock, and they are
re-converged after every other write of that chain (``after_firewall_write``)
so they always sit directly above the drop they describe.
"""

from __future__ import annotations

import base64
import binascii
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from app.common.router_firewall_lock import router_firewall_lock
from app.core.config import Settings
from app.domains.router.crypto import decrypt_secret

from .classifier import classification_columns
from .constants import (
    DEFAULT_PAGE_SIZE,
    FIREWALL_LOG_MAX_LINES_PER_MINUTE,
    FIREWALL_LOG_PER_RULE_LIMIT,
    MAX_PAGE_SIZE,
    MAX_QUERY_WINDOW_DAYS,
    ROUTEROS_ACTION_NAME,
    SEVERITY_NAMES,
    SILENT_AFTER_MINUTES,
    Attribution,
    LogSource,
    LogVendor,
    ReceivingState,
)
from .exceptions import (
    DeviceLogsBadCursorError,
    DeviceLogsDeviceError,
    DeviceLogsDisabledError,
    DeviceLogsRouterBlockedError,
    DeviceLogsRouterNotFoundError,
    FirewallLoggingBusyError,
    FirewallLoggingNeedsRemoteLoggingError,
    FirewallLoggingSwitchedOffError,
)
from .guest_events import guest_event_row
from .models import RouterRemoteLogging
from .parser import parse_line
from .repository import DeviceLogsRepository, EventFilters
from .routeros import (
    RemoteLoggingConfig,
    desired_config,
    hub_tunnel_address,
    render_script,
    router_tag,
)
from .schemas import IngestEvent

logger = logging.getLogger(__name__)


# -- device writer seam ------------------------------------------------------


@dataclass(frozen=True)
class WriterCredentials:
    host: str
    username: str
    password: str


@dataclass(frozen=True)
class WriteVerdict:
    ok: bool
    detail: str


class RemoteLoggingWriter(Protocol):
    async def apply(
        self, creds: WriterCredentials, config: RemoteLoggingConfig
    ) -> WriteVerdict: ...

    async def remove(self, creds: WriterCredentials) -> WriteVerdict: ...


class DeviceWriteFailed(Exception):
    """Raised by a writer when the device could not be reached or refused."""


class GatewayRemoteLoggingWriter:
    """The real writer: ``wyfy_device_gateway.mikrotik_remote_logging`` over
    8728. Imported lazily so this module stays importable (and unit-testable)
    without librouteros."""

    def __init__(self) -> None:
        from wyfy_device_gateway.mikrotik_remote_logging import MikroTikRemoteLogging

        self._client = MikroTikRemoteLogging()

    @staticmethod
    def _creds(creds: WriterCredentials) -> Any:
        from wyfy_device_gateway.contract import DeviceCredentials, DeviceVendor

        return DeviceCredentials(
            vendor=DeviceVendor.MIKROTIK,
            host=creds.host,
            username=creds.username,
            secret=creds.password,
        )

    async def apply(
        self, creds: WriterCredentials, config: RemoteLoggingConfig
    ) -> WriteVerdict:
        from wyfy_device_gateway.mikrotik_adapter import MikroTikDeviceError

        try:
            readback = await self._client.apply(
                self._creds(creds),
                desired_action=config.action_row(),
                desired_rules=config.rule_rows(),
            )
        except MikroTikDeviceError as exc:
            raise DeviceWriteFailed(str(exc)) from exc
        return WriteVerdict(ok=readback.ok, detail=readback.detail)

    async def remove(self, creds: WriterCredentials) -> WriteVerdict:
        from wyfy_device_gateway.mikrotik_adapter import MikroTikDeviceError

        try:
            readback = await self._client.remove(
                self._creds(creds), action_name=ROUTEROS_ACTION_NAME
            )
        except MikroTikDeviceError as exc:
            raise DeviceWriteFailed(str(exc)) from exc
        return WriteVerdict(ok=readback.ok, detail=readback.detail)


@dataclass(frozen=True)
class FirewallLoggingVerdict:
    """The gateway's ``FirewallLoggingResult``, as plain values."""

    enabled: bool
    ok: bool
    band_state: str
    targets: int
    companions: int
    skipped: tuple[str, ...]
    detail: str


class FirewallLoggingWriter(Protocol):
    async def sync(
        self, creds: WriterCredentials, *, enabled: bool
    ) -> FirewallLoggingVerdict: ...

    async def read(self, creds: WriterCredentials) -> FirewallLoggingVerdict: ...


class GatewayFirewallLoggingWriter:
    """The real writer: ``wyfy_device_gateway.mikrotik_firewall_logging``
    over 8728, imported lazily like :class:`GatewayRemoteLoggingWriter`."""

    def __init__(self) -> None:
        from wyfy_device_gateway.mikrotik_firewall_logging import (
            MikroTikFirewallLogging,
        )

        self._client = MikroTikFirewallLogging()

    @staticmethod
    def _verdict(result: Any) -> FirewallLoggingVerdict:
        return FirewallLoggingVerdict(
            enabled=bool(result.enabled),
            ok=bool(result.ok),
            band_state=str(result.band_state),
            targets=int(result.targets),
            companions=int(result.companions),
            skipped=tuple(f"{comment}: {reason}" for comment, reason in result.skipped),
            detail=str(result.detail),
        )

    async def sync(
        self, creds: WriterCredentials, *, enabled: bool
    ) -> FirewallLoggingVerdict:
        from wyfy_device_gateway.mikrotik_adapter import MikroTikDeviceError

        try:
            result = await self._client.sync(
                GatewayRemoteLoggingWriter._creds(creds), enabled=enabled
            )
        except MikroTikDeviceError as exc:
            raise DeviceWriteFailed(str(exc)) from exc
        return self._verdict(result)

    async def read(self, creds: WriterCredentials) -> FirewallLoggingVerdict:
        from wyfy_device_gateway.mikrotik_adapter import MikroTikDeviceError

        try:
            result = await self._client.read(GatewayRemoteLoggingWriter._creds(creds))
        except MikroTikDeviceError as exc:
            raise DeviceWriteFailed(str(exc)) from exc
        return self._verdict(result)


# -- helpers -----------------------------------------------------------------


def encode_cursor(received_at: datetime, event_id: int) -> str:
    raw = f"{received_at.isoformat()}|{event_id}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, int]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        at, _, event_id = base64.urlsafe_b64decode(padded).decode().partition("|")
        return datetime.fromisoformat(at), int(event_id)
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        raise DeviceLogsBadCursorError() from exc


def receiving_state(
    *,
    feature_enabled: bool,
    configured: bool,
    last_received_at: datetime | None,
    now: datetime,
) -> ReceivingState:
    if not feature_enabled:
        return ReceivingState.FEATURE_OFF
    if last_received_at is None:
        return (
            ReceivingState.AWAITING_FIRST_MESSAGE
            if configured
            else ReceivingState.NOT_CONFIGURED
        )
    if last_received_at < now - timedelta(minutes=SILENT_AFTER_MINUTES):
        return ReceivingState.SILENT
    return ReceivingState.RECEIVING


def _guest_row(event_id: int, row: dict[str, Any]) -> dict[str, Any] | None:
    return guest_event_row(
        device_log_event_id=event_id,
        attribution=row["attribution"],
        organization_id=row["organization_id"],
        location_id=row["location_id"],
        router_id=row["router_id"],
        received_at=row["received_at"],
        device_time=row["device_time"],
        topics=row["topics"],
        message=row["message"],
    )


def _id(value: uuid.UUID | None) -> str | None:
    return str(value) if value is not None else None


class DeviceLogsService:
    def __init__(
        self,
        repository: DeviceLogsRepository,
        settings: Settings,
        *,
        writer: RemoteLoggingWriter | None = None,
        firewall_writer: FirewallLoggingWriter | None = None,
        redis: Any | None = None,
        clock: Any = None,
    ) -> None:
        self.repository = repository
        self.settings = settings
        self._writer = writer
        self._firewall_writer = firewall_writer
        # Backs the router's forward-chain lock (app.common.router_firewall_
        # lock) around firewall-logging writes. None (unit tests) takes none.
        self._redis = redis
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def enabled(self) -> bool:
        return bool(self.settings.device_logs_enabled)

    def _now(self) -> datetime:
        return self._clock()

    # -- ingest --------------------------------------------------------
    async def ingest(self, events: list[IngestEvent]) -> dict[str, int]:
        owners = await self.repository.owners_by_tunnel_ip(
            {e.source_ip.strip() for e in events}
        )
        rows: list[dict[str, Any]] = []
        counts = {"attributed": 0, "unattributed": 0, "tag_mismatch": 0}
        for event in events:
            received_at = event.received_at
            if received_at.tzinfo is None:
                received_at = received_at.replace(tzinfo=UTC)
            parsed = parse_line(event.raw, received_at=received_at)
            source_ip = event.source_ip.strip()
            matches = owners.get(source_ip, [])
            owner = matches[0] if len(matches) == 1 else None
            if owner is None:
                attribution = Attribution.UNATTRIBUTED
                counts["unattributed"] += 1
            elif parsed.tag is not None and parsed.tag != router_tag(owner.router_id):
                # The line names another router: the tunnel IP was most
                # likely re-allocated while the old device still sends.
                # Keeping the IP's current owner would show one venue's
                # lines in another tenant's NetLogs, so refuse the owner
                # and keep the flag (and claimed_tag) for the operators.
                attribution = Attribution.TAG_MISMATCH
                counts["tag_mismatch"] += 1
                owner = None
            else:
                attribution = Attribution.TUNNEL_IP
                counts["attributed"] += 1
            rows.append(
                {
                    "received_at": received_at,
                    "device_time": parsed.device_time,
                    "organization_id": owner.organization_id if owner else None,
                    "location_id": owner.location_id if owner else None,
                    "router_id": owner.router_id if owner else None,
                    "source_ip": source_ip,
                    "vendor": LogVendor.MIKROTIK.value,
                    "source": LogSource.SYSLOG.value,
                    "facility": parsed.facility,
                    "severity": parsed.severity,
                    "hostname": parsed.hostname,
                    "topics": parsed.topics,
                    "message": parsed.message,
                    "attribution": attribution.value,
                    "claimed_tag": parsed.tag,
                    **classification_columns(parsed.message, topics=parsed.topics),
                }
            )
        ids = await self.repository.insert_events(rows)
        guest_rows = [
            derived
            for event_id, row in zip(ids, rows, strict=True)
            if (derived := _guest_row(event_id, row)) is not None
        ]
        await self.repository.insert_guest_events(guest_rows)
        if counts["tag_mismatch"] or counts["unattributed"]:
            logger.warning("device_logs_ingest_attribution_gaps", extra=counts)
        return {"accepted": len(rows), **counts}

    async def backfill_guest_events(self, *, batch_size: int = 1000) -> int:
        """Derive ``guest_device_events`` for stored lines that have none yet.
        Idempotent: re-running finds nothing new. Returns rows inserted."""
        inserted = 0
        after_id = 0
        while True:
            lines = await self.repository.lines_without_guest_event(
                after_id=after_id, limit=batch_size
            )
            if not lines:
                return inserted
            after_id = lines[-1].id
            guest_rows = [
                derived
                for line in lines
                if (
                    derived := guest_event_row(
                        device_log_event_id=line.id,
                        attribution=line.attribution,
                        organization_id=line.organization_id,
                        location_id=line.location_id,
                        router_id=line.router_id,
                        received_at=line.received_at,
                        device_time=line.device_time,
                        topics=line.topics,
                        message=line.message,
                    )
                )
                is not None
            ]
            inserted += await self.repository.insert_guest_events(guest_rows)

    async def backfill_classification(self, *, batch_size: int = 1000) -> int:
        """Fill the structured columns (``classifier``) on lines stored before
        they existed. Idempotent: only rows with ``category IS NULL`` are
        read, and every row read gets a category (``other`` at worst), so a
        re-run finds nothing. Returns rows updated."""
        updated = 0
        after_id = 0
        while True:
            lines = await self.repository.lines_without_category(
                after_id=after_id, limit=batch_size
            )
            if not lines:
                return updated
            after_id = lines[-1].id
            updated += await self.repository.set_classification(
                [
                    {
                        "id": line.id,
                        "received_at": line.received_at,
                        **classification_columns(line.message, topics=line.topics),
                    }
                    for line in lines
                ]
            )

    # -- viewer --------------------------------------------------------
    async def list_events(
        self,
        *,
        since: datetime | None,
        until: datetime | None,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        router_id: uuid.UUID | None,
        max_severity: int | None,
        text: str | None,
        unattributed_only: bool,
        cursor: str | None,
        limit: int | None,
    ) -> dict[str, Any]:
        now = self._now()
        until = until or now
        since = since or (until - timedelta(hours=24))
        if since > until:
            since, until = until, since
        if until - since > timedelta(days=MAX_QUERY_WINDOW_DAYS):
            since = until - timedelta(days=MAX_QUERY_WINDOW_DAYS)
        size = max(1, min(limit or DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE))
        if not self.enabled:
            # Not a query against an empty table that reads as "all quiet":
            # the page says the feature is off.
            return {
                "feature_enabled": False,
                "items": [],
                "next_cursor": None,
                "since": since,
                "until": until,
            }
        filters = EventFilters(
            since=since,
            until=until,
            organization_id=organization_id,
            location_id=location_id,
            router_id=router_id,
            max_severity=max_severity,
            text=(text or "").strip() or None,
            unattributed_only=unattributed_only,
            cursor=decode_cursor(cursor) if cursor else None,
        )
        rows = await self.repository.list_events(filters, limit=size + 1)
        has_more = len(rows) > size
        rows = rows[:size]
        items = [self._event_view(r) for r in rows]
        next_cursor = None
        if has_more and rows:
            last = rows[-1]["event"]
            next_cursor = encode_cursor(last.received_at, last.id)
        return {
            "feature_enabled": True,
            "items": items,
            "next_cursor": next_cursor,
            "since": since,
            "until": until,
        }

    @staticmethod
    def _event_view(row: dict[str, Any]) -> dict[str, Any]:
        e = row["event"]
        return {
            "id": e.id,
            "received_at": e.received_at,
            "device_time": e.device_time,
            "organization_id": _id(e.organization_id),
            "organization_name": row["organization_name"],
            "location_id": _id(e.location_id),
            "location_name": row["location_name"],
            "router_id": _id(e.router_id),
            "router_name": row["router_name"],
            "source_ip": e.source_ip,
            "vendor": e.vendor,
            "source": e.source,
            "facility": e.facility,
            "severity": e.severity,
            "severity_name": SEVERITY_NAMES.get(e.severity)
            if e.severity is not None
            else None,
            "hostname": e.hostname,
            "topics": e.topics,
            "message": e.message,
            "attribution": e.attribution,
            "claimed_tag": e.claimed_tag,
            "category": e.category,
            "protocol": e.protocol,
            "src_ip": e.src_ip,
            "dst_ip": e.dst_ip,
            "status": e.status,
            "device_mac": e.device_mac,
        }

    # -- status --------------------------------------------------------
    def _status_view(
        self,
        config: RouterRemoteLogging,
        *,
        router_name: str | None,
        location_name: str | None,
        organization_name: str | None,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        last_received_at: datetime | None,
    ) -> dict[str, Any]:
        return {
            "router_id": str(config.router_id),
            "router_name": router_name,
            "organization_id": _id(organization_id),
            "location_id": _id(location_id),
            "location_name": location_name,
            "organization_name": organization_name,
            "enabled": config.enabled,
            "remote_host": config.remote_host,
            "remote_port": config.remote_port,
            "last_applied_at": config.last_applied_at,
            "last_verified_at": config.last_verified_at,
            "verified_ok": config.verified_ok,
            "verify_detail": config.verify_detail,
            "last_received_at": last_received_at,
            "state": receiving_state(
                feature_enabled=self.enabled,
                configured=config.enabled,
                last_received_at=last_received_at,
                now=self._now(),
            ).value,
        }

    async def overview(self) -> dict[str, Any]:
        configs = await self.repository.list_configs()
        last = await self.repository.last_received_by_router(
            [c.router_id for c, *_ in configs]
        )
        routers = [
            self._status_view(
                config,
                router_name=router_name,
                location_name=location_name,
                organization_name=organization_name,
                organization_id=organization_id,
                location_id=location_id,
                last_received_at=last.get(config.router_id),
            )
            for (
                config,
                router_name,
                location_name,
                organization_name,
                organization_id,
                location_id,
            ) in configs
        ]
        unattributed = 0
        if self.enabled:
            unattributed = await self.repository.count_unattributed_since(
                self._now() - timedelta(hours=24)
            )
        return {
            "feature_enabled": self.enabled,
            "routers": routers,
            "unattributed_last_24h": unattributed,
        }

    async def _context(self, router_id: uuid.UUID) -> dict[str, Any]:
        found = await self.repository.get_router_context(router_id)
        if found is None:
            raise DeviceLogsRouterNotFoundError(router_id)
        router, peer, server, location_name, organization_name = found
        blocker: str | None = None
        blocker_detail: str | None = None
        config: RemoteLoggingConfig | None = None
        if (router.vendor or "").lower() != LogVendor.MIKROTIK.value:
            blocker = "NOT_MIKROTIK"
            blocker_detail = (
                f"This is a {router.vendor} device. Remote logging is built for "
                "MikroTik only; Omada is planned, and Aruba Instant On cannot "
                "send syslog at all."
            )
        elif peer is None or server is None:
            blocker = "NO_TUNNEL"
            blocker_detail = (
                "This router has no WireGuard tunnel, and syslog only travels "
                "inside the tunnel."
            )
        if peer is not None and server is not None and blocker is None:
            remote_host = self.settings.device_logs_remote_host or hub_tunnel_address(
                server.tunnel_network_cidr
            )
            config = desired_config(
                router_id=router.id,
                tunnel_ip=peer.tunnel_ip_address,
                remote_host=remote_host,
                remote_port=self.settings.device_logs_remote_port,
            )
        creds: WriterCredentials | None = None
        host = router.management_ip_address or router.public_ip_address
        secret = (
            decrypt_secret(router.api_credentials_encrypted)
            if router.api_credentials_encrypted
            else None
        )
        if host and router.api_username and secret:
            creds = WriterCredentials(
                host=host, username=router.api_username, password=secret
            )
        elif blocker is None:
            blocker = "NO_API_CREDENTIALS"
            blocker_detail = (
                "No RouterOS API credentials are stored for this router, so it "
                "cannot be configured or read back from here. The paste script "
                "below still works."
            )
        return {
            "router": router,
            "peer": peer,
            "location_name": location_name,
            "organization_name": organization_name,
            "blocker": blocker,
            "blocker_detail": blocker_detail,
            "config": config,
            "creds": creds,
        }

    async def router_detail(self, router_id: uuid.UUID) -> dict[str, Any]:
        ctx = await self._context(router_id)
        router = ctx["router"]
        row = await self.repository.get_config(router_id)
        last = (await self.repository.last_received_by_router([router_id])).get(
            router_id
        )
        status = (
            self._status_view(
                row,
                router_name=router.name,
                location_name=ctx["location_name"],
                organization_name=ctx["organization_name"],
                organization_id=router.organization_id,
                location_id=router.location_id,
                last_received_at=last,
            )
            if row is not None
            else None
        )
        state = receiving_state(
            feature_enabled=self.enabled,
            configured=bool(row and row.enabled),
            last_received_at=last,
            now=self._now(),
        )
        config: RemoteLoggingConfig | None = ctx["config"]
        return {
            "feature_enabled": self.enabled,
            "router_id": str(router.id),
            "router_name": router.name,
            "vendor": router.vendor,
            "location_name": ctx["location_name"],
            "organization_name": ctx["organization_name"],
            "blocker": ctx["blocker"],
            "blocker_detail": ctx["blocker_detail"],
            "tunnel_ip": ctx["peer"].tunnel_ip_address if ctx["peer"] else None,
            "status": status,
            "script": render_script(config) if config is not None else None,
            "state": state.value,
        }

    # -- device writes -------------------------------------------------
    def _require_writer(self) -> RemoteLoggingWriter:
        if self._writer is None:
            self._writer = GatewayRemoteLoggingWriter()
        return self._writer

    async def apply(
        self, router_id: uuid.UUID, *, actor_user_id: uuid.UUID
    ) -> dict[str, Any]:
        if not self.enabled:
            raise DeviceLogsDisabledError()
        ctx = await self._context(router_id)
        if ctx["blocker"] is not None:
            raise DeviceLogsRouterBlockedError(
                router_id, ctx["blocker"], ctx["blocker_detail"]
            )
        config: RemoteLoggingConfig = ctx["config"]
        try:
            verdict = await self._require_writer().apply(ctx["creds"], config)
        except DeviceWriteFailed as exc:
            raise DeviceLogsDeviceError(router_id, str(exc)) from exc
        now = self._now()
        row = await self.repository.get_config(router_id) or RouterRemoteLogging(
            router_id=router_id, created_by=actor_user_id
        )
        row.remote_host = config.remote_host
        row.remote_port = config.remote_port
        row.src_address = config.src_address
        row.tag = config.tag
        row.enabled = True
        row.last_applied_at = now
        row.last_verified_at = now
        row.verified_ok = verdict.ok
        row.verify_detail = verdict.detail
        row.updated_by = actor_user_id
        await self.repository.save_config(row)
        await self._resync_best_effort(row, ctx["creds"])
        logger.info(
            "device_logs_remote_logging_applied",
            extra={
                "router_id": str(router_id),
                "verified_ok": verdict.ok,
                "detail": verdict.detail,
                "actor_user_id": str(actor_user_id),
            },
        )
        return await self.router_detail(router_id)

    async def remove(
        self, router_id: uuid.UUID, *, actor_user_id: uuid.UUID
    ) -> dict[str, Any]:
        if not self.enabled:
            raise DeviceLogsDisabledError()
        ctx = await self._context(router_id)
        if ctx["blocker"] in ("NOT_MIKROTIK", "NO_API_CREDENTIALS"):
            raise DeviceLogsRouterBlockedError(
                router_id, ctx["blocker"], ctx["blocker_detail"]
            )
        try:
            verdict = await self._require_writer().remove(ctx["creds"])
        except DeviceWriteFailed as exc:
            raise DeviceLogsDeviceError(router_id, str(exc)) from exc
        row = await self.repository.get_config(router_id)
        if row is not None:
            now = self._now()
            row.enabled = False
            row.last_verified_at = now
            row.verified_ok = verdict.ok
            row.verify_detail = verdict.detail
            row.updated_by = actor_user_id
            await self.repository.save_config(row)
            # Remote logging is gone, so the rows would log into nothing:
            # off on the device, intent kept for the next apply.
            await self._resync_best_effort(row, ctx["creds"])
        logger.info(
            "device_logs_remote_logging_removed",
            extra={
                "router_id": str(router_id),
                "verified_ok": verdict.ok,
                "detail": verdict.detail,
                "actor_user_id": str(actor_user_id),
            },
        )
        return await self.router_detail(router_id)

    # -- firewall logging (WYFY-FW) ------------------------------------
    @property
    def firewall_logging_platform_enabled(self) -> bool:
        return self.enabled and bool(
            getattr(self.settings, "device_logs_firewall_logging_enabled", False)
        )

    def _firewall_logging_active(self, row: RouterRemoteLogging | None) -> bool:
        """The rows belong on the router: the per-router intent, remote
        logging (their only way out) and the platform switch, all on."""
        return bool(
            row is not None
            and row.enabled
            and row.firewall_logging_enabled
            and self.firewall_logging_platform_enabled
        )

    def _require_firewall_writer(self) -> FirewallLoggingWriter:
        if self._firewall_writer is None:
            self._firewall_writer = GatewayFirewallLoggingWriter()
        return self._firewall_writer

    def _firewall_lock(self, router_id: uuid.UUID):  # noqa: ANN202
        return router_firewall_lock(
            self._redis,
            router_id,
            busy_error=lambda: FirewallLoggingBusyError(router_id),
        )

    async def _sync_firewall_logging(
        self,
        row: RouterRemoteLogging | None,
        creds: WriterCredentials,
        *,
        enabled: bool,
        router_id: uuid.UUID,
    ) -> FirewallLoggingVerdict:
        """One converge of the router's companion rows, recorded on ``row``.
        The caller holds the forward-chain lock."""
        verdict = await self._require_firewall_writer().sync(creds, enabled=enabled)
        if row is not None:
            row.firewall_logging_verified_at = self._now()
            row.firewall_logging_verified_ok = verdict.ok
            row.firewall_logging_detail = verdict.detail
            await self.repository.save_config(row)
        logger.info(
            "device_logs_firewall_logging_synced",
            extra={
                "router_id": str(router_id),
                "fw_enabled": enabled,
                "fw_ok": verdict.ok,
                "fw_targets": verdict.targets,
                "fw_companions": verdict.companions,
                "fw_detail": verdict.detail,
            },
        )
        return verdict

    async def _resync_best_effort(
        self, row: RouterRemoteLogging, creds: WriterCredentials | None
    ) -> None:
        """Re-converge after a remote-logging apply/remove. Never fails the
        remote-logging write it follows; a miss is recorded on the row."""
        if not row.firewall_logging_enabled or creds is None:
            return
        try:
            async with self._firewall_lock(row.router_id):
                await self._sync_firewall_logging(
                    row,
                    creds,
                    enabled=self._firewall_logging_active(row),
                    router_id=row.router_id,
                )
        except (FirewallLoggingBusyError, DeviceWriteFailed) as exc:
            row.firewall_logging_verified_ok = False
            row.firewall_logging_detail = f"not synced: {exc}"
            await self.repository.save_config(row)
            logger.warning(
                "device_logs_firewall_logging_sync_skipped",
                extra={"router_id": str(row.router_id), "reason": str(exc)},
            )

    async def after_firewall_write(self, router_id: uuid.UUID) -> None:
        """Hook for every other writer of the router's ``chain=forward``
        (``FirewallService``), called while it still holds the lock. A
        router that never had firewall logging turned on costs one DB read
        and no device call. Never raises: the write it follows already
        happened, and its own result is what the caller reports."""
        try:
            row = await self.repository.get_config(router_id)
            if row is None or not row.firewall_logging_enabled:
                return
            ctx = await self._context(router_id)
            if ctx["creds"] is None:
                return
            await self._sync_firewall_logging(
                row,
                ctx["creds"],
                enabled=self._firewall_logging_active(row),
                router_id=router_id,
            )
        except Exception:  # noqa: BLE001 -- see docstring
            logger.warning(
                "device_logs_firewall_logging_hook_failed",
                extra={"router_id": str(router_id)},
                exc_info=True,
            )

    def _firewall_state(
        self,
        router_id: uuid.UUID,
        row: RouterRemoteLogging | None,
        *,
        device: FirewallLoggingVerdict | None,
        device_error: str | None,
    ) -> dict[str, Any]:
        return {
            "router_id": str(router_id),
            "platform_enabled": self.firewall_logging_platform_enabled,
            "router_enabled": bool(row and row.firewall_logging_enabled),
            "remote_logging_enabled": bool(row and row.enabled),
            "active": self._firewall_logging_active(row),
            "verified_at": row.firewall_logging_verified_at if row else None,
            "verified_ok": row.firewall_logging_verified_ok if row else None,
            "verify_detail": row.firewall_logging_detail if row else None,
            "device": (
                {
                    "enabled": device.enabled,
                    "ok": device.ok,
                    "band_state": device.band_state,
                    "targets": device.targets,
                    "companions": device.companions,
                    "skipped": list(device.skipped),
                    "detail": device.detail,
                }
                if device is not None
                else None
            ),
            "device_error": device_error,
            "max_lines_per_minute": FIREWALL_LOG_MAX_LINES_PER_MINUTE,
            "per_rule_limit": FIREWALL_LOG_PER_RULE_LIMIT,
        }

    async def firewall_logging_state(self, router_id: uuid.UUID) -> dict[str, Any]:
        """Stored intent and last verdict, plus a live read of the router
        when it can be reached. Writes nothing, takes no lock."""
        ctx = await self._context(router_id)
        row = await self.repository.get_config(router_id)
        device: FirewallLoggingVerdict | None = None
        device_error: str | None = None
        if ctx["creds"] is None:
            device_error = ctx["blocker_detail"]
        if ctx["creds"] is not None and ctx["blocker"] != "NOT_MIKROTIK":
            try:
                device = await self._require_firewall_writer().read(ctx["creds"])
            except DeviceWriteFailed as exc:
                device_error = str(exc)
        return self._firewall_state(
            router_id, row, device=device, device_error=device_error
        )

    async def set_firewall_logging(
        self, router_id: uuid.UUID, *, enabled: bool, actor_user_id: uuid.UUID
    ) -> dict[str, Any]:
        """Master toggle. On: needs the feature, the platform switch and
        remote logging already applied. Off: always allowed, and always
        removes from the device (idempotent). Both under the router's
        forward-chain lock, both read back."""
        ctx = await self._context(router_id)
        row = await self.repository.get_config(router_id)
        if enabled:
            if not self.enabled:
                raise DeviceLogsDisabledError()
            if not self.firewall_logging_platform_enabled:
                raise FirewallLoggingSwitchedOffError()
            if ctx["blocker"] is not None:
                raise DeviceLogsRouterBlockedError(
                    router_id, ctx["blocker"], ctx["blocker_detail"]
                )
            if row is None or not row.enabled:
                raise FirewallLoggingNeedsRemoteLoggingError(router_id)
        elif ctx["creds"] is None or ctx["blocker"] == "NOT_MIKROTIK":
            raise DeviceLogsRouterBlockedError(
                router_id,
                ctx["blocker"] or "NO_API_CREDENTIALS",
                ctx["blocker_detail"] or "",
            )
        if row is not None:
            row.firewall_logging_enabled = enabled
            row.updated_by = actor_user_id
        try:
            async with self._firewall_lock(router_id):
                verdict = await self._sync_firewall_logging(
                    row,
                    ctx["creds"],
                    enabled=enabled and self._firewall_logging_active(row),
                    router_id=router_id,
                )
        except DeviceWriteFailed as exc:
            raise DeviceLogsDeviceError(router_id, str(exc)) from exc
        logger.info(
            "device_logs_firewall_logging_set",
            extra={
                "router_id": str(router_id),
                "fw_enabled": enabled,
                "fw_ok": verdict.ok,
                "actor_user_id": str(actor_user_id),
            },
        )
        return self._firewall_state(router_id, row, device=verdict, device_error=None)

