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
"""

from __future__ import annotations

import base64
import binascii
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from app.core.config import Settings
from app.domains.router.crypto import decrypt_secret

from .constants import (
    DEFAULT_PAGE_SIZE,
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
)
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


def _id(value: uuid.UUID | None) -> str | None:
    return str(value) if value is not None else None


class DeviceLogsService:
    def __init__(
        self,
        repository: DeviceLogsRepository,
        settings: Settings,
        *,
        writer: RemoteLoggingWriter | None = None,
        clock: Any = None,
    ) -> None:
        self.repository = repository
        self.settings = settings
        self._writer = writer
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
                attribution = Attribution.TAG_MISMATCH
                counts["tag_mismatch"] += 1
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
                }
            )
        await self.repository.insert_events(rows)
        if counts["tag_mismatch"] or counts["unattributed"]:
            logger.warning("device_logs_ingest_attribution_gaps", extra=counts)
        return {"accepted": len(rows), **counts}

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
        }

    # -- status --------------------------------------------------------
    def _status_view(
        self,
        config: RouterRemoteLogging,
        *,
        router_name: str | None,
        location_name: str | None,
        organization_name: str | None,
        last_received_at: datetime | None,
    ) -> dict[str, Any]:
        return {
            "router_id": str(config.router_id),
            "router_name": router_name,
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
                last_received_at=last.get(config.router_id),
            )
            for config, router_name, location_name, organization_name in configs
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
