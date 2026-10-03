"""Aruba AP + MikroTik gateway hybrid: per-guest speed at an Aruba venue.

## Why this exists

Measured on the AP21 (staging, 2026-10-03, ``~/wyfy-ops/aruba-ap21``):
Aruba Instant On ignores every RADIUS bandwidth attribute (WISPr 512/256 kbps
sent, ~200 Mbps measured) and its cloud has no per-client rate limit at all
(only one SSID-wide per-client cap). The AP *does* obey ``Session-Timeout``.
So a per-guest speed plan cannot be enforced by the AP. The owner's decision:
put a Wyfy-managed MikroTik between the ISP and the AP, and enforce speed
there, with the queue writer that already enforces speed at every MikroTik
venue.

## What it does

* **Link (Master only).** ``location_speed_gateways`` names, for one NAS-only
  router, the MikroTik at the **same organization and location** that acts as
  its gateway. Validated on write *and* re-validated at use, so a router that
  is later moved, re-vendored or stripped of its API credentials stops being
  used rather than limiting someone else's guests.
* **Apply.** When the AP reports a guest online (Accounting-Start, and every
  Interim-Update as a self-heal), the guest's session is fed through
  ``QueueManagementService.resolve_and_assign_queue`` -- the *existing*
  writer, unchanged -- with ``router_id`` = the gateway and ``device_target``
  = the guest's IP. Same policy resolution, same ``/queue simple`` row, same
  idempotency, same superseding of a previous holder of that IP, and a
  bandwidth publish reaches these guests mid-session through the existing
  ``reapply_active_sessions_for_location`` (it reapplies from the assignment
  row, which names the gateway). After a write the row is **read back** from
  the device and compared (name, target, not disabled).
* **Key.** The IP the MikroTik actually sees. The AP's accounting carries
  ``Framed-IP-Address`` on Access-Request, Start, Interim and Stop (MEASURED,
  staging capture 2026-10-03), and it equals the IP the portal recorded on
  the session. That IP is only meaningful to the MikroTik when the AP
  *bridges* guests onto the MikroTik's LAN and the MikroTik is their DHCP
  server. With Instant On's own guest NAT/DHCP (172.16.0.x today), every
  guest reaches the MikroTik as the AP's single address and no per-guest key
  exists -- see ``~/wyfy-ops/aruba-ap21/HYBRID_MIKROTIK_GATEWAY.md``. MAC is
  deliberately not used: a ``/queue simple`` target cannot be a MAC.
* **Release.** On Accounting-Stop the queue is removed from the device and
  read back as gone before the assignment is expired; if the device cannot be
  reached the assignment stays ACTIVE and the reconcile sweep retries. That
  sweep also covers every other way a session ends (timeout sweep, operator
  Terminate, block). It does **not** remove the queue of a session that ended
  only in this platform's records while the AP may still be forwarding it --
  an AP-only venue has no disconnect path, so removing the queue there would
  turn a blocked guest *unlimited*. It waits until the AP's own
  ``Session-Timeout`` (which the Accept carried) has certainly fired.

## Gates

``Settings.aruba_hybrid_speed_gateway_enabled`` (default False) gates every
read and write here. Every entry point also requires the session's router to
be NAS-only and the queue row's router to be a linked gateway, so a
MikroTik-only or Omada venue is never touched whatever the flag says.
"""

from __future__ import annotations

import ipaddress
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import status
from sqlalchemy import select

from app.domains.router.vendor_capabilities import (
    is_controller_managed,
    is_nas_only,
    vendor_of,
)

from .constants import QueueStatus, QueueTargetType
from .device_adapters import QueueCredentials, get_queue_adapter
from .exceptions import QueueManagementError
from .models import LocationSpeedGateway, QueueAssignment

logger = logging.getLogger(__name__)

__all__ = [
    "SpeedGatewayError",
    "SpeedGatewayRepository",
    "SpeedGatewayService",
    "HybridOutcome",
    "gateway_unusable_reason",
    "release_is_due",
]

#: The only vendor whose ``/queue simple`` this module writes.
GATEWAY_VENDOR = "mikrotik"

#: Extra time after the AP's own Session-Timeout before the sweep treats a
#: session as certainly off the AP. Covers clock skew and the AP's own Stop
#: arriving late (measured: 5:15-5:24 for a 299 s timeout).
AP_CUTOFF_GRACE = timedelta(minutes=5)

#: A session with no recorded timeout has no AP-enforced end this platform
#: knows of. Its queue is kept (capped beats unlimited) for this long after
#: the row ended, then removed. A stale row is low-harm in between: the next
#: guest handed that IP supersedes it (``_retire_superseded_assignments``).
UNBOUNDED_SESSION_RELEASE_AFTER = timedelta(hours=24)


class SpeedGatewayError(QueueManagementError):
    """A refused link, with a machine-readable ``data.code``."""

    def __init__(self, code: str, message: str, *, status_code: int) -> None:
        super().__init__(message, status_code=status_code, data={"code": code})


def _refuse(code: str, message: str, status_code: int = 422) -> SpeedGatewayError:
    return SpeedGatewayError(code, message, status_code=status_code)


@dataclass(frozen=True, slots=True)
class HybridOutcome:
    """What one apply/release did. ``action`` is one of ``applied``,
    ``unchanged``, ``released``, ``skipped``, ``failed``."""

    action: str
    reason: str | None = None
    assignment_id: uuid.UUID | None = None
    verified: bool | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "reason": self.reason,
            "assignment_id": str(self.assignment_id) if self.assignment_id else None,
            "verified": self.verified,
        }


def gateway_unusable_reason(
    gateway: Any, *, organization_id: uuid.UUID, location_id: uuid.UUID
) -> str | None:
    """Why ``gateway`` cannot enforce speed for a NAS-only router of
    (``organization_id``, ``location_id``), or ``None`` if it can.

    The cross-tenant guard: a gateway of another organization or another
    location is refused, never used."""
    if gateway is None or getattr(gateway, "is_deleted", False):
        return "SPEED_GATEWAY_ROUTER_NOT_FOUND"
    if (
        vendor_of(gateway) != GATEWAY_VENDOR
        or is_controller_managed(gateway)
        or is_nas_only(gateway)
    ):
        return "SPEED_GATEWAY_WRONG_VENDOR"
    if gateway.organization_id != organization_id or gateway.location_id != location_id:
        return "SPEED_GATEWAY_LOCATION_MISMATCH"
    host = gateway.management_ip_address or gateway.public_ip_address
    if not host or not gateway.api_username or not gateway.api_credentials_encrypted:
        return "SPEED_GATEWAY_NO_CREDENTIALS"
    return None


def guest_ip_for_queue(value: str | None) -> str | None:
    """``value`` as a plain IPv4 address a ``/queue simple`` target can hold,
    or ``None``. Never raises: a malformed attribute must not fail accounting.
    """
    if not value:
        return None
    try:
        address = ipaddress.IPv4Address(str(value).strip())
    except ValueError:
        return None
    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_multicast
        or address.is_link_local
        or address == ipaddress.IPv4Address("255.255.255.255")
    ):
        return None
    return str(address)


def _target_matches(device_target: str | None, ip: str) -> bool:
    """RouterOS prints ``172.16.0.4/32``; we stored ``172.16.0.4``."""
    if not device_target:
        return False
    first = device_target.split(",")[0].strip()
    try:
        return ipaddress.ip_interface(first).ip == ipaddress.ip_address(ip)
    except ValueError:
        return False


def release_is_due(session: Any, *, now: datetime) -> bool:
    """May the sweep take this ended session's queue off the gateway?

    Only once the AP has certainly stopped forwarding it. The AP enforces the
    ``Session-Timeout`` this platform sent (MEASURED), and that value is never
    later than ``started_at + session_timeout_minutes``. A session the AP
    itself ended is released on its Stop, not here; this is for the ends the
    AP never heard of (operator Terminate, block, the expiry sweep)."""
    if session.is_active():
        return False
    timeout = getattr(session, "session_timeout_minutes", None)
    if timeout:
        return now >= session.started_at + timedelta(minutes=timeout) + AP_CUTOFF_GRACE
    ended_at = getattr(session, "ended_at", None) or session.started_at
    return now >= ended_at + UNBOUNDED_SESSION_RELEASE_AFTER


class SpeedGatewayRepository:
    """``location_speed_gateways`` plus the two cross-table reads the
    enforcer needs (the guest session row, and a gateway's live SESSION queue
    assignments)."""

    def __init__(self, session) -> None:  # noqa: ANN001 -- AsyncSession
        self.session = session

    async def get_for_nas_router(
        self, nas_router_id: uuid.UUID
    ) -> LocationSpeedGateway | None:
        result = await self.session.execute(
            select(LocationSpeedGateway).where(
                LocationSpeedGateway.nas_router_id == nas_router_id,
                LocationSpeedGateway.is_deleted.is_(False),
            )
        )
        return result.scalars().first()

    async def list_for_location(
        self, *, location_id: uuid.UUID, organization_id: uuid.UUID
    ) -> list[LocationSpeedGateway]:
        result = await self.session.execute(
            select(LocationSpeedGateway).where(
                LocationSpeedGateway.location_id == location_id,
                LocationSpeedGateway.organization_id == organization_id,
                LocationSpeedGateway.is_deleted.is_(False),
            )
        )
        return list(result.scalars().all())

    async def list_for_gateway(
        self, gateway_router_id: uuid.UUID
    ) -> list[LocationSpeedGateway]:
        result = await self.session.execute(
            select(LocationSpeedGateway).where(
                LocationSpeedGateway.gateway_router_id == gateway_router_id,
                LocationSpeedGateway.is_deleted.is_(False),
            )
        )
        return list(result.scalars().all())

    async def list_all(self) -> list[LocationSpeedGateway]:
        result = await self.session.execute(
            select(LocationSpeedGateway).where(
                LocationSpeedGateway.is_deleted.is_(False)
            )
        )
        return list(result.scalars().all())

    async def save(self, **fields: Any) -> LocationSpeedGateway:
        existing = await self.get_for_nas_router(fields["nas_router_id"])
        if existing is not None:
            for key, value in fields.items():
                setattr(existing, key, value)
            await self.session.flush()
            return existing
        row = LocationSpeedGateway(**fields)
        self.session.add(row)
        await self.session.flush()
        return row

    async def delete(self, row: LocationSpeedGateway) -> None:
        await self.session.delete(row)
        await self.session.flush()

    async def get_guest_session(self, session_id: uuid.UUID | None) -> Any:
        if session_id is None:
            return None
        from app.domains.guest.models import GuestSession

        result = await self.session.execute(
            select(GuestSession).where(GuestSession.id == session_id)
        )
        return result.scalars().first()

    async def list_live_session_assignments(
        self, *, router_id: uuid.UUID
    ) -> list[QueueAssignment]:
        """Every live SESSION-targeted assignment pushed to ``router_id``."""
        result = await self.session.execute(
            select(QueueAssignment).where(
                QueueAssignment.router_id == router_id,
                QueueAssignment.target_type == QueueTargetType.SESSION.value,
                QueueAssignment.status != QueueStatus.EXPIRED.value,
                QueueAssignment.is_deleted.is_(False),
            )
        )
        return list(result.scalars().all())


class SpeedGatewayService:
    """Master link management and the per-guest enforcer. See the module
    docstring."""

    def __init__(
        self,
        repository: SpeedGatewayRepository,
        router_lookup: Any,
        *,
        queue_service: Any = None,
        enabled: bool = False,
        adapter_factory: Callable[[str], Any] = get_queue_adapter,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.queue_service = queue_service
        self.enabled = enabled
        self._adapter_factory = adapter_factory
        self._clock = clock

    # ------------------------------------------------------------------
    # Master: link / unlink / status
    # ------------------------------------------------------------------

    async def _nas_router(self, nas_router_id: uuid.UUID) -> Any:
        from app.domains.router.exceptions import RouterNotFoundError

        try:
            router = await self.router_lookup.get_router(nas_router_id)
        except RouterNotFoundError:
            raise _refuse(
                "SPEED_GATEWAY_ROUTER_NOT_FOUND",
                "That access point is not in the fleet.",
                status.HTTP_404_NOT_FOUND,
            ) from None
        if not is_nas_only(router):
            raise _refuse(
                "SPEED_GATEWAY_NOT_NAS_ONLY",
                "A speed gateway can only be linked to an Aruba Instant On "
                "access point. MikroTik and Omada venues enforce speed "
                "themselves.",
            )
        return router

    @staticmethod
    def _router_summary(router: Any) -> dict[str, Any]:
        return {
            "router_id": str(router.id),
            "name": router.name,
            "model": router.model,
            "status": router.status,
            "has_api_credentials": bool(
                (router.management_ip_address or router.public_ip_address)
                and router.api_username
                and router.api_credentials_encrypted
            ),
        }

    async def _gateway_row(self, link: LocationSpeedGateway | None) -> Any:
        if link is None:
            return None
        try:
            return await self.router_lookup.get_router(link.gateway_router_id)
        except Exception:  # noqa: BLE001 -- a vanished router is "no gateway"
            return None

    async def status(self, nas_router_id: uuid.UUID) -> dict[str, Any]:
        nas_router = await self._nas_router(nas_router_id)
        link = await self.repository.get_for_nas_router(nas_router.id)
        gateway = await self._gateway_row(link)
        unusable = (
            gateway_unusable_reason(
                gateway,
                organization_id=nas_router.organization_id,
                location_id=nas_router.location_id,
            )
            if link is not None
            else "NOT_LINKED"
        )
        candidates = [
            self._router_summary(r)
            for r in await self.router_lookup.list_routers_in_scope(
                organization_id=nas_router.organization_id,
                location_id=nas_router.location_id,
            )
            if vendor_of(r) == GATEWAY_VENDOR
            and not is_controller_managed(r)
            and not is_nas_only(r)
            and not getattr(r, "is_deleted", False)
        ]
        return {
            "router_id": str(nas_router.id),
            "location_id": str(nas_router.location_id),
            "feature_enabled": self.enabled,
            "gateway": self._router_summary(gateway)
            if gateway is not None and link is not None
            else None,
            "gateway_problem": None if link is None else unusable,
            "per_guest_speed_active": bool(self.enabled and unusable is None),
            "candidates": candidates,
        }

    async def link(
        self,
        *,
        nas_router_id: uuid.UUID,
        gateway_router_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
    ) -> dict[str, Any]:
        """Link ``gateway_router_id`` as the speed gateway of the NAS-only
        router. Organization and location are copied from the NAS-only
        router; the gateway must already share both."""
        from app.domains.router.exceptions import RouterNotFoundError

        nas_router = await self._nas_router(nas_router_id)
        try:
            gateway = await self.router_lookup.get_router(gateway_router_id)
        except RouterNotFoundError:
            gateway = None
        reason = gateway_unusable_reason(
            gateway,
            organization_id=nas_router.organization_id,
            location_id=nas_router.location_id,
        )
        if reason is not None:
            raise _refuse(reason, _LINK_REFUSAL_MESSAGES[reason])
        previous = await self.repository.get_for_nas_router(nas_router.id)
        if previous is not None and previous.gateway_router_id != gateway.id:
            # Re-pointing: the old gateway's queues for this venue must not
            # outlive the link that put them there.
            await self._release_all_on(
                previous.gateway_router_id, nas_router_id=nas_router.id
            )
        await self.repository.save(
            organization_id=nas_router.organization_id,
            location_id=nas_router.location_id,
            nas_router_id=nas_router.id,
            gateway_router_id=gateway.id,
            updated_by=actor_user_id,
            **({} if previous is not None else {"created_by": actor_user_id}),
        )
        logger.info(
            "aruba_hybrid_gateway_linked",
            extra={
                "event_nas_router_id": str(nas_router.id),
                "event_gateway_router_id": str(gateway.id),
            },
        )
        return await self.status(nas_router.id)

    async def unlink(
        self, *, nas_router_id: uuid.UUID, actor_user_id: uuid.UUID | None
    ) -> dict[str, Any]:
        nas_router = await self._nas_router(nas_router_id)
        link = await self.repository.get_for_nas_router(nas_router.id)
        if link is not None:
            await self._release_all_on(
                link.gateway_router_id, nas_router_id=nas_router.id
            )
            await self.repository.delete(link)
            logger.info(
                "aruba_hybrid_gateway_unlinked",
                extra={
                    "event_nas_router_id": str(nas_router.id),
                    "event_gateway_router_id": str(link.gateway_router_id),
                },
            )
        return await self.status(nas_router.id)

    async def customer_per_guest_speed(
        self,
        *,
        location_id: uuid.UUID,
        organization_id: uuid.UUID | None,
    ) -> bool:
        """True iff guests at this location get per-guest speed from a linked,
        usable gateway right now. Organization is applied in the query, so
        another tenant's location reads as ``False``, same as an unlinked
        one."""
        if not self.enabled or organization_id is None:
            return False
        for link in await self.repository.list_for_location(
            location_id=location_id, organization_id=organization_id
        ):
            gateway = await self._gateway_row(link)
            if (
                gateway_unusable_reason(
                    gateway, organization_id=organization_id, location_id=location_id
                )
                is None
            ):
                return True
        return False

    # ------------------------------------------------------------------
    # Enforcement
    # ------------------------------------------------------------------

    async def resolve_gateway(self, nas_router: Any) -> Any:
        """The usable gateway for this NAS-only router, or ``None``."""
        if not self.enabled or not is_nas_only(nas_router):
            return None
        link = await self.repository.get_for_nas_router(nas_router.id)
        if link is None:
            return None
        gateway = await self._gateway_row(link)
        reason = gateway_unusable_reason(
            gateway,
            organization_id=nas_router.organization_id,
            location_id=nas_router.location_id,
        )
        if reason is not None:
            logger.warning(
                "aruba_hybrid_gateway_unusable",
                extra={
                    "event_nas_router_id": str(nas_router.id),
                    "event_gateway_router_id": str(link.gateway_router_id),
                    "event_reason": reason,
                },
            )
            return None
        return gateway

    def _credentials(self, gateway: Any) -> QueueCredentials:
        return QueueCredentials(
            host=gateway.management_ip_address or gateway.public_ip_address,
            username=gateway.api_username,
            password=self.router_lookup.get_decrypted_api_secret(gateway),
        )

    async def _read_device_row(self, gateway: Any, device_queue_id: str) -> Any:
        adapter = self._adapter_factory(gateway.vendor)
        return await adapter.read_queue_status(
            self._credentials(gateway), device_queue_id=device_queue_id
        )

    async def apply_for_session(
        self,
        *,
        session_id: uuid.UUID,
        nas_router_id: uuid.UUID,
        framed_ip: str | None = None,
        verify: bool = False,
    ) -> HybridOutcome:
        """Put (or keep) this guest's per-device queue on the gateway.

        Idempotent: an unchanged rate and IP is a no-op with no device write
        (``resolve_and_assign_queue``'s own contract). After any write -- or
        always when ``verify`` (Accounting-Start) -- the device row is read
        back; a row missing from the device is re-created once."""
        if not self.enabled:
            return HybridOutcome("skipped", "disabled")
        session = await self.repository.get_guest_session(session_id)
        if session is None or not session.is_active():
            return HybridOutcome("skipped", "session_not_active")
        if session.router_id != nas_router_id:
            return HybridOutcome("skipped", "router_mismatch")
        nas_router = await self.router_lookup.get_router(session.router_id)
        gateway = await self.resolve_gateway(nas_router)
        if gateway is None:
            return HybridOutcome("skipped", "no_gateway")
        ip = guest_ip_for_queue(framed_ip) or guest_ip_for_queue(session.ip_address)
        if ip is None:
            logger.warning(
                "aruba_hybrid_queue_no_guest_ip",
                extra={"event_session_id": str(session.id)},
            )
            return HybridOutcome("skipped", "no_guest_ip")

        before = await self._live_assignment(session.id, gateway.id)
        assignment = await self._resolve(session, gateway, ip)
        wrote = before is None or (
            before.id != assignment.id
            or before.device_queue_id != assignment.device_queue_id
            or before.device_target != assignment.device_target
            or before.queue_profile_id != assignment.queue_profile_id
        )
        if not (wrote or verify):
            return HybridOutcome("unchanged", assignment_id=assignment.id)

        verified, problem = await self._verify(gateway, assignment, ip)
        if problem == "missing_on_device":
            # Removed out of band (someone cleaned /queue simple by hand, or
            # the router was reset). Re-create once, then judge again.
            await self._forget_device_row(assignment)
            await self.queue_service.expire_assignment(
                assignment.id,
                actor_user_id=None,
                requesting_organization_id=assignment.organization_id,
                reason="aruba hybrid: queue missing on the gateway",
            )
            assignment = await self._resolve(session, gateway, ip)
            verified, problem = await self._verify(gateway, assignment, ip)
        if not verified:
            await self.queue_service.repository.update_assignment(
                assignment, {"error_message": f"read-back: {problem}"}
            )
            logger.warning(
                "aruba_hybrid_queue_readback_mismatch",
                extra={
                    "event_session_id": str(session.id),
                    "event_assignment_id": str(assignment.id),
                    "event_problem": problem,
                },
            )
            return HybridOutcome(
                "failed", problem, assignment_id=assignment.id, verified=False
            )
        logger.info(
            "aruba_hybrid_queue_applied",
            extra={
                "event_session_id": str(session.id),
                "event_assignment_id": str(assignment.id),
                "event_gateway_router_id": str(gateway.id),
                "event_device_target": ip,
            },
        )
        return HybridOutcome("applied", assignment_id=assignment.id, verified=True)

    async def _resolve(self, session: Any, gateway: Any, ip: str) -> QueueAssignment:
        return await self.queue_service.resolve_and_assign_queue(
            requesting_organization_id=session.organization_id,
            location_id=session.location_id,
            router_id=gateway.id,
            target_type=QueueTargetType.SESSION,
            target_id=session.id,
            device_target=ip,
            guest_id=session.guest_id,
        )

    async def _live_assignment(
        self, session_id: uuid.UUID, gateway_id: uuid.UUID
    ) -> QueueAssignment | None:
        rows = await self.queue_service.repository.list_assignments_for_target(
            target_type=QueueTargetType.SESSION.value, target_id=session_id
        )
        for row in rows:
            if row.router_id == gateway_id:
                return row
        return None

    async def _verify(
        self, gateway: Any, assignment: QueueAssignment, ip: str
    ) -> tuple[bool, str | None]:
        if (
            QueueStatus(assignment.status) != QueueStatus.ACTIVE
            or not assignment.device_queue_id
        ):
            return False, f"not_applied:{assignment.status}"
        row = await self._read_device_row(gateway, assignment.device_queue_id)
        if row.name is None:
            return False, "missing_on_device"
        if row.name != f"cloudguest-{assignment.id}":
            return False, "name_mismatch"
        if not _target_matches(row.target, ip):
            return False, "target_mismatch"
        if row.disabled:
            return False, "disabled_on_device"
        return True, None

    async def _forget_device_row(self, assignment: QueueAssignment) -> None:
        await self.queue_service.repository.update_assignment(
            assignment, {"device_queue_id": None}
        )

    async def release_for_session(self, *, session_id: uuid.UUID) -> HybridOutcome:
        """Take this session's queue(s) off its gateway, read back, then
        expire the assignment. Only rows on a **linked gateway** are touched,
        so a MikroTik-only venue's queues are never reached from here.

        Raises when the device could not be reached or still holds the row:
        the assignment then stays ACTIVE and the sweep retries."""
        if not self.enabled:
            return HybridOutcome("skipped", "disabled")
        session = await self.repository.get_guest_session(session_id)
        if session is None:
            return HybridOutcome("skipped", "session_not_found")
        rows = await self.queue_service.repository.list_assignments_for_target(
            target_type=QueueTargetType.SESSION.value, target_id=session_id
        )
        released: list[uuid.UUID] = []
        for row in rows:
            if row.router_id is None:
                continue
            if session.router_id not in await self._nas_routers_behind(row.router_id):
                continue
            await self._release_row(row)
            released.append(row.id)
        if not released:
            return HybridOutcome("skipped", "nothing_to_release")
        return HybridOutcome("released", assignment_id=released[0], verified=True)

    async def _nas_routers_behind(self, gateway_router_id: uuid.UUID) -> set[uuid.UUID]:
        """The NAS-only routers this gateway is linked for. A gateway may also
        run its own MikroTik hotspot at the venue; queues for *those* sessions
        (whose router is the gateway itself) are never this module's."""
        return {
            link.nas_router_id
            for link in await self.repository.list_for_gateway(gateway_router_id)
        }

    async def _ours(self, row: QueueAssignment, nas_router_ids: set[uuid.UUID]) -> Any:
        """``(is_ours, session)`` -- a row is ours only when its session is
        known and was authorized by a NAS-only router behind this gateway."""
        session = await self.repository.get_guest_session(row.target_id)
        return (session is not None and session.router_id in nas_router_ids), session

    async def _release_row(self, row: QueueAssignment) -> None:
        gateway = await self.router_lookup.get_router(row.router_id)
        device_queue_id = row.device_queue_id
        if device_queue_id:
            current = await self._read_device_row(gateway, device_queue_id)
            if current.name != f"cloudguest-{row.id}":
                # Already gone (or the id now names someone else's row --
                # RouterOS reuses ids). Never remove a row that is not ours.
                await self._forget_device_row(row)
                device_queue_id = None
        await self.queue_service.expire_assignment(
            row.id,
            actor_user_id=None,
            requesting_organization_id=row.organization_id,
            reason="aruba hybrid: guest session ended",
        )
        if device_queue_id:
            after = await self._read_device_row(gateway, device_queue_id)
            if after.name == f"cloudguest-{row.id}":
                raise RuntimeError(
                    f"queue {device_queue_id} still on gateway {gateway.id} "
                    "after removal"
                )
        logger.info(
            "aruba_hybrid_queue_released",
            extra={
                "event_assignment_id": str(row.id),
                "event_session_id": str(row.target_id),
                "event_gateway_router_id": str(row.router_id),
            },
        )

    async def _release_all_on(
        self, gateway_router_id: uuid.UUID, *, nas_router_id: uuid.UUID
    ) -> int:
        """Unlink / re-point: remove every live session queue this hybrid put
        on that gateway for that access point. Best-effort per row; the sweep
        cannot retry these once the link is gone, so failures are logged
        loudly."""
        released = 0
        for row in await self.repository.list_live_session_assignments(
            router_id=gateway_router_id
        ):
            ours, _ = await self._ours(row, {nas_router_id})
            if not ours:
                continue
            try:
                await self._release_row(row)
                released += 1
            except Exception as exc:  # noqa: BLE001 -- per-row isolation
                logger.error(
                    "aruba_hybrid_queue_release_on_unlink_failed",
                    extra={"event_assignment_id": str(row.id), "error": str(exc)},
                )
        return released

    async def reconcile(self) -> dict[str, int]:
        """The sweep: release every live gateway queue whose session ended and
        whose AP-side cut-off has certainly passed (``release_is_due``)."""
        if not self.enabled:
            return {"checked": 0, "released": 0, "failed": 0, "kept": 0}
        now = self._clock()
        checked = released = failed = kept = 0
        behind: dict[uuid.UUID, set[uuid.UUID]] = {}
        for link in await self.repository.list_all():
            behind.setdefault(link.gateway_router_id, set()).add(link.nas_router_id)
        for gateway_id, nas_router_ids in behind.items():
            for row in await self.repository.list_live_session_assignments(
                router_id=gateway_id
            ):
                ours, session = await self._ours(row, nas_router_ids)
                if not ours:
                    continue
                checked += 1
                if not release_is_due(session, now=now):
                    kept += 1
                    continue
                try:
                    await self._release_row(row)
                    released += 1
                except Exception as exc:  # noqa: BLE001 -- per-row isolation
                    failed += 1
                    logger.warning(
                        "aruba_hybrid_queue_release_failed",
                        extra={"event_assignment_id": str(row.id), "error": str(exc)},
                    )
        return {
            "checked": checked,
            "released": released,
            "failed": failed,
            "kept": kept,
        }


_LINK_REFUSAL_MESSAGES: dict[str, str] = {
    "SPEED_GATEWAY_ROUTER_NOT_FOUND": "That gateway router is not in the fleet.",
    "SPEED_GATEWAY_WRONG_VENDOR": (
        "The speed gateway must be a Wyfy-managed MikroTik router."
    ),
    "SPEED_GATEWAY_LOCATION_MISMATCH": (
        "The gateway must be a router of the same customer and the same "
        "location as the access point."
    ),
    "SPEED_GATEWAY_NO_CREDENTIALS": (
        "Wyfy has no API access to that router yet (address, API user and "
        "password are needed to write its queues)."
    ),
}
