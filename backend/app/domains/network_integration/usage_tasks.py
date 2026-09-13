"""Celery Beat task: back-fill guest session data-usage bytes for TP-Link
Omada "External Portal Server" venues from the controller's Open API.

## The gap this closes

``guest_sessions.bytes_uploaded``/``bytes_downloaded`` are written by exactly
one method -- ``app.domains.guest.service.GuestService.record_usage`` -- and
that method is called from exactly one place: ``RadiusService
.accounting_interim_update``/``accounting_stop``, i.e. off RADIUS accounting
packets. A MikroTik venue sends RADIUS Interim-Updates, so its guests' byte
counters, the dashboard's data-usage columns and bandwidth tiles, and the
mid-session FUP data-quota cutoff all work.

An Omada External-Portal venue sends **no RADIUS accounting at all** -- the
guest is authorized on the controller over Open API, and nothing on that path
ever reaches ``record_usage``. So every one of those surfaces reads zero for
an Omada guest, forever. The controller itself does have the numbers
(``traffic_up_bytes``/``traffic_down_bytes`` on each connected client), so
this sweep polls them and pushes the delta through the same sink.

## Additive, and it never touches the RADIUS path

This task is a *second, independent producer* for the one existing sink. It
does not modify ``record_usage``, ``RadiusService``, or anything on the
MikroTik/RADIUS data path -- those keep behaving exactly as before. The only
write it performs is ``record_usage``, reused verbatim, so byte-bumping, the
``_track_fup_data_usage`` FUP roll-up, and the on-quota session expiry are all
whatever ``record_usage`` already does; this module reimplements none of it.

## Omada + Open API only

Selection is ``repository.list_omada_openapi_for_usage_sync`` -- provider
``omada`` and ``auth_mode == openapi``, in SQL. A ``legacy`` (hotspot
operator) integration cannot read client traffic over the controller API at
all (contract CR-002) and is excluded there, not fetched and discarded.

## Monotonic delta, mirroring RADIUS exactly

The controller's ``traffic_*_bytes`` are cumulative session totals, the same
shape as RADIUS ``Acct-*-Octets`` running totals. So the delta is computed the
same way ``accounting_interim_update`` computes it from a total::

    up_delta = max(0, controller_total_up - session.bytes_uploaded)

``max(0, ...)`` is what makes a repeated poll a no-op (idempotent, like a
RADIUS accounting retransmit) and what keeps usage monotonic when a controller
counter restarts -- clamping at zero rather than crediting quota back, the
safer direction to be wrong in for a cap meant to be enforced.

## Matching

Each controller client is matched to an ACTIVE ``guest_session`` by device
MAC: the client's ``mac`` is normalised to a canonical hex form and looked up
against the MACs of the devices behind the venue's currently-active sessions
(``guest_devices.mac_address`` -> ``device_id`` -> ``guest_sessions
.device_id``). Sessions are scoped to the integration's synthetic fleet
``Router`` (``guest_sessions.router_id``), which is the row Omada guest
sessions are created against; device rows are resolved org-scoped. MAC
spelling differs between the two sides (Omada uses dashes on the portal
redirect, colons in some API replies; ``GuestDevice.mac_address`` is stored
upper-cased but keeps whatever separator the login supplied), so both sides
are reduced to bare uppercase hex before comparison.

## Scheduling / queue

Registered in ``app.core.celery_app`` as a Beat entry on a fixed
``OMADA_USAGE_SYNC_SWEEP_INTERVAL_SECONDS`` cadence and routed onto
``DEVICE_IO_QUEUE_NAME`` -- like the inventory sync sweep, every tick issues
real HTTPS round trips to customer-owned controllers, which is exactly what
that queue exists to keep off the default pure-DB queue.

## Failure isolation

One venue's unreachable controller must not abort the sweep for every other
venue, so each integration is wrapped individually. A provider failure is
already recorded on that integration's own event feed by ``list_clients``;
here it only increments a counter. The task returns counts and never raises
per-venue.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.core.logging import get_logger
from app.database.redis import redis_client
from app.database.session import SessionLocal
from app.domains.guest.repository import GuestRepository
from app.domains.guest.service import GuestService
from app.domains.location.repository import (
    LocationCodeCounterRepository,
    LocationRepository,
)
from app.domains.location.service import LocationService
from app.domains.organization.repository import OrganizationRepository
from app.domains.organization.service import OrganizationService
from app.domains.policy.repository import PolicyRepository
from app.domains.policy.service import PolicyService
from app.domains.rbac.repository import RBACRepository

from .constants import (
    OMADA_USAGE_SYNC_MAX_INTEGRATIONS_PER_RUN,
    TASK_RUN_OMADA_USAGE_SYNC_SWEEP,
)
from .exceptions import ProviderError
from .providers.base import ProviderClient
from .repository import NetworkIntegrationRepository
from .service import NetworkIntegrationService

logger = get_logger(__name__)

__all__ = [
    "OmadaUsageSyncSummary",
    "apply_controller_usage",
    "run_omada_usage_sync_sweep",
    "sync_omada_session_usage",
]


class _UsageRecorder(Protocol):
    """The one method this task calls on ``GuestService``. Narrow on purpose
    so the matching/delta logic below is testable without constructing a real
    service graph."""

    async def record_usage(
        self,
        *,
        session_id: uuid.UUID,
        bytes_uploaded_delta: int,
        bytes_downloaded_delta: int,
    ) -> object: ...


class _ActiveSession(Protocol):
    id: uuid.UUID
    device_id: uuid.UUID | None
    bytes_uploaded: int
    bytes_downloaded: int
    started_at: datetime


class _Device(Protocol):
    id: uuid.UUID
    mac_address: str


@dataclass
class OmadaUsageSyncSummary:
    """What one sweep run did. Mutated in place across the integration loop;
    returned to the Celery task body for the log line and result."""

    integrations_considered: int = 0
    integrations_synced: int = 0
    integrations_failed: int = 0
    sessions_updated: int = 0
    bytes_uploaded_applied: int = 0
    bytes_downloaded_applied: int = 0


def _canonical_mac(raw: str | None) -> str | None:
    """Bare uppercase hex (``"AABBCCDDEEFF"``), or ``None`` if ``raw`` is not
    a six-octet MAC.

    Deliberately separator-agnostic: it strips ``:``, ``-`` and ``.`` so the
    controller's spelling (dashes on the portal redirect, colons in some API
    replies) and ``GuestDevice.mac_address``'s stored spelling (upper-cased
    but keeping whatever separator the login supplied) compare equal. Returns
    ``None`` -- never a partial or best-effort string -- so an unparseable MAC
    simply fails to match rather than matching the wrong device."""
    if not raw:
        return None
    hex_only = (
        raw.strip().upper().replace(":", "").replace("-", "").replace(".", "")
    )
    if len(hex_only) != 12:
        return None
    if any(ch not in "0123456789ABCDEF" for ch in hex_only):
        return None
    return hex_only


_USAGE_CURSOR_KEY = "omada:usage:cursor:{session_id}"
# Comfortably longer than any guest session; if a cursor does expire mid-session
# the next sweep simply re-baselines (accrues 0 that tick), i.e. a bounded
# under-count, never a false over-count. Not a correctness dependency -- a
# durability convenience on top of the session's own persisted bytes.
_USAGE_CURSOR_TTL_SECONDS = 7 * 24 * 60 * 60


async def _load_cursors(
    redis, session_ids: Sequence[uuid.UUID]
) -> dict[uuid.UUID, tuple[int, int]]:
    """Last controller totals this sweep recorded per session. A malformed or
    missing value is treated as "never seen" (absent) so a first sight
    re-baselines rather than accruing against garbage."""
    cursors: dict[uuid.UUID, tuple[int, int]] = {}
    for session_id in session_ids:
        raw = await redis.get(_USAGE_CURSOR_KEY.format(session_id=session_id))
        if raw is None:
            continue
        if isinstance(raw, bytes):
            raw = raw.decode()
        try:
            up_str, down_str = raw.split(",", 1)
            cursors[session_id] = (int(up_str), int(down_str))
        except (ValueError, AttributeError):
            continue
    return cursors


async def _store_cursors(
    redis, new_cursors: Mapping[uuid.UUID, tuple[int, int]]
) -> None:
    for session_id, (up, down) in new_cursors.items():
        await redis.set(
            _USAGE_CURSOR_KEY.format(session_id=session_id),
            f"{up},{down}",
            ex=_USAGE_CURSOR_TTL_SECONDS,
        )


async def apply_controller_usage(
    *,
    clients: Sequence[ProviderClient],
    active_sessions: Sequence[_ActiveSession],
    devices_by_id: Mapping[uuid.UUID, _Device],
    guest_service: _UsageRecorder,
    cursors: Mapping[uuid.UUID, tuple[int, int]],
) -> tuple[int, int, int, dict[uuid.UUID, tuple[int, int]]]:
    """Match ``clients`` to ``active_sessions`` by MAC and push the delta of
    the controller's cumulative totals *since this sweep last saw them* through
    ``guest_service.record_usage``.

    Returns ``(sessions_updated, bytes_uploaded_applied, bytes_downloaded_applied,
    new_cursors)`` where ``new_cursors`` is the controller total last observed
    for each matched session, to be persisted by the caller. Pure of any DB,
    provider or cache access -- every collaborator is passed in -- which is what
    makes it the unit-test seam for the delta/matching contract.

    ## Why a per-session cursor, not ``total - session.bytes``

    Omada's ``traffic_*_bytes`` accumulate over the **client's association with
    the AP**, and a captive-portal re-authorization does not deassociate the
    client -- so those counters are NOT reset when one ``guest_session`` ends
    and the next login opens a fresh row at ``bytes = 0``. Subtracting the new
    session's ``bytes`` (0) from the still-high controller total would dump the
    entire prior session's usage into the new session as one delta and trip its
    FUP/data cap the instant the guest reconnects. So instead the delta is taken
    against the controller total this sweep *last recorded for this session*:
    the first time a session is seen, its cursor is set to the current total and
    **zero** is accrued (the inherited total is a baseline, not usage); only
    growth after that point counts. This is the standard interface-counter
    polling model, and it makes the byte lifecycle depend on the session's own
    first-sight rather than on a controller counter it does not control.

    A counter that moves backwards (a controller-side reset, or a roam to
    another AP whose counter starts lower) yields ``current < cursor``: the
    delta clamps to 0 and the cursor re-baselines at the lower value, so usage
    never runs backwards and a reset costs at most the unseen tail -- the safe
    direction to be wrong in for a cap meant to be enforced.
    """
    # Deterministic session selection: a device that overran its session
    # timeout can briefly hold an ACTIVE stale row AND a fresh re-login row at
    # once (the login path does not reuse an overrun ACTIVE session, and
    # sessions are append-only). The controller's live traffic belongs to the
    # current connection, i.e. the most recently started session -- pick that
    # one, deterministically, instead of whichever the query happened to order
    # first.
    session_by_mac: dict[str, _ActiveSession] = {}
    for session in active_sessions:
        if session.device_id is None:
            continue
        device = devices_by_id.get(session.device_id)
        if device is None:
            continue
        canonical = _canonical_mac(device.mac_address)
        if canonical is None:
            continue
        incumbent = session_by_mac.get(canonical)
        if incumbent is None or session.started_at > incumbent.started_at:
            session_by_mac[canonical] = session

    sessions_updated = 0
    up_applied = 0
    down_applied = 0
    new_cursors: dict[uuid.UUID, tuple[int, int]] = {}
    for client in clients:
        canonical = _canonical_mac(client.mac)
        if canonical is None:
            continue
        session = session_by_mac.get(canonical)
        if session is None:
            continue
        up_total = client.traffic_up_bytes
        down_total = client.traffic_down_bytes
        if up_total is None and down_total is None:
            # The controller reported no counters for this client. A missing
            # reading is not a zero -- there is nothing to baseline or accrue.
            continue
        cur_up = up_total or 0
        cur_down = down_total or 0

        prev = cursors.get(session.id)
        if prev is None:
            # First sight of this session: the controller total is a carried-in
            # baseline, not usage. Record the cursor, accrue nothing, and do not
            # call record_usage. This is the fix for the session-boundary
            # inheritance that would otherwise false-trip a data cap on
            # reconnect.
            new_cursors[session.id] = (cur_up, cur_down)
            continue
        prev_up, prev_down = prev
        up_delta = max(0, cur_up - prev_up)
        down_delta = max(0, cur_down - prev_down)
        # Re-baseline to the current reading regardless of direction so a
        # backwards move (reset/roam) does not keep re-crediting the same drop.
        new_cursors[session.id] = (cur_up, cur_down)
        if up_delta == 0 and down_delta == 0:
            # Idempotent no-op: a repeated poll with no new traffic since the
            # last sweep, exactly like a RADIUS accounting retransmit.
            continue
        await guest_service.record_usage(
            session_id=session.id,
            bytes_uploaded_delta=up_delta,
            bytes_downloaded_delta=down_delta,
        )
        sessions_updated += 1
        up_applied += up_delta
        down_applied += down_delta
    return sessions_updated, up_applied, down_applied, new_cursors


async def sync_omada_session_usage(
    *,
    ni_service: NetworkIntegrationService,
    guest_repository: GuestRepository,
    guest_service: _UsageRecorder,
    redis,
    limit: int,
) -> OmadaUsageSyncSummary:
    """Poll every eligible Omada Open-API integration once and apply its
    controller client traffic to the matching active guest sessions.

    Module-level rather than a method, matching ``run_network_integration
    _sync_sweep``: it needs a couple of services and nothing a request would
    provide, and a Celery task body has no FastAPI dependency graph to build
    one from. Runs as the platform, with no caller -- ``list_clients`` is
    invoked with ``requesting_organization_id=None`` (a deliberate platform
    read), and the only rows it can reach are the ones the selection query
    returns, each acted on strictly within its own tenant.
    """
    integrations = await ni_service.repository.list_omada_openapi_for_usage_sync(
        limit=limit
    )
    summary = OmadaUsageSyncSummary(integrations_considered=len(integrations))
    for integration in integrations:
        try:
            clients = await ni_service.list_clients(
                integration.id, requesting_organization_id=None
            )
        except ProviderError:
            # Already recorded against the integration's own event feed by
            # list_clients' failure path -- here it is only a counter.
            summary.integrations_failed += 1
            continue
        except Exception:  # noqa: BLE001 -- one venue must not stop the sweep
            logger.exception(
                "omada_usage_sync_list_clients_failed",
                extra={"integration_id": str(integration.id)},
            )
            summary.integrations_failed += 1
            continue

        # Sessions at an Omada venue are tied to the synthetic fleet Router;
        # the selection query guarantees router_id is not None.
        active_sessions = await guest_repository.list_active_sessions_for_router(
            integration.router_id
        )
        device_ids = [s.device_id for s in active_sessions if s.device_id is not None]
        devices = (
            await guest_repository.list_devices_for_session_ids(
                device_ids=device_ids,
                organization_id=integration.organization_id,
            )
            if device_ids
            else []
        )
        devices_by_id = {device.id: device for device in devices}

        cursors = await _load_cursors(redis, [s.id for s in active_sessions])
        try:
            updated, up_applied, down_applied, new_cursors = (
                await apply_controller_usage(
                    clients=clients,
                    active_sessions=active_sessions,
                    devices_by_id=devices_by_id,
                    guest_service=guest_service,
                    cursors=cursors,
                )
            )
        except Exception:  # noqa: BLE001 -- one venue must not stop the sweep
            logger.exception(
                "omada_usage_sync_apply_failed",
                extra={"integration_id": str(integration.id)},
            )
            summary.integrations_failed += 1
            continue

        # Persist cursors only after record_usage succeeded for this venue, so a
        # mid-venue failure re-baselines next tick rather than skipping usage.
        await _store_cursors(redis, new_cursors)
        summary.integrations_synced += 1
        summary.sessions_updated += updated
        summary.bytes_uploaded_applied += up_applied
        summary.bytes_downloaded_applied += down_applied
    return summary


def _build_guest_service(session: AsyncSession) -> GuestService:
    """Construct a ``GuestService`` wired with only what ``record_usage``
    actually exercises.

    ``record_usage`` reads ``self.repository`` (the byte bump, the on-quota
    expiry and the live-disconnect) and ``self.policy_lookup`` (the
    ``_track_fup_data_usage`` FUP data roll-up, a no-op when no lookup is
    wired). It never touches ``otp_service``/``voucher_service``/
    ``captive_portal_service``/``router_lookup`` -- verified against the
    method body and ``_track_fup_data_usage`` -- so those required positional
    collaborators are passed ``None`` here rather than composing the entire
    login-time service graph a worker back-filling bytes would never use. This
    is the same judgement ``guest.tasks._run_session_timeout_sweep_async``
    already makes (it calls a module-level function precisely to avoid
    building those four), applied to the one method that is not module-level.

    ``policy_lookup`` **is** wired for real -- a genuine ``PolicyService`` --
    so an Omada guest who crosses a configured FUP daily/weekly/monthly data
    cap mid-session is cut off exactly as a MikroTik guest already is; leaving
    it out would keep the byte counters live but silently drop that
    enforcement.
    """
    organization_service = OrganizationService(OrganizationRepository(session))
    location_service = LocationService(
        LocationRepository(session),
        organization_service,
        location_code_counter=LocationCodeCounterRepository(session),
    )
    policy_service = PolicyService(
        PolicyRepository(session), organization_service, location_service
    )
    return GuestService(
        GuestRepository(session),
        None,  # otp_service -- provably unused by record_usage
        None,  # voucher_service -- provably unused by record_usage
        None,  # captive_portal_service -- provably unused by record_usage
        None,  # router_lookup -- provably unused by record_usage
        policy_lookup=policy_service,
    )


async def _run_omada_usage_sync_async() -> OmadaUsageSyncSummary:
    async with SessionLocal() as session:
        try:
            ni_service = NetworkIntegrationService(
                NetworkIntegrationRepository(session),
                # Supplied so a service built here behaves like the DI one;
                # the sweep writes no audit entry of its own (a scheduled
                # poll has no human actor), mirroring the inventory sweep.
                audit_writer=RBACRepository(session),
                # No guest_session_lookup: the sweep never authorizes anyone,
                # so it must not carry the collaborator that would let it.
                guest_session_lookup=None,
                redis=redis_client,
                caller_location_scope=None,
            )
            guest_service = _build_guest_service(session)
            summary = await sync_omada_session_usage(
                ni_service=ni_service,
                # record_usage and the two repository reads all run against
                # the one GuestRepository the service already holds.
                guest_repository=guest_service.repository,
                guest_service=guest_service,
                redis=redis_client,
                limit=OMADA_USAGE_SYNC_MAX_INTEGRATIONS_PER_RUN,
            )
            await session.commit()
            return summary
        except Exception:
            await session.rollback()
            raise


@celery_app.task(name=TASK_RUN_OMADA_USAGE_SYNC_SWEEP)
def run_omada_usage_sync_sweep() -> dict[str, int]:
    """Beat-scheduled periodic task (see ``app.core.celery_app``'s
    ``beat_schedule`` -- every ``OMADA_USAGE_SYNC_SWEEP_INTERVAL_SECONDS``).
    For each active Omada Open-API venue, pull the controller's connected
    clients and bump each matching active guest session's data-usage bytes
    through ``GuestService.record_usage`` -- the same sink RADIUS accounting
    feeds for MikroTik venues, which Omada External-Portal venues never
    reach."""
    summary = run_celery_task(_run_omada_usage_sync_async())
    result = {
        "integrations_considered": summary.integrations_considered,
        "integrations_synced": summary.integrations_synced,
        "integrations_failed": summary.integrations_failed,
        "sessions_updated": summary.sessions_updated,
        "bytes_uploaded_applied": summary.bytes_uploaded_applied,
        "bytes_downloaded_applied": summary.bytes_downloaded_applied,
    }
    logger.info("omada_usage_sync_sweep_completed", extra=result)
    return result
