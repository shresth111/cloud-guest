"""Network Diagnostics business logic: real, synchronous, on-demand
``ping``/``traceroute`` execution against a router.

## Composition, not duplication, with ``app.domains.router``

This module never resolves a router itself. ``RouterLookupProtocol``
(satisfied structurally by ``app.domains.router.service.RouterService``)
is the identical narrow, duck-typed Protocol composition-over-duplication
pattern every domain in this codebase establishes -- including
``get_decrypted_api_secret``, reused directly, never re-decrypted here.
Which vendor adapter actually issues the command is resolved per-router
from ``Router.vendor`` via ``device_adapter_resolver`` (default
``device_adapters.get_diagnostics_adapter``), mirroring
``app.domains.isp.service.IspService``'s own "resolve per-router at the
point of use, never fix one adapter at construction time" convention
exactly -- injectable purely for tests.

## Tenant scoping: the organization guard was never enough

``RouterService.get_router`` enforces the *organization* boundary and
nothing narrower. That left a real hole, closed here: a caller whose
permission was checked at LOCATION scope for site A could name site B's
router in the path and run a command on it, because
``ScopeResolver.satisfies`` compares only the ``location_id`` the caller
put in ``X-Location-Id`` and never looks at which location the router in
the URL belongs to. Both sites belong to one organization, so the
organization guard saw nothing wrong. Two seeded LOCATION-scoped roles
(``network-administrator``, ``network-engineer``) hold
``network_diagnostics.execute``, so this was reachable from an ordinary
site-level networking account -- and unlike the guest/analytics instances
of this same shape, the payload was not reading a sibling site's data but
executing a command on its hardware.

Every method that narrows to one router or one site therefore calls
``app.domains.location.scoping.enforce_target_location`` -- the same
guard, with the same semantics, that the guest and live-session handlers
already use one level up. It is applied *after* ``get_router``, because
the target location is a property of the router named in the path, not
something the request states.

## Every attempt is recorded -- device failures are outcomes, not errors

``run_ping``/``run_traceroute`` never let a real device-connection/
operation failure bubble to the caller as an HTTP error -- that would
discard the very information ("this router could not be reached to run
the diagnostic") an admin asking for a diagnostic actually wants. Both
catch ``DiagnosticsDeviceConnectionError``/
``DiagnosticsDeviceOperationError`` **and ``TimeoutError``**, record a
``FAILED`` :class:`~.models.DiagnosticRun` with the real error message,
and return it like any other run.

``TimeoutError`` is the case that used to escape as a bare HTTP 500 with
no row written at all, which is the worst possible behaviour for the one
screen whose job is to say honestly whether a device could be reached.
Two independent things now prevent it: the deadline this module imposes
(see ``_execute``), and the gateway's own ``_ping_sync``/
``_traceroute_sync`` no longer letting a socket read timeout past an
``except LibRouterosError`` that never matched it (``TimeoutError`` is an
``OSError``, not a ``LibRouterosError``).

The errors that still raise directly, all of them "nothing was
attempted" rather than "the attempt failed", and none of them recorded:
``MissingDiagnosticsCredentialsError`` (a configuration problem),
``InvalidDiagnosticTargetError`` (the request never named a real
destination), and the two abuse controls below.

## Abuse controls

A diagnostic sends real packets at a caller-chosen destination from the
customer's own router, i.e. from the customer's own ISP allocation.
``run_ping``/``run_traceroute`` therefore take the same posture
``IspService.run_speed_test`` already established for the one other
action in this codebase with a real external cost: a Redis cooldown
(``SET NX EX``, refusing with the live remaining TTL rather than
queueing) plus, here, a per-organization window that the cooldown alone
cannot provide. See ``constants.py`` for why both, and what each one
actually bounds. Both are no-ops if this service was constructed without
a real ``redis`` client, exactly as ``IspService``'s are.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Protocol

from redis.asyncio import Redis

from app.domains.location.scoping import enforce_target_location
from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import (
    DEFAULT_PING_COUNT,
    DEFAULT_PING_TIMEOUT_SECONDS,
    DEFAULT_TRACEROUTE_MAX_HOPS,
    DEFAULT_TRACEROUTE_TIMEOUT_SECONDS,
    DEVICE_CONNECT_TIMEOUT_SECONDS,
    DIAGNOSTIC_COOLDOWN_REDIS_KEY_TEMPLATE,
    DIAGNOSTIC_COOLDOWN_SECONDS,
    DIAGNOSTIC_ORG_MAX_RUNS_PER_WINDOW,
    DIAGNOSTIC_ORG_RATE_LIMIT_REDIS_KEY_TEMPLATE,
    DIAGNOSTIC_ORG_RATE_LIMIT_WINDOW_SECONDS,
    DIAGNOSTIC_RUN_RETENTION_DAYS,
    DIAGNOSTIC_RUN_RETENTION_DELETE_BATCH_SIZE,
    DIAGNOSTIC_RUN_RETENTION_MAX_BATCHES_PER_RUN,
    DiagnosticStatus,
    DiagnosticType,
)
from .device_adapters import (
    BaseDiagnosticsAdapter,
    DiagnosticsCredentials,
    get_diagnostics_adapter,
)
from .events import DiagnosticRunCompleted
from .exceptions import (
    CrossOrganizationDiagnosticRunAccessError,
    DiagnosticCooldownError,
    DiagnosticRateLimitExceededError,
    DiagnosticRunNotFoundError,
    DiagnosticsDeviceConnectionError,
    DiagnosticsDeviceOperationError,
    MissingDiagnosticsCredentialsError,
)
from .models import DiagnosticRun
from .repository import NetworkDiagnosticsRepositoryProtocol
from .validators import normalize_target

logger = logging.getLogger(__name__)

# DiagnosticRun.error_message is String(500); a device or a stack can
# produce something longer, and losing the row to a database error would
# defeat the entire "every attempt is recorded" posture.
_MAX_ERROR_MESSAGE_LENGTH = 500


def _event_extra(event: object) -> dict[str, object]:
    """Flattens a frozen, ``slots=True`` ``events.py`` dataclass into
    ``logger.info(extra=)``-friendly, JSON-serializable keys -- identical
    reflection trick every other domain's own ``_event_extra`` uses."""
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


def _truncate(message: str) -> str:
    if len(message) <= _MAX_ERROR_MESSAGE_LENGTH:
        return message
    return message[: _MAX_ERROR_MESSAGE_LENGTH - 3] + "..."


class RouterLookupProtocol(Protocol):
    """The two ``RouterService`` methods this module needs -- reused
    directly, never reimplemented. Mirrors
    ``app.domains.isp.service.RouterLookupProtocol`` exactly."""

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router: ...

    def get_decrypted_api_secret(self, router: Router) -> str | None: ...


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


class NetworkDiagnosticsService:
    """Core Network Diagnostics business logic."""

    def __init__(
        self,
        repository: NetworkDiagnosticsRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
        device_adapter_resolver=get_diagnostics_adapter,
        redis: Redis | None = None,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer
        self._get_device_adapter = device_adapter_resolver
        # Optional at the type level for the same reason IspService's own
        # is: unit tests construct this service directly with no Redis, and
        # both abuse controls degrade to no-ops rather than failing the
        # request. The real FastAPI wiring always supplies the shared
        # app.database.redis.redis_client singleton -- see dependencies.py.
        self._redis = redis

    # -- guards ---------------------------------------------------------------

    def _resolve_credentials(self, router: Router) -> DiagnosticsCredentials:
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            raise MissingDiagnosticsCredentialsError(router.id)
        return DiagnosticsCredentials(
            host=host,
            username=router.api_username,
            password=secret,
            # Stated explicitly rather than inherited from the dataclass
            # default, and deliberately NOT the caller's own
            # timeout_seconds -- see constants.DEVICE_CONNECT_TIMEOUT_SECONDS.
            timeout_seconds=DEVICE_CONNECT_TIMEOUT_SECONDS,
        )

    async def _resolve_target_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
        scope_location_id: uuid.UUID | None,
    ) -> Router:
        """Resolves the router named in the path and enforces **both**
        tenant boundaries against it.

        ``get_router`` raises ``CrossOrganizationRouterAccessError`` for a
        router in another organization; ``enforce_target_location`` then
        catches the within-organization sibling-site case that an
        organization-level guard structurally cannot see. See the module
        docstring for how that second case was reachable.
        """
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        enforce_target_location(
            target_location_id=router.location_id,
            scope_location_id=scope_location_id,
            requesting_organization_id=requesting_organization_id,
        )
        return router

    async def _enforce_cooldown(self, router: Router) -> None:
        if self._redis is None:
            return
        key = DIAGNOSTIC_COOLDOWN_REDIS_KEY_TEMPLATE.format(router_id=router.id)
        acquired = await self._redis.set(
            key, "1", nx=True, ex=DIAGNOSTIC_COOLDOWN_SECONDS
        )
        if not acquired:
            ttl = await self._redis.ttl(key)
            raise DiagnosticCooldownError(
                router.id,
                ttl if ttl and ttl > 0 else DIAGNOSTIC_COOLDOWN_SECONDS,
            )

    async def _enforce_organization_rate_limit(self, router: Router) -> None:
        """INCR+EXPIRE+TTL, the identical pattern
        ``app.domains.otp.service.OtpRateLimiter`` and
        ``app.middleware.rate_limit.RateLimitMiddleware`` already use --
        reused rather than reinvented, just keyed on the organization."""
        if self._redis is None:
            return
        key = DIAGNOSTIC_ORG_RATE_LIMIT_REDIS_KEY_TEMPLATE.format(
            organization_id=router.organization_id
        )
        current = await self._redis.incr(key)
        if current == 1:
            await self._redis.expire(key, DIAGNOSTIC_ORG_RATE_LIMIT_WINDOW_SECONDS)
        if current > DIAGNOSTIC_ORG_MAX_RUNS_PER_WINDOW:
            ttl = await self._redis.ttl(key)
            raise DiagnosticRateLimitExceededError(
                ttl if ttl and ttl > 0 else DIAGNOSTIC_ORG_RATE_LIMIT_WINDOW_SECONDS
            )

    # -- execution ------------------------------------------------------------

    async def _execute(
        self,
        router: Router,
        *,
        diagnostic_type: DiagnosticType,
        target: str,
        timeout_seconds: int,
        run: Callable[[DiagnosticsCredentials, BaseDiagnosticsAdapter], Awaitable],
        actor_user_id: uuid.UUID | None,
    ) -> DiagnosticRun:
        """Runs one diagnostic under a real deadline and records it.

        ``timeout_seconds`` is the caller's own requested deadline and is
        now genuinely enforced, via ``asyncio.wait_for``. Previously it was
        accepted by the API, threaded all the way down, and discarded --
        the gateway's own ``ping`` docstring says as much. The only real
        bound was librouteros' socket timeout, and nothing bounded the
        request as a whole at all.

        **What the deadline does and does not do, precisely.** The adapter
        call is ``asyncio.to_thread``-backed, and cancelling the *await*
        does not cancel the OS thread: on expiry the caller gets an honest,
        recorded answer on time, but the worker thread stays occupied until
        its own socket read times out
        (``DEVICE_CONNECT_TIMEOUT_SECONDS``). That is strictly better than
        the previous behaviour -- an unbounded wait AND an occupied thread
        -- but it is a bound on the client's wait, not on thread
        occupancy, and it is worth knowing that the two are different.
        """
        credentials = self._resolve_credentials(router)
        adapter: BaseDiagnosticsAdapter = self._get_device_adapter(router.vendor)

        await self._enforce_cooldown(router)
        await self._enforce_organization_rate_limit(router)

        try:
            result = await asyncio.wait_for(
                run(credentials, adapter), timeout=timeout_seconds
            )
            status, result_payload, error_message = (
                DiagnosticStatus.SUCCESS,
                dataclasses.asdict(result),
                None,
            )
        except TimeoutError:
            # Both the deadline above and -- as a second line of defence --
            # a socket read timeout escaping the gateway. A bare
            # TimeoutError's str() is empty, so the message is built here
            # rather than taken from the exception.
            status, result_payload, error_message = (
                DiagnosticStatus.FAILED,
                {},
                f"{diagnostic_type.value} against '{target}' via router "
                f"{router.id} did not complete within {timeout_seconds}s",
            )
        except (
            DiagnosticsDeviceConnectionError,
            DiagnosticsDeviceOperationError,
        ) as exc:
            status, result_payload, error_message = (
                DiagnosticStatus.FAILED,
                {},
                str(exc),
            )
        return await self._record_run(
            router,
            diagnostic_type=diagnostic_type,
            target=target,
            status=status,
            result=result_payload,
            error_message=error_message,
            actor_user_id=actor_user_id,
        )

    async def run_ping(
        self,
        router_id: uuid.UUID,
        *,
        target: str,
        count: int = DEFAULT_PING_COUNT,
        timeout_seconds: int = DEFAULT_PING_TIMEOUT_SECONDS,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        scope_location_id: uuid.UUID | None = None,
    ) -> DiagnosticRun:
        normalized = normalize_target(target)
        router = await self._resolve_target_router(
            router_id,
            requesting_organization_id=requesting_organization_id,
            scope_location_id=scope_location_id,
        )
        return await self._execute(
            router,
            diagnostic_type=DiagnosticType.PING,
            target=normalized,
            timeout_seconds=timeout_seconds,
            run=lambda credentials, adapter: adapter.ping(
                credentials,
                target=normalized,
                count=count,
                timeout_seconds=timeout_seconds,
            ),
            actor_user_id=actor_user_id,
        )

    async def run_traceroute(
        self,
        router_id: uuid.UUID,
        *,
        target: str,
        max_hops: int = DEFAULT_TRACEROUTE_MAX_HOPS,
        timeout_seconds: int = DEFAULT_TRACEROUTE_TIMEOUT_SECONDS,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        scope_location_id: uuid.UUID | None = None,
    ) -> DiagnosticRun:
        normalized = normalize_target(target)
        router = await self._resolve_target_router(
            router_id,
            requesting_organization_id=requesting_organization_id,
            scope_location_id=scope_location_id,
        )
        return await self._execute(
            router,
            diagnostic_type=DiagnosticType.TRACEROUTE,
            target=normalized,
            timeout_seconds=timeout_seconds,
            run=lambda credentials, adapter: adapter.traceroute(
                credentials,
                target=normalized,
                max_hops=max_hops,
                timeout_seconds=timeout_seconds,
            ),
            actor_user_id=actor_user_id,
        )

    async def _record_run(
        self,
        router: Router,
        *,
        diagnostic_type: DiagnosticType,
        target: str,
        status: DiagnosticStatus,
        result: dict[str, object],
        error_message: str | None,
        actor_user_id: uuid.UUID | None,
    ) -> DiagnosticRun:
        run = await self.repository.create_run(
            router_id=router.id,
            organization_id=router.organization_id,
            location_id=router.location_id,
            diagnostic_type=diagnostic_type.value,
            target=target,
            status=status.value,
            result=result,
            error_message=_truncate(error_message) if error_message else None,
            executed_by_user_id=actor_user_id,
            created_by=actor_user_id,
        )
        event = DiagnosticRunCompleted(
            id=run.id,
            router_id=router.id,
            diagnostic_type=diagnostic_type.value,
            status=status.value,
        )
        logger.info("network_diagnostic_run_completed", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            entity_id=run.id,
            organization_id=run.organization_id,
            description=(
                f"{diagnostic_type.value} against '{target}' via router "
                f"{router.id} completed: {status.value}"
            ),
        )
        return run

    # -- reads ----------------------------------------------------------------

    async def get_run(
        self,
        run_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        scope_location_id: uuid.UUID | None = None,
    ) -> DiagnosticRun:
        run = await self.repository.get_run_by_id(run_id)
        if run is None:
            raise DiagnosticRunNotFoundError(run_id)
        if (
            requesting_organization_id is not None
            and run.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationDiagnosticRunAccessError()
        enforce_target_location(
            target_location_id=run.location_id,
            scope_location_id=scope_location_id,
            requesting_organization_id=requesting_organization_id,
        )
        return run

    async def list_runs(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
        scope_location_id: uuid.UUID | None = None,
    ) -> tuple[list[DiagnosticRun], object]:
        """``router_id`` is a caller-supplied query parameter naming a
        target the permission check never looked at -- the same shape as
        the ``GET /guests?location_id=`` defect, one level down. It is
        therefore resolved through ``_resolve_target_router``, which
        applies both tenant guards to it, rather than being passed
        straight to the repository as a filter.

        When no ``router_id`` is given, the listing is narrowed to
        ``scope_location_id`` instead. Without that, a caller whose
        permission was checked at LOCATION scope for one site read every
        run in the organization -- the column to filter on has been on
        every row since the table shipped and was simply never used.
        """
        location_filter: uuid.UUID | None = None
        if router_id is not None:
            await self._resolve_target_router(
                router_id,
                requesting_organization_id=requesting_organization_id,
                scope_location_id=scope_location_id,
            )
        else:
            location_filter = scope_location_id
        return await self.repository.list_runs(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            location_id=location_filter,
            page=page,
            page_size=page_size,
        )

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        *,
        entity_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        description: str,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=AuditAction.NETWORK_DIAGNOSTIC_RUN_COMPLETED.value,
            entity_type="diagnostic_run",
            entity_id=entity_id,
            description=description,
            organization_id=organization_id,
        )


async def purge_expired_runs(
    repository: NetworkDiagnosticsRepositoryProtocol,
    *,
    now: datetime | None = None,
    retention_days: int = DIAGNOSTIC_RUN_RETENTION_DAYS,
    batch_size: int = DIAGNOSTIC_RUN_RETENTION_DELETE_BATCH_SIZE,
    max_batches: int = DIAGNOSTIC_RUN_RETENTION_MAX_BATCHES_PER_RUN,
) -> dict[str, object]:
    """Deletes runs older than ``retention_days``, in bounded batches.

    Module-level rather than a ``NetworkDiagnosticsService`` method, and
    deliberately so: the sweep needs a repository and nothing else, while
    the service additionally requires a ``RouterLookupProtocol`` (i.e. a
    real ``RouterService``, itself composing ``LocationService`` and
    ``OrganizationService``) that a pure-DB retention pass would have to
    construct and never use. This is the identical reason
    ``app.domains.guest.service.enforce_session_timeouts`` sits at module
    scope -- see ``app.domains.guest.tasks``'s own docstring, which spells
    the convention out.

    Returns the real counts, including whether the per-run batch cap was
    reached, so a large backlog draining over several nightly runs is
    visible in the logs rather than silent. ``now`` is injectable so a test
    can pin the cutoff rather than sleep.
    """
    moment = now or datetime.now(UTC)
    cutoff = moment - timedelta(days=retention_days)
    deleted = 0
    batches = 0
    hit_batch_cap = False
    while True:
        if batches >= max_batches:
            hit_batch_cap = True
            break
        removed = await repository.delete_runs_older_than(cutoff, batch_size=batch_size)
        batches += 1
        deleted += removed
        if removed < batch_size:
            break
    return {
        "deleted": deleted,
        "batches": batches,
        "cutoff": cutoff.isoformat(),
        "hit_batch_cap": hit_batch_cap,
    }


__all__ = ["NetworkDiagnosticsService", "purge_expired_runs"]
