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

## Every attempt is recorded -- device failures are outcomes, not errors

``run_ping``/``run_traceroute`` never let a real device-connection/
operation failure bubble to the caller as an HTTP error -- that would
discard the very information ("this router could not be reached to run
the diagnostic") an admin asking for a diagnostic actually wants. Both
methods catch ``DiagnosticsDeviceConnectionError``/
``DiagnosticsDeviceOperationError``, record a ``FAILED``
:class:`~.models.DiagnosticRun` with the real error message, and return
it like any other run. ``MissingDiagnosticsCredentialsError`` (a
configuration problem, not a diagnostic outcome) is the one exception
that still raises directly, mirroring
``app.domains.isp.exceptions.IspMissingCredentialsError``'s identical
posture.
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from typing import Protocol

from app.domains.rbac.enums import AuditAction
from app.domains.router.models import Router

from .constants import (
    DEFAULT_PING_COUNT,
    DEFAULT_PING_TIMEOUT_SECONDS,
    DEFAULT_TRACEROUTE_MAX_HOPS,
    DEFAULT_TRACEROUTE_TIMEOUT_SECONDS,
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
    DiagnosticRunNotFoundError,
    DiagnosticsDeviceConnectionError,
    DiagnosticsDeviceOperationError,
    MissingDiagnosticsCredentialsError,
)
from .models import DiagnosticRun
from .repository import NetworkDiagnosticsRepositoryProtocol

logger = logging.getLogger(__name__)


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
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.audit_writer = audit_writer
        self._get_device_adapter = device_adapter_resolver

    def _resolve_credentials(self, router: Router) -> DiagnosticsCredentials:
        host = router.management_ip_address or router.public_ip_address
        secret = self.router_lookup.get_decrypted_api_secret(router)
        if not host or not router.api_username or not secret:
            raise MissingDiagnosticsCredentialsError(router.id)
        return DiagnosticsCredentials(
            host=host, username=router.api_username, password=secret
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
    ) -> DiagnosticRun:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        credentials = self._resolve_credentials(router)
        adapter: BaseDiagnosticsAdapter = self._get_device_adapter(router.vendor)
        try:
            result = await adapter.ping(
                credentials, target=target, count=count, timeout_seconds=timeout_seconds
            )
            status, result_payload, error_message = (
                DiagnosticStatus.SUCCESS,
                dataclasses.asdict(result),
                None,
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
            diagnostic_type=DiagnosticType.PING,
            target=target,
            status=status,
            result=result_payload,
            error_message=error_message,
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
    ) -> DiagnosticRun:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        credentials = self._resolve_credentials(router)
        adapter: BaseDiagnosticsAdapter = self._get_device_adapter(router.vendor)
        try:
            result = await adapter.traceroute(
                credentials,
                target=target,
                max_hops=max_hops,
                timeout_seconds=timeout_seconds,
            )
            status, result_payload, error_message = (
                DiagnosticStatus.SUCCESS,
                dataclasses.asdict(result),
                None,
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
            diagnostic_type=DiagnosticType.TRACEROUTE,
            target=target,
            status=status,
            result=result_payload,
            error_message=error_message,
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
            error_message=error_message,
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

    async def get_run(
        self,
        run_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> DiagnosticRun:
        run = await self.repository.get_run_by_id(run_id)
        if run is None:
            raise DiagnosticRunNotFoundError(run_id)
        if (
            requesting_organization_id is not None
            and run.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationDiagnosticRunAccessError()
        return run

    async def list_runs(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[DiagnosticRun], object]:
        return await self.repository.list_runs(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
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


__all__ = ["NetworkDiagnosticsService"]
