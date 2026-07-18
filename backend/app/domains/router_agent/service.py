"""Router Agent business logic: persistent device-credential issuance,
device-authenticated heartbeat, current-config pull, agent status push, and
provisioning-action-queue poll/complete.

This is the module ``app.domains.router_provisioning.service``'s own
docstring names as the intended caller of ``complete_provisioning_job`` --
"a future ``app.domains.router_agent`` module is expected to call
``complete_provisioning_job`` after actually performing the device-side
action." Nothing in this file re-implements router lifecycle logic, config
rendering/versioning, or the provisioning-queue state machine; it composes
with the real ``RouterService`` (BE-008) and ``RouterProvisioningService``/
``RouterProvisioningRepository`` (Module 009 Part 1) through narrow,
duck-typed protocols -- the exact cross-domain-composition-not-duplication
pattern every prior domain in this codebase already establishes.

## Design decisions worth calling out up front

**Device credential presentation: a header, not a request body.** BE-008's
device-facing precedent (``POST /routers/provisioning/check-in``) presents
its one-time provisioning token in the request body. This module
deliberately does **not** copy that shape for its own, *persistent*
credential: two of its five endpoints (``GET /agent/config``,
``GET /agent/actions``) are ``GET``s, which cannot cleanly carry a request
body across all HTTP clients/proxies a real embedded device agent might use.
Rather than presenting the credential in the body on three endpoints and
some other way on two, every device-facing endpoint in this module reads it
from one custom header, ``constants.AGENT_CREDENTIAL_HEADER``
(``X-Agent-Credential``) -- deliberately **not** ``Authorization: Bearer``,
which is already semantically owned by ``app.domains.auth``/RBAC's
platform-user JWT scheme (``CurrentUser``); using a distinctly-named header
keeps the two credential spaces visibly separate and makes it obvious at a
glance that ``dependencies.CurrentAgent`` is not ``RequirePermission``/
``CurrentUser`` wearing a disguise.

**When the credential is issued: additively, inside the check-in response,
not a separate "activate" endpoint.** By the time BE-008's check-in call
returns, the one-time provisioning token it validated has already been
consumed (single-use, per ``RouterProvisioningToken.used_at``) -- that
check-in call is the device's **last** opportunity to prove its identity
with a credential this platform already trusts. A separate
``POST /agent/activate`` endpoint would need its own credential to
authenticate that call, and the only candidate (the just-consumed
provisioning token) cannot be reused without either weakening its
single-use guarantee or accepting an unauthenticated activation call
(anyone could claim an agent credential for any router mid-provisioning).
Returning the newly-issued credential directly in check-in's own response is
therefore both simpler and strictly more secure. See
``app.domains.router.router.provisioning_check_in`` for the (additive-only)
endpoint change this implies, and ``app.domains.router.schemas
.ProvisioningCheckInResponse`` for the two new, optional fields.

**Response envelope: minimal, not ``ApiResponse``.** Every endpoint in
``router.py`` returns its own small Pydantic schema directly, mirroring
``ProvisioningCheckInResponse``'s "the calling device is not expected to
parse a rich, user-facing API contract" reasoning -- see ``schemas.py``'s
module docstring.

**Identity verification *is* credential validation -- no second endpoint.**
``dependencies.py``'s ``CurrentAgent`` dependency (hash-compare against
``credential_hash``, expiry, revocation, then resolving the *server-side*
``router_id`` the credential is bound to) is this module's complete identity
-verification mechanism. There is deliberately no serial-number/MAC-address
tamper-check layered on top: unlike the check-in flow (where the device
supplies its own claimed identity facts in the request body before any
``Router`` row is bound to it), every agent call's ``router_id`` here comes
from the *credential* itself, never from client-supplied input -- there is
nothing for a caller to spoof that this dependency doesn't already derive
server-side.
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Protocol

from app.domains.router.models import Router
from app.domains.router_provisioning.constants import ProvisioningJobStatus
from app.domains.router_provisioning.models import ConfigVersion, ProvisioningJob
from app.domains.router_provisioning.validators import validate_job_belongs_to_router

from .constants import (
    AGENT_CREDENTIAL_BYTES,
    AGENT_CREDENTIAL_TTL_DAYS,
    AgentLicenseStatus,
    RouterAgentEventType,
)
from .events import (
    AgentActionCompleted,
    AgentActionsClaimed,
    AgentCredentialIssued,
    AgentHeartbeatReceived,
    AgentStatusReported,
)
from .exceptions import NoConfigAssignedError
from .models import RouterAgentCredential
from .repository import RouterAgentRepositoryProtocol

logger = logging.getLogger(__name__)


def hash_credential(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


# ============================================================================
# Narrow cross-domain protocols (composition, not duplication)
# ============================================================================


class RouterLookupProtocol(Protocol):
    """The subset of BE-008's real ``RouterService`` surface this module
    needs: liveness (``heartbeat``) and updating the one existing field a
    status push may refresh (``update_router``, for
    ``Router.routeros_version``)."""

    async def heartbeat(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None = None,
        routeros_version: str | None = None,
        management_ip_address: str | None = None,
    ) -> Router: ...

    async def update_router(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        data: dict[str, object],
    ) -> Router: ...


class ConfigVersionLookupProtocol(Protocol):
    """The single read ``app.domains.router_provisioning.repository
    .RouterProvisioningRepository`` already exposes for "what is this
    router's current live config" -- composed directly (this module adds no
    new method to that repository for it, see module docstring)."""

    async def get_latest_applied_version(
        self, router_id: uuid.UUID, *, exclude_version_id: uuid.UUID | None = None
    ) -> ConfigVersion | None: ...


class ProvisioningJobQueueLookupProtocol(Protocol):
    """The existing ``RouterProvisioningRepository.list_active_jobs_for_router``
    (queued + running) -- this module filters/transitions the queued subset
    itself rather than asking that repository for a narrower query, since the
    existing method already answers "what should this router's agent be
    working on" completely (see ``poll_actions``)."""

    async def list_active_jobs_for_router(
        self, router_id: uuid.UUID
    ) -> list[ProvisioningJob]: ...


class ProvisioningJobLifecycleProtocol(Protocol):
    """The subset of ``RouterProvisioningService``'s real surface this
    module needs: picking a queued job up (``start_provisioning_job``) and
    reporting its outcome (``complete_provisioning_job`` -- the exact seam
    that service's own module docstring names this module as the caller
    of)."""

    async def get_job(self, job_id: uuid.UUID) -> ProvisioningJob: ...

    async def start_provisioning_job(self, job_id: uuid.UUID) -> ProvisioningJob: ...

    async def complete_provisioning_job(
        self,
        job_id: uuid.UUID,
        *,
        success: bool,
        error_message: str | None = None,
    ) -> ProvisioningJob: ...


class RouterEventWriter(Protocol):
    """The minimal surface this service needs to write into Module 009 Part
    1's shared ``router_events`` table (``RouterProvisioningRepository``
    already implements this method) -- composition, not a second event
    table. See ``constants.RouterAgentEventType`` for why this module's own
    ``event_type`` values are a separate ``StrEnum``."""

    async def create_event(self, **fields: object) -> object: ...


# ============================================================================
# Service
# ============================================================================


class RouterAgentService:
    """Core router-agent business logic."""

    def __init__(
        self,
        repository: RouterAgentRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        config_version_lookup: ConfigVersionLookupProtocol,
        job_queue_lookup: ProvisioningJobQueueLookupProtocol,
        job_lifecycle: ProvisioningJobLifecycleProtocol,
        *,
        event_writer: RouterEventWriter | None = None,
        credential_ttl_days: int = AGENT_CREDENTIAL_TTL_DAYS,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.config_version_lookup = config_version_lookup
        self.job_queue_lookup = job_queue_lookup
        self.job_lifecycle = job_lifecycle
        self.event_writer = event_writer
        self.credential_ttl_days = credential_ttl_days

    # ========================================================================
    # Credential issuance
    # ========================================================================

    async def issue_credential_for_router(
        self, router: Router
    ) -> tuple[RouterAgentCredential, str]:
        """Issues this router's persistent agent credential, called
        immediately after a successful BE-008 provisioning check-in (see
        module docstring for why this, rather than a separate ``/activate``
        endpoint). If a credential already exists for this router (a
        factory-reset -> re-provision -> check-in cycle), **rotates** it in
        place -- new hash, new expiry, ``rotation_count`` incremented,
        un-revoked if it had been -- rather than creating a second row
        (``router_id`` is unique). Returns the plaintext exactly once, the
        same "shown once, never retrievable again" convention
        ``RouterService.generate_provisioning_token``/
        ``RouterProvisioningService.rotate_secret`` already established."""
        plaintext = secrets.token_urlsafe(AGENT_CREDENTIAL_BYTES)
        now = datetime.now(UTC)
        expires_at = now + timedelta(days=self.credential_ttl_days)

        existing = await self.repository.get_by_router_id(router.id)
        if existing is None:
            credential = await self.repository.create_credential(
                router_id=router.id,
                credential_hash=hash_credential(plaintext),
                issued_at=now,
                expires_at=expires_at,
                last_used_at=None,
                revoked_at=None,
                rotation_count=0,
                agent_software_version=None,
                capabilities={},
                license_key=None,
                license_status=AgentLicenseStatus.UNKNOWN.value,
                last_status_report_at=None,
            )
        else:
            credential = await self.repository.update_credential(
                existing,
                {
                    "credential_hash": hash_credential(plaintext),
                    "issued_at": now,
                    "expires_at": expires_at,
                    "revoked_at": None,
                    "last_used_at": None,
                    "rotation_count": existing.rotation_count + 1,
                },
            )

        event = AgentCredentialIssued(
            router_id=router.id,
            credential_id=credential.id,
            rotation_count=credential.rotation_count,
        )
        await self._record_event(
            router.id,
            RouterAgentEventType.CREDENTIAL_ISSUED,
            message=f"Agent credential issued (rotation {credential.rotation_count})",
            metadata={"credential_id": str(credential.id)},
        )
        logger.info("agent_credential_issued", extra=_event_extra(event))
        return credential, plaintext

    # ========================================================================
    # Heartbeat
    # ========================================================================

    async def heartbeat(
        self,
        *,
        router: Router,
        routeros_version: str | None = None,
        management_ip_address: str | None = None,
    ) -> Router:
        """Composes with ``RouterService.heartbeat`` directly -- the real
        device-authenticated counterpart to BE-008's admin-testing
        ``POST /routers/{id}/heartbeat`` endpoint (which stays exactly as-is,
        gated by ``RequirePermission("routers.manage")``, for admin/manual
        use). Deliberately not recorded as a ``RouterEvent`` -- heartbeats
        are frequent device telemetry, not a notable status change, the
        identical reasoning BE-008 itself already documents for why they are
        never audited either."""
        previous_status = router.status
        updated = await self.router_lookup.heartbeat(
            router_id=router.id,
            requesting_organization_id=None,
            routeros_version=routeros_version,
            management_ip_address=management_ip_address,
        )
        event = AgentHeartbeatReceived(
            router_id=router.id, previous_status=previous_status
        )
        logger.info("agent_heartbeat_received", extra=_event_extra(event))
        return updated

    # ========================================================================
    # Config pull
    # ========================================================================

    async def get_current_config(self, *, router_id: uuid.UUID) -> ConfigVersion:
        """The router's current, latest-*applied* ``ConfigVersion`` --
        composes with ``RouterProvisioningRepository.get_latest_applied_version``
        directly (the exact read that method already answers; see module
        docstring for why no new method was added to that repository)."""
        version = await self.config_version_lookup.get_latest_applied_version(router_id)
        if version is None:
            raise NoConfigAssignedError(router_id)
        return version

    # ========================================================================
    # Status push
    # ========================================================================

    async def report_status(
        self,
        *,
        router: Router,
        credential: RouterAgentCredential,
        routeros_version: str | None,
        agent_software_version: str | None,
        capabilities: dict[str, object],
        license_key: str | None,
        license_status: AgentLicenseStatus,
    ) -> RouterAgentCredential:
        """Updates BE-008's existing ``Router.routeros_version`` (via
        ``RouterService.update_router``, composed -- never a duplicate
        column here) only when a value was reported *and it actually
        changed*, to avoid writing an ``audit_log_entries`` row (which
        ``update_router`` always produces) on every routine status push --
        every other field is genuinely new and lives on this module's own
        ``RouterAgentCredential`` row, updated unconditionally on every call
        (mirrors ``RouterHealthSnapshot``'s own "recorded every call, never
        audited" posture)."""
        if routeros_version is not None and routeros_version != router.routeros_version:
            await self.router_lookup.update_router(
                actor_user_id=None,
                router_id=router.id,
                requesting_organization_id=None,
                data={"routeros_version": routeros_version},
            )

        now = datetime.now(UTC)
        updated_credential = await self.repository.update_credential(
            credential,
            {
                "agent_software_version": agent_software_version,
                "capabilities": dict(capabilities),
                "license_key": license_key,
                "license_status": license_status.value,
                "last_status_report_at": now,
            },
        )
        await self._record_event(
            router.id,
            RouterAgentEventType.STATUS_REPORTED,
            message="Agent status report received",
            metadata={
                "agent_software_version": agent_software_version,
                "license_status": license_status.value,
            },
        )
        event = AgentStatusReported(
            router_id=router.id,
            agent_software_version=agent_software_version,
            license_status=license_status.value,
        )
        logger.info("agent_status_reported", extra=_event_extra(event))
        return updated_credential

    # ========================================================================
    # Action queue: poll + complete
    # ========================================================================

    async def poll_actions(self, *, router_id: uuid.UUID) -> list[ProvisioningJob]:
        """Returns every job this router's agent should currently be working
        on: freshly-``queued`` jobs are atomically claimed (transitioned to
        ``running`` via ``RouterProvisioningService.start_provisioning_job``
        -- the exact seam that service's own docstring names for "a real
        worker picking a job off the queue") *and* any job already
        ``running`` from a previous poll (e.g. the agent restarted mid-job)
        is included as-is, so the agent always sees its complete current
        workload rather than silently losing visibility of an in-flight
        job."""
        active_jobs = await self.job_queue_lookup.list_active_jobs_for_router(router_id)
        claimed_ids: list[uuid.UUID] = []
        result: list[ProvisioningJob] = []
        for job in active_jobs:
            if job.status == ProvisioningJobStatus.QUEUED.value:
                job = await self.job_lifecycle.start_provisioning_job(job.id)
                claimed_ids.append(job.id)
            result.append(job)

        if claimed_ids:
            event = AgentActionsClaimed(router_id=router_id, job_ids=tuple(claimed_ids))
            logger.info("agent_actions_claimed", extra=_event_extra(event))
        return result

    async def complete_action(
        self,
        *,
        router_id: uuid.UUID,
        job_id: uuid.UUID,
        success: bool,
        error_message: str | None = None,
    ) -> ProvisioningJob:
        """Reports a job's real-world outcome by calling
        ``RouterProvisioningService.complete_provisioning_job`` -- the exact
        seam ``router_provisioning.service``'s own module docstring names
        this module as the caller of, after actually performing the
        device-side action. ``validate_job_belongs_to_router`` (reused
        directly from ``router_provisioning.validators``, not duplicated)
        guards against one router's agent completing another router's job."""
        job = await self.job_lifecycle.get_job(job_id)
        validate_job_belongs_to_router(job, router_id)
        completed = await self.job_lifecycle.complete_provisioning_job(
            job_id, success=success, error_message=error_message
        )
        event = AgentActionCompleted(
            router_id=router_id, job_id=job_id, success=success
        )
        logger.info("agent_action_completed", extra=_event_extra(event))
        return completed

    # ========================================================================
    # Internal helpers
    # ========================================================================

    async def _record_event(
        self,
        router_id: uuid.UUID,
        event_type: RouterAgentEventType,
        *,
        message: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> None:
        if self.event_writer is not None:
            now = datetime.now(UTC)
            await self.event_writer.create_event(
                router_id=router_id,
                event_type=event_type.value,
                message=message,
                occurred_at=now,
                event_metadata=metadata or {},
            )


def _event_extra(event: object) -> dict[str, object]:
    """Flattens a frozen, ``slots=True`` ``events.py`` dataclass into
    ``logger.info(extra=)``-friendly, JSON-serializable keys (``vars()``
    doesn't work on slotted dataclasses -- there is no instance
    ``__dict__`` -- hence ``dataclasses.fields`` reflection instead)."""
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


__all__ = [
    "RouterAgentService",
    "RouterLookupProtocol",
    "ConfigVersionLookupProtocol",
    "ProvisioningJobQueueLookupProtocol",
    "ProvisioningJobLifecycleProtocol",
    "RouterEventWriter",
]
