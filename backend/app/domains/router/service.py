"""Router business logic: device CRUD, location-hierarchy validation,
lifecycle management, credential encryption, and zero-touch provisioning.

Design notes worth calling out (see ``docs/router/ROUTER_ARCHITECTURE.md``
for the full write-up):

* Hierarchy validation: a router must belong to a real, non-archived
  location. Rather than re-querying the ``locations`` table with raw SQL
  (which would duplicate ``LocationService``'s own notion of "does this
  location exist and is it archived"), this service composes with
  ``LocationService`` through a narrow, duck-typed ``LocationLookupProtocol``
  (just ``get_location``) -- the exact cross-domain-composition-not-
  duplication pattern ``LocationService`` itself uses for
  ``OrganizationService``.
* Tenant scoping additionally composes with ``OrganizationService`` through
  ``OrganizationLookupProtocol`` (the identical narrow protocol
  ``LocationService`` defines) -- needed because ``Router.organization_id``
  is a denormalized copy (see §1 of the architecture doc) and the "is the
  caller an MSP whose child owns this router's organization" check requires
  reading the organization's own ``parent_organization_id``, which
  ``LocationLookupProtocol`` has no reason to expose.
* ``location_id``/``organization_id`` are immutable after creation -- a
  router "moving" location/org is a decommission-and-re-register operation,
  mirroring ``Location.organization_id``'s own immutability decision.
* Status transitions are validated against the explicit
  ``ROUTER_STATUS_TRANSITIONS`` graph (``app.domains.router.enums``) --
  every mutation that changes ``status`` goes through ``_transition_status``,
  which is the single place that graph is consulted.
* Router API credentials are Fernet-encrypted (``app.domains.router.crypto``)
  before ever reaching the repository -- this service never persists a
  plaintext secret.
* Zero-touch provisioning tokens are single-use, hashed (SHA-256, not
  Argon2id -- see ``docs/router/ROUTER_ARCHITECTURE.md`` §5 for why a fast
  hash is the right choice for a high-entropy random token) bearer
  credentials; the plaintext is returned exactly once, at generation time,
  and never again.
* Audit logging reuses RBAC's existing ``audit_log_entries`` table via the
  same narrow, duck-typed ``AuditLogWriter`` protocol shape
  ``LocationService``/``OrganizationService``/``UserService`` use.
  Heartbeats are deliberately **not** audited (see §6 of the architecture
  doc) -- they are frequent device telemetry, not an admin-driven event, and
  would otherwise flood the audit trail; they are still recorded via
  ``logger.info`` for operational visibility.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from app.common.exceptions import CloudGuestError
from app.database.utils.pagination import PaginationMeta
from app.domains.location.enums import LocationStatus
from app.domains.location.exceptions import LocationArchivedError
from app.domains.location.models import Location
from app.domains.organization.models import Organization
from app.domains.rbac.enums import AuditAction

from .crypto import decrypt_secret, encrypt_secret
from .enums import ROUTER_STATUS_TRANSITIONS, RouterStatus
from .exceptions import (
    CrossOrganizationRouterAccessError,
    DuplicateMacAddressError,
    DuplicateSerialNumberError,
    InvalidRouterStatusTransitionError,
    ProvisioningTokenAlreadyUsedError,
    ProvisioningTokenExpiredError,
    ProvisioningTokenGenerationNotAllowedError,
    ProvisioningTokenNotFoundError,
    ProvisioningTokenRouterStateError,
    RouterDecommissionedError,
    RouterNotFoundError,
)
from .models import Router, RouterProvisioningToken
from .repository import RouterRepositoryProtocol

logger = logging.getLogger(__name__)

# Statuses from which an ordinary heartbeat/check-in-style liveness signal
# may legally move a router toward ONLINE. PENDING_PROVISIONING (must first
# check in with a token), SUSPENDED, and DECOMMISSIONED (both require an
# explicit administrative transition) are deliberately excluded.
_HEARTBEAT_ELIGIBLE_STATUSES = frozenset(
    {RouterStatus.PROVISIONING, RouterStatus.ONLINE, RouterStatus.OFFLINE}
)

_TOKEN_BYTES = 32


class LocationLookupProtocol(Protocol):
    """The minimal surface this service needs from ``LocationService`` to
    validate a router's parent location, without depending on the rest of
    ``LocationService``'s CRUD/lifecycle surface."""

    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Location: ...


class OrganizationLookupProtocol(Protocol):
    """The minimal surface this service needs from ``OrganizationService``
    for MSP-child tenant scoping -- the identical narrow protocol
    ``LocationService`` itself defines for the same reason."""

    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization: ...


class AuditLogWriter(Protocol):
    """The minimal surface this service needs to write into RBAC's shared
    ``audit_log_entries`` table, without depending on the rest of
    ``RBACRepositoryProtocol``."""

    async def create_audit_log_entry(self, **fields: object) -> object: ...


def _hash_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def _normalize_mac(mac_address: str) -> str:
    return mac_address.strip().upper()


class RouterService:
    """Core router device business logic."""

    def __init__(
        self,
        repository: RouterRepositoryProtocol,
        location_lookup: LocationLookupProtocol,
        organization_lookup: OrganizationLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
        provisioning_token_ttl_hours: int = 24,
    ) -> None:
        self.repository = repository
        self.location_lookup = location_lookup
        self.organization_lookup = organization_lookup
        self.audit_writer = audit_writer
        self.provisioning_token_ttl_hours = provisioning_token_ttl_hours

    # -- reads -----------------------------------------------------------------

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router:
        router = await self.repository.get_by_id(
            router_id, include_deleted=include_deleted
        )
        if router is None:
            raise RouterNotFoundError(router_id)
        await self._enforce_organization_scope(router, requesting_organization_id)
        return router

    async def get_by_serial_number(self, serial_number: str) -> Router:
        router = await self.repository.get_by_serial_number(serial_number)
        if router is None:
            raise RouterNotFoundError(serial_number)
        return router

    async def get_by_mac_address(self, mac_address: str) -> Router:
        router = await self.repository.get_by_mac_address(_normalize_mac(mac_address))
        if router is None:
            raise RouterNotFoundError(mac_address)
        return router

    async def list_routers(
        self,
        *,
        location_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
        search: str | None = None,
        status: RouterStatus | None = None,
    ) -> tuple[list[Router], PaginationMeta]:
        # Delegates the "does this caller have access to this location" check
        # entirely to LocationService -- see module docstring.
        await self.location_lookup.get_location(
            location_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_routers(
            location_id=location_id,
            page=page,
            page_size=page_size,
            search=search,
            status=status.value if status else None,
        )

    # -- writes ------------------------------------------------------------------

    async def create_router(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        location_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        name: str,
        serial_number: str,
        mac_address: str,
        model: str,
        management_ip_address: str | None = None,
        public_ip_address: str | None = None,
        api_username: str | None = None,
        api_secret: str | None = None,
        settings: dict[str, Any] | None = None,
    ) -> Router:
        location = await self.location_lookup.get_location(
            location_id, requesting_organization_id=requesting_organization_id
        )
        if location.status == LocationStatus.ARCHIVED.value:
            raise LocationArchivedError(location_id)

        normalized_serial = serial_number.strip()
        normalized_mac = _normalize_mac(mac_address)
        if await self.repository.get_by_serial_number(normalized_serial):
            raise DuplicateSerialNumberError(normalized_serial)
        if await self.repository.get_by_mac_address(normalized_mac):
            raise DuplicateMacAddressError(normalized_mac)

        router = await self.repository.create_router(
            location_id=location_id,
            organization_id=location.organization_id,
            name=name,
            serial_number=normalized_serial,
            mac_address=normalized_mac,
            model=model,
            status=RouterStatus.PENDING_PROVISIONING.value,
            management_ip_address=management_ip_address,
            public_ip_address=public_ip_address,
            api_username=api_username,
            api_credentials_encrypted=encrypt_secret(api_secret)
            if api_secret
            else None,
            settings=settings or {},
            created_by=actor_user_id,
        )
        await self._audit(
            actor_user_id,
            AuditAction.ROUTER_CREATED,
            router=router,
            description=f"Router '{router.name}' ({router.serial_number}) created",
        )
        return router

    async def update_router(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        data: dict[str, object],
    ) -> Router:
        router = await self.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        if router.status == RouterStatus.DECOMMISSIONED.value:
            raise RouterDecommissionedError(router_id)

        update_data = dict(data)
        # location_id/organization_id are immutable after creation -- the
        # schema layer never exposes either field, so there is nothing for
        # this service to strip in practice; defensively strip regardless in
        # case a future caller constructs `data` by hand, mirroring
        # LocationService.update_location's own convention.
        update_data.pop("location_id", None)
        update_data.pop("organization_id", None)
        update_data.pop("status", None)

        if update_data.get("mac_address") is not None:
            normalized = _normalize_mac(str(update_data["mac_address"]))
            existing = await self.repository.get_by_mac_address(normalized)
            if existing is not None and existing.id != router.id:
                raise DuplicateMacAddressError(normalized)
            update_data["mac_address"] = normalized

        if update_data.get("serial_number") is not None:
            normalized = str(update_data["serial_number"]).strip()
            existing = await self.repository.get_by_serial_number(normalized)
            if existing is not None and existing.id != router.id:
                raise DuplicateSerialNumberError(normalized)
            update_data["serial_number"] = normalized

        api_secret = update_data.pop("api_secret", None)
        if api_secret:
            update_data["api_credentials_encrypted"] = encrypt_secret(str(api_secret))

        updated = await self.repository.update_router(
            router, {**update_data, "updated_by": actor_user_id}
        )
        await self._audit(
            actor_user_id,
            AuditAction.ROUTER_UPDATED,
            router=updated,
            description=f"Router '{updated.name}' updated",
        )
        return updated

    async def decommission_router(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> Router:
        router = await self.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        self._validate_transition(router, RouterStatus.DECOMMISSIONED)

        updated = await self.repository.update_router(
            router,
            {"status": RouterStatus.DECOMMISSIONED.value, "updated_by": actor_user_id},
        )
        updated = await self.repository.soft_delete_router(updated)
        await self._audit(
            actor_user_id,
            AuditAction.ROUTER_DECOMMISSIONED,
            router=updated,
            description=f"Router '{updated.name}' decommissioned",
        )
        return updated

    async def suspend_router(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> Router:
        return await self._set_status(
            actor_user_id=actor_user_id,
            router_id=router_id,
            requesting_organization_id=requesting_organization_id,
            new_status=RouterStatus.SUSPENDED,
            action=AuditAction.ROUTER_SUSPENDED,
        )

    async def reinstate_router(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> Router:
        """Reinstates a suspended router to ``OFFLINE`` (not ``ONLINE``) --
        only a heartbeat/check-in may ever assert "currently reachable", see
        ``docs/router/ROUTER_ARCHITECTURE.md`` §2."""
        return await self._set_status(
            actor_user_id=actor_user_id,
            router_id=router_id,
            requesting_organization_id=requesting_organization_id,
            new_status=RouterStatus.OFFLINE,
            action=AuditAction.ROUTER_REINSTATED,
        )

    async def heartbeat(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None = None,
        routeros_version: str | None = None,
        management_ip_address: str | None = None,
    ) -> Router:
        """Records a liveness signal from (or on behalf of) a router.

        When the router is currently ``PROVISIONING``, this is also the
        signal that completes provisioning (``PROVISIONING -> ONLINE``) --
        see the module/architecture docs for why no separate
        "complete-provisioning" endpoint exists. When ``ONLINE``/``OFFLINE``,
        always (re-)confirms ``ONLINE`` and refreshes ``last_seen_at``.
        Deliberately not audited -- see module docstring.
        """
        router = await self.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        current = RouterStatus(router.status)
        if current not in _HEARTBEAT_ELIGIBLE_STATUSES:
            raise InvalidRouterStatusTransitionError(
                current.value, RouterStatus.ONLINE.value
            )
        if current != RouterStatus.ONLINE:
            self._validate_transition(router, RouterStatus.ONLINE)

        now = datetime.now(UTC)
        update_data: dict[str, object] = {
            "status": RouterStatus.ONLINE.value,
            "last_seen_at": now,
            "last_health_check_at": now,
            "health_status": "healthy",
        }
        if routeros_version is not None:
            update_data["routeros_version"] = routeros_version
        if management_ip_address is not None:
            update_data["management_ip_address"] = management_ip_address

        updated = await self.repository.update_router(router, update_data)
        logger.info(
            "router_heartbeat",
            extra={"router_id": str(router.id), "previous_status": current.value},
        )
        return updated

    # -- zero-touch provisioning --------------------------------------------------

    async def generate_provisioning_token(
        self,
        *,
        actor_user_id: uuid.UUID,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> tuple[RouterProvisioningToken, str]:
        """Generates a single-use provisioning bearer token, returning the
        plaintext exactly once -- it is never retrievable again (only its
        SHA-256 hash is persisted)."""
        router = await self.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        if router.status != RouterStatus.PENDING_PROVISIONING.value:
            raise ProvisioningTokenGenerationNotAllowedError(router_id, router.status)

        plaintext = secrets.token_urlsafe(_TOKEN_BYTES)
        now = datetime.now(UTC)
        token = await self.repository.create_provisioning_token(
            router_id=router.id,
            token_hash=_hash_token(plaintext),
            expires_at=now + timedelta(hours=self.provisioning_token_ttl_hours),
            used_at=None,
            created_by_user_id=actor_user_id,
            created_by=actor_user_id,
        )
        await self._audit(
            actor_user_id,
            AuditAction.ROUTER_PROVISIONING_TOKEN_GENERATED,
            router=router,
            description=f"Provisioning token generated for router '{router.name}'",
        )
        return token, plaintext

    async def check_in(self, *, plaintext_token: str) -> Router:
        """Device-presented token exchange: validates and consumes a
        provisioning token, transitioning the router
        ``PENDING_PROVISIONING -> PROVISIONING``. Not a user-authenticated
        operation -- see ``docs/router/ROUTER_ARCHITECTURE.md`` §5 for the
        auth-scheme reasoning."""
        token = await self.repository.get_provisioning_token_by_hash(
            _hash_token(plaintext_token)
        )
        if token is None:
            raise ProvisioningTokenNotFoundError()

        now = datetime.now(UTC)
        if token.is_used():
            raise ProvisioningTokenAlreadyUsedError()
        if token.is_expired(now=now):
            raise ProvisioningTokenExpiredError()

        # include_deleted=True: a router that moved on (e.g. was
        # decommissioned, which also soft-deletes it) before the device ever
        # presented the token must still be found, so the caller gets the
        # more informative ProvisioningTokenRouterStateError rather than a
        # misleading RouterNotFoundError.
        router = await self.repository.get_by_id(token.router_id, include_deleted=True)
        if router is None:
            raise RouterNotFoundError(token.router_id)
        if router.status != RouterStatus.PENDING_PROVISIONING.value:
            raise ProvisioningTokenRouterStateError(router.id, router.status)

        await self.repository.mark_provisioning_token_used(token, used_at=now)
        updated = await self.repository.update_router(
            router,
            {"status": RouterStatus.PROVISIONING.value, "last_seen_at": now},
        )
        await self._audit(
            None,
            AuditAction.ROUTER_PROVISIONED,
            router=updated,
            description=f"Router '{updated.name}' checked in for provisioning",
        )
        return updated

    # -- credential access ---------------------------------------------------------

    def get_decrypted_api_secret(self, router: Router) -> str | None:
        """Decrypts and returns the router's stored RouterOS API secret
        (password or API key), or ``None`` if no credentials are stored yet."""
        if router.api_credentials_encrypted is None:
            return None
        return decrypt_secret(router.api_credentials_encrypted)

    # -- internal helpers -------------------------------------------------------

    def _validate_transition(self, router: Router, new_status: RouterStatus) -> None:
        """Consults the exhaustive ``ROUTER_STATUS_TRANSITIONS`` graph.
        Deliberately has **no** "same status is a no-op" shortcut -- e.g.
        decommissioning an already-``DECOMMISSIONED`` router must raise
        (that status has no outgoing edges at all, including to itself),
        the same for suspending an already-``SUSPENDED`` router. The one
        legitimate same-status case (``ONLINE -> ONLINE`` as an idempotent
        heartbeat refresh) is handled explicitly by ``heartbeat`` itself,
        which skips calling this method in that case rather than special-
        casing it here."""
        current = RouterStatus(router.status)
        legal_targets = ROUTER_STATUS_TRANSITIONS.get(current, frozenset())
        if new_status not in legal_targets:
            raise InvalidRouterStatusTransitionError(current.value, new_status.value)

    async def _set_status(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        new_status: RouterStatus,
        action: AuditAction,
    ) -> Router:
        router = await self.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        self._validate_transition(router, new_status)

        updated = await self.repository.update_router(
            router, {"status": new_status.value, "updated_by": actor_user_id}
        )
        await self._audit(
            actor_user_id,
            action,
            router=updated,
            description=f"Router '{updated.name}' {new_status.value}",
        )
        return updated

    async def _enforce_organization_scope(
        self, router: Router, requesting_organization_id: uuid.UUID | None
    ) -> None:
        """Enforces tenant scoping for an existing router resolved by id --
        mirrors ``LocationService._enforce_organization_scope`` exactly, one
        level down the hierarchy."""
        if requesting_organization_id is None:
            return
        if router.organization_id == requesting_organization_id:
            return
        organization = await self.organization_lookup.get_organization(
            router.organization_id, include_deleted=True
        )
        if organization.parent_organization_id == requesting_organization_id:
            return
        raise CrossOrganizationRouterAccessError()

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        router: Router,
        description: str,
        metadata: dict[str, object] | None = None,
    ) -> None:
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action=action.value,
                entity_type="router",
                entity_id=router.id,
                description=description,
                event_metadata=metadata or {},
                organization_id=router.organization_id,
                location_id=router.location_id,
            )
        logger.info(
            "router_audit_event",
            extra={"action": action.value, "entity_id": str(router.id)},
        )


__all__ = [
    "RouterService",
    "LocationLookupProtocol",
    "OrganizationLookupProtocol",
    "AuditLogWriter",
    "CloudGuestError",
]
