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
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from app.common.exceptions import CloudGuestError
from app.database.utils.pagination import PaginationMeta
from app.domains.location.enums import LocationStatus
from app.domains.location.exceptions import LocationArchivedError
from app.domains.location.models import Location
from app.domains.monitoring.constants import ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES
from app.domains.network_config.constants import BootstrapMode
from app.domains.organization.models import Organization
from app.domains.rbac.enums import AuditAction

from .audit_changes import (
    REDACTED_PLACEHOLDER,
    describe_router_changes,
    router_field_changes,
)
from .constants import (
    ROUTER_REACHABILITY_FLEET_OUTAGE_MIN_ROUTERS,
    ROUTER_REACHABILITY_FLEET_OUTAGE_RATIO,
    ROUTER_REACHABILITY_HITS_TO_RESOLVE,
    ROUTER_REACHABILITY_MISSES_TO_ALERT,
    ROUTER_REACHABILITY_SILENCE_SECONDS,
)
from .crypto import decrypt_secret, encrypt_secret
from .device_credential_rotator import (
    DeviceCredentialRotationError,
    DeviceCredentialRotatorProtocol,
)
from .enums import (
    ROUTER_STATUS_TRANSITIONS,
    RouterHealthStatus,
    RouterReachabilityState,
    RouterStatus,
)
from .exceptions import (
    BootstrapLocationCodeMissingError,
    CrossOrganizationRouterAccessError,
    DuplicateMacAddressError,
    DuplicateSerialNumberError,
    InvalidRouterStatusTransitionError,
    ProvisioningTokenAlreadyUsedError,
    ProvisioningTokenExpiredError,
    ProvisioningTokenGenerationNotAllowedError,
    ProvisioningTokenNotFoundError,
    ProvisioningTokenRouterStateError,
    RemoteBootstrapNeverEnrolledError,
    RouterDecommissionedError,
    RouterLiveCredentialRotationFailedError,
    RouterNotFoundError,
    RouterVendorChangeRefusedError,
    RouterVendorNotProvisionableError,
    RouterVendorNotSupportedError,
)
from .models import Router, RouterProvisioningToken
from .repository import RouterRepositoryProtocol
from .vendor_capabilities import (
    AGENT_EVIDENCE_FIELDS,
    SUPPORTED_ROUTER_VENDORS,
    controller_state_for,
    is_controller_managed,
    looks_like_mikrotik_hardware,
    supports_zero_touch_provisioning,
    vendor_claim_is_contradicted,
)


@dataclass(frozen=True, slots=True)
class ControllerContext:
    """The controller half of a router's serialization.

    A value object rather than a tuple so the three fields cannot be
    reordered at a call site, and so the agent-managed case -- every field
    at its default -- is constructible in one obvious way.
    """

    state: str | None = None
    reason: str | None = None
    last_contacted_at: datetime | None = None
    vendor_claim_is_contradicted: bool = False


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


class TunnelLivenessProbe(Protocol):
    """The confirmation half of ``RouterService.sweep_router_reachability``:
    "these routers have stopped calling us -- are their tunnels gone too?"

    Returns one entry per router asked about:

    * ``True``  -- the tunnel is demonstrably alive right now. Silence is
      then OUR problem (a broken agent script, an expired scheduler), not
      the venue's power, and no outage alert may be raised.
    * ``False`` -- the tunnel is gone as well. Two independent signals now
      agree the site is unreachable.
    * ``None`` (or a missing key) -- we could not tell. The probe may only
      ever WITHHOLD an alert, never manufacture one, so an unanswerable
      probe falls back to absence alone, which is exactly the answer with
      no probe wired at all.

    Deliberately a narrow protocol rather than a dependency on
    ``WireGuardService``: this domain has no business knowing what a peer
    or a hub bridge is, and the sweep must stay fully testable without one.
    """

    async def __call__(
        self, routers: list[Router]
    ) -> dict[uuid.UUID, bool | None]: ...


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
        credential_rotator: DeviceCredentialRotatorProtocol | None = None,
    ) -> None:
        self.repository = repository
        self.location_lookup = location_lookup
        self.organization_lookup = organization_lookup
        self.audit_writer = audit_writer
        self.provisioning_token_ttl_hours = provisioning_token_ttl_hours
        # None in most test harnesses (no live device to push to) -- see
        # ``_rotate_live_api_secret_if_needed``'s own docstring for exactly
        # what happens when this is unset vs. configured.
        self.credential_rotator = credential_rotator

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

    async def router_names_for_ids(
        self, router_ids: Sequence[uuid.UUID]
    ) -> dict[uuid.UUID, str]:
        """Resolve a batch of router ids to their display names in one query,
        for a caller labelling rows that reference routers by id (the
        guest-session list's Router column).

        A thin pass-through to :meth:`RouterRepository.names_for_routers`
        -- deliberately NOT org-scoped, for the reason documented there: the
        caller has already established its right to these rows. Read-only.
        """
        return await self.repository.names_for_routers(router_ids)

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

    async def controller_context(
        self, routers: Sequence[Router]
    ) -> dict[uuid.UUID, ControllerContext]:
        """FIX-PLAN D2's ``controller_state`` for each of these rows.

        ONE extra query per response, not one per row, and none at all for a
        page with no controller-managed row on it -- the overwhelmingly
        common case, since `CONTROLLER_MANAGED_VENDORS` holds one vendor and
        most venues are MikroTik.

        **Every caller that serializes a router must go through this**, and
        the route module has no path that skips it. That is not tidiness: a
        `controller_state` of `None` means "this row is not reached through a
        controller", and if a write path could emit `None` merely because it
        had not looked, the field would mean two different things on two
        responses about the same row. Resolved everywhere, or the value could
        not be trusted anywhere.
        """
        contexts = {
            r.id: ControllerContext(
                vendor_claim_is_contradicted=vendor_claim_is_contradicted(r)
            )
            for r in routers
        }
        controller_rows = [r for r in routers if controller_state_for(r, None)]
        if not controller_rows:
            return contexts
        integrations = await self.repository.integrations_for_routers(
            [r.id for r in controller_rows]
        )
        for router in controller_rows:
            integration = integrations.get(router.id)
            derived = controller_state_for(router, integration)
            if derived is None:  # pragma: no cover - filtered above
                continue
            state, reason = derived
            contexts[router.id] = ControllerContext(
                state=state,
                reason=reason,
                # `last_sync_at`, and nothing else. Both probe paths state
                # that they persist nothing, deliberately -- a manual probe
                # is an operator action, and the scheduled sync is what "are
                # we still reaching this controller" means. So there is no
                # `last_probe_at` to prefer, and inventing one would be a
                # second, more optimistic answer to the same question.
                last_contacted_at=getattr(integration, "last_sync_at", None),
                vendor_claim_is_contradicted=False,
            )
        return contexts

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
        vendor: str = "mikrotik",
        management_ip_address: str | None = None,
        public_ip_address: str | None = None,
        api_username: str | None = None,
        api_secret: str | None = None,
        snmp_enabled: bool = False,
        snmp_community: str | None = None,
        snmp_version: str | None = None,
        snmp_port: int | None = None,
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
            vendor=vendor,
            status=RouterStatus.PENDING_PROVISIONING.value,
            management_ip_address=management_ip_address,
            public_ip_address=public_ip_address,
            api_username=api_username,
            api_credentials_encrypted=encrypt_secret(api_secret)
            if api_secret
            else None,
            snmp_enabled=snmp_enabled,
            snmp_community_encrypted=encrypt_secret(snmp_community)
            if snmp_community
            else None,
            snmp_version=snmp_version,
            snmp_port=snmp_port,
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

        # The write-only secrets leave `update_data` under one name and come
        # back under another; remember which spellings the *caller* actually
        # sent so the audit trail can name the field the operator touched
        # rather than only the column it landed in.
        inbound_secret_fields: list[str] = []

        api_secret = update_data.pop("api_secret", None)
        if api_secret:
            inbound_secret_fields.append("api_secret")
            await self._rotate_live_api_secret_if_needed(
                router, update_data=update_data, new_secret=str(api_secret)
            )
            update_data["api_credentials_encrypted"] = encrypt_secret(str(api_secret))

        # Mirrors api_secret's own "write-only, encrypt-on-the-way-in"
        # handling immediately above -- see Router.snmp_community_encrypted's
        # own docstring for why this gets the same Fernet treatment.
        snmp_community = update_data.pop("snmp_community", None)
        if snmp_community:
            inbound_secret_fields.append("snmp_community")
            update_data["snmp_community_encrypted"] = encrypt_secret(
                str(snmp_community)
            )

        # Snapshot the pre-update values as PLAIN DATA, now, before the
        # repository is called. `GenericRepository.update` setattrs onto the
        # instance it is handed, so `router` and `updated` below are the very
        # same ORM object -- a reference captured here would be read back
        # already mutated and every diff would come out empty. Only keys the
        # caller is actually writing are snapshotted; `updated_by` is
        # bookkeeping the audit row already carries as its actor.
        before_values = {key: getattr(router, key, None) for key in update_data}
        changes = router_field_changes(before_values, update_data)

        # `api_secret`/`snmp_community` were popped above, so the diff just
        # taken names `api_credentials_encrypted`/`snmp_community_encrypted`
        # -- the columns -- and not the fields the request carried. Diff the
        # inbound names too, so a management-access PUT reads "an api_secret
        # was set" and not only "a ciphertext column moved". These go through
        # `router_field_changes` rather than having the `{"redacted": True}`
        # sentinel written by hand here, so what counts as a secret is
        # decided in exactly one place; REDACTED_PLACEHOLDER only ever stands
        # in for "a value arrived", and because both keys are redacted it is
        # discarded rather than recorded. (The ciphertext column always reads
        # as changed, since Fernet is non-deterministic -- which is itself a
        # reason it must stay redacted: a deterministic scheme would leak
        # whether the same secret was re-submitted.)
        changes.update(
            router_field_changes(
                dict.fromkeys(inbound_secret_fields),
                dict.fromkeys(inbound_secret_fields, REDACTED_PLACEHOLDER),
            )
        )

        updated = await self.repository.update_router(
            router, {**update_data, "updated_by": actor_user_id}
        )
        # A genuine no-op (the caller re-sent the values already on file)
        # keeps the plain wording -- appending an empty or invented field
        # list would be worse than the terse entry this replaces.
        summary = describe_router_changes(changes)
        description = f"Router '{updated.name}' updated"
        if summary:
            description = f"{description}: {summary}"
        await self._audit(
            actor_user_id,
            AuditAction.ROUTER_UPDATED,
            router=updated,
            description=description,
            metadata={"changes": changes},
        )
        return updated

    async def change_router_vendor(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        vendor: str,
        reason: str,
        override_contradicting_evidence: bool = False,
    ) -> Router:
        """Records what kind of device a fleet row is.

        Deliberately NOT a branch of :meth:`update_router`. ``vendor`` is not
        a property of the row in the way ``name`` or ``model`` are -- it is
        the switch that decides whether the alert evaluator judges this
        device, whether the ZTP dashboard lists it, whether the readiness
        checklist runs, and whether seven device domains will speak to it. A
        field with that blast radius needs its own route, its own scope, its
        own reason and its own refusals, and folding it back into the generic
        update is how it ended up org-scoped and unaudited in the first
        place.

        The route above this is GLOBAL-scoped, so
        ``requesting_organization_id`` is not a parameter: a platform
        operator is looking at any tenant's device, the same shape
        ``decommission_router`` and ``update_router_management_access`` use.

        Three refusals, in order:

        1. **A vendor the platform does not implement.** The column is free
           text and everything outside ``CONTROLLER_MANAGED_VENDORS`` reads
           as an agent-managed MikroTik, so ``"unifi"`` would not mark the
           device unsupported -- it would claim an agent runs on it.
        2. **A live network integration references this row.** Not evidence
           about the device but a dependency on the value: the integration's
           provider is what chose the vendor string, and
           ``guest_sessions.router_id`` is NOT NULL, so changing it out from
           under a live integration makes two rows disagree about the same
           device. Not overridable -- detach the integration first.
        3. **The device's own data contradicts the claim.** Only when moving
           *to* a controller-managed vendor: a heartbeat, a RouterOS version,
           RouterOS API credentials on file, or a MikroTik model string all
           say this is not a controller. Overridable, explicitly and in
           writing, because a genuinely re-purposed device is a real if rare
           thing -- and because a refusal with no way past it is a refusal
           people route around with a manual UPDATE.

        Moving *to* an agent-managed vendor is never refused by (3). That
        direction is the correction: the seven rows relabelled in 2026-09 all
        carry agent evidence, and requiring an override to undo the damage
        would be asking the operator to overrule the very evidence proving
        them right.
        """
        if vendor not in SUPPORTED_ROUTER_VENDORS:
            raise RouterVendorNotSupportedError(vendor, SUPPORTED_ROUTER_VENDORS)

        router = await self.get_router(router_id, requesting_organization_id=None)
        if router.status == RouterStatus.DECOMMISSIONED.value:
            raise RouterDecommissionedError(router_id)

        previous_vendor = router.vendor
        if previous_vendor == vendor:
            # A no-op is not an error -- the console may be replaying a
            # request -- but it must not write an audit entry claiming a
            # change, which is the exact dishonesty this work removes.
            return router

        integration_count = await self.repository.count_integrations_referencing_router(
            router_id
        )
        if integration_count:
            raise RouterVendorChangeRefusedError(
                router_id,
                vendor,
                [
                    f"{integration_count} live network integration(s) "
                    "reference this device, and the integration's provider "
                    "is what decides its type. Remove or re-point the "
                    "integration first"
                ],
            )

        contradictions: list[str] = []
        if is_controller_managed(vendor):
            evidence = [
                field
                for field in AGENT_EVIDENCE_FIELDS
                if getattr(router, field, None) is not None
            ]
            if evidence:
                contradictions.append(
                    "this device has behaved like one of ours (" +
                    ", ".join(evidence) + " is set), and a controller never "
                    "checks in, reports a RouterOS version, or holds "
                    "RouterOS API credentials"
                )
            if looks_like_mikrotik_hardware(router.model):
                contradictions.append(
                    f"its model is recorded as '{router.model}', which is "
                    "MikroTik hardware"
                )
        if contradictions and not override_contradicting_evidence:
            raise RouterVendorChangeRefusedError(router_id, vendor, contradictions)

        updated = await self.repository.update_router(
            router, {"vendor": vendor, "updated_by": actor_user_id}
        )
        # Built by hand rather than through `router_field_changes`, because
        # this change set carries two things a generic field diff has no
        # place knowing about: the operator's written reason, and whether
        # they overruled the device's own evidence to get here. Both are the
        # first things anyone asks six weeks later.
        changes: dict[str, object] = {
            "vendor": {"from": previous_vendor, "to": vendor},
            "reason": reason,
        }
        description = (
            f"Router '{updated.name}' device type changed: "
            f"vendor {previous_vendor} -> {vendor}"
        )
        if contradictions:
            changes["evidence_overridden"] = contradictions
            description += " (contradicting evidence overridden)"
        await self._audit(
            actor_user_id,
            AuditAction.ROUTER_UPDATED,
            router=updated,
            description=f"{description}. Reason: {reason}",
            metadata={"changes": changes},
        )
        return updated

    async def _rotate_live_api_secret_if_needed(
        self,
        router: Router,
        *,
        update_data: dict[str, object],
        new_secret: str,
    ) -> None:
        """Pushes ``new_secret`` to the live device *before*
        ``update_router`` persists it, whenever this is a genuine
        rotation of an already-working credential -- closes the gap
        documented on ``RouterLiveCredentialRotationFailedError`` (the
        production "Permission denied for user cloudguest-api" incident:
        Master Console's Setup Script panel regenerates and persists a
        new ``api_secret`` on every run against an already-provisioned
        router, whether or not the resulting script chunk is ever
        actually re-applied on the physical device).

        Deliberately a no-op (falls through to the old "just persist it"
        behavior) in three cases, each for a different reason:

        * ``self.credential_rotator`` is unset -- test harnesses that pass
          no rotator to ``make_service`` (most tests in this module).
          Production DI (``app.domains.router.dependencies.get_router_service``)
          always configures the gateway-backed rotator singleton.
        * The router has no existing ``management_ip_address``/
          ``public_ip_address``, ``api_username``, or
          ``api_credentials_encrypted`` on file yet -- this *is* the
          first-time issuance case (a fresh device enrollment via
          ``onGenerate``'s ``pending_provisioning``/``provisioning``
          branch), where there is no old device password to
          authenticate a live push with and nothing has drifted out of
          sync yet -- the device gets its first real password from the
          "API Access" script chunk the admin is about to run, same as
          today.
        * ``update_data`` is simultaneously changing
          ``management_ip_address``/``public_ip_address``/
          ``api_username`` in the same call -- too ambiguous to safely
          guess which host/username the *old* secret was ever valid
          against; out of scope for this fix (this combination is not
          how Master Console's own Setup Script panel calls this
          endpoint -- it only ever sends ``api_username``/``api_secret``
          together, and always the same fixed ``API_ACCESS_USERNAME``).

        Otherwise, attempts the real push and raises
        :class:`RouterLiveCredentialRotationFailedError` -- and, because
        this runs before ``update_data["api_credentials_encrypted"]`` is
        ever set, the caller's transaction never reaches
        ``repository.update_router`` at all -- on failure. Either the
        device confirms the new password before the DB ever learns
        about it, or the DB keeps the old (still-device-matching) secret
        and the caller's ``PUT`` fails loudly instead of silently
        drifting out of sync."""
        if self.credential_rotator is None:
            return
        if (
            "management_ip_address" in update_data
            or "public_ip_address" in update_data
            or "api_username" in update_data
        ):
            return

        host = router.management_ip_address or router.public_ip_address
        username = router.api_username
        old_secret = self.get_decrypted_api_secret(router)
        if not host or not username or not old_secret:
            # First-time issuance -- nothing on the device to rotate yet.
            return

        try:
            await self.credential_rotator.rotate_password(
                host=host,
                username=username,
                old_password=old_secret,
                new_password=new_secret,
            )
        except DeviceCredentialRotationError as exc:
            raise RouterLiveCredentialRotationFailedError(router.id, str(exc)) from exc

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

    async def reset_to_pending_provisioning(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> Router:
        """Transitions an ``ONLINE``/``OFFLINE`` router back to
        ``PENDING_PROVISIONING`` -- added for Module 009
        (``app.domains.router_provisioning``)'s factory-reset workflow: a
        factory-reset device has had its configuration wiped and, in the
        real world, must be zero-touch-provisioned again from scratch, the
        same state a brand-new router record starts in. Eligibility
        (``ONLINE``/``OFFLINE`` only) is enforced by the caller
        (``RouterProvisioningService``, via
        ``validators.validate_router_eligible_for_factory_reset``) before
        this method is ever invoked; this method itself only consults the
        transition graph (``ROUTER_STATUS_TRANSITIONS``), exactly like
        every other status-changing method on this service."""
        return await self._set_status(
            actor_user_id=actor_user_id,
            router_id=router_id,
            requesting_organization_id=requesting_organization_id,
            new_status=RouterStatus.PENDING_PROVISIONING,
            action=AuditAction.ROUTER_FACTORY_RESET,
        )

    async def heartbeat(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None = None,
        routeros_version: str | None = None,
        management_ip_address: str | None = None,
        public_ip_address: str | None = None,
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
        # The primary WAN's own live address -- reported by the setup
        # script's heartbeat scheduler (see network_config/renderers-style
        # `buildRouterSetupScriptChunks`'s "Heartbeat" chunk on the frontend)
        # alongside management_ip_address, same "device tells us, we just
        # record it" posture. Distinct from management_ip_address: that one
        # is the WireGuard tunnel address this platform dials back into;
        # this is the router's own outward-facing WAN1 IP, already read
        # elsewhere as a fallback management target
        # (see app.domains.isp.service._resolve_credentials-style
        # `router.management_ip_address or router.public_ip_address`).
        if public_ip_address is not None:
            update_data["public_ip_address"] = public_ip_address

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
        SHA-256 hash is persisted).

        Also allowed while ``PROVISIONING`` (not just ``PENDING_PROVISIONING``):
        the dashboard's own Setup Script panel calls check-in itself right
        after minting a token, to bake the resulting agent credential into a
        ready-to-paste script -- which already advances the router to
        ``PROVISIONING`` before a single line has actually been pasted onto
        the device. If that admin never finishes pasting the script (closed
        the tab, the bridge call for an optional add-on failed, wanted to
        regenerate with different options), the router was previously stuck
        in ``PROVISIONING`` forever with no real device having claimed the
        old token -- regenerating is safe here since nothing physical has
        happened yet; the only actual completion signal is a real heartbeat
        (see ``heartbeat``'s own docstring)."""
        router = await self.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        # Checked before the status ladder below, because "wrong status" is
        # a temporary answer and this one is permanent -- a controller-managed
        # device is never going to be in a status where a token is useful.
        # `app.domains.router_provisioning.adapters.get_provisioning_adapter`
        # would refuse this vendor a few steps later anyway; refusing here
        # means the operator is told before a single-use token is minted and
        # handed to them, rather than after.
        if not supports_zero_touch_provisioning(router):
            raise RouterVendorNotProvisionableError(router_id, router.vendor)
        if router.status not in (
            RouterStatus.PENDING_PROVISIONING.value,
            RouterStatus.PROVISIONING.value,
        ):
            raise ProvisioningTokenGenerationNotAllowedError(router_id, router.status)

        # `check_in` below only ever accepts PENDING_PROVISIONING -- a fresh
        # attempt from PROVISIONING must rewind first, or the token this
        # just minted would be unusable by the very check-in call the
        # dashboard makes right after (see this method's own docstring).
        if router.status == RouterStatus.PROVISIONING.value:
            router = await self.repository.update_router(
                router, {"status": RouterStatus.PENDING_PROVISIONING.value}
            )

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

    async def preview_bootstrap_script(
        self,
        *,
        actor_user_id: uuid.UUID,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        api_base_url: str,
        mode: BootstrapMode = BootstrapMode.ONSITE,
    ) -> tuple[str, list[str], datetime]:
        """Mint a provisioning token and render the Step 1 bootstrap script
        in the requested mode (see ``BootstrapMode``'s own docstring for
        the two orderings and why they exist).

        **Why an explicit ``mode`` parameter rather than deriving it from
        ``last_seen_at``/status/peer state:** the safety property the split
        exists for -- "is a human physically at the router, holding a
        recovery path the tunnel does not provide?" -- is a fact about the
        operator, not about any database row. ``last_seen_at`` says the
        router *was* reachable, never where the technician is standing; a
        stale row would silently select the destructive ordering for a
        live router (this fleet's own history includes exactly that class
        of stale-state incident). So the caller declares intent, and this
        method refuses only the *provably unsafe* combination: remote mode
        for a router that has never checked in
        (``RemoteBootstrapNeverEnrolledError`` -- nothing to protect, no
        tunnel to deliver through, and the remote script's own on-device
        guards would refuse anyway). On-site remains valid for any
        token-eligible router, live or not, because a technician with
        console access may legitimately choose aggressive teardown.

        Remote mode on a live (``ONLINE``/``OFFLINE``) router first rewinds
        it to ``PENDING_PROVISIONING`` through the transition graph's
        existing re-provision edge (audited as
        ``ROUTER_REMOTE_REPROVISION_STARTED``, not ``ROUTER_FACTORY_RESET``
        -- nothing was wiped), because ``check_in`` only accepts
        ``PENDING_PROVISIONING`` and ``generate_provisioning_token`` only
        mints from ``PENDING_PROVISIONING``/``PROVISIONING``. Server-side,
        the eventual check-in **rotates** the existing peer in place --
        same tunnel IP, fresh platform keypair
        (``WireGuardService.ensure_tunnel_for_check_in``) -- which is what
        makes the staged cutover a key rotation rather than a re-plumbing.

        Returns ``(location_code, lines, token_expires_at)``. See
        ``app.domains.network_config.renderers.render_bootstrap_script``."""
        from app.domains.network_config.renderers import render_bootstrap_script

        router = await self.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        if mode is BootstrapMode.REMOTE:
            if router.last_seen_at is None:
                raise RemoteBootstrapNeverEnrolledError(router_id)
            if router.status in (
                RouterStatus.ONLINE.value,
                RouterStatus.OFFLINE.value,
            ):
                router = await self._set_status(
                    actor_user_id=actor_user_id,
                    router_id=router_id,
                    requesting_organization_id=requesting_organization_id,
                    new_status=RouterStatus.PENDING_PROVISIONING,
                    action=AuditAction.ROUTER_REMOTE_REPROVISION_STARTED,
                )
            elif router.status not in (
                RouterStatus.PENDING_PROVISIONING.value,
                RouterStatus.PROVISIONING.value,
            ):
                # SUSPENDED/DECOMMISSIONED: same refusal token minting
                # would produce, raised here so the message points at the
                # actual blocker before any state is touched.
                raise ProvisioningTokenGenerationNotAllowedError(
                    router_id, router.status
                )
        location = await self.location_lookup.get_location(
            router.location_id,
            requesting_organization_id=requesting_organization_id,
        )
        if not location.location_code:
            raise BootstrapLocationCodeMissingError(router_id)

        token, plaintext = await self.generate_provisioning_token(
            actor_user_id=actor_user_id,
            router_id=router_id,
            requesting_organization_id=requesting_organization_id,
        )
        lines = render_bootstrap_script(
            location_code=location.location_code,
            provisioning_token=plaintext,
            api_base_url=api_base_url,
            mode=mode,
        )
        return location.location_code, lines, token.expires_at

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

        consumed = await self.repository.mark_provisioning_token_used(
            token, used_at=now
        )
        if not consumed:
            # Lost the race: another concurrent check-in for this same
            # token committed its atomic compare-and-set first. Treat it
            # exactly like the upfront ``token.is_used()`` check above --
            # the TOCTOU window between that read and this write is
            # precisely what the compare-and-set in
            # ``mark_provisioning_token_used`` closes.
            raise ProvisioningTokenAlreadyUsedError()
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

    async def sweep_expired_provisioning_tokens(self) -> int:
        """Beat-scheduled sweep support (see
        ``app.domains.router.tasks.run_provisioning_token_cleanup_sweep``):
        finds every ``RouterProvisioningToken`` whose ``expires_at`` has
        already passed and that was never consumed (``used_at IS NULL``),
        and soft-deletes each one via
        ``repository.soft_delete_provisioning_token`` -- the same
        ``BaseModel``-provided ``is_deleted``/``deleted_at`` soft-delete
        convention every other domain in this codebase already uses (e.g.
        ``app.domains.guest.repository.GuestRepository
        .soft_delete_nas_client``), never a hand-rolled raw-SQL delete. A
        soft-deleted token can never again be presented at ``check_in``
        (``get_provisioning_token_by_hash`` only ever looks up
        non-deleted rows through ``GenericRepository``), which is the
        actual goal here: a stale, expired token sitting around forever is
        both dead weight and a lingering (if already-unusable) credential
        this sweep now proactively retires.

        A single token's own soft-delete failing (e.g. a transient DB
        error) is logged and skipped, never aborting the sweep for every
        other expired token -- mirrors every other Beat-scheduled sweep in
        this codebase's identical per-item failure-isolation contract
        (e.g. ``app.domains.isp.service.run_health_check_sweep``'s own
        per-link isolation). Returns the number of tokens actually
        soft-deleted. Deliberately not audited (mirrors ``heartbeat``'s own
        "system-driven housekeeping, not an admin action" posture) -- an
        expired, never-used token silently aging out is routine, not an
        event an admin needs an audit-log entry for."""
        now = datetime.now(UTC)
        expired_tokens = await self.repository.list_expired_unused_provisioning_tokens(
            now=now
        )
        cleaned = 0
        for token in expired_tokens:
            try:
                await self.repository.soft_delete_provisioning_token(token)
                cleaned += 1
            except Exception as exc:  # noqa: BLE001 -- per-token isolation, see docstring
                logger.warning(
                    "router_provisioning_token_cleanup_sweep_token_failed",
                    extra={"token_id": str(token.id), "error": str(exc)},
                )
        return cleaned

    async def sweep_stale_heartbeats(self) -> dict[str, int]:
        """Beat-scheduled sweep (see
        ``app.domains.router.tasks.run_stale_heartbeat_sweep``): moves every
        ``ONLINE`` router whose last heartbeat is older than
        ``ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES`` to ``OFFLINE``.

        THIS WRITER DID NOT EXIST. ``heartbeat()`` was the only thing that
        ever wrote ``ONLINE`` and nothing ever wrote it back, so a router
        that stopped answering weeks ago still read as online -- on the
        customer dashboard, in Master console, and to every consumer of
        ``Router.status`` including analytics and alerting. The frontend now
        derives liveness from ``last_seen_at`` staleness itself, which fixes
        what a person SEES; this fixes what the platform BELIEVES. Both are
        needed: the frontend fix cannot help a report, an export, or a
        future alert rule.

        THE THRESHOLD IS THE ONE ALREADY IN USE, not a new one.
        ``compute_lifecycle_stage`` and ``compute_internet_availability``
        have always read staleness at
        ``ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES``; the frontend's
        ``location-liveness`` module uses the same number. A second,
        slightly different definition of "offline" is how two screens start
        disagreeing about one router.

        ONLY ``ONLINE`` ROUTERS ARE TOUCHED. ``PROVISIONING`` is deliberately
        left alone: a router mid-setup has never sent a heartbeat by
        definition (the only transition out of ``PROVISIONING`` is
        ``heartbeat``), so sweeping it would mark every router being
        installed right now as offline. ``PENDING_PROVISIONING``,
        ``SUSPENDED`` and ``DECOMMISSIONED`` are administrative states that a
        missed heartbeat has no business overriding -- and
        ``ROUTER_STATUS_TRANSITIONS`` does not permit those edges anyway.

        Per-router failure isolation, mirroring
        ``sweep_expired_provisioning_tokens`` above and every other
        Beat-scheduled sweep here: one router's transition failing is logged
        and skipped, never aborting the sweep for the rest.

        AUDITED, unlike the token sweep. An expired token aging out is
        routine housekeeping; a router being declared offline is a
        statement about a venue's service that someone may later have to
        account for -- with a null actor, because no human performed it.
        Returns counts rather than a bare int so a run that swept nothing is
        distinguishable from a run that failed on everything."""
        cutoff = datetime.now(UTC) - timedelta(
            minutes=ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES
        )
        stale = await self.repository.list_online_routers_with_stale_heartbeat(
            cutoff=cutoff
        )
        marked = 0
        failed = 0
        for router in stale:
            try:
                # `health_status` and `last_health_check_at` move WITH the
                # status, never independently of it.
                #
                # This used to write `status` alone, so a router swept
                # offline kept whatever `health_status` its last successful
                # heartbeat had written -- permanently "healthy". Confirmed
                # live 2026-08-27 on router 01c9171e: `status='offline'`
                # alongside `health_status='healthy'`, i.e. the console
                # answering "is this router up?" two different ways on two
                # different screens, from one row.
                #
                # UNHEALTHY, not None/"unknown": this sweep is not an
                # absence of information, it is a positive finding. We know
                # the router has not checked in for longer than the stale
                # cutoff, and `RouterHealthStatus`'s own docstring defines
                # this field as "is this router currently reachable" --
                # which we have just determined it is not. `None` would mean
                # "no health check has ever run", which would be a lie in
                # the opposite direction.
                updated = await self.repository.update_router(
                    router,
                    {
                        "status": RouterStatus.OFFLINE.value,
                        "health_status": RouterHealthStatus.UNHEALTHY.value,
                        "last_health_check_at": datetime.now(UTC),
                    },
                )
                await self._audit(
                    None,
                    AuditAction.ROUTER_MARKED_OFFLINE,
                    router=updated,
                    description=(
                        f"Router '{updated.name}' marked offline -- no heartbeat for "
                        f"more than {ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES} minutes"
                    ),
                )
                marked += 1
            except Exception as exc:  # noqa: BLE001 -- per-router isolation, see docstring
                failed += 1
                logger.warning(
                    "router_stale_heartbeat_sweep_router_failed",
                    extra={"router_id": str(router.id), "error": str(exc)},
                )
        return {"considered": len(stale), "marked_offline": marked, "failed": failed}

    async def sweep_router_reachability(
        self,
        *,
        now: datetime | None = None,
        previous_sweep_at: datetime | None = None,
        tunnel_probe: TunnelLivenessProbe | None = None,
    ) -> dict[str, int]:
        """Beat-scheduled sweep (every
        ``ROUTER_REACHABILITY_SWEEP_INTERVAL_SECONDS`` = 30s): the fast,
        alert-only answer to "is this site talking to us right now?".

        ## Why this exists next to ``sweep_stale_heartbeats`` rather than
        ## inside it

        The founder asked for an email within two minutes of a site going
        down. ``sweep_stale_heartbeats`` cannot deliver that and must not be
        made to: its 15-minute ``ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES`` is
        shared, on purpose, with ``compute_lifecycle_stage``,
        ``compute_internet_availability`` and the frontend's
        ``location-liveness`` module, and its own docstring says that a
        second, slightly different definition of "offline" is how two
        screens start disagreeing about one router. So nothing here touches
        ``status``, ``last_seen_at``, ``health_status`` or that constant.
        This sweep writes one new column that nothing else reads, answering
        a narrower question with its own name.

        ## The signal, and why it is already fast enough

        Absence of agent contact -- ``router_agent_credentials.last_used_at``,
        which ``CurrentAgent`` stamps on every device-authenticated request.
        The agent scheduler polls ``GET /agent/authorized-macs`` every 60
        seconds against the heartbeat's 5 minutes, so this column is five
        times fresher than ``last_seen_at`` and it has been ticking on the
        real fleet the whole time. No new device-side scheduler, no new
        per-router network round trip, nothing to re-provision on 800
        routers.

        ## What absence does NOT prove, and the three guards for it

        "We stopped hearing from you" is ambiguous: the venue lost power,
        the uplink died, our API was redeploying, the broker hiccuped, or
        the WireGuard hub went away. All five look identical from here.
        Three guards keep that ambiguity from becoming a 3am false alarm:

        1. **The awake-window guard.** If the previous run of this sweep was
           longer ago than the silence window, we were not awake to hear
           from anyone, so nobody's silence means anything -- the pass is
           skipped without touching a counter. This is what stops our own
           deploys from paging the founder: on 2026-09-07 the api container
           restarted at 03:49:19, and a sweep that reasoned over that gap
           would have declared the whole fleet down.
        2. **The fleet-outage guard.** If at least
           ``ROUTER_REACHABILITY_FLEET_OUTAGE_RATIO`` of the routers we
           actually evaluated look silent in the same 30-second window (and
           there are at least
           ``ROUTER_REACHABILITY_FLEET_OUTAGE_MIN_ROUTERS`` of them for
           "most" to mean anything), the likelier explanation is us, not all
           of them. Counters are frozen, one log line is emitted, nobody is
           emailed.
        3. **The tunnel confirmation.** ``tunnel_probe`` -- when the caller
           supplies one -- reports each router's live WireGuard state from
           the hub's own ``wg show wg0 dump``. A router that has stopped
           calling us but whose tunnel is demonstrably still passing traffic
           is not a venue outage; it is a broken agent script, and it is
           logged as one instead of being alerted on. A probe that cannot
           answer (hub unreachable, peer unknown) returns ``None`` and this
           falls back to absence alone -- the guard can only ever prevent an
           alert, never manufacture one.

        ## Debounce, and the flapping night this is sized against

        ``ROUTER_REACHABILITY_MISSES_TO_ALERT`` consecutive misses are
        required to declare UNREACHABLE, and
        ``ROUTER_REACHABILITY_HITS_TO_RESOLVE`` consecutive hits -- ten
        minutes' worth -- to call it recovered. The asymmetry is the flap
        guard. On 2026-09-07 one router went down at 03:50, returned at
        04:12, and went down again at 04:16. Resolving on first contact
        would have produced four emails in 35 minutes; requiring sustained
        recovery collapses it to one "down" and one "back up", with no
        separate cooldown table, because the alert simply never closes in
        between and the Alert Engine's own de-duplication key refuses to
        open a second one while the first is open.

        ## Per-router isolation

        Same discipline as ``sweep_stale_heartbeats`` above: one router's
        update failing is logged and skipped, never aborting the sweep for
        the rest.
        """
        moment = now or datetime.now(UTC)
        candidates = await self.repository.list_reachability_candidates(now=moment)
        result = {
            "considered": len(candidates),
            "silent": 0,
            "marked_unreachable": 0,
            "marked_reachable": 0,
            "tunnel_alive_despite_silence": 0,
            "skipped_platform_gap": 0,
            "skipped_fleet_outage": 0,
            "failed": 0,
        }
        if not candidates:
            return result

        # Guard 1: were we even awake for the window we are about to judge?
        awake_for = timedelta(seconds=ROUTER_REACHABILITY_SILENCE_SECONDS)
        if previous_sweep_at is None or moment - previous_sweep_at > awake_for:
            result["skipped_platform_gap"] = len(candidates)
            logger.warning(
                "router_reachability_sweep_skipped_platform_gap",
                extra={
                    "considered": len(candidates),
                    "previous_sweep_at": (
                        previous_sweep_at.isoformat() if previous_sweep_at else None
                    ),
                },
            )
            return result

        silence_cutoff = moment - awake_for
        silent = [
            (router, contact)
            for router, contact in candidates
            if contact is None or contact < silence_cutoff
        ]
        result["silent"] = len(silent)

        # Guard 2: most of the fleet cannot go dark at once. That is us.
        if (
            len(candidates) >= ROUTER_REACHABILITY_FLEET_OUTAGE_MIN_ROUTERS
            and len(silent) / len(candidates)
            >= ROUTER_REACHABILITY_FLEET_OUTAGE_RATIO
        ):
            result["skipped_fleet_outage"] = len(silent)
            logger.error(
                "router_reachability_sweep_skipped_fleet_outage",
                extra={"considered": len(candidates), "silent": len(silent)},
            )
            return result

        # Guard 3: ask the tunnel whether they are really gone.
        tunnel_alive: dict[uuid.UUID, bool | None] = {}
        if silent and tunnel_probe is not None:
            try:
                tunnel_alive = await tunnel_probe([router for router, _ in silent])
            except Exception as exc:  # noqa: BLE001 -- confirmation is optional
                # A probe that cannot answer must never block the alert; it
                # exists only to withhold one. Falling back to absence alone
                # is the same answer we would give with no probe wired at
                # all.
                logger.warning(
                    "router_reachability_tunnel_probe_failed",
                    extra={"silent": len(silent), "error": str(exc)},
                )

        silent_ids = set()
        abstain_ids = set()
        for router, _contact in silent:
            if tunnel_alive.get(router.id) is True:
                # Silent to us, but its tunnel is demonstrably still up.
                # That is our agent script, not their power.
                #
                # Neither a miss nor a hit, and the distinction matters in
                # both directions. Counting it as a miss would alert a
                # venue whose Wi-Fi is fine. Counting it as a hit would let
                # an already-open outage alert resolve itself -- mailing
                # "back online and has stayed up" about a router we have
                # not actually heard a word from. We have no evidence
                # either way about the agent, so the router's state and
                # counters are left exactly as they are and the fact is
                # logged for us to fix, which is whose problem it is.
                result["tunnel_alive_despite_silence"] += 1
                abstain_ids.add(router.id)
                logger.warning(
                    "router_reachability_agent_silent_but_tunnel_alive",
                    extra={"router_id": str(router.id), "router_name": router.name},
                )
                continue
            silent_ids.add(router.id)

        for router, _contact in candidates:
            if router.id in abstain_ids:
                continue
            try:
                if router.id in silent_ids:
                    result[
                        "marked_unreachable"
                    ] += await self._record_reachability_miss(router, moment)
                else:
                    result["marked_reachable"] += await self._record_reachability_hit(
                        router, moment
                    )
            except Exception as exc:  # noqa: BLE001 -- per-router isolation, see docstring
                result["failed"] += 1
                logger.warning(
                    "router_reachability_sweep_router_failed",
                    extra={"router_id": str(router.id), "error": str(exc)},
                )
        return result

    async def _record_reachability_miss(self, router: Router, moment: datetime) -> int:
        """One observation of silence. Returns 1 if this observation is the
        one that flipped the router to UNREACHABLE, else 0."""
        misses = (router.reachability_consecutive_misses or 0) + 1
        update: dict[str, object] = {
            "reachability_consecutive_misses": misses,
            "reachability_consecutive_hits": 0,
        }
        flipped = 0
        if (
            misses >= ROUTER_REACHABILITY_MISSES_TO_ALERT
            and router.reachability_state != RouterReachabilityState.UNREACHABLE.value
        ):
            update["reachability_state"] = RouterReachabilityState.UNREACHABLE.value
            update["reachability_state_changed_at"] = moment
            flipped = 1
            logger.warning(
                "router_reachability_marked_unreachable",
                extra={
                    "router_id": str(router.id),
                    "router_name": router.name,
                    "organization_id": str(router.organization_id),
                    "consecutive_misses": misses,
                },
            )
        await self.repository.update_router(router, update)
        return flipped

    async def _record_reachability_hit(self, router: Router, moment: datetime) -> int:
        """One observation of contact. Returns 1 if this observation is the
        one that flipped the router back to REACHABLE, else 0.

        Writes nothing at all in the overwhelmingly common case -- an
        already-``reachable`` router with clean counters -- so a healthy
        fleet costs this sweep one SELECT every 30 seconds and no UPDATEs.
        """
        state = router.reachability_state
        if state == RouterReachabilityState.UNREACHABLE.value:
            hits = (router.reachability_consecutive_hits or 0) + 1
            update: dict[str, object] = {
                "reachability_consecutive_hits": hits,
                "reachability_consecutive_misses": 0,
            }
            if hits < ROUTER_REACHABILITY_HITS_TO_RESOLVE:
                # Back in touch, but not yet trusted to stay. This is the
                # flap guard: the alert stays open and no "it's back" email
                # goes out until the site has held on for the full window.
                await self.repository.update_router(router, update)
                return 0
            update["reachability_state"] = RouterReachabilityState.REACHABLE.value
            update["reachability_state_changed_at"] = moment
            await self.repository.update_router(router, update)
            logger.info(
                "router_reachability_marked_reachable",
                extra={
                    "router_id": str(router.id),
                    "router_name": router.name,
                    "consecutive_hits": hits,
                },
            )
            return 1

        if (
            state == RouterReachabilityState.REACHABLE.value
            and not router.reachability_consecutive_misses
            and not router.reachability_consecutive_hits
        ):
            return 0

        first_time = state != RouterReachabilityState.REACHABLE.value
        update = {
            "reachability_state": RouterReachabilityState.REACHABLE.value,
            "reachability_consecutive_misses": 0,
            "reachability_consecutive_hits": 0,
        }
        if first_time:
            update["reachability_state_changed_at"] = moment
        await self.repository.update_router(router, update)
        return 0

    # -- credential access ---------------------------------------------------------

    def get_decrypted_api_secret(self, router: Router) -> str | None:
        """Decrypts and returns the router's stored RouterOS API secret
        (password or API key), or ``None`` if no credentials are stored yet."""
        if router.api_credentials_encrypted is None:
            return None
        return decrypt_secret(router.api_credentials_encrypted)

    def get_decrypted_snmp_community(self, router: Router) -> str | None:
        """Decrypts and returns the router's own stored SNMP community
        string, or ``None`` if none is configured on this specific router
        -- mirrors ``get_decrypted_api_secret`` exactly. Callers that also
        want the real platform-wide fallback
        (``Settings.snmp_default_community``) apply it themselves, the
        same "per-router override, platform default fallback" resolution
        ``run_router_snmp_metrics_poll_sweep`` performs for
        ``snmp_version``/``snmp_port`` too -- this method only ever
        reports what this specific router itself has configured, never a
        blended/fallback value, so callers that need to distinguish "this
        router has no override" from "the resolved value happens to equal
        the default" still can."""
        if router.snmp_community_encrypted is None:
            return None
        return decrypt_secret(router.snmp_community_encrypted)

    async def reveal_credentials(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> Router:
        """Operator-facing counterpart to `get_decrypted_api_secret` --
        that method is an internal building block other services call when
        THEY need to connect to the router (no audit trail needed, it's not
        a human viewing a secret). This one is called directly from
        `router.router`'s `/routers/{id}/remote-access` endpoint, i.e. a
        human clicking "reveal" in Master Console's Remote Access panel --
        that's a materially different event worth its own audit entry
        (`AuditAction.ROUTER_CREDENTIALS_REVEALED`), so it's a separate
        method rather than the router.py endpoint just calling
        `get_decrypted_api_secret` directly and skipping the audit."""
        router = await self.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        await self._audit(
            actor_user_id,
            AuditAction.ROUTER_CREDENTIALS_REVEALED,
            router=router,
            description=(
                f"Remote-access credentials revealed for router '{router.name}'"
            ),
        )
        return router

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
