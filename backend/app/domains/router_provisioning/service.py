"""Router Provisioning business logic: configuration templates/variables/
profiles/versions (render, diff, apply, rollback), a durable provisioning
queue, device-initiated enrollment + approval, backup/restore, factory
reset, router secret rotation, and health/event history.

Design notes worth calling out (see ``docs/router_provisioning/FLOW.md`` for
the full write-up):

* **Composition, not duplication, with BE-008.** This service never queries
  the ``routers`` table directly -- it composes with the real
  ``RouterService`` through a narrow, duck-typed ``RouterLookupProtocol``
  (the exact cross-domain-composition pattern ``RouterService`` itself uses
  for ``LocationService``/``OrganizationService``), and with
  ``LocationService`` through the identical, already-established
  ``LocationLookupProtocol`` shape for the one place this module needs a
  location directly (denormalizing a ``LOCATION``-scoped variable's
  ``organization_id``). Tenant isolation is therefore inherited for free
  everywhere a router is resolved by id: ``RouterLookupProtocol.get_router``
  already raises ``CrossOrganizationRouterAccessError`` for a caller acting
  outside its own organization (or an MSP's child organizations).
* **Redis is the dispatch transport, Postgres is the durable source of
  truth.** See ``models.ProvisioningJob``'s module docstring and
  ``repository.RedisProvisioningQueueDispatcher``.
* **Apply/backup/restore/factory-reset all funnel through the same two
  primitives**: ``_enqueue_job`` (create the durable job row + push to
  Redis) and ``complete_provisioning_job`` (the single seam where a
  completed job's real-world side effects -- a version becoming ``applied``,
  a restore producing a new version, a factory reset flipping the router's
  BE-008 status -- are actually realized). Nothing in this sandbox has a
  live device to call back through that seam automatically; a future
  ``app.domains.router_agent`` module is expected to call
  ``complete_provisioning_job`` after actually performing the device-side
  action. This module deliberately does not expose it over HTTP (see
  ``router.py``) -- it only manages the workflow/queue side.
* **Audit logging reuses RBAC's ``audit_log_entries``** via the same narrow
  ``AuditLogWriter`` protocol shape ``RouterService``/``LocationService``/
  ``OrganizationService``/``UserService`` all use. A curated subset of
  events (enrollment approved/rejected, secret rotated, config applied/
  rolled back, backup created, restore completed) are written to *both*
  ``audit_log_entries`` and this module's own, higher-volume
  ``RouterEvent`` table -- see ``models.py``'s module docstring for why the
  two tables exist separately at all.
"""

from __future__ import annotations

import difflib
import logging
import re
import secrets
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from app.domains.location.models import Location
from app.domains.rbac.enums import AuditAction
from app.domains.router.crypto import decrypt_secret, encrypt_secret
from app.domains.router.enums import RouterStatus
from app.domains.router.exceptions import RouterDecommissionedError, RouterNotFoundError
from app.domains.router.models import Router

from .constants import (
    DEFAULT_MAX_JOB_ATTEMPTS,
    ROTATED_SECRET_BYTES,
    TEMPLATE_PLACEHOLDER_PATTERN,
    ConfigVariableScope,
    ConfigVersionStatus,
    EnrollmentStatus,
    ProvisioningJobStatus,
    ProvisioningJobType,
    RouterEventType,
)
from .exceptions import (
    ConfigTemplateNotFoundError,
    ConfigVariableNotFoundError,
    ConfigVersionNotFoundError,
    CrossOrganizationTemplateAccessError,
    CrossOrganizationVariableAccessError,
    DuplicateConfigVariableError,
    DuplicatePendingEnrollmentError,
    InvalidConfigVariableScopeError,
    NoAppliedConfigToBackupError,
    ProvisioningJobNotFoundError,
    RouterEnrollmentNotFoundError,
    UnresolvedTemplateVariablesError,
)
from .models import (
    ConfigProfile,
    ConfigTemplate,
    ConfigVariable,
    ConfigVersion,
    ProvisioningJob,
    RouterEnrollmentRequest,
    RouterEvent,
    RouterHealthSnapshot,
)
from .repository import QueueDispatcherProtocol, RouterProvisioningRepositoryProtocol
from .validators import (
    validate_backup_version,
    validate_config_version_transition,
    validate_enrollment_pending,
    validate_job_transition,
    validate_mac_address_format,
    validate_no_existing_router_conflict,
    validate_router_can_receive_config,
    validate_router_eligible_for_factory_reset,
    validate_template_scope,
    validate_variable_scope,
    validate_version_belongs_to_router,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Narrow cross-domain protocols (composition, not duplication)
# ============================================================================


class RouterLookupProtocol(Protocol):
    """The subset of ``RouterService``'s real surface this module needs --
    device lookup/creation/update, credential rotation, and the
    factory-reset status transition Module 009 additively contributed to
    BE-008 (``reset_to_pending_provisioning``)."""

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Router: ...

    async def get_by_serial_number(self, serial_number: str) -> Router: ...

    async def get_by_mac_address(self, mac_address: str) -> Router: ...

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
        settings: dict[str, object] | None = None,
    ) -> Router: ...

    async def update_router(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        data: dict[str, object],
    ) -> Router: ...

    async def reset_to_pending_provisioning(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> Router: ...

    async def heartbeat(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None = None,
        routeros_version: str | None = None,
        management_ip_address: str | None = None,
    ) -> Router: ...


class LocationLookupProtocol(Protocol):
    """The minimal surface this service needs from ``LocationService`` --
    used only to denormalize ``organization_id`` (and enforce tenant scope)
    when creating a ``LOCATION``-scoped :class:`~.models.ConfigVariable`."""

    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Location: ...


class AuditLogWriter(Protocol):
    """The minimal surface this service needs to write into RBAC's shared
    ``audit_log_entries`` table."""

    async def create_audit_log_entry(self, **fields: object) -> object: ...


# ============================================================================
# Read-model
# ============================================================================


@dataclass(frozen=True, slots=True)
class ProvisioningStatus:
    """The aggregate view returned by ``get_provisioning_status``: BE-008's
    own ``Router.status``, this module's notion of the router's current
    config profile/latest version, and any in-flight queue jobs."""

    router: Router
    profile: ConfigProfile | None
    latest_version: ConfigVersion | None
    active_jobs: list[ProvisioningJob]


# ============================================================================
# Template rendering
# ============================================================================


def render_template(template_content: str, variables: Mapping[str, str]) -> str:
    """Substitutes every ``{{variable_name}}`` placeholder in
    ``template_content`` with its resolved value from ``variables``. Raises
    ``UnresolvedTemplateVariablesError`` if any placeholder has no matching
    key -- a rendered RouterOS config script with a literal, un-substituted
    ``{{...}}`` left in it is not a config CloudGuest should ever queue for
    a real device."""
    missing: list[str] = []

    def _substitute(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in variables:
            missing.append(name)
            return match.group(0)
        return variables[name]

    rendered = TEMPLATE_PLACEHOLDER_PATTERN.sub(_substitute, template_content)
    if missing:
        raise UnresolvedTemplateVariablesError(missing)
    return rendered


# ============================================================================
# Service
# ============================================================================


class RouterProvisioningService:
    """Core router-provisioning business logic."""

    def __init__(
        self,
        repository: RouterProvisioningRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        location_lookup: LocationLookupProtocol,
        *,
        queue_dispatcher: QueueDispatcherProtocol,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.location_lookup = location_lookup
        self.queue_dispatcher = queue_dispatcher
        self.audit_writer = audit_writer

    # ========================================================================
    # Config templates
    # ========================================================================

    async def create_template(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        name: str,
        template_content: str,
        description: str | None = None,
        applicable_router_model: str | None = None,
        is_active: bool = True,
    ) -> ConfigTemplate:
        is_system_template = requesting_organization_id is None
        validate_template_scope(
            is_system_template=is_system_template,
            organization_id=requesting_organization_id,
        )
        template = await self.repository.create_template(
            organization_id=requesting_organization_id,
            name=name,
            description=description,
            is_system_template=is_system_template,
            applicable_router_model=applicable_router_model,
            template_content=template_content,
            is_active=is_active,
            created_by=actor_user_id,
        )
        logger.info("config_template_created", extra={"template_id": str(template.id)})
        return template

    async def get_template(
        self,
        template_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> ConfigTemplate:
        template = await self.repository.get_template(template_id)
        if template is None:
            raise ConfigTemplateNotFoundError(template_id)
        self._enforce_template_scope(template, requesting_organization_id)
        return template

    async def list_templates(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[ConfigTemplate], object]:
        return await self.repository.list_templates(
            requesting_organization_id=requesting_organization_id,
            page=page,
            page_size=page_size,
        )

    async def update_template(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        template_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        data: dict[str, object],
    ) -> ConfigTemplate:
        template = await self.get_template(
            template_id, requesting_organization_id=requesting_organization_id
        )
        update_data = dict(data)
        # organization_id/is_system_template are immutable after creation --
        # a template "moving" tenants is not a real operation, mirroring
        # Router/Location's own hierarchy-immutability convention.
        update_data.pop("organization_id", None)
        update_data.pop("is_system_template", None)
        updated = await self.repository.update_template(
            template, {**update_data, "updated_by": actor_user_id}
        )
        logger.info("config_template_updated", extra={"template_id": str(updated.id)})
        return updated

    async def delete_template(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        template_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> ConfigTemplate:
        template = await self.get_template(
            template_id, requesting_organization_id=requesting_organization_id
        )
        deactivated = await self.repository.update_template(
            template, {"is_active": False, "updated_by": actor_user_id}
        )
        return await self.repository.soft_delete_template(deactivated)

    def _enforce_template_scope(
        self,
        template: ConfigTemplate,
        requesting_organization_id: uuid.UUID | None,
    ) -> None:
        if template.organization_id is None:
            return  # a system template is usable/visible by anyone
        if requesting_organization_id is None:
            return  # a platform-level caller may act on any template
        if template.organization_id != requesting_organization_id:
            raise CrossOrganizationTemplateAccessError()

    # ========================================================================
    # Config variables
    # ========================================================================

    async def create_variable(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        scope_type: ConfigVariableScope,
        key: str,
        value: str,
        is_secret: bool = False,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        router_id: uuid.UUID | None = None,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> ConfigVariable:
        validate_variable_scope(
            scope_type=scope_type,
            organization_id=organization_id,
            location_id=location_id,
            router_id=router_id,
        )
        (
            resolved_org_id,
            resolved_location_id,
            resolved_router_id,
        ) = await self._resolve_variable_scope_fks(
            scope_type=scope_type,
            organization_id=organization_id,
            location_id=location_id,
            router_id=router_id,
            requesting_organization_id=requesting_organization_id,
        )
        existing = await self.repository.find_variable(
            scope_type=scope_type.value,
            organization_id=resolved_org_id,
            location_id=resolved_location_id,
            router_id=resolved_router_id,
            key=key,
        )
        if existing is not None:
            raise DuplicateConfigVariableError(scope_type.value, key)

        stored_value = encrypt_secret(value) if is_secret else value
        variable = await self.repository.create_variable(
            scope_type=scope_type.value,
            organization_id=resolved_org_id,
            location_id=resolved_location_id,
            router_id=resolved_router_id,
            key=key,
            value=stored_value,
            is_secret=is_secret,
            created_by=actor_user_id,
        )
        logger.info(
            "config_variable_created",
            extra={"variable_id": str(variable.id), "scope_type": scope_type.value},
        )
        return variable

    async def get_variable(self, variable_id: uuid.UUID) -> ConfigVariable:
        variable = await self.repository.get_variable(variable_id)
        if variable is None:
            raise ConfigVariableNotFoundError(variable_id)
        return variable

    async def list_variables(
        self,
        *,
        scope_type: ConfigVariableScope | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[ConfigVariable], object]:
        return await self.repository.list_variables(
            scope_type=scope_type.value if scope_type else None,
            page=page,
            page_size=page_size,
        )

    async def update_variable(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        variable_id: uuid.UUID,
        value: str | None = None,
        is_secret: bool | None = None,
    ) -> ConfigVariable:
        variable = await self.get_variable(variable_id)
        new_is_secret = is_secret if is_secret is not None else variable.is_secret
        update_data: dict[str, object] = {"updated_by": actor_user_id}
        if value is not None:
            update_data["value"] = encrypt_secret(value) if new_is_secret else value
        if is_secret is not None:
            update_data["is_secret"] = is_secret
        return await self.repository.update_variable(variable, update_data)

    async def delete_variable(
        self, *, actor_user_id: uuid.UUID | None, variable_id: uuid.UUID
    ) -> ConfigVariable:
        variable = await self.get_variable(variable_id)
        return await self.repository.soft_delete_variable(variable)

    async def resolve_variables(self, router: Router) -> dict[str, str]:
        """Resolves every variable visible to ``router``, merging
        **router-level > location-level > organization-level > global
        defaults** (most-specific wins). Implemented as four ordered
        passes, lowest-precedence first, each overwriting any same-``key``
        entry from the pass before it -- so the last (router-level) pass
        always wins for any key present at more than one tier."""
        resolved: dict[str, str] = {}
        for row in await self.repository.list_global_variables():
            resolved[row.key] = self._plain_value(row)
        for row in await self.repository.list_organization_variables(
            router.organization_id
        ):
            resolved[row.key] = self._plain_value(row)
        for row in await self.repository.list_location_variables(router.location_id):
            resolved[row.key] = self._plain_value(row)
        for row in await self.repository.list_router_variables(router.id):
            resolved[row.key] = self._plain_value(row)
        return resolved

    @staticmethod
    def _plain_value(variable: ConfigVariable) -> str:
        return decrypt_secret(variable.value) if variable.is_secret else variable.value

    async def _resolve_variable_scope_fks(
        self,
        *,
        scope_type: ConfigVariableScope,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        router_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> tuple[uuid.UUID | None, uuid.UUID | None, uuid.UUID | None]:
        """Returns the fully denormalized ``(organization_id, location_id,
        router_id)`` triple for a variable at the given scope, composing
        with ``RouterLookupProtocol``/``LocationLookupProtocol`` (never
        querying ``routers``/``locations`` directly) both to denormalize the
        parent hierarchy and to enforce tenant scoping along the way."""
        if scope_type is ConfigVariableScope.ROUTER:
            router = await self.router_lookup.get_router(
                router_id, requesting_organization_id=requesting_organization_id
            )
            return router.organization_id, router.location_id, router.id
        if scope_type is ConfigVariableScope.LOCATION:
            location = await self.location_lookup.get_location(
                location_id, requesting_organization_id=requesting_organization_id
            )
            return location.organization_id, location.id, None
        # ORGANIZATION scope -- organization_id may itself be null (a global
        # default), which only a platform-level (no org context) caller may
        # create.
        if organization_id is not None:
            if (
                requesting_organization_id is not None
                and organization_id != requesting_organization_id
            ):
                raise CrossOrganizationVariableAccessError()
        elif requesting_organization_id is not None:
            raise InvalidConfigVariableScopeError(
                "organization-scoped callers cannot create a global-default "
                "variable (organization_id=null)"
            )
        return organization_id, None, None

    # ========================================================================
    # Config profiles + version creation
    # ========================================================================

    async def assign_profile(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        template_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> tuple[ConfigProfile, ConfigVersion]:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        validate_router_can_receive_config(router)

        template = await self.repository.get_template(template_id)
        if template is None or not template.is_active:
            raise ConfigTemplateNotFoundError(template_id)
        self._enforce_template_scope(template, router.organization_id)

        variables = await self.resolve_variables(router)
        rendered_content = render_template(template.template_content, variables)

        now = datetime.now(UTC)
        existing_profile = await self.repository.get_profile_for_router(router.id)
        if existing_profile is not None:
            profile = await self.repository.update_profile(
                existing_profile,
                {
                    "template_id": template.id,
                    "assigned_by_user_id": actor_user_id,
                    "assigned_at": now,
                    "updated_by": actor_user_id,
                },
            )
        else:
            profile = await self.repository.create_profile(
                router_id=router.id,
                template_id=template.id,
                assigned_by_user_id=actor_user_id,
                assigned_at=now,
                created_by=actor_user_id,
            )

        version_number = await self.repository.get_next_version_number(router.id)
        version = await self.repository.create_version(
            router_id=router.id,
            profile_id=profile.id,
            version_number=version_number,
            rendered_content=rendered_content,
            status=ConfigVersionStatus.DRAFT.value,
            created_by_user_id=actor_user_id,
            applied_at=None,
            rollback_of_version_id=None,
            is_backup=False,
            created_by=actor_user_id,
        )
        await self._record_event(
            router,
            RouterEventType.CONFIG_VERSION_DRAFTED,
            message=(
                f"Draft config version {version.version_number} created from "
                f"template '{template.name}'"
            ),
            metadata={"template_id": str(template.id), "version_id": str(version.id)},
        )
        return profile, version

    # ========================================================================
    # Config versions: read / diff / rollback / apply
    # ========================================================================

    async def get_version(
        self,
        *,
        router_id: uuid.UUID,
        version_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> ConfigVersion:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        version = await self.repository.get_version(version_id)
        if version is None:
            raise ConfigVersionNotFoundError(version_id)
        validate_version_belongs_to_router(version, router.id)
        return version

    async def list_versions(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[ConfigVersion], object]:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_versions_for_router(
            router.id, page=page, page_size=page_size
        )

    async def diff_versions(
        self,
        *,
        router_id: uuid.UUID,
        version_id: uuid.UUID,
        other_version_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> tuple[ConfigVersion, ConfigVersion, list[str]]:
        version_a = await self.get_version(
            router_id=router_id,
            version_id=version_id,
            requesting_organization_id=requesting_organization_id,
        )
        version_b = await self.get_version(
            router_id=router_id,
            version_id=other_version_id,
            requesting_organization_id=requesting_organization_id,
        )
        diff_lines = list(
            difflib.unified_diff(
                version_a.rendered_content.splitlines(),
                version_b.rendered_content.splitlines(),
                fromfile=f"v{version_a.version_number}",
                tofile=f"v{version_b.version_number}",
                lineterm="",
            )
        )
        return version_a, version_b, diff_lines

    async def rollback_to_version(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        target_version_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> ConfigVersion:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        validate_router_can_receive_config(router)
        target = await self.repository.get_version(target_version_id)
        if target is None:
            raise ConfigVersionNotFoundError(target_version_id)
        validate_version_belongs_to_router(target, router.id)

        version_number = await self.repository.get_next_version_number(router.id)
        new_version = await self.repository.create_version(
            router_id=router.id,
            profile_id=target.profile_id,
            version_number=version_number,
            rendered_content=target.rendered_content,
            status=ConfigVersionStatus.DRAFT.value,
            created_by_user_id=actor_user_id,
            applied_at=None,
            rollback_of_version_id=target.id,
            is_backup=False,
            created_by=actor_user_id,
        )
        await self._record_event(
            router,
            RouterEventType.CONFIG_VERSION_DRAFTED,
            message=(
                f"Draft rollback version {new_version.version_number} created, "
                f"targeting version {target.version_number}"
            ),
            metadata={"target_version_id": str(target.id)},
        )
        return new_version

    async def apply_version(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        version_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> tuple[ConfigVersion, ProvisioningJob]:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        validate_router_can_receive_config(router)
        version = await self.repository.get_version(version_id)
        if version is None:
            raise ConfigVersionNotFoundError(version_id)
        validate_version_belongs_to_router(version, router.id)
        validate_config_version_transition(
            ConfigVersionStatus(version.status), ConfigVersionStatus.PENDING_APPLY
        )

        has_prior_applied = (
            await self.repository.get_latest_applied_version(router.id) is not None
        )
        job_type = (
            ProvisioningJobType.CONFIG_PUSH
            if has_prior_applied
            else ProvisioningJobType.INITIAL_CONFIG
        )
        job = await self._enqueue_job(
            router=router,
            job_type=job_type,
            payload={"config_version_id": str(version.id)},
            requested_by_user_id=actor_user_id,
        )
        updated_version = await self.repository.update_version(
            version,
            {
                "status": ConfigVersionStatus.PENDING_APPLY.value,
                "updated_by": actor_user_id,
            },
        )
        return updated_version, job

    # ========================================================================
    # Provisioning queue
    # ========================================================================

    async def _enqueue_job(
        self,
        *,
        router: Router,
        job_type: ProvisioningJobType,
        payload: dict[str, object],
        requested_by_user_id: uuid.UUID | None,
    ) -> ProvisioningJob:
        now = datetime.now(UTC)
        job = await self.repository.create_job(
            router_id=router.id,
            job_type=job_type.value,
            status=ProvisioningJobStatus.QUEUED.value,
            payload=payload,
            attempts=0,
            max_attempts=DEFAULT_MAX_JOB_ATTEMPTS,
            scheduled_at=now,
            started_at=None,
            completed_at=None,
            error_message=None,
            requested_by_user_id=requested_by_user_id,
            created_by=requested_by_user_id,
        )
        await self.queue_dispatcher.enqueue(job.id)
        await self._record_event(
            router,
            RouterEventType.PROVISIONING_QUEUED,
            message=f"'{job_type.value}' job queued",
            metadata={"job_id": str(job.id)},
        )
        logger.info(
            "provisioning_job_enqueued",
            extra={"job_id": str(job.id), "job_type": job_type.value},
        )
        return job

    async def get_job(self, job_id: uuid.UUID) -> ProvisioningJob:
        job = await self.repository.get_job(job_id)
        if job is None:
            raise ProvisioningJobNotFoundError(job_id)
        return job

    async def start_provisioning_job(self, job_id: uuid.UUID) -> ProvisioningJob:
        """Transitions ``queued -> running``. The seam a real
        ``app.domains.router_agent`` worker would call when it picks a job
        off the Redis queue to begin work."""
        job = await self.get_job(job_id)
        current = ProvisioningJobStatus(job.status)
        validate_job_transition(current, ProvisioningJobStatus.RUNNING)
        now = datetime.now(UTC)
        return await self.repository.update_job(
            job,
            {
                "status": ProvisioningJobStatus.RUNNING.value,
                "attempts": job.attempts + 1,
                "started_at": now,
            },
        )

    async def complete_provisioning_job(
        self,
        job_id: uuid.UUID,
        *,
        success: bool,
        error_message: str | None = None,
    ) -> ProvisioningJob:
        """Transitions ``running -> succeeded``/``failed`` and realizes the
        job's real-world side effect -- see module docstring's "single seam"
        note. This is the method a future ``app.domains.router_agent``
        module calls back through after actually performing the device-side
        action; this module never calls it on its own (there is no live
        device in this sandbox to have actually succeeded or failed yet)."""
        job = await self.get_job(job_id)
        current = ProvisioningJobStatus(job.status)
        target = (
            ProvisioningJobStatus.SUCCEEDED if success else ProvisioningJobStatus.FAILED
        )
        validate_job_transition(current, target)

        now = datetime.now(UTC)
        updated_job = await self.repository.update_job(
            job,
            {
                "status": target.value,
                "completed_at": now,
                "error_message": None if success else error_message,
            },
        )
        router = await self.router_lookup.get_router(
            job.router_id, include_deleted=True
        )
        job_type = ProvisioningJobType(job.job_type)

        if success:
            await self._complete_job_success(router, job_type, job, now)
        else:
            await self._complete_job_failure(router, job_type, job, error_message)
        return updated_job

    async def _complete_job_success(
        self,
        router: Router,
        job_type: ProvisioningJobType,
        job: ProvisioningJob,
        now: datetime,
    ) -> None:
        if job_type in (
            ProvisioningJobType.INITIAL_CONFIG,
            ProvisioningJobType.CONFIG_PUSH,
        ):
            version_id = uuid.UUID(str(job.payload["config_version_id"]))
            version = await self.repository.get_version(version_id)
            if version is None:
                raise ConfigVersionNotFoundError(version_id)
            validate_config_version_transition(
                ConfigVersionStatus(version.status), ConfigVersionStatus.APPLIED
            )
            previous_current = await self.repository.get_latest_applied_version(
                router.id, exclude_version_id=version.id
            )
            await self.repository.update_version(
                version,
                {"status": ConfigVersionStatus.APPLIED.value, "applied_at": now},
            )
            is_rollback = version.rollback_of_version_id is not None
            if is_rollback and previous_current is not None:
                validate_config_version_transition(
                    ConfigVersionStatus(previous_current.status),
                    ConfigVersionStatus.ROLLED_BACK,
                )
                await self.repository.update_version(
                    previous_current, {"status": ConfigVersionStatus.ROLLED_BACK.value}
                )
            await self._record_event(
                router,
                RouterEventType.CONFIG_APPLIED,
                message=f"Config version {version.version_number} applied",
                metadata={"version_id": str(version.id), "job_id": str(job.id)},
            )
            await self._audit_router(
                job.requested_by_user_id,
                AuditAction.ROUTER_CONFIG_VERSION_ROLLED_BACK
                if is_rollback
                else AuditAction.ROUTER_CONFIG_VERSION_APPLIED,
                router=router,
                description=(
                    f"Config version {version.version_number} applied to "
                    f"router '{router.name}'"
                ),
            )
        elif job_type is ProvisioningJobType.RESTORE:
            backup_id = uuid.UUID(str(job.payload["backup_version_id"]))
            backup = await self.repository.get_version(backup_id)
            if backup is None:
                raise ConfigVersionNotFoundError(backup_id)
            previous_current = await self.repository.get_latest_applied_version(
                router.id
            )
            version_number = await self.repository.get_next_version_number(router.id)
            new_version = await self.repository.create_version(
                router_id=router.id,
                profile_id=backup.profile_id,
                version_number=version_number,
                rendered_content=backup.rendered_content,
                status=ConfigVersionStatus.APPLIED.value,
                created_by_user_id=job.requested_by_user_id,
                applied_at=now,
                rollback_of_version_id=backup.id,
                is_backup=False,
                created_by=job.requested_by_user_id,
            )
            if previous_current is not None:
                await self.repository.update_version(
                    previous_current, {"status": ConfigVersionStatus.ROLLED_BACK.value}
                )
            await self._record_event(
                router,
                RouterEventType.RESTORE_COMPLETED,
                message=f"Restored from backup version {backup.version_number}",
                metadata={
                    "backup_version_id": str(backup.id),
                    "new_version_id": str(new_version.id),
                    "job_id": str(job.id),
                },
            )
            await self._audit_router(
                job.requested_by_user_id,
                AuditAction.ROUTER_RESTORE_COMPLETED,
                router=router,
                description=f"Router '{router.name}' restored from backup",
            )
        elif job_type is ProvisioningJobType.FACTORY_RESET:
            # Realizes the status transition via BE-008's own
            # RouterService.reset_to_pending_provisioning -- which writes its
            # own audit_log_entries row (AuditAction.ROUTER_FACTORY_RESET)
            # through RouterService's existing _audit mechanism, so this
            # branch only adds our own device-history RouterEvent, never a
            # second audit_log_entries row for the same fact.
            await self.router_lookup.reset_to_pending_provisioning(
                actor_user_id=job.requested_by_user_id,
                router_id=router.id,
                requesting_organization_id=None,
            )
            await self._record_event(
                router,
                RouterEventType.FACTORY_RESET_COMPLETED,
                message="Factory reset completed; router reset to pending_provisioning",
                metadata={"job_id": str(job.id)},
            )
        elif job_type is ProvisioningJobType.BACKUP:
            source_version_id = uuid.UUID(str(job.payload["source_version_id"]))
            source_version = await self.repository.get_version(source_version_id)
            if source_version is None:
                raise ConfigVersionNotFoundError(source_version_id)
            version_number = await self.repository.get_next_version_number(router.id)
            backup_version = await self.repository.create_version(
                router_id=router.id,
                profile_id=source_version.profile_id,
                version_number=version_number,
                rendered_content=source_version.rendered_content,
                status=ConfigVersionStatus.APPLIED.value,
                created_by_user_id=job.requested_by_user_id,
                applied_at=now,
                rollback_of_version_id=None,
                is_backup=True,
                created_by=job.requested_by_user_id,
            )
            await self._record_event(
                router,
                RouterEventType.BACKUP_CREATED,
                message=f"Backup created (version {backup_version.version_number})",
                metadata={
                    "backup_version_id": str(backup_version.id),
                    "job_id": str(job.id),
                },
            )
            await self._audit_router(
                job.requested_by_user_id,
                AuditAction.ROUTER_BACKUP_CREATED,
                router=router,
                description=f"Backup created for router '{router.name}'",
            )

    async def _complete_job_failure(
        self,
        router: Router,
        job_type: ProvisioningJobType,
        job: ProvisioningJob,
        error_message: str | None,
    ) -> None:
        if job_type in (
            ProvisioningJobType.INITIAL_CONFIG,
            ProvisioningJobType.CONFIG_PUSH,
        ):
            version_id = uuid.UUID(str(job.payload["config_version_id"]))
            version = await self.repository.get_version(version_id)
            if version is not None:
                validate_config_version_transition(
                    ConfigVersionStatus(version.status), ConfigVersionStatus.FAILED
                )
                await self.repository.update_version(
                    version, {"status": ConfigVersionStatus.FAILED.value}
                )
            event_type = RouterEventType.CONFIG_APPLY_FAILED
        elif job_type is ProvisioningJobType.RESTORE:
            event_type = RouterEventType.RESTORE_FAILED
        elif job_type is ProvisioningJobType.FACTORY_RESET:
            event_type = RouterEventType.FACTORY_RESET_FAILED
        else:
            event_type = RouterEventType.CONFIG_APPLY_FAILED
        await self._record_event(
            router,
            event_type,
            message=error_message,
            metadata={"job_id": str(job.id)},
        )

    # ========================================================================
    # Backup / restore / factory reset / secret rotation
    # ========================================================================

    async def create_backup(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> ProvisioningJob:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        source_version = await self.repository.get_latest_applied_version(router.id)
        if source_version is None:
            raise NoAppliedConfigToBackupError(router.id)
        return await self._enqueue_job(
            router=router,
            job_type=ProvisioningJobType.BACKUP,
            payload={"source_version_id": str(source_version.id)},
            requested_by_user_id=actor_user_id,
        )

    async def restore_backup(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        backup_version_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> ProvisioningJob:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        validate_router_can_receive_config(router)
        backup = await self.repository.get_version(backup_version_id)
        if backup is None:
            raise ConfigVersionNotFoundError(backup_version_id)
        validate_version_belongs_to_router(backup, router.id)
        validate_backup_version(backup)
        await self._record_event(
            router,
            RouterEventType.RESTORE_QUEUED,
            message=f"Restore from backup version {backup.version_number} queued",
        )
        return await self._enqueue_job(
            router=router,
            job_type=ProvisioningJobType.RESTORE,
            payload={"backup_version_id": str(backup.id)},
            requested_by_user_id=actor_user_id,
        )

    async def factory_reset(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> ProvisioningJob:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        validate_router_eligible_for_factory_reset(router)
        await self._record_event(
            router, RouterEventType.FACTORY_RESET_QUEUED, message="Factory reset queued"
        )
        return await self._enqueue_job(
            router=router,
            job_type=ProvisioningJobType.FACTORY_RESET,
            payload={},
            requested_by_user_id=actor_user_id,
        )

    async def rotate_secret(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> tuple[Router, str]:
        """Generates new RouterOS API credentials and stores them
        Fernet-encrypted via BE-008's existing
        ``RouterService.update_router`` (which itself calls
        ``app.domains.router.crypto.encrypt_secret`` internally) -- this
        method never touches ``crypto.py``/encryption directly, it only
        supplies the new plaintext and lets BE-008's own, already-audited
        update path do the encrypting. Returns the new plaintext secret
        exactly once, mirroring ``RouterService.generate_provisioning_token``'s
        own "shown once, never retrievable again" convention."""
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        if router.status == RouterStatus.DECOMMISSIONED.value:
            raise RouterDecommissionedError(router.id)

        new_secret = secrets.token_urlsafe(ROTATED_SECRET_BYTES)
        updated_router = await self.router_lookup.update_router(
            actor_user_id=actor_user_id,
            router_id=router.id,
            requesting_organization_id=requesting_organization_id,
            data={"api_secret": new_secret},
        )
        await self._record_event(
            updated_router,
            RouterEventType.SECRET_ROTATED,
            message="Router API credentials rotated",
        )
        await self._audit_router(
            actor_user_id,
            AuditAction.ROUTER_SECRET_ROTATED,
            router=updated_router,
            description=f"API credentials rotated for router '{updated_router.name}'",
        )
        return updated_router, new_secret

    # ========================================================================
    # Provisioning status
    # ========================================================================

    async def get_provisioning_status(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> ProvisioningStatus:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        profile = await self.repository.get_profile_for_router(router.id)
        latest_version = await self.repository.get_latest_version_for_router(router.id)
        active_jobs = await self.repository.list_active_jobs_for_router(router.id)
        return ProvisioningStatus(
            router=router,
            profile=profile,
            latest_version=latest_version,
            active_jobs=active_jobs,
        )

    async def list_jobs(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[ProvisioningJob], object]:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_jobs_for_router(
            router.id, page=page, page_size=page_size
        )

    # ========================================================================
    # Device-initiated enrollment
    # ========================================================================

    async def submit_enrollment(
        self, *, serial_number: str, mac_address: str, model: str
    ) -> RouterEnrollmentRequest:
        normalized_serial = serial_number.strip()
        normalized_mac = validate_mac_address_format(mac_address)

        existing_by_serial = await self._find_active_router(
            serial_number=normalized_serial
        )
        existing_by_mac = await self._find_active_router(mac_address=normalized_mac)
        validate_no_existing_router_conflict(
            existing_by_serial=existing_by_serial,
            existing_by_mac=existing_by_mac,
            identifier=normalized_serial,
        )

        duplicate_pending = await self.repository.find_pending_enrollment(
            serial_number=normalized_serial, mac_address=normalized_mac
        )
        if duplicate_pending is not None:
            raise DuplicatePendingEnrollmentError(normalized_serial)

        now = datetime.now(UTC)
        enrollment = await self.repository.create_enrollment(
            serial_number=normalized_serial,
            mac_address=normalized_mac,
            model=model,
            requested_at=now,
            status=EnrollmentStatus.PENDING.value,
        )
        await self._audit(
            None,
            AuditAction.ROUTER_ENROLLMENT_SUBMITTED,
            entity_type="router_enrollment_request",
            entity_id=enrollment.id,
            description=f"Enrollment submitted for serial '{normalized_serial}'",
        )
        logger.info(
            "router_enrollment_submitted", extra={"enrollment_id": str(enrollment.id)}
        )
        return enrollment

    async def _find_active_router(
        self, *, serial_number: str | None = None, mac_address: str | None = None
    ) -> Router | None:
        try:
            if serial_number is not None:
                return await self.router_lookup.get_by_serial_number(serial_number)
            return await self.router_lookup.get_by_mac_address(mac_address or "")
        except RouterNotFoundError:
            return None

    async def get_enrollment(self, enrollment_id: uuid.UUID) -> RouterEnrollmentRequest:
        enrollment = await self.repository.get_enrollment(enrollment_id)
        if enrollment is None:
            raise RouterEnrollmentNotFoundError(enrollment_id)
        return enrollment

    async def list_pending_enrollments(
        self, *, page: int = 1, page_size: int = 25
    ) -> tuple[list[RouterEnrollmentRequest], object]:
        return await self.repository.list_pending_enrollments(
            page=page, page_size=page_size
        )

    async def approve_enrollment(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        enrollment_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID,
        name: str,
        management_ip_address: str | None = None,
        public_ip_address: str | None = None,
        api_username: str | None = None,
        api_secret: str | None = None,
    ) -> tuple[RouterEnrollmentRequest, Router]:
        enrollment = await self.get_enrollment(enrollment_id)
        validate_enrollment_pending(enrollment)

        # Race-condition re-check: another approval (or an unrelated direct
        # BE-008 registration) may have claimed this serial/MAC since
        # submission.
        existing_by_serial = await self._find_active_router(
            serial_number=enrollment.serial_number
        )
        existing_by_mac = await self._find_active_router(
            mac_address=enrollment.mac_address
        )
        validate_no_existing_router_conflict(
            existing_by_serial=existing_by_serial,
            existing_by_mac=existing_by_mac,
            identifier=enrollment.serial_number,
        )

        router = await self.router_lookup.create_router(
            actor_user_id=actor_user_id,
            location_id=location_id,
            requesting_organization_id=requesting_organization_id,
            name=name,
            serial_number=enrollment.serial_number,
            mac_address=enrollment.mac_address,
            model=enrollment.model,
            management_ip_address=management_ip_address,
            public_ip_address=public_ip_address,
            api_username=api_username,
            api_secret=api_secret,
        )

        now = datetime.now(UTC)
        updated_enrollment = await self.repository.update_enrollment(
            enrollment,
            {
                "status": EnrollmentStatus.APPROVED.value,
                "reviewed_by_user_id": actor_user_id,
                "reviewed_at": now,
                "approved_router_id": router.id,
                "updated_by": actor_user_id,
            },
        )
        await self._record_event(
            router,
            RouterEventType.ENROLLMENT_APPROVED,
            message=f"Enrollment {enrollment.id} approved",
        )
        await self._audit_router(
            actor_user_id,
            AuditAction.ROUTER_ENROLLMENT_APPROVED,
            router=router,
            description=(
                f"Enrollment for serial '{enrollment.serial_number}' approved"
            ),
        )
        return updated_enrollment, router

    async def reject_enrollment(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        enrollment_id: uuid.UUID,
        rejection_reason: str,
    ) -> RouterEnrollmentRequest:
        enrollment = await self.get_enrollment(enrollment_id)
        validate_enrollment_pending(enrollment)

        now = datetime.now(UTC)
        updated = await self.repository.update_enrollment(
            enrollment,
            {
                "status": EnrollmentStatus.REJECTED.value,
                "reviewed_by_user_id": actor_user_id,
                "reviewed_at": now,
                "rejection_reason": rejection_reason,
                "updated_by": actor_user_id,
            },
        )
        await self._audit(
            actor_user_id,
            AuditAction.ROUTER_ENROLLMENT_REJECTED,
            entity_type="router_enrollment_request",
            entity_id=enrollment.id,
            description=(
                f"Enrollment for serial '{enrollment.serial_number}' rejected: "
                f"{rejection_reason}"
            ),
        )
        return updated

    # ========================================================================
    # Health / event history
    # ========================================================================

    async def record_health_snapshot(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        cpu_usage_percent: float | None = None,
        memory_usage_percent: float | None = None,
        uptime_seconds: int | None = None,
        connected_clients_count: int | None = None,
        routeros_version: str | None = None,
        management_ip_address: str | None = None,
    ) -> tuple[Router, RouterHealthSnapshot]:
        """Supplements (never replaces) BE-008's own heartbeat: calls
        ``RouterService.heartbeat`` first (reusing its existing liveness/
        status-transition logic exactly as-is), then persists a full
        history row with the richer metrics BE-008's own single "current
        snapshot" fields don't retain -- composition, not a second heartbeat
        endpoint."""
        router = await self.router_lookup.heartbeat(
            router_id=router_id,
            requesting_organization_id=requesting_organization_id,
            routeros_version=routeros_version,
            management_ip_address=management_ip_address,
        )
        now = datetime.now(UTC)
        snapshot = await self.repository.create_health_snapshot(
            router_id=router.id,
            recorded_at=now,
            health_status=router.health_status,
            cpu_usage_percent=cpu_usage_percent,
            memory_usage_percent=memory_usage_percent,
            uptime_seconds=uptime_seconds,
            connected_clients_count=connected_clients_count,
        )
        logger.info(
            "router_health_snapshot_recorded", extra={"router_id": str(router.id)}
        )
        return router, snapshot

    async def list_health_history(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[RouterHealthSnapshot], object]:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_health_snapshots_for_router(
            router.id, page=page, page_size=page_size
        )

    async def list_events(
        self,
        *,
        router_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[RouterEvent], object]:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        return await self.repository.list_events_for_router(
            router.id, page=page, page_size=page_size
        )

    # ========================================================================
    # Internal: event + audit helpers
    # ========================================================================

    async def _record_event(
        self,
        router: Router,
        event_type: RouterEventType,
        *,
        message: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> RouterEvent:
        now = datetime.now(UTC)
        event = await self.repository.create_event(
            router_id=router.id,
            event_type=event_type.value,
            message=message,
            occurred_at=now,
            event_metadata=metadata or {},
        )
        logger.info(
            "router_event_recorded",
            extra={"router_id": str(router.id), "event_type": event_type.value},
        )
        return event

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        entity_id: uuid.UUID | None,
        description: str,
        entity_type: str = "router",
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        metadata: dict[str, object] | None = None,
    ) -> None:
        if self.audit_writer is not None:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action=action.value,
                entity_type=entity_type,
                entity_id=entity_id,
                description=description,
                event_metadata=metadata or {},
                organization_id=organization_id,
                location_id=location_id,
            )
        logger.info(
            "router_provisioning_audit_event",
            extra={
                "action": action.value,
                "entity_id": str(entity_id) if entity_id else None,
            },
        )

    async def _audit_router(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        router: Router,
        description: str,
        metadata: dict[str, object] | None = None,
    ) -> None:
        await self._audit(
            actor_user_id,
            action,
            entity_type="router",
            entity_id=router.id,
            description=description,
            organization_id=router.organization_id,
            location_id=router.location_id,
            metadata=metadata,
        )


__all__ = [
    "RouterProvisioningService",
    "RouterLookupProtocol",
    "LocationLookupProtocol",
    "AuditLogWriter",
    "ProvisioningStatus",
    "render_template",
]
