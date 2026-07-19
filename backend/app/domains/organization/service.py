"""Organization business logic: tenant CRUD, MSP hierarchy validation, and
membership lifecycle management.

Design notes worth calling out (see
``docs/organization/ORGANIZATION_ARCHITECTURE.md`` for the full write-up):

* MSP modeling: an MSP is just an ``Organization`` row with
  ``org_type == MSP``. Only MSP-type organizations may hold children
  (``parent_organization_id`` pointing at them); circular hierarchies are
  rejected the same way RBAC rejects circular ``parent_role_id`` chains
  (``_validate_parent_assignment`` walks the proposed parent's ancestry).
* Tenant scoping mirrors ``RBACService``'s
  ``_enforce_role_tenant_access``/``list_roles`` pattern: a caller with no
  ``requesting_organization_id`` (a platform-level, GLOBAL-scoped role) may
  act on any organization; a caller acting within organization A may only
  read/mutate A itself or A's children (if A is an MSP).
* Membership vs. RBAC role assignment: this service never touches
  ``user_roles``. It only answers "does this user belong to this
  organization" -- assigning what the user can *do* once a member is a
  separate ``RBACService.assign_role_to_user`` call made by the caller
  (e.g. the router layer), not something this service does on the member's
  behalf.
* Audit logging reuses RBAC's ``audit_log_entries`` table via a narrow,
  duck-typed ``AuditLogWriter`` protocol (just ``create_audit_log_entry``)
  rather than importing ``RBACRepository`` directly -- this keeps the
  Organization domain from depending on RBAC's full repository surface for
  what is, structurally, a single shared side-table write.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Protocol

from app.common.exceptions import CloudGuestError
from app.database.utils.pagination import PaginationMeta
from app.domains.rbac.enums import AuditAction

from .enums import MembershipStatus, OrganizationStatus, OrganizationType
from .exceptions import (
    CircularOrganizationHierarchyError,
    CrossOrganizationAccessError,
    DuplicateMembershipError,
    DuplicateSlugError,
    InvalidMembershipStatusTransitionError,
    LastActiveMemberError,
    MembershipSuspendedError,
    MspDowngradeWithChildrenError,
    NotAnMspOrganizationError,
    OrganizationArchivedError,
    OrganizationMembershipNotFoundError,
    OrganizationNotFoundError,
)
from .models import Organization, OrganizationMember
from .repository import OrganizationRepositoryProtocol

logger = logging.getLogger(__name__)

_MAX_HIERARCHY_DEPTH = 50


class AuditLogWriter(Protocol):
    """The minimal surface this service needs to write into RBAC's shared
    ``audit_log_entries`` table, without depending on the rest of
    ``RBACRepositoryProtocol``."""

    async def create_audit_log_entry(self, **fields: object) -> object: ...


def _normalize_slug(slug: str) -> str:
    return slug.strip().lower()


def _enum_value(value: object) -> object:
    return value.value if isinstance(value, Enum) else value


class OrganizationService:
    """Core organization business logic."""

    def __init__(
        self,
        repository: OrganizationRepositoryProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.audit_writer = audit_writer

    # -- reads -----------------------------------------------------------------

    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization:
        organization = await self.repository.get_by_id(
            organization_id, include_deleted=include_deleted
        )
        if organization is None:
            raise OrganizationNotFoundError(organization_id)
        return organization

    async def get_by_slug(self, slug: str) -> Organization:
        organization = await self.repository.get_by_slug(_normalize_slug(slug))
        if organization is None:
            raise OrganizationNotFoundError(slug)
        return organization

    async def list_organizations(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int = 1,
        page_size: int = 25,
        search: str | None = None,
        status: OrganizationStatus | None = None,
        org_type: OrganizationType | None = None,
    ) -> tuple[list[Organization], PaginationMeta]:
        """Platform-level callers (no ``requesting_organization_id`` -- a
        GLOBAL-scoped role) see every organization. Org-scoped callers see
        only their own organization plus its children (if it is an MSP)."""
        return await self.repository.list_organizations(
            page=page,
            page_size=page_size,
            search=search,
            status=status.value if status else None,
            org_type=org_type.value if org_type else None,
            scope_organization_id=requesting_organization_id,
        )

    async def list_children(self, organization_id: uuid.UUID) -> list[Organization]:
        organization = await self.get_organization(organization_id)
        if not organization.is_msp():
            raise NotAnMspOrganizationError(organization_id)
        return await self.repository.list_children(organization_id)

    # -- writes ------------------------------------------------------------------

    async def create_organization(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        name: str,
        slug: str,
        contact_email: str,
        legal_name: str | None = None,
        org_type: OrganizationType = OrganizationType.STANDARD,
        status: OrganizationStatus = OrganizationStatus.ACTIVE,
        parent_organization_id: uuid.UUID | None = None,
        contact_phone: str | None = None,
        timezone: str = "UTC",
        default_locale: str = "en",
        settings: dict[str, Any] | None = None,
        subscription_tier: str | None = None,
    ) -> Organization:
        normalized_slug = _normalize_slug(slug)
        if await self.repository.get_by_slug(normalized_slug) is not None:
            raise DuplicateSlugError(normalized_slug)

        if parent_organization_id is not None:
            await self._assert_valid_parent(parent_organization_id)

        organization = await self.repository.create_organization(
            name=name,
            slug=normalized_slug,
            legal_name=legal_name,
            org_type=org_type.value,
            status=status.value,
            parent_organization_id=parent_organization_id,
            contact_email=contact_email.lower(),
            contact_phone=contact_phone,
            timezone=timezone,
            default_locale=default_locale,
            settings=settings or {},
            subscription_tier=subscription_tier,
            created_by=actor_user_id,
        )
        await self._audit(
            actor_user_id,
            AuditAction.ORGANIZATION_CREATED,
            entity_id=organization.id,
            description=f"Organization '{organization.name}' created",
            organization_id=organization.id,
        )
        return organization

    async def update_organization(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        data: dict[str, object],
    ) -> Organization:
        organization = await self.get_organization(organization_id)
        self._enforce_tenant_access(organization, requesting_organization_id)

        if organization.status == OrganizationStatus.ARCHIVED.value:
            raise OrganizationArchivedError(organization_id)

        update_data = dict(data)

        if update_data.get("slug") is not None:
            normalized = _normalize_slug(str(update_data["slug"]))
            existing = await self.repository.get_by_slug(normalized)
            if existing is not None and existing.id != organization.id:
                raise DuplicateSlugError(normalized)
            update_data["slug"] = normalized

        if update_data.get("contact_email") is not None:
            update_data["contact_email"] = str(update_data["contact_email"]).lower()

        new_parent_id = update_data.get("parent_organization_id")
        if new_parent_id is not None:
            await self._assert_valid_parent(
                new_parent_id, current_organization_id=organization.id
            )

        new_org_type = update_data.get("org_type")
        if new_org_type is not None:
            normalized_org_type = _enum_value(new_org_type)
            if (
                organization.org_type == OrganizationType.MSP.value
                and normalized_org_type != OrganizationType.MSP.value
            ):
                children = await self.repository.list_children(organization.id)
                if children:
                    raise MspDowngradeWithChildrenError(organization.id)
            update_data["org_type"] = normalized_org_type

        updated = await self.repository.update_organization(
            organization, {**update_data, "updated_by": actor_user_id}
        )
        await self._audit(
            actor_user_id,
            AuditAction.ORGANIZATION_UPDATED,
            entity_id=updated.id,
            description=f"Organization '{updated.name}' updated",
            organization_id=updated.id,
        )
        return updated

    async def archive_organization(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> Organization:
        organization = await self.get_organization(organization_id)
        self._enforce_tenant_access(organization, requesting_organization_id)

        updated = await self.repository.update_organization(
            organization,
            {"status": OrganizationStatus.ARCHIVED.value, "updated_by": actor_user_id},
        )
        updated = await self.repository.soft_delete_organization(updated)
        await self._audit(
            actor_user_id,
            AuditAction.ORGANIZATION_ARCHIVED,
            entity_id=updated.id,
            description=f"Organization '{updated.name}' archived",
            organization_id=updated.id,
        )
        return updated

    async def suspend_organization(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> Organization:
        return await self._set_status(
            actor_user_id=actor_user_id,
            organization_id=organization_id,
            requesting_organization_id=requesting_organization_id,
            new_status=OrganizationStatus.SUSPENDED,
            action=AuditAction.ORGANIZATION_SUSPENDED,
        )

    async def activate_organization(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> Organization:
        return await self._set_status(
            actor_user_id=actor_user_id,
            organization_id=organization_id,
            requesting_organization_id=requesting_organization_id,
            new_status=OrganizationStatus.ACTIVE,
            action=AuditAction.ORGANIZATION_ACTIVATED,
        )

    async def _set_status(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        new_status: OrganizationStatus,
        action: AuditAction,
    ) -> Organization:
        organization = await self.get_organization(organization_id)
        self._enforce_tenant_access(organization, requesting_organization_id)
        if organization.status == OrganizationStatus.ARCHIVED.value:
            raise OrganizationArchivedError(organization_id)

        updated = await self.repository.update_organization(
            organization, {"status": new_status.value, "updated_by": actor_user_id}
        )
        await self._audit(
            actor_user_id,
            action,
            entity_id=updated.id,
            description=f"Organization '{updated.name}' {new_status.value}",
            organization_id=updated.id,
        )
        return updated

    async def sync_subscription_tier(
        self,
        *,
        organization_id: uuid.UUID,
        subscription_tier: str | None,
    ) -> Organization:
        """Narrow, additive hook for the Billing domain (BE-013 Part 1):
        keeps the legacy, denormalized ``Organization.subscription_tier``
        label in sync with the real ``License``/``Plan`` relationship that
        domain now maintains as the actual source of truth. See
        ``app.domains.billing.models``'s module docstring for the full
        decision write-up of why ``subscription_tier`` -- reserved,
        unpopulated, and documented as carrying "no pricing/entitlement
        logic" since Module 005 -- is kept as a best-effort, write-only-from-
        Billing's-perspective convenience column rather than removed or
        duplicated.

        Deliberately minimal: writes exactly one column, no other
        organization state is touched, no
        ``OrganizationStatus.ARCHIVED``/tenant-scope check is performed
        (billing operations are platform-level and already independently
        authorized by RBAC before this is ever called), and no audit entry
        is written here -- ``app.domains.billing.service.LicenseService``
        already writes its own ``license_assigned``/``license_upgraded``/
        ``license_downgraded`` audit row for the event that triggers this
        sync; a second, organization-flavoured audit row for the same
        moment would be pure duplication.
        """
        organization = await self.get_organization(organization_id)
        return await self.repository.update_organization(
            organization, {"subscription_tier": subscription_tier}
        )

    async def _assert_valid_parent(
        self,
        parent_organization_id: uuid.UUID,
        *,
        current_organization_id: uuid.UUID | None = None,
    ) -> None:
        if (
            current_organization_id is not None
            and parent_organization_id == current_organization_id
        ):
            raise CircularOrganizationHierarchyError(
                current_organization_id, parent_organization_id
            )

        parent = await self.repository.get_by_id(parent_organization_id)
        if parent is None:
            raise OrganizationNotFoundError(parent_organization_id)
        if not parent.is_msp():
            raise NotAnMspOrganizationError(parent_organization_id)

        if current_organization_id is not None:
            chain = await self.repository.get_parent_chain(
                parent_organization_id, max_depth=_MAX_HIERARCHY_DEPTH
            )
            if any(ancestor.id == current_organization_id for ancestor in chain):
                raise CircularOrganizationHierarchyError(
                    current_organization_id, parent_organization_id
                )

    def _enforce_tenant_access(
        self, organization: Organization, requesting_organization_id: uuid.UUID | None
    ) -> None:
        if requesting_organization_id is None:
            return
        if organization.id == requesting_organization_id:
            return
        if organization.parent_organization_id == requesting_organization_id:
            return
        raise CrossOrganizationAccessError()

    # -- membership --------------------------------------------------------------

    async def list_members(
        self, organization_id: uuid.UUID, *, status: MembershipStatus | None = None
    ) -> list[OrganizationMember]:
        await self.get_organization(organization_id)
        return await self.repository.list_members(
            organization_id, status=status.value if status else None
        )

    async def list_user_organizations(
        self, user_id: uuid.UUID, *, status: MembershipStatus | None = None
    ) -> list[OrganizationMember]:
        return await self.repository.list_user_memberships(
            user_id, status=status.value if status else None
        )

    async def invite_member(
        self,
        *,
        actor_user_id: uuid.UUID,
        organization_id: uuid.UUID,
        user_id: uuid.UUID,
        is_primary_contact: bool = False,
    ) -> OrganizationMember:
        organization = await self.get_organization(organization_id)
        if organization.status == OrganizationStatus.ARCHIVED.value:
            raise OrganizationArchivedError(organization_id)

        existing = await self.repository.get_membership(organization_id, user_id)
        if existing is not None:
            if existing.status in (
                MembershipStatus.ACTIVE.value,
                MembershipStatus.INVITED.value,
            ):
                raise DuplicateMembershipError(organization_id, user_id)
            if existing.status == MembershipStatus.SUSPENDED.value:
                raise MembershipSuspendedError(organization_id, user_id)

        member = await self.repository.create_membership(
            organization_id=organization_id,
            user_id=user_id,
            status=MembershipStatus.INVITED.value,
            invited_by_user_id=actor_user_id,
            invited_at=datetime.now(UTC),
            joined_at=None,
            is_primary_contact=is_primary_contact,
            created_by=actor_user_id,
        )
        await self._audit(
            actor_user_id,
            AuditAction.ORGANIZATION_MEMBER_INVITED,
            entity_id=member.id,
            entity_type="organization_member",
            description=f"User {user_id} invited to organization {organization_id}",
            organization_id=organization_id,
            metadata={"target_user_id": str(user_id)},
        )
        return member

    async def accept_invite(
        self,
        *,
        user_id: uuid.UUID,
        organization_id: uuid.UUID,
        member_id: uuid.UUID,
    ) -> OrganizationMember:
        member = await self._get_member_in_organization(organization_id, member_id)
        if member.user_id != user_id:
            raise OrganizationMembershipNotFoundError(member_id)
        if member.status != MembershipStatus.INVITED.value:
            raise InvalidMembershipStatusTransitionError(
                f"Membership {member_id} is not in an invited state and cannot be "
                "accepted"
            )

        updated = await self.repository.update_membership(
            member,
            {
                "status": MembershipStatus.ACTIVE.value,
                "joined_at": datetime.now(UTC),
                "updated_by": user_id,
            },
        )
        await self._audit(
            user_id,
            AuditAction.ORGANIZATION_MEMBER_ACCEPTED,
            entity_id=updated.id,
            entity_type="organization_member",
            description=(
                f"User {user_id} accepted invite to organization {organization_id}"
            ),
            organization_id=organization_id,
        )
        return updated

    async def remove_member(
        self,
        *,
        actor_user_id: uuid.UUID,
        organization_id: uuid.UUID,
        member_id: uuid.UUID,
    ) -> OrganizationMember:
        member = await self._get_member_in_organization(organization_id, member_id)
        if member.status == MembershipStatus.REMOVED.value:
            raise InvalidMembershipStatusTransitionError(
                f"Membership {member_id} has already been removed"
            )

        if member.status == MembershipStatus.ACTIVE.value:
            active_count = await self.repository.count_active_members(organization_id)
            if active_count <= 1:
                raise LastActiveMemberError(organization_id)

        updated = await self.repository.update_membership(
            member,
            {"status": MembershipStatus.REMOVED.value, "updated_by": actor_user_id},
        )
        await self._audit(
            actor_user_id,
            AuditAction.ORGANIZATION_MEMBER_REMOVED,
            entity_id=updated.id,
            entity_type="organization_member",
            description=(
                f"Membership {member_id} removed from organization {organization_id}"
            ),
            organization_id=organization_id,
            metadata={"target_user_id": str(member.user_id)},
        )
        return updated

    async def change_member_status(
        self,
        *,
        actor_user_id: uuid.UUID,
        organization_id: uuid.UUID,
        member_id: uuid.UUID,
        new_status: MembershipStatus,
    ) -> OrganizationMember:
        """General-purpose status transition (e.g. suspend/reactivate an
        existing member) -- exposed at the service layer for administrative
        use even where no dedicated REST endpoint calls it directly today."""
        member = await self._get_member_in_organization(organization_id, member_id)

        if (
            new_status == MembershipStatus.REMOVED
            and member.status == MembershipStatus.ACTIVE.value
        ):
            active_count = await self.repository.count_active_members(organization_id)
            if active_count <= 1:
                raise LastActiveMemberError(organization_id)

        updated = await self.repository.update_membership(
            member, {"status": new_status.value, "updated_by": actor_user_id}
        )
        await self._audit(
            actor_user_id,
            AuditAction.ORGANIZATION_MEMBER_STATUS_CHANGED,
            entity_id=updated.id,
            entity_type="organization_member",
            description=(
                f"Membership {member_id} status changed to '{new_status.value}'"
            ),
            organization_id=organization_id,
            metadata={"target_user_id": str(member.user_id)},
        )
        return updated

    async def _get_member_in_organization(
        self, organization_id: uuid.UUID, member_id: uuid.UUID
    ) -> OrganizationMember:
        member = await self.repository.get_membership_by_id(member_id)
        if member is None or member.organization_id != organization_id:
            raise OrganizationMembershipNotFoundError(member_id)
        return member

    # -- internal helpers -------------------------------------------------------

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        entity_id: uuid.UUID | None,
        description: str,
        entity_type: str = "organization",
        organization_id: uuid.UUID | None = None,
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
                location_id=None,
            )
        logger.info(
            "organization_audit_event",
            extra={
                "action": action.value,
                "entity_id": str(entity_id) if entity_id else None,
            },
        )


__all__ = [
    "OrganizationService",
    "AuditLogWriter",
    "CloudGuestError",
]
