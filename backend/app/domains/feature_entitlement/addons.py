"""Master-console add-on control: lock/unlock a paid add-on per organization.

Contract: ``wyfy-specs/guest-marketing-campaigns.md`` §3 and §5.9.

An add-on is a BOOLEAN ``PlanFeatureKey`` listed in
``billing.constants.ADDON_FEATURE_KEYS`` (today only ``guest_marketing``).
Its effective value is the organization's live ``OrganizationFeatureOverride``
row when one exists, the plan's value otherwise -- the same merge
``LicenseService.get_entitlement_snapshot`` performs, so what this panel
shows is exactly what ``RequireFeature`` enforces.

## Why these routes take ``organization_id`` from the path and are still safe

Every route here is ``RequirePermission(..., scope=ScopeType.GLOBAL)``. A
GLOBAL pin means only a GLOBAL-scoped grant satisfies the check, so an
organization- or MSP-scoped holder of ``billing.manage`` is refused before
the handler runs. The path id is therefore never compared against a caller's
own tenant: there is no tenant caller that can reach it.

## One transaction, cache after commit

Locking cancels the organization's scheduled/sending campaigns in the same
database transaction as the override write and its audit row. The Redis
entitlement snapshot is invalidated only *after* the commit: invalidating
first would let a concurrent request re-cache the pre-commit answer.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from fastapi import status

from app.common.exceptions import CloudGuestError
from app.domains.billing.constants import (
    ADDON_FEATURE_KEYS,
    FEATURE_REQUIRES,
    PlanFeatureKey,
)
from app.domains.billing.models import OrganizationFeatureOverride
from app.domains.billing.repository import FeatureOverrideRepositoryProtocol
from app.domains.organization.exceptions import OrganizationNotFoundError
from app.domains.rbac.enums import AuditAction

from .service import FEATURE_META


class AddonNotFoundError(CloudGuestError):
    def __init__(self, addon_key: str) -> None:
        super().__init__(
            f"'{addon_key}' is not an add-on that can be locked or unlocked",
            status_code=status.HTTP_404_NOT_FOUND,
            data={"error_code": "addon_not_found"},
        )


class AddonOrganizationNotFoundError(CloudGuestError):
    def __init__(self, organization_id: uuid.UUID) -> None:
        super().__init__(
            f"Organization not found: {organization_id}",
            status_code=status.HTTP_404_NOT_FOUND,
            data={"error_code": "organization_not_found"},
        )


class OrganizationLookupProtocol(Protocol):
    async def get_organization(self, organization_id: uuid.UUID) -> object: ...


class PlanFeatureLookupProtocol(Protocol):
    """Satisfied by ``billing.service.LicenseService``."""

    async def get_plan_feature_enabled(
        self, organization_id: uuid.UUID, feature_key: PlanFeatureKey
    ) -> bool: ...


class AddonCampaignHookProtocol(Protocol):
    """What locking an add-on has to do to that add-on's in-flight work.
    Implemented for ``guest_marketing`` by
    ``marketing.repository.MarketingRepository``."""

    async def count_active_campaigns(self, organization_id: uuid.UUID) -> int: ...

    async def cancel_active_campaigns_for_lock(
        self, organization_id: uuid.UUID
    ) -> int: ...


class UserNameLookupProtocol(Protocol):
    async def get_user_names(
        self, user_ids: list[uuid.UUID]
    ) -> dict[uuid.UUID, str]: ...


class SqlUserNameLookup:
    """``UserNameLookupProtocol`` over the ``users`` table: "First Last"."""

    def __init__(self, session: object) -> None:
        self.session = session

    async def get_user_names(self, user_ids: list[uuid.UUID]) -> dict[uuid.UUID, str]:
        from sqlalchemy import select

        from app.domains.auth.models import User

        ids = [user_id for user_id in user_ids if user_id is not None]
        if not ids:
            return {}
        result = await self.session.execute(  # type: ignore[attr-defined]
            select(User.id, User.first_name, User.last_name).where(User.id.in_(ids))
        )
        return {
            row.id: " ".join(part for part in (row.first_name, row.last_name) if part)
            for row in result
        }


class AuditWriterProtocol(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


class EntitlementCacheProtocol(Protocol):
    async def invalidate(self, organization_id: uuid.UUID) -> None: ...


class CommitterProtocol(Protocol):
    async def commit(self) -> None: ...


@dataclass(frozen=True)
class AddonOverrideView:
    is_enabled: bool
    reason: str | None
    set_by_id: uuid.UUID | None
    set_by_name: str | None
    set_at: datetime


@dataclass(frozen=True)
class AddonView:
    key: str
    name: str
    description: str
    enabled: bool
    source: str
    plan_value: bool
    override: AddonOverrideView | None
    active_campaign_count: int
    # The prerequisite add-on keeping this one off, if any (spec §12.3:
    # guest_marketing_byo is only effective while guest_marketing is).
    blocked_by: str | None = None


class AddonService:
    def __init__(
        self,
        *,
        organizations: OrganizationLookupProtocol,
        plan_features: PlanFeatureLookupProtocol,
        overrides: FeatureOverrideRepositoryProtocol,
        campaign_hooks: dict[str, AddonCampaignHookProtocol],
        user_names: UserNameLookupProtocol,
        audit_writer: AuditWriterProtocol,
        entitlement_cache: EntitlementCacheProtocol,
        committer: CommitterProtocol,
    ) -> None:
        self.organizations = organizations
        self.plan_features = plan_features
        self.overrides = overrides
        self.campaign_hooks = campaign_hooks
        self.user_names = user_names
        self.audit_writer = audit_writer
        self.entitlement_cache = entitlement_cache
        self.committer = committer

    # -- reads ---------------------------------------------------------------

    async def list_addons(self, organization_id: uuid.UUID) -> list[AddonView]:
        await self._require_organization(organization_id)
        return [
            await self._view(organization_id, key)
            for key in sorted(ADDON_FEATURE_KEYS, key=lambda k: k.value)
        ]

    # -- writes --------------------------------------------------------------

    async def set_addon(
        self,
        organization_id: uuid.UUID,
        addon_key: str,
        *,
        enabled: bool,
        reason: str | None,
        actor_user_id: uuid.UUID,
    ) -> tuple[AddonView, int]:
        key = self._require_addon(addon_key)
        await self._require_organization(organization_id)

        existing = await self.overrides.get_live(organization_id, key.value)
        if existing is None:
            await self.overrides.create(
                organization_id=organization_id,
                feature_key=key.value,
                is_enabled=enabled,
                reason=reason,
                set_by_user_id=actor_user_id,
                created_by=actor_user_id,
            )
        else:
            await self.overrides.update(
                existing,
                {
                    "is_enabled": enabled,
                    "reason": reason,
                    "set_by_user_id": actor_user_id,
                    "updated_by": actor_user_id,
                },
            )
        cancelled = 0
        if not enabled:
            cancelled = await self._cancel_active(organization_id, key)
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=AuditAction.ORGANIZATION_FEATURE_OVERRIDE_SET.value,
            entity_type="organization_feature_override",
            entity_id=organization_id,
            organization_id=organization_id,
            description=(
                f"Add-on '{key.value}' {'unlocked' if enabled else 'locked'}"
                + (f"; {cancelled} active campaign(s) cancelled" if cancelled else "")
            ),
            event_metadata={
                "feature_key": key.value,
                "is_enabled": enabled,
                "reason": reason,
                "cancelled_campaign_count": cancelled,
            },
        )
        await self.committer.commit()
        await self.entitlement_cache.invalidate(organization_id)
        return await self._view(organization_id, key), cancelled

    async def clear_addon(
        self,
        organization_id: uuid.UUID,
        addon_key: str,
        *,
        actor_user_id: uuid.UUID,
    ) -> tuple[AddonView, int]:
        key = self._require_addon(addon_key)
        await self._require_organization(organization_id)

        existing = await self.overrides.get_live(organization_id, key.value)
        if existing is not None:
            await self.overrides.soft_delete(existing)
        plan_value = await self.plan_features.get_plan_feature_enabled(
            organization_id, key
        )
        effective = (await self._view(organization_id, key)).enabled
        cancelled = 0
        if not effective:
            cancelled = await self._cancel_active(organization_id, key)
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=AuditAction.ORGANIZATION_FEATURE_OVERRIDE_CLEARED.value,
            entity_type="organization_feature_override",
            entity_id=organization_id,
            organization_id=organization_id,
            description=(
                f"Add-on '{key.value}' reset to plan default "
                f"({'enabled' if plan_value else 'locked'})"
            ),
            event_metadata={
                "feature_key": key.value,
                "plan_value": plan_value,
                "had_override": existing is not None,
                "cancelled_campaign_count": cancelled,
            },
        )
        await self.committer.commit()
        await self.entitlement_cache.invalidate(organization_id)
        return await self._view(organization_id, key), cancelled

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _require_addon(addon_key: str) -> PlanFeatureKey:
        try:
            key = PlanFeatureKey(addon_key)
        except ValueError as exc:
            raise AddonNotFoundError(addon_key) from exc
        if key not in ADDON_FEATURE_KEYS:
            raise AddonNotFoundError(addon_key)
        return key

    async def _require_organization(self, organization_id: uuid.UUID) -> None:
        try:
            await self.organizations.get_organization(organization_id)
        except OrganizationNotFoundError as exc:
            raise AddonOrganizationNotFoundError(organization_id) from exc

    async def _cancel_active(
        self, organization_id: uuid.UUID, key: PlanFeatureKey
    ) -> int:
        hook = self.campaign_hooks.get(key.value)
        if hook is None:
            return 0
        return await hook.cancel_active_campaigns_for_lock(organization_id)

    async def _view(self, organization_id: uuid.UUID, key: PlanFeatureKey) -> AddonView:
        plan_value = await self.plan_features.get_plan_feature_enabled(
            organization_id, key
        )
        override_row: (
            OrganizationFeatureOverride | None
        ) = await self.overrides.get_live(organization_id, key.value)
        override: AddonOverrideView | None = None
        if override_row is not None:
            names = (
                await self.user_names.get_user_names([override_row.set_by_user_id])
                if override_row.set_by_user_id
                else {}
            )
            override = AddonOverrideView(
                is_enabled=override_row.is_enabled,
                reason=override_row.reason,
                set_by_id=override_row.set_by_user_id,
                set_by_name=names.get(override_row.set_by_user_id)
                if override_row.set_by_user_id
                else None,
                set_at=override_row.updated_at or override_row.created_at,
            )
        hook = self.campaign_hooks.get(key.value)
        active = await hook.count_active_campaigns(organization_id) if hook else 0
        name, description, _category = FEATURE_META.get(
            key, (key.value, key.value, "general")
        )
        enabled = override.is_enabled if override else plan_value
        blocked_by: str | None = None
        prerequisite = FEATURE_REQUIRES.get(key)
        if (
            prerequisite is not None
            and not (await self._view(organization_id, prerequisite)).enabled
        ):
            blocked_by = prerequisite.value
            enabled = False
        return AddonView(
            key=key.value,
            name=name,
            description=description,
            blocked_by=blocked_by,
            enabled=enabled,
            source="override" if override else "plan",
            plan_value=plan_value,
            override=override,
            active_campaign_count=active,
        )


__all__ = [
    "AddonNotFoundError",
    "AddonOrganizationNotFoundError",
    "AddonService",
    "AddonView",
    "SqlUserNameLookup",
]
