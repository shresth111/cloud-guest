"""System Settings domain business logic: ``SystemSettingsService``.

The platform-wide (GLOBAL-scope) configuration store, wired to the RBAC
``system_settings.*`` permission that was seeded but never had a table
behind it. Ships one real setting end-to-end -- the default plan (+
optional feature overrides) applied to newly-provisioned customer
organizations -- to prove the read/validate/persist/audit pattern the next
platform setting will follow.

## What this domain does NOT do (yet), deliberately

It *stores* the new-customer defaults; it does not yet *consume* them.
Org/customer provisioning
(``app.domains.customer_provisioning``/``app.domains.location
.provisioning_service``) still creates licenses exactly as it does today.
Wiring provisioning to read ``new_customer_default_plan_id`` from this
store is a small, safe follow-up (noted in the PR) rather than something
folded in here, so this change cannot alter how any org is provisioned
until that hookup is made and reviewed on its own.

## Validation + audit

A ``PUT`` that names a ``new_customer_default_plan_id`` validates the plan
actually exists (``DefaultPlanNotFoundError`` otherwise -- storing a
dangling id would only surface on a real customer's first day). Feature
overrides are validated against the real feature catalog
(``PlanFeatureKey``). Every ``PUT`` that changes at least one value writes
one ``SYSTEM_SETTINGS_UPDATED`` audit entry through RBAC's shared
``audit_log_entries`` table, carrying the changed keys (old + new) in
``event_metadata`` -- the same narrow ``AuditLogWriter`` protocol shape the
Channel Partner/Organization/Voucher domains use. A no-op ``PUT`` (nothing
actually changed) writes no audit row.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Protocol

from app.domains.billing.constants import PlanFeatureKey
from app.domains.rbac.enums import AuditAction

from .constants import SystemSettingKey
from .exceptions import DefaultPlanNotFoundError, UnknownFeatureOverrideError
from .repository import SystemSettingsRepositoryProtocol
from .schemas import (
    FeatureOverride,
    PlatformSettingsResponse,
    PlatformSettingsUpdateRequest,
)

logger = logging.getLogger(__name__)

_VALID_FEATURE_KEYS = {key.value for key in PlanFeatureKey}


class AuditLogWriter(Protocol):
    """The minimal surface this service needs to write into RBAC's shared
    ``audit_log_entries`` table, without depending on the rest of
    ``RBACRepositoryProtocol`` -- mirrors
    ``app.domains.channel_partner.service.AuditLogWriter``'s identical
    narrow protocol shape exactly."""

    async def create_audit_log_entry(self, **fields: object) -> object: ...


class PlanReader(Protocol):
    """The one billing capability this service depends on: resolve a plan by
    id to confirm it exists. Kept to a one-method protocol so a unit test
    can supply a trivial fake instead of the whole ``PlanRepository``."""

    async def get_by_id(
        self, plan_id: uuid.UUID, *, include_deleted: bool = False
    ) -> object | None: ...


class SystemSettingsService:
    def __init__(
        self,
        repository: SystemSettingsRepositoryProtocol,
        *,
        plan_reader: PlanReader,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.plan_reader = plan_reader
        self.audit_writer = audit_writer

    # -- read -----------------------------------------------------------------

    async def get_platform_settings(self) -> PlatformSettingsResponse:
        values = await self.repository.get_all_values()
        return _response_from_values(values)

    # -- write ----------------------------------------------------------------

    async def update_platform_settings(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        body: PlatformSettingsUpdateRequest,
    ) -> PlatformSettingsResponse:
        current = await self.repository.get_all_values()
        changes: dict[str, dict[str, Any]] = {}

        if body.new_customer_default_plan_id is not None:
            new_plan_id = await self._validated_plan_id(
                body.new_customer_default_plan_id
            )
            key = SystemSettingKey.NEW_CUSTOMER_DEFAULT_PLAN_ID.value
            old_plan_id = current.get(key)
            if new_plan_id != old_plan_id:
                await self.repository.upsert(
                    key, new_plan_id, actor_user_id=actor_user_id
                )
                changes[key] = {"old": old_plan_id, "new": new_plan_id}

        if body.new_customer_default_feature_overrides is not None:
            overrides = self._validated_overrides(
                body.new_customer_default_feature_overrides
            )
            key = SystemSettingKey.NEW_CUSTOMER_DEFAULT_FEATURE_OVERRIDES.value
            old_overrides = current.get(key) or []
            if overrides != old_overrides:
                await self.repository.upsert(
                    key, overrides, actor_user_id=actor_user_id
                )
                changes[key] = {"old": old_overrides, "new": overrides}

        if changes:
            await self._record_audit(actor_user_id=actor_user_id, changes=changes)

        return await self.get_platform_settings()

    # -- helpers --------------------------------------------------------------

    async def _validated_plan_id(self, raw: str) -> str | None:
        """Resolves and validates the incoming default-plan id. An empty
        string positively clears the default (stored as ``None``)."""
        candidate = raw.strip()
        if not candidate:
            return None
        try:
            plan_uuid = uuid.UUID(candidate)
        except ValueError as exc:
            raise DefaultPlanNotFoundError(candidate) from exc
        plan = await self.plan_reader.get_by_id(plan_uuid)
        if plan is None:
            raise DefaultPlanNotFoundError(candidate)
        return str(plan_uuid)

    def _validated_overrides(
        self, overrides: list[FeatureOverride]
    ) -> list[dict[str, Any]]:
        """Validates each override's ``feature_key`` against the real feature
        catalog and normalises to a JSON-safe list, de-duplicating on
        ``feature_key`` (last write wins)."""
        resolved: dict[str, bool] = {}
        for override in overrides:
            if override.feature_key not in _VALID_FEATURE_KEYS:
                raise UnknownFeatureOverrideError(override.feature_key)
            resolved[override.feature_key] = override.enabled
        return [
            {"feature_key": key, "enabled": enabled}
            for key, enabled in resolved.items()
        ]

    async def _record_audit(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        changes: dict[str, dict[str, Any]],
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=AuditAction.SYSTEM_SETTINGS_UPDATED.value,
            entity_type="system_setting",
            entity_id=None,
            description=(
                "Platform settings updated: " + ", ".join(sorted(changes.keys()))
            ),
            event_metadata={"changes": changes},
            organization_id=None,
            location_id=None,
        )


def _response_from_values(values: dict[str, Any]) -> PlatformSettingsResponse:
    plan_id = values.get(SystemSettingKey.NEW_CUSTOMER_DEFAULT_PLAN_ID.value)
    raw_overrides = (
        values.get(SystemSettingKey.NEW_CUSTOMER_DEFAULT_FEATURE_OVERRIDES.value) or []
    )
    overrides = [
        FeatureOverride(
            feature_key=str(item["feature_key"]),
            enabled=bool(item["enabled"]),
        )
        for item in raw_overrides
        if isinstance(item, dict) and "feature_key" in item and "enabled" in item
    ]
    return PlatformSettingsResponse(
        new_customer_default_plan_id=str(plan_id) if plan_id else None,
        new_customer_default_feature_overrides=overrides,
    )
