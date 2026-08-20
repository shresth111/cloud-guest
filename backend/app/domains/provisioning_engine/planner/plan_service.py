"""Configuration plan orchestration (build + persist + approve)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Protocol

from app.domains.isp.models import IspLink
from app.domains.router.models import Router
from app.domains.router_provisioning.models import ConfigVersion

from .compile import compile_configuration_plan
from .constants import PlanStatus, VerificationScope
from .exceptions import (
    ConfigurationPlanNotApprovableError,
    ConfigurationPlanNotFoundError,
    ConfigurationPlanNotPreparableError,
    ConfigurationPlanNotRenderableError,
    NoRouterSnapshotError,
    RouterSnapshotNotFoundError,
)
from .managed_resource_repository import ManagedRouterResourceRepositoryProtocol
from .managed_resources import build_managed_resource_rows
from .management_safety import plan_requires_safety_net
from .plan_engine import build_configuration_plan, plan_to_persist_dict
from .plan_repository import ConfigurationPlanRepositoryProtocol
from .repository import RouterSnapshotRepositoryProtocol
from .schemas import (
    BuildConfigurationPlanRequest,
    ConfigurationPlanPrepareResponse,
    ConfigurationPlanRenderResponse,
    ConfigurationPlanResponse,
    GuestNetworkRequest,
)
from .verification_repository import VerificationRunRepositoryProtocol
from .wan_verification import wan_verification_gate_passes


class RouterLookupProtocol(Protocol):
    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> Router: ...


class IspLinkLookupProtocol(Protocol):
    async def list_links(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        router_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[IspLink], object]: ...


class ConfigVersionCreatorProtocol(Protocol):
    async def create_version_from_content(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        rendered_content: str,
        requesting_organization_id: uuid.UUID | None,
    ) -> ConfigVersion: ...


class PreApplyBackupCreatorProtocol(Protocol):
    async def create_pre_apply_backup_from_content(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        router_id: uuid.UUID,
        rendered_content: str,
        requesting_organization_id: uuid.UUID | None,
    ) -> ConfigVersion: ...


def _wan_interfaces_from_links(links: list[IspLink]) -> set[str]:
    names: set[str] = set()
    for link in links:
        if not link.is_enabled:
            continue
        for value in (
            link.physical_interface,
            link.routing_interface,
            link.interface,
        ):
            if value:
                names.add(str(value))
    return names


def _requested_config_payload(
    request: GuestNetworkRequest, decisions: list
) -> dict[str, object]:
    return {
        "guest_network": request.model_dump(mode="json"),
        "decisions": [item.model_dump(mode="json") for item in decisions],
    }


def _parse_requested_config(raw: dict[str, object]) -> tuple[GuestNetworkRequest, list]:
    from .schemas import PlanDecision

    if "guest_network" in raw:
        guest = GuestNetworkRequest.model_validate(raw["guest_network"])
        decisions = [
            PlanDecision.model_validate(item) for item in (raw.get("decisions") or [])
        ]
        return guest, decisions
    return GuestNetworkRequest.model_validate(raw), []


class ConfigurationPlanService:
    def __init__(
        self,
        plan_repository: ConfigurationPlanRepositoryProtocol,
        snapshot_repository: RouterSnapshotRepositoryProtocol,
        verification_repository: VerificationRunRepositoryProtocol,
        managed_resource_repository: ManagedRouterResourceRepositoryProtocol,
        router_lookup: RouterLookupProtocol,
        isp_link_lookup: IspLinkLookupProtocol,
    ) -> None:
        self.plan_repository = plan_repository
        self.snapshot_repository = snapshot_repository
        self.verification_repository = verification_repository
        self.managed_resource_repository = managed_resource_repository
        self.router_lookup = router_lookup
        self.isp_link_lookup = isp_link_lookup

    async def _wan_gate_passes(self, router_id: uuid.UUID) -> bool:
        links, _meta = await self.isp_link_lookup.list_links(
            requesting_organization_id=None,
            router_id=router_id,
            page=1,
            page_size=100,
        )
        enabled_ids = {link.id for link in links if link.is_enabled}
        if not enabled_ids:
            return False
        runs = await self.verification_repository.list_latest_group_for_router(
            router_id, scope=VerificationScope.WAN.value
        )
        return wan_verification_gate_passes(enabled_link_ids=enabled_ids, runs=runs)

    async def build_plan(
        self,
        router_id: uuid.UUID,
        body: BuildConfigurationPlanRequest,
        *,
        snapshot_id: uuid.UUID | None,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
    ) -> ConfigurationPlanResponse:
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        if snapshot_id is not None:
            snapshot = await self.snapshot_repository.get_by_id(snapshot_id)
            if snapshot is None or snapshot.router_id != router_id:
                raise RouterSnapshotNotFoundError(snapshot_id)
        else:
            snapshot = await self.snapshot_repository.get_latest_for_router(router_id)
            if snapshot is None:
                raise NoRouterSnapshotError(router_id)

        links, _meta = await self.isp_link_lookup.list_links(
            requesting_organization_id=requesting_organization_id,
            router_id=router_id,
            page=1,
            page_size=100,
        )
        preview = build_configuration_plan(
            snapshot=snapshot,
            snapshot_id=str(snapshot.id),
            router_id=str(router_id),
            request=body.requested_config,
            wan_interfaces=_wan_interfaces_from_links(links),
            wan_gate_passes=await self._wan_gate_passes(router_id),
        )
        row = await self.plan_repository.create(
            {
                **plan_to_persist_dict(
                    preview,
                    router_id=router.id,
                    organization_id=router.organization_id,
                    location_id=router.location_id,
                    snapshot_id=snapshot.id,
                    actor_user_id=actor_user_id,
                ),
                "requested_config": _requested_config_payload(
                    preview.requested_config, preview.decisions
                ),
            }
        )
        return self._row_to_response(row)

    async def get_plan(
        self,
        router_id: uuid.UUID,
        plan_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None,
    ) -> ConfigurationPlanResponse:
        await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        row = await self.plan_repository.get_by_id(plan_id, router_id=router_id)
        if row is None:
            raise ConfigurationPlanNotFoundError(plan_id)
        return self._row_to_response(row)

    async def approve_plan(
        self,
        router_id: uuid.UUID,
        plan_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> ConfigurationPlanResponse:
        await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        row = await self.plan_repository.get_by_id(plan_id, router_id=router_id)
        if row is None:
            raise ConfigurationPlanNotFoundError(plan_id)
        if row.status in {PlanStatus.BLOCKED.value, PlanStatus.APPLIED.value}:
            raise ConfigurationPlanNotApprovableError(plan_id, row.status)
        updated = await self.plan_repository.update(
            row,
            {
                "status": PlanStatus.APPROVED.value,
                "approved_by_user_id": actor_user_id,
                "approved_at": datetime.now(UTC),
            },
        )
        return self._row_to_response(updated)

    async def render_plan(
        self,
        router_id: uuid.UUID,
        plan_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        config_version_creator: ConfigVersionCreatorProtocol,
    ) -> ConfigurationPlanRenderResponse:
        await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        row = await self.plan_repository.get_by_id(plan_id, router_id=router_id)
        if row is None:
            raise ConfigurationPlanNotFoundError(plan_id)
        if row.status != PlanStatus.APPROVED.value:
            raise ConfigurationPlanNotRenderableError(plan_id, row.status)
        if row.rendered_version_id is not None:
            raise ConfigurationPlanNotRenderableError(plan_id, row.status)

        plan = self._row_to_response(row)
        if plan.conflicts:
            raise ConfigurationPlanNotRenderableError(plan_id, row.status)

        await self.plan_repository.update(row, {"status": PlanStatus.RENDERING.value})
        compiled = compile_configuration_plan(plan)
        version = await config_version_creator.create_version_from_content(
            actor_user_id=actor_user_id,
            router_id=router_id,
            rendered_content=compiled.script,
            requesting_organization_id=requesting_organization_id,
        )
        router = await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        await self.managed_resource_repository.create_many(
            build_managed_resource_rows(
                plan,
                plan_id=plan_id,
                router_id=router.id,
                organization_id=router.organization_id,
                location_id=router.location_id,
            )
        )
        updated = await self.plan_repository.update(
            row,
            {
                "status": PlanStatus.RENDERING.value,
                "rendered_version_id": version.id,
            },
        )
        return ConfigurationPlanRenderResponse(
            plan_id=str(updated.id),
            config_version_id=str(version.id),
            config_version_number=int(version.version_number),
            status=PlanStatus(updated.status),
            profiles_used=compiled.profiles_used,
            secret_refs=compiled.secret_refs,
            line_count=compiled.line_count,
            requires_safety_net=plan_requires_safety_net(plan.actions),
        )

    async def prepare_plan(
        self,
        router_id: uuid.UUID,
        plan_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        backup_creator: PreApplyBackupCreatorProtocol,
    ) -> ConfigurationPlanPrepareResponse:
        await self.router_lookup.get_router(
            router_id, requesting_organization_id=requesting_organization_id
        )
        row = await self.plan_repository.get_by_id(plan_id, router_id=router_id)
        if row is None:
            raise ConfigurationPlanNotFoundError(plan_id)
        if row.status not in {
            PlanStatus.APPROVED.value,
            PlanStatus.RENDERING.value,
        }:
            raise ConfigurationPlanNotPreparableError(plan_id, row.status)
        if row.pre_apply_backup_version_id is not None:
            raise ConfigurationPlanNotPreparableError(plan_id, row.status)

        plan = self._row_to_response(row)
        from app.domains.network_config.profiles.safety_net import (
            render_pre_apply_export_marker,
        )

        backup = await backup_creator.create_pre_apply_backup_from_content(
            actor_user_id=actor_user_id,
            router_id=router_id,
            rendered_content=render_pre_apply_export_marker(
                snapshot_id=str(row.snapshot_id)
            ),
            requesting_organization_id=requesting_organization_id,
        )
        updated = await self.plan_repository.update(
            row,
            {"pre_apply_backup_version_id": backup.id},
        )
        return ConfigurationPlanPrepareResponse(
            plan_id=str(updated.id),
            pre_apply_backup_version_id=str(backup.id),
            pre_apply_backup_version_number=int(backup.version_number),
            status=PlanStatus(updated.status),
            requires_safety_net=plan_requires_safety_net(plan.actions),
        )

    def _row_to_response(self, row: object) -> ConfigurationPlanResponse:
        from .constants import PlanRisk
        from .plan_models import ConfigurationPlan
        from .schemas import PlanAction, PlanConflict, PlanSummary

        assert isinstance(row, ConfigurationPlan)
        guest, decisions = _parse_requested_config(dict(row.requested_config or {}))
        actions = [PlanAction.model_validate(item) for item in (row.actions or [])]
        conflicts = [
            PlanConflict.model_validate(item) for item in (row.conflicts or [])
        ]
        highest = PlanRisk.NONE
        rank = {PlanRisk.NONE: 0, PlanRisk.LOW: 1, PlanRisk.MANAGEMENT_CONNECTIVITY: 2}
        for action in actions:
            if rank[action.risk] > rank[highest]:
                highest = action.risk
        return ConfigurationPlanResponse(
            id=str(row.id),
            router_id=str(row.router_id),
            snapshot_id=str(row.snapshot_id),
            status=PlanStatus(row.status),
            engine_version=row.engine_version,
            requested_config=guest,
            actions=actions,
            conflicts=conflicts,
            decisions=decisions,
            summary=PlanSummary(
                action_count=len(actions),
                conflict_count=len(conflicts),
                decision_count=len(decisions),
                highest_risk=highest,
            ),
        )


__all__ = ["ConfigurationPlanService"]
