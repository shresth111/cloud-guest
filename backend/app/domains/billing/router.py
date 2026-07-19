"""FastAPI routes for the Billing domain (BE-013 Part 1: Plan + License +
Usage Core).

## RBAC permission-key reuse

``app.domains.rbac.seed.MODULE_ACTIONS`` already seeds two modules this
domain's spec maps cleanly onto -- ``PermissionModule.BILLING``
(``read``/``update``/``export``/``manage``, no dedicated ``create``/
``delete``) and ``PermissionModule.SUBSCRIPTIONS`` (``create``/``read``/
``update``/``delete``/``manage``) -- both already seeded since BE-004, both
already granted to the ``Billing Manager``/``Super Admin``/``Platform
Admin`` system roles at ``GLOBAL`` scope (see ``app.domains.rbac.seed
.SYSTEM_ROLES``). No new ``PermissionModule`` value is added.

* **Plans** (the pricing/entitlement catalog) reuse ``billing.*``: creation/
  deactivation use ``billing.manage`` (no seeded ``create``/``delete``
  action for this module -- the same "reuse the closest seeded action for
  an admin-gated write" precedent ``app.domains.monitoring.router`` already
  establishes for ``alerts.manage``/``notifications.manage``), update uses
  its own seeded ``billing.update``, every read uses ``billing.read``.
  Create/update/deactivate are additionally pinned to ``scope=
  ScopeType.GLOBAL`` explicitly -- the pricing catalog is a platform-wide
  resource, and per the spec, only a Super-Admin-class, platform-scoped
  role should be able to create/edit it (in this codebase's seed data,
  that's ``Super Admin``/``Platform Admin``/``Billing Manager``, the three
  roles holding ``billing.manage``/``billing.update`` at ``GLOBAL`` scope --
  see ``docs/rbac/PERMISSION_MATRIX.md``). ``GET /plans``/``GET
  /plans/{id}`` use the inferred (header-based) scope like every other
  read endpoint in this codebase, since reading the catalog is not a
  platform-only concern.
* **Licenses** reuse ``subscriptions.*``: assignment uses its own seeded
  ``subscriptions.create``; suspend/activate/upgrade/downgrade/cancel reuse
  ``subscriptions.update`` (a state transition on an existing entity, not a
  new create/delete -- mirrors ``alerts.update`` covering
  acknowledge/resolve in ``app.domains.monitoring.router``); every read
  uses ``subscriptions.read``. No explicit ``scope=`` override -- these
  operate on one organization's own license, so the ordinary inferred
  (``X-Organization-Id``-driven) scope resolution applies, exactly like
  every other tenant-scoped write in this codebase.
* **Usage** reuses ``billing.*``: ``GET /usage/{organization_id}`` uses
  ``billing.read``; ``POST /usage/{organization_id}/refresh`` uses
  ``billing.update`` (it mutates persisted ``UsageMetric`` rows).

``POST /licenses/{id}/cancel`` is one additive endpoint beyond the spec's
explicit list: ``CANCELLED`` is a first-class, required state in
``constants.LicenseStatus``'s transition graph, and per this codebase's own
"every documented state must be reachable via a real API path" discipline,
a state with no route to reach it would be dead on arrival -- see
``docs/billing/FLOW.md`` for the full write-up.

## Plan visibility (public vs. private)

``GET /plans`` composes directly with ``app.domains.rbac.authorization
.AccessValidator.has_permission`` (the same "check an extra, independent
permission inline in the route" pattern
``app.domains.monitoring.router._authenticate_websocket`` already
establishes) to decide whether the caller may see private
(``is_public = False``) plans: only a caller who independently holds
``billing.manage`` at ``GLOBAL`` scope may pass ``include_private=true``;
every other caller always sees public plans only, regardless of the query
parameter. ``GET /plans/{id}`` performs no such filtering -- knowing a
specific plan's id (e.g. because your organization's own license already
references it) is treated as sufficient to read it.

All responses use the standard ``ApiResponse``/``build_response`` envelope.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.dependencies import get_current_user
from app.domains.auth.models import AuthUser
from app.domains.auth.schemas import MessageResponse
from app.domains.rbac.authorization import AccessValidator
from app.domains.rbac.dependencies import (
    RequireOrganization,
    RequirePermission,
    get_access_validator,
)
from app.domains.rbac.enums import ScopeType

from .constants import PlanType
from .dependencies import get_license_service, get_plan_service, get_usage_service
from .models import License, LicenseChangeLog, Plan, PlanFeature
from .schemas import (
    LicenseAssignRequest,
    LicenseChangeLogResponse,
    LicenseDowngradeRequest,
    LicenseResponse,
    LicenseSuspendRequest,
    LicenseUpgradeRequest,
    PlanCreateRequest,
    PlanFeatureResponse,
    PlanListResponse,
    PlanResponse,
    PlanUpdateRequest,
    UsageLimitCheckResponse,
    UsageMetricResponse,
    UsageSummaryResponse,
)
from .service import LicenseService, PlanService, UsageService, UsageValidationResult

router = APIRouter(tags=["Billing"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _feature_response(feature: PlanFeature) -> PlanFeatureResponse:
    return PlanFeatureResponse(
        id=str(feature.id),
        feature_key=feature.feature_key,
        feature_type=feature.feature_type,
        limit_value=feature.limit_value,
        is_enabled=feature.is_enabled,
        tier_value=feature.tier_value,
    )


def _plan_response(plan: Plan, features: list[PlanFeature]) -> PlanResponse:
    return PlanResponse(
        id=str(plan.id),
        name=plan.name,
        slug=plan.slug,
        plan_type=plan.plan_type,
        description=plan.description,
        billing_cycle=plan.billing_cycle,
        base_price=plan.base_price,
        currency=plan.currency,
        is_active=plan.is_active,
        is_public=plan.is_public,
        created_by_user_id=(
            str(plan.created_by_user_id) if plan.created_by_user_id else None
        ),
        sort_order=plan.sort_order,
        features=[_feature_response(feature) for feature in features],
        created_at=plan.created_at,
        updated_at=plan.updated_at,
    )


def _license_response(license_: License) -> LicenseResponse:
    return LicenseResponse(
        id=str(license_.id),
        organization_id=str(license_.organization_id),
        plan_id=str(license_.plan_id),
        status=license_.status,
        activated_at=license_.activated_at,
        expires_at=license_.expires_at,
        suspended_at=license_.suspended_at,
        suspended_reason=license_.suspended_reason,
        cancelled_at=license_.cancelled_at,
        created_at=license_.created_at,
        updated_at=license_.updated_at,
    )


def _change_log_response(entry: LicenseChangeLog) -> LicenseChangeLogResponse:
    return LicenseChangeLogResponse(
        id=str(entry.id),
        from_plan_id=str(entry.from_plan_id) if entry.from_plan_id else None,
        to_plan_id=str(entry.to_plan_id),
        change_type=entry.change_type,
        changed_at=entry.changed_at,
        changed_by_user_id=(
            str(entry.changed_by_user_id) if entry.changed_by_user_id else None
        ),
        reason=entry.reason,
    )


def _usage_summary_response(
    organization_id: uuid.UUID, result: UsageValidationResult
) -> UsageSummaryResponse:
    return UsageSummaryResponse(
        organization_id=str(organization_id),
        metrics=[
            UsageMetricResponse(
                metric_key=metric.metric_key,
                period_start=metric.period_start,
                period_end=metric.period_end,
                value=metric.value,
                recorded_at=metric.recorded_at,
            )
            for metric in result.metrics
        ],
        limit_checks=[
            UsageLimitCheckResponse(
                metric_key=check.metric_key,
                current_value=check.current_value,
                limit_value=check.limit_value,
                exceeded=check.exceeded,
            )
            for check in result.limit_checks
        ],
        any_limit_exceeded=result.any_limit_exceeded,
    )


# ============================================================================
# Plans
# ============================================================================


@router.post(
    "/plans",
    response_model=ApiResponse[PlanResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("billing.manage", scope=ScopeType.GLOBAL))],
)
async def create_plan(
    request: Request,
    payload: PlanCreateRequest,
    user: AuthUser = Depends(get_current_user),
    service: PlanService = Depends(get_plan_service),
):
    plan = await service.create_plan(
        actor_user_id=uuid.UUID(user.id),
        name=payload.name,
        slug=payload.slug,
        plan_type=payload.plan_type.value,
        description=payload.description,
        billing_cycle=payload.billing_cycle.value,
        base_price=payload.base_price,
        currency=payload.currency,
        is_active=payload.is_active,
        is_public=payload.is_public,
        sort_order=payload.sort_order,
        features=[feature.model_dump() for feature in payload.features],
    )
    features = await service.list_features(plan.id)
    return build_response(
        success=True,
        message="Plan created",
        data=_plan_response(plan, features).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/plans",
    response_model=ApiResponse[PlanListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.read"))],
)
async def list_plans(
    request: Request,
    include_private: bool = Query(default=False),
    is_active: bool | None = Query(default=True),
    plan_type: PlanType | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    user: AuthUser = Depends(get_current_user),
    access_validator: AccessValidator = Depends(get_access_validator),
    service: PlanService = Depends(get_plan_service),
):
    may_see_private = include_private and await access_validator.has_permission(
        uuid.UUID(user.id), "billing.manage", scope_type=ScopeType.GLOBAL
    )
    items, meta = await service.list_plans(
        page=page,
        page_size=page_size,
        include_private=may_see_private,
        is_active=is_active,
        plan_type=plan_type.value if plan_type else None,
    )
    responses = []
    for plan in items:
        features = await service.list_features(plan.id)
        responses.append(_plan_response(plan, features))
    payload = PlanListResponse(
        items=responses,
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Plans retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/plans/{plan_id}",
    response_model=ApiResponse[PlanResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.read"))],
)
async def get_plan(
    request: Request,
    plan_id: uuid.UUID,
    service: PlanService = Depends(get_plan_service),
):
    plan = await service.get_plan(plan_id)
    features = await service.list_features(plan_id)
    return build_response(
        success=True,
        message="Plan retrieved",
        data=_plan_response(plan, features).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.put(
    "/plans/{plan_id}",
    response_model=ApiResponse[PlanResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.update", scope=ScopeType.GLOBAL))],
)
async def update_plan(
    request: Request,
    plan_id: uuid.UUID,
    payload: PlanUpdateRequest,
    user: AuthUser = Depends(get_current_user),
    service: PlanService = Depends(get_plan_service),
):
    data = payload.model_dump(exclude_unset=True, exclude={"features"})
    if "billing_cycle" in data and payload.billing_cycle is not None:
        data["billing_cycle"] = payload.billing_cycle.value
    features = (
        [feature.model_dump() for feature in payload.features]
        if payload.features is not None
        else None
    )
    plan = await service.update_plan(
        actor_user_id=uuid.UUID(user.id),
        plan_id=plan_id,
        data=data,
        features=features,
    )
    result_features = await service.list_features(plan.id)
    return build_response(
        success=True,
        message="Plan updated",
        data=_plan_response(plan, result_features).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.delete(
    "/plans/{plan_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.manage", scope=ScopeType.GLOBAL))],
)
async def deactivate_plan(
    request: Request,
    plan_id: uuid.UUID,
    user: AuthUser = Depends(get_current_user),
    service: PlanService = Depends(get_plan_service),
):
    await service.deactivate_plan(actor_user_id=uuid.UUID(user.id), plan_id=plan_id)
    return build_response(
        success=True,
        message="Plan deactivated",
        data=MessageResponse(message="Plan deactivated").model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Licenses
# ============================================================================


@router.post(
    "/licenses",
    response_model=ApiResponse[LicenseResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("subscriptions.create"))],
)
async def assign_license(
    request: Request,
    payload: LicenseAssignRequest,
    user: AuthUser = Depends(get_current_user),
    service: LicenseService = Depends(get_license_service),
):
    license_ = await service.assign_license(
        actor_user_id=uuid.UUID(user.id),
        organization_id=payload.organization_id,
        plan_id=payload.plan_id,
        expires_at=payload.expires_at,
    )
    return build_response(
        success=True,
        message="License assigned",
        data=_license_response(license_).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/licenses/me",
    response_model=ApiResponse[LicenseResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("subscriptions.read"))],
)
async def get_my_license(
    request: Request,
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: LicenseService = Depends(get_license_service),
):
    license_ = await service.get_license_for_organization(organization_id)
    return build_response(
        success=True,
        message="License retrieved",
        data=_license_response(license_).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/licenses/{organization_id}",
    response_model=ApiResponse[LicenseResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("subscriptions.read"))],
)
async def get_license(
    request: Request,
    organization_id: uuid.UUID,
    service: LicenseService = Depends(get_license_service),
):
    license_ = await service.get_license_for_organization(organization_id)
    return build_response(
        success=True,
        message="License retrieved",
        data=_license_response(license_).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/licenses/{license_id}/history",
    response_model=ApiResponse[list[LicenseChangeLogResponse]],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("subscriptions.read"))],
)
async def get_license_history(
    request: Request,
    license_id: uuid.UUID,
    service: LicenseService = Depends(get_license_service),
):
    entries = await service.list_change_history(license_id)
    return build_response(
        success=True,
        message="License change history retrieved",
        data=[_change_log_response(entry).model_dump(mode="json") for entry in entries],
        request_id=_request_id(request),
    )


@router.post(
    "/licenses/{license_id}/activate",
    response_model=ApiResponse[LicenseResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("subscriptions.update"))],
)
async def activate_license(
    request: Request,
    license_id: uuid.UUID,
    user: AuthUser = Depends(get_current_user),
    service: LicenseService = Depends(get_license_service),
):
    license_ = await service.activate_license(
        actor_user_id=uuid.UUID(user.id), license_id=license_id
    )
    return build_response(
        success=True,
        message="License activated",
        data=_license_response(license_).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/licenses/{license_id}/suspend",
    response_model=ApiResponse[LicenseResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("subscriptions.update"))],
)
async def suspend_license(
    request: Request,
    license_id: uuid.UUID,
    payload: LicenseSuspendRequest,
    user: AuthUser = Depends(get_current_user),
    service: LicenseService = Depends(get_license_service),
):
    license_ = await service.suspend_license(
        actor_user_id=uuid.UUID(user.id), license_id=license_id, reason=payload.reason
    )
    return build_response(
        success=True,
        message="License suspended",
        data=_license_response(license_).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/licenses/{license_id}/cancel",
    response_model=ApiResponse[LicenseResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("subscriptions.update"))],
)
async def cancel_license(
    request: Request,
    license_id: uuid.UUID,
    user: AuthUser = Depends(get_current_user),
    service: LicenseService = Depends(get_license_service),
):
    license_ = await service.cancel_license(
        actor_user_id=uuid.UUID(user.id), license_id=license_id
    )
    return build_response(
        success=True,
        message="License cancelled",
        data=_license_response(license_).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/licenses/{license_id}/upgrade",
    response_model=ApiResponse[LicenseResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("subscriptions.update"))],
)
async def upgrade_license(
    request: Request,
    license_id: uuid.UUID,
    payload: LicenseUpgradeRequest,
    user: AuthUser = Depends(get_current_user),
    service: LicenseService = Depends(get_license_service),
):
    license_ = await service.upgrade_license(
        actor_user_id=uuid.UUID(user.id),
        license_id=license_id,
        new_plan_id=payload.new_plan_id,
        reason=payload.reason,
    )
    return build_response(
        success=True,
        message="License upgraded",
        data=_license_response(license_).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/licenses/{license_id}/downgrade",
    response_model=ApiResponse[LicenseResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("subscriptions.update"))],
)
async def downgrade_license(
    request: Request,
    license_id: uuid.UUID,
    payload: LicenseDowngradeRequest,
    user: AuthUser = Depends(get_current_user),
    service: LicenseService = Depends(get_license_service),
):
    license_ = await service.downgrade_license(
        actor_user_id=uuid.UUID(user.id),
        license_id=license_id,
        new_plan_id=payload.new_plan_id,
        reason=payload.reason,
    )
    return build_response(
        success=True,
        message="License downgraded",
        data=_license_response(license_).model_dump(mode="json"),
        request_id=_request_id(request),
    )


# ============================================================================
# Usage
# ============================================================================


@router.get(
    "/usage/{organization_id}",
    response_model=ApiResponse[UsageSummaryResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.read"))],
)
async def get_usage(
    request: Request,
    organization_id: uuid.UUID,
    service: UsageService = Depends(get_usage_service),
):
    result = await service.validate_usage_against_license(organization_id)
    return build_response(
        success=True,
        message="Usage retrieved",
        data=_usage_summary_response(organization_id, result).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/usage/{organization_id}/refresh",
    response_model=ApiResponse[UsageSummaryResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.update"))],
)
async def refresh_usage(
    request: Request,
    organization_id: uuid.UUID,
    service: UsageService = Depends(get_usage_service),
):
    await service.record_current_usage(organization_id)
    result = await service.validate_usage_against_license(organization_id)
    return build_response(
        success=True,
        message="Usage refreshed",
        data=_usage_summary_response(organization_id, result).model_dump(mode="json"),
        request_id=_request_id(request),
    )


__all__ = ["router"]
