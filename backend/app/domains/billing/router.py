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

## BE-013 Part 2 additions: Subscriptions + Coupons

* **Subscriptions** reuse ``subscriptions.*`` exactly like Licenses above:
  ``POST /subscriptions`` -> ``subscriptions.create``; ``GET
  /subscriptions/{organization_id}`` -> ``subscriptions.read``;
  ``cancel``/``reactivate``/``pause``/``resume`` -> ``subscriptions.update``
  (state transitions on an existing entity). No explicit ``scope=``
  override -- ordinary inferred, tenant-scoped resolution.
* **Coupons** reuse ``billing.*`` -- there is no dedicated coupon-shaped
  permission module, and a coupon is fundamentally a pricing-catalog
  concept (a discount against a ``Plan``'s price), the same category
  ``Plan`` itself already falls into. ``POST``/``PUT``/``DELETE`` (create/
  update/deactivate) use ``billing.manage``/``billing.update``/
  ``billing.manage`` pinned to ``scope=ScopeType.GLOBAL`` -- the exact same
  "only a Super-Admin-class, platform-scoped role may write the pricing
  catalog" rule Plans already establish above, since an uncontrolled coupon
  is a direct revenue-impacting instrument regardless of whether it is
  GLOBAL or organization-specific. Reads use ``billing.read``. ``POST
  /coupons/validate`` -- the no-side-effect, customer-facing checkout-time
  eligibility check -- instead uses ``subscriptions.read``: it is not a
  billing-catalog-admin action, it is the same kind of "read my own
  organization's subscription-relevant state" action ``GET /subscriptions/
  {organization_id}`` already is, just phrased as a check instead of a
  fetch.
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

from .constants import DiscountType, PlanType
from .dependencies import (
    get_coupon_service,
    get_license_service,
    get_plan_service,
    get_subscription_service,
    get_usage_service,
)
from .models import Coupon, License, LicenseChangeLog, Plan, PlanFeature, Subscription
from .schemas import (
    CouponCreateRequest,
    CouponListResponse,
    CouponResponse,
    CouponUpdateRequest,
    CouponValidateRequest,
    CouponValidateResponse,
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
    SubscriptionCancelRequest,
    SubscriptionCreateRequest,
    SubscriptionResponse,
    UsageLimitCheckResponse,
    UsageMetricResponse,
    UsageSummaryResponse,
)
from .service import (
    CouponService,
    LicenseService,
    PlanService,
    SubscriptionService,
    UsageService,
    UsageValidationResult,
)
from .validators import compute_discount_amount

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


def _subscription_response(subscription: Subscription) -> SubscriptionResponse:
    return SubscriptionResponse(
        id=str(subscription.id),
        organization_id=str(subscription.organization_id),
        license_id=str(subscription.license_id),
        plan_id=str(subscription.plan_id),
        status=subscription.status,
        billing_cycle=subscription.billing_cycle,
        current_period_start=subscription.current_period_start,
        current_period_end=subscription.current_period_end,
        trial_end=subscription.trial_end,
        auto_renew=subscription.auto_renew,
        cancel_at_period_end=subscription.cancel_at_period_end,
        started_at=subscription.started_at,
        cancelled_at=subscription.cancelled_at,
        applied_coupon_id=(
            str(subscription.applied_coupon_id)
            if subscription.applied_coupon_id
            else None
        ),
        created_at=subscription.created_at,
        updated_at=subscription.updated_at,
    )


def _coupon_response(
    coupon: Coupon, applicable_plan_ids: list[uuid.UUID]
) -> CouponResponse:
    return CouponResponse(
        id=str(coupon.id),
        code=coupon.code,
        discount_type=coupon.discount_type,
        discount_value=coupon.discount_value,
        currency=coupon.currency,
        organization_id=(
            str(coupon.organization_id) if coupon.organization_id else None
        ),
        max_uses=coupon.max_uses,
        current_uses=coupon.current_uses,
        valid_from=coupon.valid_from,
        valid_until=coupon.valid_until,
        is_active=coupon.is_active,
        applicable_plan_ids=[str(plan_id) for plan_id in applicable_plan_ids],
        created_at=coupon.created_at,
        updated_at=coupon.updated_at,
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


# ============================================================================
# Subscriptions (BE-013 Part 2)
# ============================================================================


@router.post(
    "/subscriptions",
    response_model=ApiResponse[SubscriptionResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("subscriptions.create"))],
)
async def create_subscription(
    request: Request,
    payload: SubscriptionCreateRequest,
    user: AuthUser = Depends(get_current_user),
    service: SubscriptionService = Depends(get_subscription_service),
):
    subscription = await service.create_subscription(
        actor_user_id=uuid.UUID(user.id),
        organization_id=payload.organization_id,
        plan_id=payload.plan_id,
        coupon_code=payload.coupon_code,
    )
    return build_response(
        success=True,
        message="Subscription created",
        data=_subscription_response(subscription).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/subscriptions/{organization_id}",
    response_model=ApiResponse[SubscriptionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("subscriptions.read"))],
)
async def get_subscription(
    request: Request,
    organization_id: uuid.UUID,
    service: SubscriptionService = Depends(get_subscription_service),
):
    subscription = await service.get_subscription_for_organization(organization_id)
    return build_response(
        success=True,
        message="Subscription retrieved",
        data=_subscription_response(subscription).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/subscriptions/{subscription_id}/cancel",
    response_model=ApiResponse[SubscriptionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("subscriptions.update"))],
)
async def cancel_subscription(
    request: Request,
    subscription_id: uuid.UUID,
    payload: SubscriptionCancelRequest,
    user: AuthUser = Depends(get_current_user),
    service: SubscriptionService = Depends(get_subscription_service),
):
    subscription = await service.cancel_subscription(
        actor_user_id=uuid.UUID(user.id),
        subscription_id=subscription_id,
        immediate=payload.immediate,
    )
    return build_response(
        success=True,
        message="Subscription cancelled",
        data=_subscription_response(subscription).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/subscriptions/{subscription_id}/reactivate",
    response_model=ApiResponse[SubscriptionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("subscriptions.update"))],
)
async def reactivate_subscription(
    request: Request,
    subscription_id: uuid.UUID,
    user: AuthUser = Depends(get_current_user),
    service: SubscriptionService = Depends(get_subscription_service),
):
    subscription = await service.reactivate_subscription(
        actor_user_id=uuid.UUID(user.id), subscription_id=subscription_id
    )
    return build_response(
        success=True,
        message="Subscription reactivated",
        data=_subscription_response(subscription).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/subscriptions/{subscription_id}/pause",
    response_model=ApiResponse[SubscriptionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("subscriptions.update"))],
)
async def pause_subscription(
    request: Request,
    subscription_id: uuid.UUID,
    user: AuthUser = Depends(get_current_user),
    service: SubscriptionService = Depends(get_subscription_service),
):
    subscription = await service.pause_subscription(
        actor_user_id=uuid.UUID(user.id), subscription_id=subscription_id
    )
    return build_response(
        success=True,
        message="Subscription paused",
        data=_subscription_response(subscription).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/subscriptions/{subscription_id}/resume",
    response_model=ApiResponse[SubscriptionResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("subscriptions.update"))],
)
async def resume_subscription(
    request: Request,
    subscription_id: uuid.UUID,
    user: AuthUser = Depends(get_current_user),
    service: SubscriptionService = Depends(get_subscription_service),
):
    subscription = await service.resume_subscription(
        actor_user_id=uuid.UUID(user.id), subscription_id=subscription_id
    )
    return build_response(
        success=True,
        message="Subscription resumed",
        data=_subscription_response(subscription).model_dump(mode="json"),
        request_id=_request_id(request),
    )


# ============================================================================
# Coupons (BE-013 Part 2)
# ============================================================================


@router.post(
    "/coupons",
    response_model=ApiResponse[CouponResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("billing.manage", scope=ScopeType.GLOBAL))],
)
async def create_coupon(
    request: Request,
    payload: CouponCreateRequest,
    user: AuthUser = Depends(get_current_user),
    service: CouponService = Depends(get_coupon_service),
):
    coupon = await service.create_coupon(
        actor_user_id=uuid.UUID(user.id),
        code=payload.code,
        discount_type=payload.discount_type.value,
        discount_value=payload.discount_value,
        currency=payload.currency,
        organization_id=payload.organization_id,
        max_uses=payload.max_uses,
        valid_from=payload.valid_from,
        valid_until=payload.valid_until,
        is_active=payload.is_active,
        applicable_plan_ids=payload.applicable_plan_ids,
    )
    plan_ids = await service.list_applicable_plan_ids(coupon.id)
    return build_response(
        success=True,
        message="Coupon created",
        data=_coupon_response(coupon, plan_ids).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/coupons",
    response_model=ApiResponse[CouponListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.read"))],
)
async def list_coupons(
    request: Request,
    organization_id: uuid.UUID | None = Query(default=None),
    is_active: bool | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    service: CouponService = Depends(get_coupon_service),
):
    items, meta = await service.list_coupons(
        page=page,
        page_size=page_size,
        organization_id=organization_id,
        is_active=is_active,
    )
    responses = []
    for coupon in items:
        plan_ids = await service.list_applicable_plan_ids(coupon.id)
        responses.append(_coupon_response(coupon, plan_ids))
    payload = CouponListResponse(
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
        message="Coupons retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/coupons/{coupon_id}",
    response_model=ApiResponse[CouponResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.read"))],
)
async def get_coupon(
    request: Request,
    coupon_id: uuid.UUID,
    service: CouponService = Depends(get_coupon_service),
):
    coupon = await service.get_coupon(coupon_id)
    plan_ids = await service.list_applicable_plan_ids(coupon.id)
    return build_response(
        success=True,
        message="Coupon retrieved",
        data=_coupon_response(coupon, plan_ids).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.put(
    "/coupons/{coupon_id}",
    response_model=ApiResponse[CouponResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.update", scope=ScopeType.GLOBAL))],
)
async def update_coupon(
    request: Request,
    coupon_id: uuid.UUID,
    payload: CouponUpdateRequest,
    user: AuthUser = Depends(get_current_user),
    service: CouponService = Depends(get_coupon_service),
):
    data = payload.model_dump(exclude_unset=True, exclude={"applicable_plan_ids"})
    if "discount_type" in data and payload.discount_type is not None:
        data["discount_type"] = payload.discount_type.value
    coupon = await service.update_coupon(
        actor_user_id=uuid.UUID(user.id),
        coupon_id=coupon_id,
        data=data,
        applicable_plan_ids=payload.applicable_plan_ids,
    )
    plan_ids = await service.list_applicable_plan_ids(coupon.id)
    return build_response(
        success=True,
        message="Coupon updated",
        data=_coupon_response(coupon, plan_ids).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.delete(
    "/coupons/{coupon_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.manage", scope=ScopeType.GLOBAL))],
)
async def deactivate_coupon(
    request: Request,
    coupon_id: uuid.UUID,
    user: AuthUser = Depends(get_current_user),
    service: CouponService = Depends(get_coupon_service),
):
    await service.deactivate_coupon(
        actor_user_id=uuid.UUID(user.id), coupon_id=coupon_id
    )
    return build_response(
        success=True,
        message="Coupon deactivated",
        data=MessageResponse(message="Coupon deactivated").model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/coupons/validate",
    response_model=ApiResponse[CouponValidateResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("subscriptions.read"))],
)
async def validate_coupon(
    request: Request,
    payload: CouponValidateRequest,
    service: CouponService = Depends(get_coupon_service),
):
    """Real-time, no-side-effect eligibility check a checkout UI calls
    before actually applying a coupon -- writes no ``CouponUsage`` row and
    never increments ``current_uses`` (see ``CouponService.validate_coupon``
    vs. its mutating counterpart, ``apply_coupon``)."""
    coupon = await service.validate_coupon(
        code=payload.code,
        organization_id=payload.organization_id,
        plan_id=payload.plan_id,
    )
    estimated_discount = None
    if payload.base_amount is not None:
        estimated_discount = compute_discount_amount(
            discount_type=DiscountType(coupon.discount_type),
            discount_value=coupon.discount_value,
            base_amount=payload.base_amount,
        )
    response = CouponValidateResponse(
        valid=True,
        code=coupon.code,
        discount_type=coupon.discount_type,
        discount_value=coupon.discount_value,
        currency=coupon.currency,
        estimated_discount_amount=estimated_discount,
    )
    return build_response(
        success=True,
        message="Coupon is valid",
        data=response.model_dump(mode="json"),
        request_id=_request_id(request),
    )


__all__ = ["router"]
