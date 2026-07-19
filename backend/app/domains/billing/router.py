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

## BE-013 Part 3 additions: Payments + Payment Methods + Webhooks

* **Payments** reuse ``billing.*`` -- a payment is fundamentally a
  billing-admin action with no dedicated ``create``/``delete`` seeded
  action (the same "reuse the closest seeded action" precedent Plans/
  Coupons already establish above): ``POST /payments`` (initiate) ->
  ``billing.manage``; ``POST /payments/{id}/refund``/``POST
  /payments/{id}/retry`` -> ``billing.manage`` (both are consequential,
  revenue-impacting writes); every read -> ``billing.read``. No
  ``scope=ScopeType.GLOBAL`` pin -- unlike the platform-wide pricing
  catalog (Plans/Coupons), a ``Payment`` is a real, tenant-owned resource
  (``organization_id`` on every row), so ordinary inferred, tenant-scoped
  resolution applies, exactly like Licenses/Subscriptions. ``GET
  /payments``/``GET /payments/{id}`` both additionally enforce real tenant
  isolation in the service layer (``PaymentService.get_payment``'s
  ``organization_id`` filter, resolved from the caller's ``X-Organization-
  Id`` header via ``RequireOrganization``) -- a payment belonging to a
  different organization reports as not-found, never leaking its
  existence.
* **Payment Methods** reuse ``billing.*`` identically: register/remove ->
  ``billing.manage`` (a tokenized-reference write, security-sensitive);
  list -> ``billing.read``. ``POST``/``GET /payments/methods`` and
  ``DELETE /payments/methods/{id}`` are registered **before**
  ``GET /payments/{payment_id}``/its siblings in this file -- mirrors
  ``GET /licenses/me``'s identical "the more specific literal path must be
  registered before the wildcard path it could otherwise be shadowed by"
  ordering requirement already established above in this same router.
* **Webhooks** (``POST /webhooks/stripe``/``POST /webhooks/razorpay``) are
  **provider-authenticated via real HMAC-SHA256 signature verification,
  not RBAC** -- the identical "no platform-user identity for this caller"
  reasoning BE-008's device check-in and BE-010's RADIUS endpoints already
  establish for a non-human caller this codebase still must accept
  requests from. Raw request bodies are read via ``await request.body()``
  (never a Pydantic-parsed body model, since signature verification
  covers the exact raw bytes) and passed through
  ``webhooks.verify_stripe_event``/``webhooks.verify_razorpay_signature``
  before any processing. Response shape: a plain ``{"received": True}``
  dict on success (status ``200``) -- not the standard ``ApiResponse``
  envelope, since neither provider parses the response body at all, only
  the status code, and Stripe's own documented example payload is exactly
  this shape. An invalid signature raises ``WebhookSignatureInvalidError``
  (a real ``CloudGuestError`` -- ``400``, rendered via the same global
  exception handler every other domain's errors already go through, since
  there is no reason for this one error case to bypass that uniform
  machinery). Any *other* unhandled exception during processing propagates
  to a ``500`` -- a deliberate choice: both providers' own real retry
  policies re-deliver on a ``5xx``, which is exactly the right behavior
  for a genuine, possibly-transient internal failure (a database blip),
  whereas a permanently-invalid signature (``400``) is correctly never
  retried into succeeding.
"""

from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, Query, Request, Response, status

from app.common.responses import ApiResponse, build_response
from app.core.config import Settings, get_settings
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

from .constants import DiscountType, InvoiceStatus, PaymentStatus, PlanType
from .dependencies import (
    get_billing_profile_service,
    get_coupon_service,
    get_invoice_service,
    get_license_service,
    get_payment_method_service,
    get_payment_repository,
    get_payment_service,
    get_plan_service,
    get_renewal_service,
    get_subscription_service,
    get_tax_rate_service,
    get_usage_service,
    get_webhook_event_dedup,
)
from .exceptions import WebhookSignatureInvalidError
from .invoice_pdf import SellerInfo, render_invoice_pdf
from .models import (
    BillingProfile,
    Coupon,
    CreditDebitNote,
    Invoice,
    InvoiceItem,
    License,
    LicenseChangeLog,
    Payment,
    PaymentMethod,
    Plan,
    PlanFeature,
    Subscription,
    TaxRate,
)
from .renewal_service import RenewalService
from .repository import PaymentRepositoryProtocol
from .schemas import (
    BillingProfileResponse,
    BillingProfileUpsertRequest,
    CouponCreateRequest,
    CouponListResponse,
    CouponResponse,
    CouponUpdateRequest,
    CouponValidateRequest,
    CouponValidateResponse,
    CreditDebitNoteResponse,
    CreditNoteIssueRequest,
    DebitNoteIssueRequest,
    InvoiceItemResponse,
    InvoiceListResponse,
    InvoiceResponse,
    LicenseAssignRequest,
    LicenseChangeLogResponse,
    LicenseDowngradeRequest,
    LicenseResponse,
    LicenseSuspendRequest,
    LicenseUpgradeRequest,
    PaymentInitiateRequest,
    PaymentListResponse,
    PaymentMethodListResponse,
    PaymentMethodRegisterRequest,
    PaymentMethodResponse,
    PaymentRefundRequest,
    PaymentResponse,
    PlanCreateRequest,
    PlanFeatureResponse,
    PlanListResponse,
    PlanResponse,
    PlanUpdateRequest,
    SubscriptionCancelRequest,
    SubscriptionCreateRequest,
    SubscriptionResponse,
    TaxRateCreateRequest,
    TaxRateListResponse,
    TaxRateResponse,
    TaxRateUpdateRequest,
    UsageLimitCheckResponse,
    UsageMetricResponse,
    UsageSummaryResponse,
)
from .service import (
    BillingProfileService,
    CouponService,
    InvoiceService,
    LicenseService,
    PaymentMethodService,
    PaymentService,
    PlanService,
    SubscriptionService,
    TaxRateService,
    UsageService,
    UsageValidationResult,
)
from .validators import compute_discount_amount
from .webhooks import (
    WebhookEventDedupProtocol,
    log_signature_failure,
    process_razorpay_event,
    process_stripe_event,
    verify_razorpay_signature,
    verify_stripe_event,
)

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


# ============================================================================
# Payments (BE-013 Part 3) -- see module docstring for the full RBAC/scope
# write-up.
# ============================================================================


def _payment_response(payment: Payment) -> PaymentResponse:
    return PaymentResponse(
        id=str(payment.id),
        organization_id=str(payment.organization_id),
        subscription_id=(
            str(payment.subscription_id) if payment.subscription_id else None
        ),
        amount=payment.amount,
        currency=payment.currency,
        status=payment.status,
        provider=payment.provider,
        provider_payment_id=payment.provider_payment_id,
        idempotency_key=payment.idempotency_key,
        failure_reason=payment.failure_reason,
        refunded_amount=payment.refunded_amount,
        created_at=payment.created_at,
        updated_at=payment.updated_at,
    )


def _payment_method_response(payment_method: PaymentMethod) -> PaymentMethodResponse:
    return PaymentMethodResponse(
        id=str(payment_method.id),
        organization_id=str(payment_method.organization_id),
        provider=payment_method.provider,
        provider_payment_method_id=payment_method.provider_payment_method_id,
        method_type=payment_method.method_type,
        last4=payment_method.last4,
        is_default=payment_method.is_default,
        is_active=payment_method.is_active,
        created_at=payment_method.created_at,
        updated_at=payment_method.updated_at,
    )


@router.post(
    "/payments",
    response_model=ApiResponse[PaymentResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("billing.manage"))],
)
async def initiate_payment(
    request: Request,
    payload: PaymentInitiateRequest,
    user: AuthUser = Depends(get_current_user),
    service: PaymentService = Depends(get_payment_service),
):
    payment = await service.initiate_payment(
        actor_user_id=uuid.UUID(user.id),
        organization_id=payload.organization_id,
        subscription_id=payload.subscription_id,
        amount=payload.amount,
        currency=payload.currency,
        provider=payload.provider.value,
        idempotency_key=payload.idempotency_key,
    )
    return build_response(
        success=True,
        message="Payment initiated",
        data=_payment_response(payment).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/payments",
    response_model=ApiResponse[PaymentListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.read"))],
)
async def list_payments(
    request: Request,
    organization_id: uuid.UUID = Depends(RequireOrganization),
    status_filter: PaymentStatus | None = Query(default=None, alias="status"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    service: PaymentService = Depends(get_payment_service),
):
    items, meta = await service.list_payments(
        page=page,
        page_size=page_size,
        organization_id=organization_id,
        status=status_filter.value if status_filter else None,
    )
    payload = PaymentListResponse(
        items=[_payment_response(payment) for payment in items],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Payments retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


# ----------------------------------------------------------------------------
# Payment Methods -- registered BEFORE /payments/{payment_id} below; see
# module docstring for why (mirrors /licenses/me's identical ordering
# requirement).
# ----------------------------------------------------------------------------


@router.post(
    "/payments/methods",
    response_model=ApiResponse[PaymentMethodResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("billing.manage"))],
)
async def register_payment_method(
    request: Request,
    payload: PaymentMethodRegisterRequest,
    user: AuthUser = Depends(get_current_user),
    service: PaymentMethodService = Depends(get_payment_method_service),
):
    payment_method = await service.register_payment_method(
        actor_user_id=uuid.UUID(user.id),
        organization_id=payload.organization_id,
        provider=payload.provider.value,
        provider_payment_method_id=payload.provider_payment_method_id,
        method_type=payload.method_type.value,
        last4=payload.last4,
        is_default=payload.is_default,
    )
    return build_response(
        success=True,
        message="Payment method registered",
        data=_payment_method_response(payment_method).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/payments/methods",
    response_model=ApiResponse[PaymentMethodListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.read"))],
)
async def list_payment_methods(
    request: Request,
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: PaymentMethodService = Depends(get_payment_method_service),
):
    items = await service.list_payment_methods(organization_id)
    payload = PaymentMethodListResponse(
        items=[_payment_method_response(payment_method) for payment_method in items]
    )
    return build_response(
        success=True,
        message="Payment methods retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.delete(
    "/payments/methods/{payment_method_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.manage"))],
)
async def remove_payment_method(
    request: Request,
    payment_method_id: uuid.UUID,
    user: AuthUser = Depends(get_current_user),
    service: PaymentMethodService = Depends(get_payment_method_service),
):
    await service.remove_payment_method(
        actor_user_id=uuid.UUID(user.id), payment_method_id=payment_method_id
    )
    return build_response(
        success=True,
        message="Payment method removed",
        data=MessageResponse(message="Payment method removed").model_dump(),
        request_id=_request_id(request),
    )


# ----------------------------------------------------------------------------
# /payments/{payment_id} and its sub-actions -- see the ordering note above.
# ----------------------------------------------------------------------------


@router.get(
    "/payments/{payment_id}",
    response_model=ApiResponse[PaymentResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.read"))],
)
async def get_payment(
    request: Request,
    payment_id: uuid.UUID,
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: PaymentService = Depends(get_payment_service),
):
    payment = await service.get_payment(payment_id, organization_id=organization_id)
    return build_response(
        success=True,
        message="Payment retrieved",
        data=_payment_response(payment).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/payments/{payment_id}/refund",
    response_model=ApiResponse[PaymentResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.manage"))],
)
async def refund_payment(
    request: Request,
    payment_id: uuid.UUID,
    payload: PaymentRefundRequest,
    user: AuthUser = Depends(get_current_user),
    service: PaymentService = Depends(get_payment_service),
):
    payment = await service.refund_payment(
        actor_user_id=uuid.UUID(user.id), payment_id=payment_id, amount=payload.amount
    )
    return build_response(
        success=True,
        message="Payment refunded",
        data=_payment_response(payment).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/payments/{payment_id}/retry",
    response_model=ApiResponse[PaymentResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.manage"))],
)
async def retry_payment(
    request: Request,
    payment_id: uuid.UUID,
    user: AuthUser = Depends(get_current_user),
    service: PaymentService = Depends(get_payment_service),
):
    payment = await service.retry_failed_payment(
        actor_user_id=uuid.UUID(user.id), payment_id=payment_id
    )
    return build_response(
        success=True,
        message="Payment retried",
        data=_payment_response(payment).model_dump(mode="json"),
        request_id=_request_id(request),
    )


# ============================================================================
# Webhooks (BE-013 Part 3) -- provider-authenticated via real signature
# verification, NOT RBAC. See module docstring for the full write-up.
# ============================================================================


@router.post("/webhooks/stripe", status_code=status.HTTP_200_OK)
async def stripe_webhook(
    request: Request,
    settings: Settings = Depends(get_settings),
    payment_repository: PaymentRepositoryProtocol = Depends(get_payment_repository),
    renewal_service: RenewalService = Depends(get_renewal_service),
    dedup: WebhookEventDedupProtocol = Depends(get_webhook_event_dedup),
    invoice_service: InvoiceService = Depends(get_invoice_service),
):
    payload = await request.body()
    signature_header = request.headers.get("stripe-signature", "")
    try:
        event = verify_stripe_event(
            payload,
            signature_header=signature_header,
            secret=settings.stripe_webhook_secret,
            tolerance_seconds=settings.stripe_webhook_tolerance_seconds,
        )
    except WebhookSignatureInvalidError as exc:
        log_signature_failure("stripe", str(exc))
        raise
    await process_stripe_event(
        event,
        payment_repository=payment_repository,
        renewal_service=renewal_service,
        dedup=dedup,
        invoice_service=invoice_service,
    )
    return {"received": True}


@router.post("/webhooks/razorpay", status_code=status.HTTP_200_OK)
async def razorpay_webhook(
    request: Request,
    settings: Settings = Depends(get_settings),
    payment_repository: PaymentRepositoryProtocol = Depends(get_payment_repository),
    renewal_service: RenewalService = Depends(get_renewal_service),
    dedup: WebhookEventDedupProtocol = Depends(get_webhook_event_dedup),
    invoice_service: InvoiceService = Depends(get_invoice_service),
):
    payload = await request.body()
    signature = request.headers.get("x-razorpay-signature", "")
    try:
        verify_razorpay_signature(
            payload, signature=signature, secret=settings.razorpay_webhook_secret
        )
    except WebhookSignatureInvalidError as exc:
        log_signature_failure("razorpay", str(exc))
        raise
    body = json.loads(payload or b"{}")
    body["_event_id"] = request.headers.get("x-razorpay-event-id", "")
    await process_razorpay_event(
        body,
        payment_repository=payment_repository,
        renewal_service=renewal_service,
        dedup=dedup,
        invoice_service=invoice_service,
    )
    return {"received": True}


# ============================================================================
# BE-013 Part 4: Invoice Engine + Tax/GST
#
# ## RBAC permission-key reuse
#
# ``PermissionModule.INVOICES`` (seeded since BE-004: create/read/update/
# delete/export/approve/manage) covers every ``/invoices`` endpoint below --
# ``invoices.read`` for every read (including the PDF download, which is
# fundamentally an export of an already-generated invoice's own content --
# ``invoices.export`` is the seeded action this maps to precisely);
# ``invoices.manage`` for every consequential financial write (void, credit
# note, debit note) -- the same "reuse the closest seeded action for a
# consequential write" precedent Payments' own refund/retry already
# establish via ``billing.manage``. None of these endpoints enforce
# tenant-organization matching against the caller's own scope context --
# mirrors ``POST /payments/{id}/refund``/``retry``'s identical "an admin
# action operating directly on the entity by id" precedent (only the
# *read*-side ``GET /invoices``/``GET /invoices/{id}`` enforce real tenant
# isolation, via ``RequireOrganization`` + the service layer's own
# ``organization_id`` filter). Tax rates (``/billing/tax-rates``) and the
# organization's own billing profile (``/billing/profile``) reuse
# ``billing.*`` exactly like Plans/Coupons/Payments before them: tax rates
# are a platform-wide pricing/tax catalog concern, pinned to
# ``scope=ScopeType.GLOBAL`` for writes (mirrors Plans/Coupons); the billing
# profile is a real, tenant-owned resource (ordinary inferred scope, no
# GLOBAL pin), mirroring Payments/PaymentMethods.
# ============================================================================


def _invoice_item_response(item: InvoiceItem) -> InvoiceItemResponse:
    return InvoiceItemResponse(
        id=str(item.id),
        description=item.description,
        quantity=item.quantity,
        unit_price=item.unit_price,
        amount=item.amount,
    )


def _note_response(note: CreditDebitNote) -> CreditDebitNoteResponse:
    return CreditDebitNoteResponse(
        id=str(note.id),
        invoice_id=str(note.invoice_id),
        note_type=note.note_type,
        note_number=note.note_number,
        amount=note.amount,
        reason=note.reason,
        issued_at=note.issued_at,
    )


def _invoice_response(
    invoice: Invoice, items: list[InvoiceItem], notes: list[CreditDebitNote]
) -> InvoiceResponse:
    return InvoiceResponse(
        id=str(invoice.id),
        organization_id=str(invoice.organization_id),
        subscription_id=(
            str(invoice.subscription_id) if invoice.subscription_id else None
        ),
        payment_id=str(invoice.payment_id) if invoice.payment_id else None,
        invoice_number=invoice.invoice_number,
        status=invoice.status,
        issue_date=invoice.issue_date,
        due_date=invoice.due_date,
        subtotal=invoice.subtotal,
        cgst_amount=invoice.cgst_amount,
        sgst_amount=invoice.sgst_amount,
        igst_amount=invoice.igst_amount,
        tax_amount=invoice.tax_amount,
        tax_rate_percentage=invoice.tax_rate_percentage,
        total_amount=invoice.total_amount,
        currency=invoice.currency,
        billing_snapshot=invoice.billing_snapshot,
        items=[_invoice_item_response(item) for item in items],
        notes=[_note_response(note) for note in notes],
        created_at=invoice.created_at,
        updated_at=invoice.updated_at,
    )


def _tax_rate_response(tax_rate: TaxRate) -> TaxRateResponse:
    return TaxRateResponse(
        id=str(tax_rate.id),
        name=tax_rate.name,
        tax_type=tax_rate.tax_type,
        rate_percentage=tax_rate.rate_percentage,
        country_code=tax_rate.country_code,
        is_active=tax_rate.is_active,
        created_at=tax_rate.created_at,
        updated_at=tax_rate.updated_at,
    )


def _billing_profile_response(profile: BillingProfile) -> BillingProfileResponse:
    return BillingProfileResponse(
        id=str(profile.id),
        organization_id=str(profile.organization_id),
        billing_name=profile.billing_name,
        billing_address_line1=profile.billing_address_line1,
        billing_address_line2=profile.billing_address_line2,
        billing_city=profile.billing_city,
        billing_state=profile.billing_state,
        billing_country=profile.billing_country,
        billing_postal_code=profile.billing_postal_code,
        gst_identifier=profile.gst_identifier,
        tax_exempt=profile.tax_exempt,
        created_at=profile.created_at,
        updated_at=profile.updated_at,
    )


@router.get(
    "/invoices",
    response_model=ApiResponse[InvoiceListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("invoices.read"))],
)
async def list_invoices(
    request: Request,
    organization_id: uuid.UUID = Depends(RequireOrganization),
    status_filter: InvoiceStatus | None = Query(default=None, alias="status"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    service: InvoiceService = Depends(get_invoice_service),
):
    items, meta = await service.list_invoices(
        page=page,
        page_size=page_size,
        organization_id=organization_id,
        status=status_filter.value if status_filter else None,
    )
    responses = []
    for invoice in items:
        line_items = await service.list_items(invoice.id)
        notes = await service.list_notes(invoice.id)
        responses.append(_invoice_response(invoice, line_items, notes))
    payload = InvoiceListResponse(
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
        message="Invoices retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/invoices/{invoice_id}",
    response_model=ApiResponse[InvoiceResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("invoices.read"))],
)
async def get_invoice(
    request: Request,
    invoice_id: uuid.UUID,
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: InvoiceService = Depends(get_invoice_service),
):
    invoice = await service.get_invoice(invoice_id, organization_id=organization_id)
    items = await service.list_items(invoice.id)
    notes = await service.list_notes(invoice.id)
    return build_response(
        success=True,
        message="Invoice retrieved",
        data=_invoice_response(invoice, items, notes).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/invoices/{invoice_id}/download",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("invoices.export"))],
)
async def download_invoice(
    invoice_id: uuid.UUID,
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: InvoiceService = Depends(get_invoice_service),
    settings: Settings = Depends(get_settings),
):
    """Returns the real, rendered invoice PDF -- ``reportlab``-generated
    bytes, not the standard ``ApiResponse`` envelope (a file download, the
    same "raw bytes + Content-Type/Content-Disposition" shape
    ``app.domains.analytics.report_router``'s own export-download endpoint
    already establishes for this codebase)."""
    invoice = await service.get_invoice(invoice_id, organization_id=organization_id)
    items = await service.list_items(invoice.id)
    notes = await service.list_notes(invoice.id)
    seller = SellerInfo(
        legal_business_name=settings.platform_legal_business_name,
        gstin=settings.platform_gstin,
        state=settings.platform_gst_state,
        country=settings.platform_gst_country,
    )
    pdf_bytes = render_invoice_pdf(invoice, items, seller=seller, notes=notes)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{invoice.invoice_number}.pdf"'
            )
        },
    )


@router.post(
    "/invoices/{invoice_id}/void",
    response_model=ApiResponse[InvoiceResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("invoices.manage"))],
)
async def void_invoice(
    request: Request,
    invoice_id: uuid.UUID,
    user: AuthUser = Depends(get_current_user),
    service: InvoiceService = Depends(get_invoice_service),
):
    invoice = await service.void_invoice(
        actor_user_id=uuid.UUID(user.id), invoice_id=invoice_id
    )
    items = await service.list_items(invoice.id)
    notes = await service.list_notes(invoice.id)
    return build_response(
        success=True,
        message="Invoice voided",
        data=_invoice_response(invoice, items, notes).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/invoices/{invoice_id}/credit-note",
    response_model=ApiResponse[CreditDebitNoteResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("invoices.manage"))],
)
async def issue_credit_note(
    request: Request,
    invoice_id: uuid.UUID,
    payload: CreditNoteIssueRequest,
    user: AuthUser = Depends(get_current_user),
    service: InvoiceService = Depends(get_invoice_service),
):
    note = await service.issue_credit_note(
        actor_user_id=uuid.UUID(user.id),
        invoice_id=invoice_id,
        amount=payload.amount,
        reason=payload.reason,
    )
    return build_response(
        success=True,
        message="Credit note issued",
        data=_note_response(note).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/invoices/{invoice_id}/debit-note",
    response_model=ApiResponse[CreditDebitNoteResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("invoices.manage"))],
)
async def issue_debit_note(
    request: Request,
    invoice_id: uuid.UUID,
    payload: DebitNoteIssueRequest,
    user: AuthUser = Depends(get_current_user),
    service: InvoiceService = Depends(get_invoice_service),
):
    note = await service.issue_debit_note(
        actor_user_id=uuid.UUID(user.id),
        invoice_id=invoice_id,
        amount=payload.amount,
        reason=payload.reason,
    )
    return build_response(
        success=True,
        message="Debit note issued",
        data=_note_response(note).model_dump(mode="json"),
        request_id=_request_id(request),
    )


# ----------------------------------------------------------------------------
# Tax rates -- Super Admin "Manage Taxes" (platform-wide, GLOBAL-pinned,
# mirrors Plans/Coupons above).
# ----------------------------------------------------------------------------


@router.post(
    "/billing/tax-rates",
    response_model=ApiResponse[TaxRateResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("billing.manage", scope=ScopeType.GLOBAL))],
)
async def create_tax_rate(
    request: Request,
    payload: TaxRateCreateRequest,
    user: AuthUser = Depends(get_current_user),
    service: TaxRateService = Depends(get_tax_rate_service),
):
    tax_rate = await service.create_tax_rate(
        actor_user_id=uuid.UUID(user.id),
        name=payload.name,
        tax_type=payload.tax_type.value,
        rate_percentage=payload.rate_percentage,
        country_code=payload.country_code,
        is_active=payload.is_active,
    )
    return build_response(
        success=True,
        message="Tax rate created",
        data=_tax_rate_response(tax_rate).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/billing/tax-rates",
    response_model=ApiResponse[TaxRateListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.read"))],
)
async def list_tax_rates(
    request: Request,
    country_code: str | None = Query(default=None, min_length=2, max_length=2),
    is_active: bool | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    service: TaxRateService = Depends(get_tax_rate_service),
):
    items, meta = await service.list_tax_rates(
        page=page, page_size=page_size, country_code=country_code, is_active=is_active
    )
    payload = TaxRateListResponse(
        items=[_tax_rate_response(tax_rate) for tax_rate in items],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Tax rates retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.put(
    "/billing/tax-rates/{tax_rate_id}",
    response_model=ApiResponse[TaxRateResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.update", scope=ScopeType.GLOBAL))],
)
async def update_tax_rate(
    request: Request,
    tax_rate_id: uuid.UUID,
    payload: TaxRateUpdateRequest,
    user: AuthUser = Depends(get_current_user),
    service: TaxRateService = Depends(get_tax_rate_service),
):
    data = payload.model_dump(exclude_unset=True)
    if "tax_type" in data and payload.tax_type is not None:
        data["tax_type"] = payload.tax_type.value
    tax_rate = await service.update_tax_rate(
        actor_user_id=uuid.UUID(user.id), tax_rate_id=tax_rate_id, data=data
    )
    return build_response(
        success=True,
        message="Tax rate updated",
        data=_tax_rate_response(tax_rate).model_dump(mode="json"),
        request_id=_request_id(request),
    )


# ----------------------------------------------------------------------------
# Billing profile -- an organization's own billing address/GSTIN. Registered
# BEFORE /billing/tax-rates has no path-shape overlap, but /billing/profile/me
# must still be registered before /billing/profile/{organization_id} -- the
# same literal-before-wildcard ordering requirement /licenses/me establishes.
# ----------------------------------------------------------------------------


@router.post(
    "/billing/profile",
    response_model=ApiResponse[BillingProfileResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.update"))],
)
async def upsert_billing_profile(
    request: Request,
    payload: BillingProfileUpsertRequest,
    user: AuthUser = Depends(get_current_user),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: BillingProfileService = Depends(get_billing_profile_service),
):
    profile = await service.upsert_billing_profile(
        actor_user_id=uuid.UUID(user.id),
        organization_id=organization_id,
        billing_name=payload.billing_name,
        billing_address_line1=payload.billing_address_line1,
        billing_address_line2=payload.billing_address_line2,
        billing_city=payload.billing_city,
        billing_state=payload.billing_state,
        billing_country=payload.billing_country,
        billing_postal_code=payload.billing_postal_code,
        gst_identifier=payload.gst_identifier,
        tax_exempt=payload.tax_exempt,
    )
    return build_response(
        success=True,
        message="Billing profile saved",
        data=_billing_profile_response(profile).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/billing/profile/me",
    response_model=ApiResponse[BillingProfileResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.read"))],
)
async def get_my_billing_profile(
    request: Request,
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: BillingProfileService = Depends(get_billing_profile_service),
):
    profile = await service.get_billing_profile(organization_id)
    return build_response(
        success=True,
        message="Billing profile retrieved",
        data=_billing_profile_response(profile).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/billing/profile/{organization_id}",
    response_model=ApiResponse[BillingProfileResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("billing.read"))],
)
async def get_billing_profile(
    request: Request,
    organization_id: uuid.UUID,
    service: BillingProfileService = Depends(get_billing_profile_service),
):
    profile = await service.get_billing_profile(organization_id)
    return build_response(
        success=True,
        message="Billing profile retrieved",
        data=_billing_profile_response(profile).model_dump(mode="json"),
        request_id=_request_id(request),
    )


__all__ = ["router"]
