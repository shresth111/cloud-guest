"""Pydantic request/response schemas for the Billing API.

All response schemas follow the same pydantic v2 conventions as every other
domain (``ConfigDict``, ``from_attributes``, explicit ``Field``
descriptions) and are wrapped in the project's standard
``ApiResponse``/``build_response`` envelope by ``router.py``.

Money (``Plan.base_price``) and usage (``UsageMetric.value``,
``PlanFeature.limit_value``) fields are typed ``Decimal`` throughout, never
``float`` -- pydantic v2 serializes ``Decimal`` to a JSON string by default
(``model_dump(mode="json")``), preserving exact precision end to end.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from .constants import (
    BillingCycle,
    DiscountType,
    InvoiceStatus,
    LicenseChangeType,
    LicenseStatus,
    NoteType,
    PaymentMethodType,
    PaymentProvider,
    PaymentStatus,
    PlanFeatureKey,
    PlanFeatureType,
    PlanType,
    SubscriptionStatus,
    TaxType,
    UsageMetricKey,
)

__all__ = [
    "PlanFeatureCreateRequest",
    "PlanCreateRequest",
    "PlanUpdateRequest",
    "PlanFeatureResponse",
    "PlanResponse",
    "PlanListResponse",
    "LicenseAssignRequest",
    "LicenseSuspendRequest",
    "LicenseUpgradeRequest",
    "LicenseDowngradeRequest",
    "LicenseChangeLogResponse",
    "LicenseResponse",
    "UsageMetricResponse",
    "UsageLimitCheckResponse",
    "UsageSummaryResponse",
    "SubscriptionCreateRequest",
    "SubscriptionCancelRequest",
    "SubscriptionResponse",
    "CouponCreateRequest",
    "CouponUpdateRequest",
    "CouponResponse",
    "CouponListResponse",
    "CouponValidateRequest",
    "CouponValidateResponse",
    "PaymentInitiateRequest",
    "PaymentRefundRequest",
    "PaymentResponse",
    "PaymentListResponse",
    "PaymentMethodRegisterRequest",
    "PaymentMethodResponse",
    "PaymentMethodListResponse",
    "TaxRateCreateRequest",
    "TaxRateUpdateRequest",
    "TaxRateResponse",
    "TaxRateListResponse",
    "BillingProfileUpsertRequest",
    "BillingProfileResponse",
    "InvoiceItemResponse",
    "CreditDebitNoteResponse",
    "CreditNoteIssueRequest",
    "DebitNoteIssueRequest",
    "InvoiceResponse",
    "InvoiceListResponse",
    "SubscriptionRenewalSettingsUpdateRequest",
    "RevenueTrendPointResponse",
    "SuperAdminRevenueDashboardResponse",
    "ChurnRateResponse",
    "SuperAdminSubscriptionDashboardResponse",
    "CustomerBillingSummaryRowResponse",
    "SuperAdminCustomerBillingDashboardResponse",
    "FailedPaymentRowResponse",
    "SuperAdminFailedPaymentsDashboardResponse",
    "SuperAdminBillingDashboardResponse",
    "CustomerBillingDashboardResponse",
]


# ============================================================================
# Plan / PlanFeature
# ============================================================================


class PlanFeatureCreateRequest(BaseModel):
    feature_key: PlanFeatureKey
    feature_type: PlanFeatureType
    limit_value: Decimal | None = Field(default=None, ge=0)
    is_enabled: bool | None = None
    tier_value: str | None = None


class PlanCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=200)
    slug: str = Field(..., min_length=2, max_length=150)
    plan_type: PlanType
    description: str | None = Field(default=None, max_length=2000)
    billing_cycle: BillingCycle = BillingCycle.MONTHLY
    base_price: Decimal = Field(..., ge=0)
    currency: str = Field(default="USD", min_length=3, max_length=3)
    is_active: bool = True
    is_public: bool = True
    sort_order: int = 0
    features: list[PlanFeatureCreateRequest] = Field(default_factory=list)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Professional",
                "slug": "professional",
                "plan_type": "professional",
                "description": "For growing multi-location deployments.",
                "billing_cycle": "monthly",
                "base_price": "199.00",
                "currency": "USD",
                "is_active": True,
                "is_public": True,
                "sort_order": 3,
                "features": [
                    {
                        "feature_key": "max_locations",
                        "feature_type": "limit",
                        "limit_value": "10",
                    },
                    {
                        "feature_key": "white_label",
                        "feature_type": "boolean",
                        "is_enabled": True,
                    },
                ],
            }
        }
    )


class PlanUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    billing_cycle: BillingCycle | None = None
    base_price: Decimal | None = Field(default=None, ge=0)
    currency: str | None = Field(default=None, min_length=3, max_length=3)
    is_active: bool | None = None
    is_public: bool | None = None
    sort_order: int | None = None
    features: list[PlanFeatureCreateRequest] | None = Field(
        default=None,
        description=(
            "When provided, fully replaces this plan's feature set "
            "(existing rows are deleted and these are inserted)."
        ),
    )


class PlanFeatureResponse(BaseModel):
    id: str
    feature_key: str
    feature_type: str
    limit_value: Decimal | None
    is_enabled: bool | None
    tier_value: str | None

    model_config = ConfigDict(from_attributes=True)


class PlanResponse(BaseModel):
    id: str
    name: str
    slug: str
    plan_type: str
    description: str | None
    billing_cycle: str
    base_price: Decimal
    currency: str
    is_active: bool
    is_public: bool
    created_by_user_id: str | None
    sort_order: int
    features: list[PlanFeatureResponse] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PlanListResponse(BaseModel):
    items: list[PlanResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


# ============================================================================
# License
# ============================================================================


class LicenseAssignRequest(BaseModel):
    organization_id: uuid.UUID
    plan_id: uuid.UUID
    expires_at: datetime | None = None


class LicenseSuspendRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500)


class LicenseUpgradeRequest(BaseModel):
    new_plan_id: uuid.UUID
    reason: str | None = Field(default=None, max_length=500)


class LicenseDowngradeRequest(BaseModel):
    new_plan_id: uuid.UUID
    reason: str | None = Field(default=None, max_length=500)


class LicenseChangeLogResponse(BaseModel):
    id: str
    from_plan_id: str | None
    to_plan_id: str
    change_type: LicenseChangeType
    changed_at: datetime
    changed_by_user_id: str | None
    reason: str | None

    model_config = ConfigDict(from_attributes=True)


class LicenseResponse(BaseModel):
    id: str
    organization_id: str
    plan_id: str
    status: LicenseStatus
    activated_at: datetime | None
    expires_at: datetime | None
    suspended_at: datetime | None
    suspended_reason: str | None
    cancelled_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Usage
# ============================================================================


class UsageMetricResponse(BaseModel):
    metric_key: UsageMetricKey
    period_start: datetime
    period_end: datetime
    value: Decimal
    recorded_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UsageLimitCheckResponse(BaseModel):
    metric_key: UsageMetricKey
    current_value: Decimal
    limit_value: Decimal
    exceeded: bool


class UsageSummaryResponse(BaseModel):
    organization_id: str
    metrics: list[UsageMetricResponse]
    limit_checks: list[UsageLimitCheckResponse]
    any_limit_exceeded: bool


# ============================================================================
# Subscription (BE-013 Part 2)
# ============================================================================


class SubscriptionCreateRequest(BaseModel):
    organization_id: uuid.UUID
    plan_id: uuid.UUID
    coupon_code: str | None = Field(default=None, min_length=1, max_length=50)


class SubscriptionCancelRequest(BaseModel):
    immediate: bool = Field(
        default=False,
        description=(
            "true = cancel right now (License suspended immediately). "
            "false = schedule cancellation for the end of the current "
            "billing period (cancel_at_period_end)."
        ),
    )


class SubscriptionResponse(BaseModel):
    id: str
    organization_id: str
    license_id: str
    plan_id: str
    status: SubscriptionStatus
    billing_cycle: str
    current_period_start: datetime
    current_period_end: datetime
    trial_end: datetime | None
    auto_renew: bool
    cancel_at_period_end: bool
    started_at: datetime
    cancelled_at: datetime | None
    applied_coupon_id: str | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Coupon (BE-013 Part 2)
# ============================================================================


class CouponCreateRequest(BaseModel):
    code: str = Field(..., min_length=2, max_length=50)
    discount_type: DiscountType
    discount_value: Decimal = Field(..., ge=0)
    currency: str | None = Field(default=None, min_length=3, max_length=3)
    organization_id: uuid.UUID | None = Field(
        default=None,
        description="Omit/null for a GLOBAL coupon usable by any organization.",
    )
    max_uses: int | None = Field(default=None, ge=1)
    valid_from: datetime
    valid_until: datetime | None = None
    is_active: bool = True
    applicable_plan_ids: list[uuid.UUID] = Field(
        default_factory=list,
        description="Empty = applicable to every plan.",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "code": "SAVE20",
                "discount_type": "percentage",
                "discount_value": "20",
                "max_uses": 100,
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2026-12-31T23:59:59Z",
                "is_active": True,
                "applicable_plan_ids": [],
            }
        }
    )


class CouponUpdateRequest(BaseModel):
    discount_type: DiscountType | None = None
    discount_value: Decimal | None = Field(default=None, ge=0)
    currency: str | None = Field(default=None, min_length=3, max_length=3)
    max_uses: int | None = Field(default=None, ge=1)
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    is_active: bool | None = None
    applicable_plan_ids: list[uuid.UUID] | None = Field(
        default=None,
        description="When provided, fully replaces this coupon's plan restrictions.",
    )


class CouponResponse(BaseModel):
    id: str
    code: str
    discount_type: str
    discount_value: Decimal
    currency: str | None
    organization_id: str | None
    max_uses: int | None
    current_uses: int
    valid_from: datetime
    valid_until: datetime | None
    is_active: bool
    applicable_plan_ids: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CouponListResponse(BaseModel):
    items: list[CouponResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class CouponValidateRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=50)
    organization_id: uuid.UUID
    plan_id: uuid.UUID
    base_amount: Decimal | None = Field(
        default=None,
        ge=0,
        description=(
            "Optional -- when provided, the response includes the real "
            "computed discount against this amount (e.g. the plan's own "
            "base_price)."
        ),
    )


class CouponValidateResponse(BaseModel):
    valid: bool
    code: str
    discount_type: str
    discount_value: Decimal
    currency: str | None
    estimated_discount_amount: Decimal | None = Field(
        default=None,
        description="Only populated when the request included base_amount.",
    )


# ============================================================================
# Payment / PaymentMethod (BE-013 Part 3)
# ============================================================================


class PaymentInitiateRequest(BaseModel):
    organization_id: uuid.UUID
    subscription_id: uuid.UUID | None = Field(
        default=None,
        description="Set when this charge is a manual renewal retry/one-off "
        "against an existing subscription; omit for a standalone one-off "
        "charge.",
    )
    amount: Decimal = Field(..., gt=0)
    currency: str = Field(default="USD", min_length=3, max_length=3)
    provider: PaymentProvider
    idempotency_key: str = Field(
        ...,
        min_length=8,
        max_length=255,
        description=(
            "Caller-supplied idempotency key. The SAME key presented twice "
            "always resolves to the SAME Payment row -- this platform "
            "never double-charges for a repeated key, enforced by a real "
            "database unique constraint (see models.Payment's own "
            "docstring)."
        ),
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "organization_id": "11111111-1111-1111-1111-111111111111",
                "amount": "49.99",
                "currency": "USD",
                "provider": "stripe",
                "idempotency_key": "checkout-9f3e2a1b4c5d",
            }
        }
    )


class PaymentRefundRequest(BaseModel):
    amount: Decimal | None = Field(
        default=None,
        gt=0,
        description="Omit for a full refund of the remaining chargeable "
        "amount; set for a partial refund.",
    )


class PaymentResponse(BaseModel):
    id: str
    organization_id: str
    subscription_id: str | None
    amount: Decimal
    currency: str
    status: PaymentStatus
    provider: PaymentProvider
    provider_payment_id: str | None
    idempotency_key: str
    failure_reason: str | None
    refunded_amount: Decimal
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PaymentListResponse(BaseModel):
    items: list[PaymentResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class PaymentMethodRegisterRequest(BaseModel):
    organization_id: uuid.UUID
    provider: PaymentProvider
    provider_payment_method_id: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description=(
            "The provider's own opaque tokenized reference (e.g. a Stripe "
            "'pm_...' id) -- NEVER a raw card number/CVV. This platform "
            "never handles or stores raw card data."
        ),
    )
    method_type: PaymentMethodType
    last4: str | None = Field(default=None, min_length=4, max_length=4)
    is_default: bool = False

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "organization_id": "11111111-1111-1111-1111-111111111111",
                "provider": "stripe",
                "provider_payment_method_id": "pm_1NExampleToken",
                "method_type": "card",
                "last4": "4242",
                "is_default": True,
            }
        }
    )


class PaymentMethodResponse(BaseModel):
    id: str
    organization_id: str
    provider: PaymentProvider
    provider_payment_method_id: str
    method_type: PaymentMethodType
    last4: str | None
    is_default: bool
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PaymentMethodListResponse(BaseModel):
    items: list[PaymentMethodResponse]


# ============================================================================
# BE-013 Part 4: Invoice Engine + Tax/GST
# ============================================================================


class TaxRateCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    tax_type: TaxType
    rate_percentage: Decimal = Field(..., ge=0, le=100)
    country_code: str = Field(..., min_length=2, max_length=2)
    is_active: bool = True

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "India GST",
                "tax_type": "gst",
                "rate_percentage": "18.00",
                "country_code": "IN",
                "is_active": True,
            }
        }
    )


class TaxRateUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=100)
    tax_type: TaxType | None = None
    rate_percentage: Decimal | None = Field(default=None, ge=0, le=100)
    country_code: str | None = Field(default=None, min_length=2, max_length=2)
    is_active: bool | None = None


class TaxRateResponse(BaseModel):
    id: str
    name: str
    tax_type: str
    rate_percentage: Decimal
    country_code: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TaxRateListResponse(BaseModel):
    items: list[TaxRateResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class BillingProfileUpsertRequest(BaseModel):
    billing_name: str = Field(..., min_length=2, max_length=200)
    billing_address_line1: str = Field(..., min_length=2, max_length=255)
    billing_address_line2: str | None = Field(default=None, max_length=255)
    billing_city: str = Field(..., min_length=1, max_length=100)
    billing_state: str = Field(..., min_length=1, max_length=100)
    billing_country: str = Field(..., min_length=2, max_length=2)
    billing_postal_code: str = Field(..., min_length=1, max_length=20)
    gst_identifier: str | None = Field(default=None, max_length=20)
    tax_exempt: bool = False

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "billing_name": "Acme Hospitality Pvt Ltd",
                "billing_address_line1": "221B Baker Street",
                "billing_address_line2": None,
                "billing_city": "Mumbai",
                "billing_state": "Maharashtra",
                "billing_country": "IN",
                "billing_postal_code": "400001",
                "gst_identifier": "27AAAAA0000A1Z5",
                "tax_exempt": False,
            }
        }
    )


class BillingProfileResponse(BaseModel):
    id: str
    organization_id: str
    billing_name: str
    billing_address_line1: str
    billing_address_line2: str | None
    billing_city: str
    billing_state: str
    billing_country: str
    billing_postal_code: str
    gst_identifier: str | None
    tax_exempt: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class InvoiceItemResponse(BaseModel):
    id: str
    description: str
    quantity: Decimal
    unit_price: Decimal
    amount: Decimal

    model_config = ConfigDict(from_attributes=True)


class CreditDebitNoteResponse(BaseModel):
    id: str
    invoice_id: str
    note_type: NoteType
    note_number: str
    amount: Decimal
    reason: str
    issued_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CreditNoteIssueRequest(BaseModel):
    amount: Decimal = Field(..., gt=0)
    reason: str = Field(..., min_length=3, max_length=1000)


class DebitNoteIssueRequest(BaseModel):
    amount: Decimal = Field(..., gt=0)
    reason: str = Field(..., min_length=3, max_length=1000)


class InvoiceResponse(BaseModel):
    id: str
    organization_id: str
    subscription_id: str | None
    payment_id: str | None
    invoice_number: str
    status: InvoiceStatus
    issue_date: datetime
    due_date: datetime
    subtotal: Decimal
    cgst_amount: Decimal
    sgst_amount: Decimal
    igst_amount: Decimal
    tax_amount: Decimal
    tax_rate_percentage: Decimal
    total_amount: Decimal
    currency: str
    billing_snapshot: dict[str, object]
    items: list[InvoiceItemResponse] = Field(default_factory=list)
    notes: list[CreditDebitNoteResponse] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class InvoiceListResponse(BaseModel):
    items: list[InvoiceResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


# ============================================================================
# BE-013 Part 5: Super Admin + Customer Billing Dashboards
# ============================================================================


class SubscriptionRenewalSettingsUpdateRequest(BaseModel):
    auto_renew: bool = Field(
        ...,
        description=(
            "Whether this subscription should be automatically charged/"
            "renewed at the end of its current billing period."
        ),
    )


class RevenueTrendPointResponse(BaseModel):
    month: str = Field(..., description='"YYYY-MM" label.')
    gross_amount: Decimal
    refunded_amount: Decimal
    net_amount: Decimal


class SuperAdminRevenueDashboardResponse(BaseModel):
    """This domain's OWN real Revenue Dashboard -- composed entirely from
    this domain's own ``Payment``/``Subscription``/``Plan`` tables. This is
    a distinct capability from, and does not modify,
    ``app.domains.analytics.dashboard_schemas.RevenueMetricsResponse``
    (a separate, pre-existing, still-honest ``available=False`` placeholder
    -- see ``service.py``'s own Part 5 section docstring for the full
    write-up of why the two are deliberately kept separate)."""

    total_revenue: Decimal
    total_refunded: Decimal
    mrr: Decimal
    arr: Decimal
    active_paying_subscription_count: int
    trend: list[RevenueTrendPointResponse]
    currency_note: str


class ChurnRateResponse(BaseModel):
    period_start: datetime
    period_end: datetime
    active_at_period_start: int
    cancelled_this_period: int
    churn_rate: float | None = Field(
        default=None,
        description=(
            "cancelled_this_period / active_at_period_start. null when "
            "active_at_period_start is 0 -- an honest 'not computable' "
            "outcome, never a fabricated 0.0."
        ),
    )


class SuperAdminSubscriptionDashboardResponse(BaseModel):
    counts_by_status: dict[str, int]
    counts_by_plan_type: dict[str, int]
    churn: ChurnRateResponse


class CustomerBillingSummaryRowResponse(BaseModel):
    organization_id: str
    organization_name: str
    plan_id: str
    plan_name: str
    plan_slug: str
    subscription_status: str
    lifetime_revenue: Decimal
    outstanding_invoice_count: int

    model_config = ConfigDict(from_attributes=True)


class SuperAdminCustomerBillingDashboardResponse(BaseModel):
    items: list[CustomerBillingSummaryRowResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class FailedPaymentRowResponse(BaseModel):
    payment: PaymentResponse
    retry_eligible: bool = Field(
        ...,
        description=(
            "Reuses the exact same rule PaymentService.retry_failed_payment "
            "itself enforces (status == FAILED)."
        ),
    )


class SuperAdminFailedPaymentsDashboardResponse(BaseModel):
    items: list[FailedPaymentRowResponse]
    page: int
    page_size: int
    total_items: int
    counts_by_provider: dict[str, int]


class SuperAdminBillingDashboardResponse(BaseModel):
    """The full, composite Super Admin Billing Dashboard -- mirrors
    ``app.domains.analytics.dashboard_schemas.SuperAdminDashboardResponse``'s
    own "one endpoint, one composite payload" shape."""

    revenue: SuperAdminRevenueDashboardResponse
    subscriptions: SuperAdminSubscriptionDashboardResponse
    customers: SuperAdminCustomerBillingDashboardResponse
    failed_payments: SuperAdminFailedPaymentsDashboardResponse


class CustomerBillingDashboardResponse(BaseModel):
    """The unified, tenant-scoped "Customer Billing Dashboard" -- current
    License/Plan/Subscription status, a real usage-vs-limit snapshot,
    recent invoices/payments, and registered payment methods."""

    license: LicenseResponse
    plan: PlanResponse
    subscription: SubscriptionResponse
    usage: UsageSummaryResponse
    recent_invoices: list[InvoiceResponse]
    payment_methods: list[PaymentMethodResponse]
    recent_payments: list[PaymentResponse]
