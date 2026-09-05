"""Feature entitlement service.

Returns available platform features and manages per-customer feature toggles.
Feature definitions are driven by the billing domain's PlanFeatureKey enum
and Plan features — this service provides a customer-facing view of entitlements
rather than implementing its own feature store.
"""

from __future__ import annotations

import logging
import uuid

from app.domains.billing.constants import (
    BOOLEAN_FEATURE_KEYS,
    LIMIT_FEATURE_KEYS,
    TIER_FEATURE_KEYS,
    PlanFeatureKey,
    SupportTier,
)
from app.domains.billing.service import (
    EntitlementChecker,
    SuperAdminBillingDashboardService,
)

from .exceptions import PerCustomerFeatureOverrideNotSupportedError
from .schemas import (
    CustomerFeaturesResponse,
    CustomerFeaturesUpdateResponse,
    CustomerFeatureValue,
    FeatureInfo,
    FeatureListResponse,
)

logger = logging.getLogger(__name__)

FEATURE_META: dict[PlanFeatureKey, tuple[str, str, str]] = {
    PlanFeatureKey.CAPTIVE_PORTAL_BUILDER: (
        "Captive Portal Builder",
        "Design and customize guest captive portals",
        "portal",
    ),
    PlanFeatureKey.AI_FEATURES: (
        "AI Features",
        "AI-powered network insights and recommendations",
        "ai",
    ),
    PlanFeatureKey.ANALYTICS: (
        "Analytics",
        "Advanced analytics and reporting",
        "analytics",
    ),
    PlanFeatureKey.MONITORING: (
        "Monitoring",
        "Real-time network monitoring and alerts",
        "monitoring",
    ),
    PlanFeatureKey.WHITE_LABEL: (
        "White Label",
        "Custom branding and white-label portals",
        "branding",
    ),
    PlanFeatureKey.VOUCHER_LOGIN: ("Vouchers", "Voucher-based guest access", "guest"),
    PlanFeatureKey.AUDIT_LOGS: (
        "Audit Logs",
        "Comprehensive audit trail",
        "compliance",
    ),
    PlanFeatureKey.API_ACCESS: (
        "API Access",
        "Programmatic API access",
        "integrations",
    ),
    PlanFeatureKey.FREERADIUS: (
        "RADIUS",
        "RADIUS authentication and accounting",
        "network",
    ),
    PlanFeatureKey.VLAN: ("VLAN", "VLAN management and segmentation", "network"),
    PlanFeatureKey.DHCP: ("DHCP", "DHCP pool management", "network"),
    PlanFeatureKey.WIREGUARD: ("WireGuard", "WireGuard VPN management", "network"),
    PlanFeatureKey.CAMPAIGNS: (
        "Campaigns",
        "Marketing campaign management",
        "marketing",
    ),
    PlanFeatureKey.SOCIAL_LOGIN: (
        "Social Login",
        "Social media login for guests",
        "auth",
    ),
    PlanFeatureKey.MFA: ("MFA", "Multi-factor authentication for admins", "security"),
    PlanFeatureKey.EXPORTS: ("Exports", "CSV/Excel/PDF export capabilities", "reports"),
    PlanFeatureKey.ISP_FAILOVER: (
        "ISP Failover",
        "Automatic ISP failover and routing",
        "network",
    ),
}


class FeatureEntitlementService:
    def __init__(
        self,
        billing_dashboard: SuperAdminBillingDashboardService,
        entitlement_checker: EntitlementChecker,
    ) -> None:
        self.billing_dashboard = billing_dashboard
        # The same object ``RequireFeature`` gates live requests against, so
        # this domain reports exactly what the platform enforces.
        self.entitlement_checker = entitlement_checker

    async def list_features(self) -> FeatureListResponse:
        features = []
        for key in PlanFeatureKey:
            meta = FEATURE_META.get(
                key, (key.value, key.value.replace("_", " ").title(), "general")
            )
            is_limit = key in LIMIT_FEATURE_KEYS
            # ``support_level`` is the one TIER-typed feature key this
            # domain has today (``TIER_FEATURE_KEYS`` -- see that
            # constant's own docstring) -- it must never be reported as
            # ``"boolean"``: a plain on/off toggle has no legal
            # ``tier_value`` to send, and ``validate_feature_value``
            # correctly rejects a TIER-typed override with none (this is
            # exactly the bug that let the Smart Location Provisioning
            # wizard's "Features" step send a shapeless ``support_level``
            # override).
            is_tier = key in TIER_FEATURE_KEYS
            features.append(FeatureInfo(
                key=key.value,
                name=meta[0],
                description=meta[1],
                category=meta[2],
                type="limit" if is_limit else "tier" if is_tier else "boolean",
                default_enabled=key in BOOLEAN_FEATURE_KEYS and key not in (
                    PlanFeatureKey.WHITE_LABEL,
                    PlanFeatureKey.AI_FEATURES,
                    PlanFeatureKey.ISP_FAILOVER,
                ),
                tier_options=[tier.value for tier in SupportTier] if is_tier else [],
                default_tier_value=SupportTier.BASIC.value if is_tier else None,
            ))
        return FeatureListResponse(features=features)

    async def get_customer_features(
        self, customer_id: uuid.UUID
    ) -> CustomerFeaturesResponse:
        """This customer's real entitlements, read off their license and plan.

        Previously this ignored ``customer_id`` entirely and returned the same
        constant list for every customer -- every ``PlanFeatureKey`` enabled
        except ``AI_FEATURES``/``WHITE_LABEL``, with ``limits={}`` -- under a
        comment that said "In a real implementation, this would check the
        customer's plan features from the billing domain. For now, return all
        available features with reasonable defaults."

        The billing domain has done exactly that all along:
        ``EntitlementChecker.get_snapshot`` is the same cache-or-fetch read
        model ``RequireFeature`` gates live requests against, assembled from
        real ``License`` and ``PlanFeature`` rows. This is now a thin adapter
        over it, so what this endpoint reports and what the platform actually
        enforces can no longer disagree.
        """
        snapshot = await self.entitlement_checker.get_snapshot(customer_id)

        feature_values = []
        for key in PlanFeatureKey:
            limits: dict[str, object] = {}
            # LIMIT-typed keys carry a number (max_locations, sms_quota, ...)
            # and TIER-typed keys carry a tier string (support_level). Both are
            # reported under `limits` rather than being flattened into the
            # boolean, which is what made the old response unable to express a
            # plan's actual ceilings at all.
            if key.value in snapshot.limits:
                limits["value"] = snapshot.limits[key.value]
            if key.value in snapshot.tiers:
                limits["tier_value"] = snapshot.tiers[key.value]

            feature_values.append(
                CustomerFeatureValue(
                    feature_key=key.value,
                    enabled=snapshot.has_feature(key)
                    or key.value in snapshot.limits
                    or key.value in snapshot.tiers,
                    limits=limits,
                )
            )

        return CustomerFeaturesResponse(
            customer_id=str(customer_id),
            features=feature_values,
        )

    async def update_customer_features(
        self, customer_id: uuid.UUID, features: list[CustomerFeatureValue]
    ) -> CustomerFeaturesUpdateResponse:
        """Always refuses -- see
        :class:`~.exceptions.PerCustomerFeatureOverrideNotSupportedError`.

        There is no per-customer override model in the billing domain to write
        to: entitlements are a property of the plan. This method used to echo
        the caller's own payload back with ``"Customer features updated"`` and
        persist nothing, so the failure was invisible to the operator who
        thought they had just granted a customer a feature.
        """
        raise PerCustomerFeatureOverrideNotSupportedError()
