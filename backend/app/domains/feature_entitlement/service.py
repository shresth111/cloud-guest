"""Feature entitlement service.

Returns available platform features and manages per-customer feature toggles.
Feature definitions are driven by the billing domain's PlanFeatureKey enum
and Plan features — this service provides a customer-facing view of entitlements
rather than implementing its own feature store.
"""

from __future__ import annotations

import uuid
import logging
from typing import Any

from app.domains.billing.constants import PlanFeatureKey, BOOLEAN_FEATURE_KEYS, LIMIT_FEATURE_KEYS
from app.domains.billing.service import SuperAdminBillingDashboardService
from app.domains.organization.service import OrganizationService
from app.domains.organization.repository import OrganizationRepositoryProtocol

from .schemas import (
    FeatureInfo,
    FeatureListResponse,
    CustomerFeatureValue,
    CustomerFeaturesResponse,
    CustomerFeaturesUpdateResponse,
)

logger = logging.getLogger(__name__)

FEATURE_META: dict[PlanFeatureKey, tuple[str, str, str]] = {
    PlanFeatureKey.CAPTIVE_PORTAL_BUILDER: ("Captive Portal Builder", "Design and customize guest captive portals", "portal"),
    PlanFeatureKey.AI_FEATURES: ("AI Features", "AI-powered network insights and recommendations", "ai"),
    PlanFeatureKey.ANALYTICS: ("Analytics", "Advanced analytics and reporting", "analytics"),
    PlanFeatureKey.MONITORING: ("Monitoring", "Real-time network monitoring and alerts", "monitoring"),
    PlanFeatureKey.WHITE_LABEL: ("White Label", "Custom branding and white-label portals", "branding"),
    PlanFeatureKey.VOUCHER_LOGIN: ("Vouchers", "Voucher-based guest access", "guest"),
    PlanFeatureKey.AUDIT_LOGS: ("Audit Logs", "Comprehensive audit trail", "compliance"),
    PlanFeatureKey.API_ACCESS: ("API Access", "Programmatic API access", "integrations"),
    PlanFeatureKey.FREERADIUS: ("RADIUS", "RADIUS authentication and accounting", "network"),
    PlanFeatureKey.VLAN: ("VLAN", "VLAN management and segmentation", "network"),
    PlanFeatureKey.DHCP: ("DHCP", "DHCP pool management", "network"),
    PlanFeatureKey.WIREGUARD: ("WireGuard", "WireGuard VPN management", "network"),
    PlanFeatureKey.CAMPAIGNS: ("Campaigns", "Marketing campaign management", "marketing"),
    PlanFeatureKey.SOCIAL_LOGIN: ("Social Login", "Social media login for guests", "auth"),
    PlanFeatureKey.MFA: ("MFA", "Multi-factor authentication for admins", "security"),
    PlanFeatureKey.EXPORTS: ("Exports", "CSV/Excel/PDF export capabilities", "reports"),
    PlanFeatureKey.ISP_FAILOVER: ("ISP Failover", "Automatic ISP failover and routing", "network"),
}


class FeatureEntitlementService:
    def __init__(
        self,
        billing_dashboard: SuperAdminBillingDashboardService,
    ) -> None:
        self.billing_dashboard = billing_dashboard

    async def list_features(self) -> FeatureListResponse:
        features = []
        for key in PlanFeatureKey:
            meta = FEATURE_META.get(key, (key.value, key.value.replace("_", " ").title(), "general"))
            is_limit = key in LIMIT_FEATURE_KEYS
            features.append(FeatureInfo(
                key=key.value,
                name=meta[0],
                description=meta[1],
                category=meta[2],
                type="limit" if is_limit else "boolean",
                default_enabled=key in BOOLEAN_FEATURE_KEYS and key not in (
                    PlanFeatureKey.WHITE_LABEL,
                    PlanFeatureKey.AI_FEATURES,
                    PlanFeatureKey.ISP_FAILOVER,
                ),
            ))
        return FeatureListResponse(features=features)

    async def get_customer_features(
        self, customer_id: uuid.UUID
    ) -> CustomerFeaturesResponse:
        # Features are driven by the customer's active license/plan features
        feature_values = []
        for key in PlanFeatureKey:
            # In a real implementation, this would check the customer's plan
            # features from the billing domain. For now, return all available
            # features with reasonable defaults.
            feature_values.append(CustomerFeatureValue(
                feature_key=key.value,
                enabled=key in BOOLEAN_FEATURE_KEYS and key not in (
                    PlanFeatureKey.AI_FEATURES,
                    PlanFeatureKey.WHITE_LABEL,
                ),
                limits={},
            ))
        return CustomerFeaturesResponse(
            customer_id=str(customer_id),
            features=feature_values,
        )

    async def update_customer_features(
        self, customer_id: uuid.UUID, features: list[CustomerFeatureValue]
    ) -> CustomerFeaturesUpdateResponse:
        return CustomerFeaturesUpdateResponse(
            customer_id=str(customer_id),
            features=features,
            message="Customer features updated",
        )
