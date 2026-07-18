"""Constants for the Subscription domain."""

from enum import Enum

class PlanCode(str, Enum):
    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"

class SubscriptionStatus(str, Enum):
    TRIALING = "trialing"
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    SUSPENDED = "suspended"

class BillingCycle(str, Enum):
    MONTHLY = "monthly"
    YEARLY = "yearly"

DEFAULT_PLAN_LIMITS = {
    PlanCode.FREE: {
        "organizations": 1,
        "locations": 1,
        "routers": 1,
        "users": 2,
        "guest_sessions": 100,
        "api_requests": 1000,
        "captive_portals": 1,
        "reports": False,
        "storage_gb": 1,
        "retention_days": 7
    },
    PlanCode.STARTER: {
        "organizations": 1,
        "locations": 3,
        "routers": 3,
        "users": 5,
        "guest_sessions": 1000,
        "api_requests": 10000,
        "captive_portals": 2,
        "reports": True,
        "storage_gb": 10,
        "retention_days": 30
    },
    PlanCode.PROFESSIONAL: {
        "organizations": 5,
        "locations": 15,
        "routers": 15,
        "users": 20,
        "guest_sessions": 10000,
        "api_requests": 100000,
        "captive_portals": 5,
        "reports": True,
        "storage_gb": 50,
        "retention_days": 90
    },
    PlanCode.BUSINESS: {
        "organizations": 20,
        "locations": 100,
        "routers": 100,
        "users": 100,
        "guest_sessions": 100000,
        "api_requests": 1000000,
        "captive_portals": 20,
        "reports": True,
        "storage_gb": 500,
        "retention_days": 365
    },
    PlanCode.ENTERPRISE: {
        "organizations": -1,  # Unlimited
        "locations": -1,
        "routers": -1,
        "users": -1,
        "guest_sessions": -1,
        "api_requests": -1,
        "captive_portals": -1,
        "reports": True,
        "storage_gb": -1,
        "retention_days": -1
    }
}
