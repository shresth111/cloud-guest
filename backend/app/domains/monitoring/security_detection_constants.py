"""Names and fixed values for ``security_detections``.

Kept apart from that module because ``app.core.celery_app`` imports the task
name and interval to build ``beat_schedule``, and the task module itself
imports ``celery_app``: importing it from there would be a cycle.
"""

from __future__ import annotations

TASK_SECURITY_DETECTION_SWEEP = (
    "app.domains.monitoring.security_detections.security_detection_sweep"
)
SECURITY_DETECTION_SWEEP_INTERVAL_SECONDS = 300.0

SECURITY_EVENT_SOURCE_DOMAIN = "security_detection"
SECURITY_EVENT_TYPE_PREFIX = "security."

REDIS_KEY_PREFIX = "security_detection"
# Two overlapping sweeps would double the read load for nothing. The lock
# outlives a normal run by far and expires before the next-but-one tick.
SWEEP_LOCK_TTL_SECONDS = 540
# A row committed a moment before the previous sweep's ``now`` can become
# visible to readers only after that sweep ran its query. Re-reading this
# much of the previous window costs almost nothing, and dedup drops the
# repeats.
WATERMARK_OVERLAP_SECONDS = 120
# First run for a rule (no watermark yet): look this far back.
INITIAL_LOOKBACK_MINUTES = 15

# Seeded system roles that only Wyfy staff (or MSP partners) may inherit
# from. A tenant custom role whose parent chain reaches one of these
# inherits platform permissions -- see rbac.authorization's recursive walk.
PLATFORM_ROLE_SLUGS = (
    "super-admin",
    "platform-admin",
    "platform-support",
    "billing-manager",
    "msp-owner",
    "msp-admin",
)
MSP_ROLE_SLUGS = ("msp-owner", "msp-admin")

# Permission modules that are GLOBAL-only by design (rbac.enums comments
# say "belongs to no organization"). Matched as ``<module>.`` prefixes.
PLATFORM_ONLY_PERMISSION_MODULES = (
    "demo_requests",
    "quotations",
    "channel_partners",
    "device_console",
    "traffic_flows",
    "device_logs",
)
PLATFORM_ONLY_PERMISSION_KEYS = (
    "organizations.create",
    "organizations.delete",
    "subscriptions.create",
    "subscriptions.update",
    "users.impersonate",
)

# Audit actions only a platform operator should ever be the actor of.
PLATFORM_ONLY_AUDIT_ACTIONS = (
    "license_activated",
    "license_assigned",
    "organization_created",
    "device_console_command_executed",
    "impersonation_started",
    "organization_feature_override_set",
    "credits_adjusted",
)
CREDENTIAL_REVEAL_AUDIT_ACTIONS = (
    "router_credentials_revealed",
    "router_local_admin_password_revealed",
)

# Webhook event types that must resolve to a payment row when processed.
PAYMENT_WEBHOOK_EVENT_TYPES = (
    "payment.captured",
    "payment.failed",
    "payment_intent.succeeded",
    "payment_intent.payment_failed",
)

__all__ = [
    "CREDENTIAL_REVEAL_AUDIT_ACTIONS",
    "INITIAL_LOOKBACK_MINUTES",
    "MSP_ROLE_SLUGS",
    "PAYMENT_WEBHOOK_EVENT_TYPES",
    "PLATFORM_ONLY_AUDIT_ACTIONS",
    "PLATFORM_ONLY_PERMISSION_KEYS",
    "PLATFORM_ONLY_PERMISSION_MODULES",
    "PLATFORM_ROLE_SLUGS",
    "REDIS_KEY_PREFIX",
    "SECURITY_DETECTION_SWEEP_INTERVAL_SECONDS",
    "SECURITY_EVENT_SOURCE_DOMAIN",
    "SECURITY_EVENT_TYPE_PREFIX",
    "SWEEP_LOCK_TTL_SECONDS",
    "TASK_SECURITY_DETECTION_SWEEP",
    "WATERMARK_OVERLAP_SECONDS",
]
