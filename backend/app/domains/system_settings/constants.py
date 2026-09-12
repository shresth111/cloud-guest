"""System Settings domain constants.

The set of platform-wide (GLOBAL-scope) configuration keys this store
knows about. The store itself is a generic ``key -> JSONB value`` table
(see ``models.SystemSetting``) so a new platform setting is one enum member
plus a typed field on the schema, no migration -- but the *keys* are a
closed, enumerated set here rather than free-form strings, so a typo in a
key name is a Python error at import time, not a silently-ignored write.
"""

from __future__ import annotations

from enum import StrEnum


class SystemSettingKey(StrEnum):
    """Every platform setting key persisted in ``system_settings``.

    One member per setting. ``NEW_CUSTOMER_DEFAULT_PLAN_ID`` is the first
    real one -- the default billing plan a newly-provisioned customer
    organization should be placed on. ``NEW_CUSTOMER_DEFAULT_FEATURE_OVERRIDES``
    is the small, optional companion: per-feature on/off overrides layered
    on top of that plan's own features at provisioning time.
    """

    NEW_CUSTOMER_DEFAULT_PLAN_ID = "new_customer_default_plan_id"
    NEW_CUSTOMER_DEFAULT_FEATURE_OVERRIDES = "new_customer_default_feature_overrides"
