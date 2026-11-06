"""Security detection sweep: read-only rules over the audit, OTP, session
and billing tables, run by Celery beat every 5 minutes.

Why this exists: the data that shows an attack was already being written
(``audit_log_entries``, ``otp_requests``, ``guest_sessions``,
``role_permissions``, ``login_attempts``), but nothing read it. The alert
engine only watches network health. See the SOC report of 2026-11-06, §4.

## Shape

Each rule is one ``SELECT`` over a bounded window and returns
:class:`DetectionHit` values. The sweep:

1. takes a Redis lock, so two beat ticks never overlap;
2. runs every rule in its **own** read-only transaction with
   ``SET LOCAL statement_timeout``, so a slow or broken rule is cancelled
   by Postgres and cannot hold locks or starve the request path. A rule
   that fails is logged and skipped; the others still run;
3. reads each rule's own watermark from Redis (the end of its last good
   run, minus a small overlap), clamped to
   ``security_detection_max_lookback_minutes``. Volume rules use a fixed
   rolling window instead and ignore the watermark;
4. drops hits already reported for the same ``(rule, subject)`` in the last
   ``security_detection_dedup_hours`` (Redis ``SET NX EX``);
5. writes one ``platform_events`` row per new hit
   (``category='security'``) and sends **one** digest email per sweep to
   ``platform_alert_emails``, the same channel ``billing.tasks
   ._send_reconciliation_alert`` uses.

## What a tenant can see

Nothing. Security events are written with ``organization_id`` NULL (the
tenant's id goes in ``metadata.organization_id``).
``GET /monitoring/events`` filters by the caller's organization, so only a
GLOBAL caller ever reads these rows. Tenant ``EVENT_OCCURRED`` alert rules
match only their own organization's events, so they never fire on them
either. Telling a tenant admin that their self-escalation was spotted would
only help them.

## Personal data

Rules never put a phone number, an email or an OTP identifier into a hit
in full. Emails go through ``app.common.masking.mask_email``. Dedup keys are
hashed before they reach Redis.

## Cost

Every windowed query filters on ``created_at``, which every ``BaseModel``
table indexes (``ix_<table>_created_at``), so each is an index range scan
over minutes of rows. The ``roles``/``role_scopes``/``user_roles`` reads are
on tables of a few hundred rows. Every query has a ``LIMIT``.
"""

from __future__ import annotations

import contextlib
import hashlib
import re
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from sqlalchemy import text

from app.common.masking import mask_email
from app.core.async_task_bridge import run_celery_task
from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.core.logging import get_logger
from app.database.redis import create_redis_client
from app.database.session import SessionLocal

from .constants import EventCategory, EventSeverity
from .security_detection_constants import (
    CREDENTIAL_REVEAL_AUDIT_ACTIONS,
    INITIAL_LOOKBACK_MINUTES,
    MSP_ROLE_SLUGS,
    PAYMENT_WEBHOOK_EVENT_TYPES,
    PLATFORM_ONLY_AUDIT_ACTIONS,
    PLATFORM_ONLY_PERMISSION_KEYS,
    PLATFORM_ONLY_PERMISSION_MODULES,
    PLATFORM_ROLE_SLUGS,
    REDIS_KEY_PREFIX,
    SECURITY_EVENT_SOURCE_DOMAIN,
    SECURITY_EVENT_TYPE_PREFIX,
    SWEEP_LOCK_TTL_SECONDS,
    TASK_SECURITY_DETECTION_SWEEP,
    WATERMARK_OVERLAP_SECONDS,
)

logger = get_logger(__name__)

P1 = "P1"
P2 = "P2"
P3 = "P3"
_PRIORITY_SEVERITY = {
    P1: EventSeverity.CRITICAL.value,
    P2: EventSeverity.WARNING.value,
    P3: EventSeverity.INFO.value,
}
_PRIORITY_ORDER = {P1: 0, P2: 1, P3: 2}


# ============================================================================
# Value types
# ============================================================================


@dataclass(frozen=True, slots=True)
class DetectionHit:
    """One finding. ``subject`` is the dedup unit (a role+permission, a
    router+actor, "platform" for a volume rule); it is hashed before use.
    ``details`` must already be free of personal data."""

    rule: str
    subject: str
    priority: str
    title: str
    message: str
    organization_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def severity(self) -> str:
        return _PRIORITY_SEVERITY[self.priority]

    @property
    def event_type(self) -> str:
        return f"{SECURITY_EVENT_TYPE_PREFIX}{self.rule}"


@dataclass(frozen=True, slots=True)
class DetectionWindow:
    since: datetime
    now: datetime


@dataclass(frozen=True, slots=True)
class Thresholds:
    """Read once per sweep from ``Settings`` (see the
    ``security_detection_*`` block in ``app.core.config``)."""

    max_hits_per_rule: int = 50
    sms_hourly_max: int = 300
    sms_baseline_multiplier: float = 3.0
    sms_baseline_min_count: int = 30
    venueless_otp_hourly_max: int = 20
    venue_sms_hourly_max: int = 100
    otp_verify_ratio_min: float = 0.2
    otp_verify_ratio_min_sample: int = 50
    webhook_rejected_max: int = 5
    login_failures_per_email_max: int = 20
    login_failures_total_max: int = 50
    login_failures_distinct_emails: int = 10
    voucher_failures_per_location_max: int = 30
    otp_failures_per_code_max: int = 10

    @classmethod
    def from_settings(cls, settings: Any) -> Thresholds:
        prefix = "security_detection_"
        values = {
            name: getattr(settings, prefix + name)
            for name in cls.__dataclass_fields__
            if hasattr(settings, prefix + name)
        }
        return cls(**values)


RuleFn = Callable[[Any, DetectionWindow, Thresholds], Awaitable[list[DetectionHit]]]


@dataclass(frozen=True, slots=True)
class DetectionRule:
    name: str
    run: RuleFn
    # False: the rule looks at a fixed rolling window ending at ``now`` and
    # ignores the watermark (volume/ratio rules).
    windowed: bool = True


class RedisLike(Protocol):
    async def get(self, key: str) -> Any: ...

    async def set(
        self, key: str, value: str, *, nx: bool = ..., ex: int = ...
    ) -> Any: ...

    async def delete(self, *keys: str) -> Any: ...


# ============================================================================
# Small helpers
# ============================================================================


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:32]


def _s(value: Any) -> str | None:
    return None if value is None else str(value)


def _masked_email(value: Any) -> str | None:
    return mask_email(str(value)) if value else None


def _platform_key_regex() -> str:
    modules = "|".join(re.escape(m) for m in PLATFORM_ONLY_PERMISSION_MODULES)
    return rf"^({modules})\."


async def _rows(session: Any, sql: str, params: dict[str, Any]) -> list[Any]:
    result = await session.execute(text(sql), params)
    return list(result.mappings().all())


def _base_params(window: DetectionWindow, cfg: Thresholds) -> dict[str, Any]:
    return {"since": window.since, "now": window.now, "limit": cfg.max_hits_per_rule}


# Who counts as a Wyfy operator: an active, unexpired GLOBAL assignment of a
# seeded system role that belongs to no organization (super-admin,
# platform-admin, platform-support, billing-manager). Derived from state,
# not a hard-coded email list, so a new operator needs no code change.
_PLATFORM_OPS_CTE = """
platform_ops AS (
    SELECT DISTINCT ur.user_id
      FROM user_roles ur
      JOIN roles r ON r.id = ur.role_id
     WHERE ur.is_active AND NOT ur.is_deleted
       AND ur.scope_type = 'global'
       AND (ur.expires_at IS NULL OR ur.expires_at > CAST(:now AS timestamptz))
       AND r.is_system_role AND r.organization_id IS NULL
       AND r.scope_type = 'global' AND NOT r.is_deleted
)"""

# A role a tenant could have written: not seeded, and either owned by an
# organization or created by someone who is not an operator.
_TENANT_ROLE_PREDICATE = """
    NOT r.is_system_role AND NOT r.is_deleted
    AND (r.organization_id IS NOT NULL
         OR (r.created_by IS NOT NULL
             AND r.created_by NOT IN (SELECT user_id FROM platform_ops)))"""

# An audited action taken by an operator while impersonating a tenant user is
# the operator's action (the impersonator id lands in metadata, see
# rbac.repository.create_audit_log_entry).
_NOT_IMPERSONATED_BY_OPERATOR = """
    NOT COALESCE(a.metadata->>'impersonator_user_id', '') IN
        (SELECT user_id::text FROM platform_ops)"""


# ============================================================================
# P1 rules: RBAC self-escalation
# ============================================================================


async def rule_tenant_role_platform_key(
    session: Any, window: DetectionWindow, cfg: Thresholds
) -> list[DetectionHit]:
    """R1: a permission granted to a tenant role that the seeded
    Organization Owner does not hold, or that is platform-only by name."""
    sql = f"""
    WITH {_PLATFORM_OPS_CTE},
    owner_keys AS (
        SELECT rp.permission_id
          FROM role_permissions rp JOIN roles r ON r.id = rp.role_id
         WHERE r.slug = 'organization-owner' AND r.is_system_role
           AND NOT rp.is_deleted
    )
    SELECT rp.id AS grant_id, r.id AS role_id, r.slug AS role_slug,
           r.organization_id, p.key AS permission_key, rp.granted_by,
           gu.email AS granted_by_email
      FROM role_permissions rp
      JOIN roles r ON r.id = rp.role_id
      JOIN permissions p ON p.id = rp.permission_id
      LEFT JOIN users gu ON gu.id = rp.granted_by
     WHERE rp.created_at >= CAST(:since AS timestamptz)
       AND rp.created_at < CAST(:now AS timestamptz)
       AND NOT rp.is_deleted
       AND {_TENANT_ROLE_PREDICATE}
       AND (
            (EXISTS (SELECT 1 FROM owner_keys)
             AND rp.permission_id NOT IN (SELECT permission_id FROM owner_keys))
            OR p.key ~ :key_regex
            OR p.key = ANY(:platform_keys)
       )
     ORDER BY rp.created_at
     LIMIT :limit
    """
    params = _base_params(window, cfg) | {
        "key_regex": _platform_key_regex(),
        "platform_keys": list(PLATFORM_ONLY_PERMISSION_KEYS),
    }
    return [
        DetectionHit(
            rule="tenant_role_platform_key",
            subject=f"{row['role_id']}:{row['permission_key']}",
            priority=P1,
            title="Tenant role granted a platform-only permission",
            message=(
                f"Role {row['role_slug']} ({row['role_id']}) now holds "
                f"'{row['permission_key']}', which no tenant role should hold."
            ),
            organization_id=_s(row["organization_id"]),
            details={
                "role_id": _s(row["role_id"]),
                "permission_key": row["permission_key"],
                "granted_by_user_id": _s(row["granted_by"]),
                "granted_by": _masked_email(row["granted_by_email"]),
            },
        )
        for row in await _rows(session, sql, params)
    ]


async def rule_tenant_role_global_scope(
    session: Any, window: DetectionWindow, cfg: Thresholds
) -> list[DetectionHit]:
    """R2a: a tenant role whose own scope, or one of its allowed scopes, is
    GLOBAL. ``roles.updated_at`` is unindexed, but the table is tiny."""
    sql = f"""
    WITH {_PLATFORM_OPS_CTE}
    SELECT r.id AS role_id, r.slug AS role_slug, r.organization_id,
           r.scope_type, r.updated_by
      FROM roles r
     WHERE {_TENANT_ROLE_PREDICATE}
       AND (r.created_at >= CAST(:since AS timestamptz)
            OR r.updated_at >= CAST(:since AS timestamptz)
            OR EXISTS (SELECT 1 FROM role_scopes x
                        WHERE x.role_id = r.id AND NOT x.is_deleted
                          AND x.created_at >= CAST(:since AS timestamptz)))
       AND (r.scope_type = 'global'
            OR EXISTS (SELECT 1 FROM role_scopes rs
                        WHERE rs.role_id = r.id AND NOT rs.is_deleted
                          AND rs.scope_type = 'global'))
     LIMIT :limit
    """
    return [
        DetectionHit(
            rule="tenant_role_global_scope",
            subject=str(row["role_id"]),
            priority=P1,
            title="Tenant role claims GLOBAL scope",
            message=(
                f"Role {row['role_slug']} ({row['role_id']}) has scope "
                f"'{row['scope_type']}' or allows GLOBAL assignment."
            ),
            organization_id=_s(row["organization_id"]),
            details={
                "role_id": _s(row["role_id"]),
                "scope_type": row["scope_type"],
                "updated_by_user_id": _s(row["updated_by"]),
            },
        )
        for row in await _rows(session, sql, _base_params(window, cfg))
    ]


async def rule_tenant_role_inherits_platform_role(
    session: Any, window: DetectionWindow, cfg: Thresholds
) -> list[DetectionHit]:
    """R2b: a tenant role whose ``parent_role_id`` chain reaches a GLOBAL or
    platform/MSP system role. Permissions are inherited recursively
    (``rbac.authorization``), so this is escalation without any
    ``permission_assigned`` row at all."""
    sql = f"""
    WITH RECURSIVE {_PLATFORM_OPS_CTE},
    changed AS (
        SELECT r.id FROM roles r
         WHERE {_TENANT_ROLE_PREDICATE}
           AND r.parent_role_id IS NOT NULL
           AND (r.created_at >= CAST(:since AS timestamptz)
                OR r.updated_at >= CAST(:since AS timestamptz))
    ),
    chain AS (
        SELECT c.id AS root_id, r.parent_role_id AS ancestor_id, 1 AS depth
          FROM changed c JOIN roles r ON r.id = c.id
        UNION ALL
        SELECT ch.root_id, p.parent_role_id, ch.depth + 1
          FROM chain ch JOIN roles p ON p.id = ch.ancestor_id
         WHERE p.parent_role_id IS NOT NULL AND ch.depth < 20
    )
    SELECT DISTINCT ON (root.id)
           root.id AS role_id, root.slug AS role_slug, root.organization_id,
           anc.id AS ancestor_id, anc.slug AS ancestor_slug,
           anc.scope_type AS ancestor_scope, root.updated_by
      FROM chain ch
      JOIN roles root ON root.id = ch.root_id
      JOIN roles anc ON anc.id = ch.ancestor_id
     WHERE anc.scope_type = 'global'
        OR (anc.is_system_role AND anc.slug = ANY(:platform_slugs))
     ORDER BY root.id, ch.depth
     LIMIT :limit
    """
    params = _base_params(window, cfg) | {"platform_slugs": list(PLATFORM_ROLE_SLUGS)}
    return [
        DetectionHit(
            rule="tenant_role_inherits_platform_role",
            subject=f"{row['role_id']}:{row['ancestor_id']}",
            priority=P1,
            title="Tenant role inherits from a platform role",
            message=(
                f"Role {row['role_slug']} ({row['role_id']}) has "
                f"'{row['ancestor_slug']}' in its parent chain and inherits "
                "its permissions."
            ),
            organization_id=_s(row["organization_id"]),
            details={
                "role_id": _s(row["role_id"]),
                "ancestor_slug": row["ancestor_slug"],
                "ancestor_scope": row["ancestor_scope"],
                "updated_by_user_id": _s(row["updated_by"]),
            },
        )
        for row in await _rows(session, sql, params)
    ]


async def rule_tenant_override_platform_key(
    session: Any, window: DetectionWindow, cfg: Thresholds
) -> list[DetectionHit]:
    """R1 second lane: a per-user ``allow`` override of a platform-only key
    granted to someone who is not an operator."""
    sql = f"""
    WITH {_PLATFORM_OPS_CTE}
    SELECT po.id AS override_id, po.user_id, u.email, p.key AS permission_key,
           po.organization_id, po.granted_by
      FROM permission_overrides po
      JOIN permissions p ON p.id = po.permission_id
      LEFT JOIN users u ON u.id = po.user_id
     WHERE po.created_at >= CAST(:since AS timestamptz)
       AND po.created_at < CAST(:now AS timestamptz)
       AND po.is_active AND NOT po.is_deleted AND po.effect = 'allow'
       AND po.user_id NOT IN (SELECT user_id FROM platform_ops)
       AND (p.key ~ :key_regex OR p.key = ANY(:platform_keys))
     LIMIT :limit
    """
    params = _base_params(window, cfg) | {
        "key_regex": _platform_key_regex(),
        "platform_keys": list(PLATFORM_ONLY_PERMISSION_KEYS),
    }
    return [
        DetectionHit(
            rule="tenant_override_platform_key",
            subject=f"{row['user_id']}:{row['permission_key']}",
            priority=P1,
            title="Platform-only permission override granted to a tenant user",
            message=(
                f"User {row['user_id']} was granted an allow override for "
                f"'{row['permission_key']}'."
            ),
            organization_id=_s(row["organization_id"]),
            details={
                "user_id": _s(row["user_id"]),
                "user": _masked_email(row["email"]),
                "permission_key": row["permission_key"],
                "granted_by_user_id": _s(row["granted_by"]),
            },
        )
        for row in await _rows(session, sql, params)
    ]


# ============================================================================
# P1 rules: platform actions by tenants
# ============================================================================


async def rule_credential_reveal_by_non_operator(
    session: Any, window: DetectionWindow, cfg: Thresholds
) -> list[DetectionHit]:
    """R4: the platform's management password for a router was revealed to
    someone who is not an operator."""
    sql = f"""
    WITH {_PLATFORM_OPS_CTE}
    SELECT a.id, a.action, a.actor_user_id, u.email, a.organization_id,
           a.entity_id AS router_id
      FROM audit_log_entries a
      LEFT JOIN users u ON u.id = a.actor_user_id
     WHERE a.created_at >= CAST(:since AS timestamptz)
       AND a.created_at < CAST(:now AS timestamptz)
       AND a.action = ANY(:actions)
       AND (a.actor_user_id IS NULL
            OR a.actor_user_id NOT IN (SELECT user_id FROM platform_ops))
       AND {_NOT_IMPERSONATED_BY_OPERATOR}
     ORDER BY a.created_at
     LIMIT :limit
    """
    params = _base_params(window, cfg) | {
        "actions": list(CREDENTIAL_REVEAL_AUDIT_ACTIONS)
    }
    return [
        DetectionHit(
            rule="credential_reveal_by_non_operator",
            subject=f"{row['router_id']}:{row['actor_user_id']}",
            priority=P1,
            title="Router credentials revealed to a non-operator",
            message=(
                f"{row['action']} on router {row['router_id']} by "
                f"{_masked_email(row['email']) or 'no user'}. Treat the router "
                "as compromised until its credentials are rotated."
            ),
            organization_id=_s(row["organization_id"]),
            details={
                "audit_entry_id": _s(row["id"]),
                "action": row["action"],
                "router_id": _s(row["router_id"]),
                "actor_user_id": _s(row["actor_user_id"]),
                "actor": _masked_email(row["email"]),
            },
        )
        for row in await _rows(session, sql, params)
    ]


async def rule_platform_action_by_tenant(
    session: Any, window: DetectionWindow, cfg: Thresholds
) -> list[DetectionHit]:
    """R5: a tenant user is the actor of an action only operators take.
    ``organization_created`` by an MSP owner/admin is their job, so MSP
    holders are exempt for that one action."""
    sql = f"""
    WITH {_PLATFORM_OPS_CTE},
    msp_users AS (
        SELECT DISTINCT ur.user_id FROM user_roles ur JOIN roles r ON r.id = ur.role_id
         WHERE ur.is_active AND NOT ur.is_deleted AND r.is_system_role
           AND r.slug = ANY(:msp_slugs)
    )
    SELECT a.id, a.action, a.actor_user_id, u.email, a.organization_id,
           a.entity_type, a.entity_id
      FROM audit_log_entries a
      LEFT JOIN users u ON u.id = a.actor_user_id
     WHERE a.created_at >= CAST(:since AS timestamptz)
       AND a.created_at < CAST(:now AS timestamptz)
       AND a.action = ANY(:actions)
       AND a.actor_user_id IS NOT NULL
       AND a.actor_user_id NOT IN (SELECT user_id FROM platform_ops)
       AND NOT (a.action = 'organization_created'
                AND a.actor_user_id IN (SELECT user_id FROM msp_users))
       AND {_NOT_IMPERSONATED_BY_OPERATOR}
     ORDER BY a.created_at
     LIMIT :limit
    """
    params = _base_params(window, cfg) | {
        "actions": list(PLATFORM_ONLY_AUDIT_ACTIONS),
        "msp_slugs": list(MSP_ROLE_SLUGS),
    }
    return [
        DetectionHit(
            rule="platform_action_by_tenant",
            subject=f"{row['actor_user_id']}:{row['action']}",
            priority=P1,
            title="Tenant user performed a platform-only action",
            message=(
                f"{_masked_email(row['email']) or row['actor_user_id']} did "
                f"'{row['action']}' on {row['entity_type']} {row['entity_id']}."
            ),
            organization_id=_s(row["organization_id"]),
            details={
                "audit_entry_id": _s(row["id"]),
                "action": row["action"],
                "actor_user_id": _s(row["actor_user_id"]),
                "actor": _masked_email(row["email"]),
                "entity_id": _s(row["entity_id"]),
            },
        )
        for row in await _rows(session, sql, params)
    ]


# ============================================================================
# P1 rules: OTP / SMS volume
# ============================================================================


async def rule_otp_sms_volume(
    session: Any, window: DetectionWindow, cfg: Thresholds
) -> list[DetectionHit]:
    """R6: platform-wide SMS OTPs in the last hour against the same hour on
    each of the previous 7 days. Fires over ``sms_hourly_max`` outright, or
    over ``multiplier`` x baseline once past ``sms_baseline_min_count``."""
    sql = """
    SELECT
      (SELECT count(*) FROM otp_requests
        WHERE channel = 'sms'
          AND created_at >= CAST(:hour_ago AS timestamptz)
          AND created_at < CAST(:now AS timestamptz)) AS current_count,
      (SELECT count(*) FROM otp_requests o
         JOIN generate_series(1, 7) AS d(n)
           ON o.created_at >= CAST(:hour_ago AS timestamptz)
                              - make_interval(days => d.n)
          AND o.created_at < CAST(:now AS timestamptz)
                             - make_interval(days => d.n)
        WHERE o.channel = 'sms') AS baseline_total
    """
    params = {"now": window.now, "hour_ago": window.now - timedelta(hours=1)}
    row = (await _rows(session, sql, params))[0]
    current = int(row["current_count"])
    baseline = int(row["baseline_total"]) / 7.0
    over_cap = current > cfg.sms_hourly_max
    over_baseline = (
        current >= cfg.sms_baseline_min_count
        and current > cfg.sms_baseline_multiplier * baseline
    )
    if not (over_cap or over_baseline):
        return []
    return [
        DetectionHit(
            rule="otp_sms_volume",
            subject="platform",
            priority=P1,
            title="SMS OTP volume spike (possible SMS pumping)",
            message=(
                f"{current} SMS OTPs in the last hour; the same hour averaged "
                f"{baseline:.1f} over the last 7 days."
            ),
            details={
                "last_hour": current,
                "baseline_hourly_avg": round(baseline, 1),
                "hourly_cap": cfg.sms_hourly_max,
                "multiplier": cfg.sms_baseline_multiplier,
            },
        )
    ]


async def rule_otp_venueless_volume(
    session: Any, window: DetectionWindow, cfg: Thresholds
) -> list[DetectionHit]:
    """R7 (venue-less, P1): OTPs with no organization skip every venue gate,
    which is the pumping lane."""
    sql = """
    SELECT count(*) AS n, count(DISTINCT identifier) AS numbers,
           count(*) FILTER (WHERE channel = 'sms') AS sms
      FROM otp_requests
     WHERE organization_id IS NULL
       AND created_at >= CAST(:hour_ago AS timestamptz)
       AND created_at < CAST(:now AS timestamptz)
    """
    params = {"now": window.now, "hour_ago": window.now - timedelta(hours=1)}
    row = (await _rows(session, sql, params))[0]
    n = int(row["n"])
    if n <= cfg.venueless_otp_hourly_max:
        return []
    return [
        DetectionHit(
            rule="otp_venueless_volume",
            subject="platform",
            priority=P1,
            title="Venue-less OTP requests over threshold",
            message=(
                f"{n} OTPs with no organization in the last hour "
                f"({int(row['numbers'])} distinct identifiers)."
            ),
            details={
                "last_hour": n,
                "sms": int(row["sms"]),
                "distinct_identifiers": int(row["numbers"]),
                "hourly_max": cfg.venueless_otp_hourly_max,
            },
        )
    ]


# ============================================================================
# P1 rules: billing
# ============================================================================


async def rule_billing_webhook_unmatched(
    session: Any, window: DetectionWindow, cfg: Thresholds
) -> list[DetectionHit]:
    """R10a: a payment webhook that was verified and processed but resolved
    to no payment row (``entity_type='webhook_event'``)."""
    sql = """
    SELECT a.id, a.metadata->>'provider' AS provider,
           a.metadata->>'event_type' AS event_type
      FROM audit_log_entries a
     WHERE a.created_at >= CAST(:since AS timestamptz)
       AND a.created_at < CAST(:now AS timestamptz)
       AND a.action = 'billing_webhook_received'
       AND a.entity_type = 'webhook_event'
       AND a.metadata->>'event_type' = ANY(:event_types)
     ORDER BY a.created_at
     LIMIT :limit
    """
    params = _base_params(window, cfg) | {
        "event_types": list(PAYMENT_WEBHOOK_EVENT_TYPES)
    }
    return [
        DetectionHit(
            rule="billing_webhook_unmatched",
            subject=str(row["id"]),
            priority=P1,
            title="Payment webhook matched no payment",
            message=(
                f"{row['provider']} '{row['event_type']}' was processed but "
                "matched no payment row. Reconcile against the gateway."
            ),
            details={
                "audit_entry_id": _s(row["id"]),
                "provider": row["provider"],
                "event_type": row["event_type"],
            },
        )
        for row in await _rows(session, sql, params)
    ]


async def rule_license_activated_without_payment(
    session: Any, window: DetectionWindow, cfg: Thresholds
) -> list[DetectionHit]:
    """R10b: a license activated by the system (actor NULL = the webhook
    path) with no succeeded payment for that organization around it."""
    sql = """
    SELECT a.id, a.organization_id, a.entity_id AS license_id
      FROM audit_log_entries a
     WHERE a.created_at >= CAST(:since AS timestamptz)
       AND a.created_at < CAST(:now AS timestamptz)
       AND a.action = 'license_activated'
       AND a.actor_user_id IS NULL
       AND NOT EXISTS (
           SELECT 1 FROM payments p
            WHERE p.organization_id = a.organization_id
              AND p.status = 'succeeded' AND NOT p.is_deleted
              AND (p.updated_at BETWEEN a.created_at - interval '2 days'
                                    AND a.created_at + interval '1 hour'
                   OR p.created_at BETWEEN a.created_at - interval '2 days'
                                       AND a.created_at + interval '1 hour'))
     ORDER BY a.created_at
     LIMIT :limit
    """
    return [
        DetectionHit(
            rule="license_activated_without_payment",
            subject=str(row["id"]),
            priority=P1,
            title="License activated with no succeeded payment",
            message=(
                f"License {row['license_id']} was activated by the system with "
                "no succeeded payment for its organization in the prior 2 days."
            ),
            organization_id=_s(row["organization_id"]),
            details={
                "audit_entry_id": _s(row["id"]),
                "license_id": _s(row["license_id"]),
            },
        )
        for row in await _rows(session, sql, _base_params(window, cfg))
    ]


# ============================================================================
# P1 rule: vouchers across tenants
# ============================================================================


async def rule_voucher_cross_tenant(
    session: Any, window: DetectionWindow, cfg: Thresholds
) -> list[DetectionHit]:
    """R14 (vouchers): a guest session whose voucher belongs to another
    organization (P1), or to a batch pinned to another location (P2)."""
    sql = """
    SELECT gs.id AS session_id, gs.organization_id AS session_org,
           gs.location_id AS session_location, v.id AS voucher_id,
           v.organization_id AS voucher_org, vb.organization_id AS batch_org,
           vb.location_id AS batch_location, gs.router_id
      FROM guest_sessions gs
      JOIN vouchers v ON v.id = gs.voucher_id
      JOIN voucher_batches vb ON vb.id = v.batch_id
     WHERE gs.created_at >= CAST(:since AS timestamptz)
       AND gs.created_at < CAST(:now AS timestamptz)
       AND gs.voucher_id IS NOT NULL
       AND (gs.organization_id <> v.organization_id
            OR gs.organization_id <> vb.organization_id
            OR (vb.location_id IS NOT NULL AND vb.location_id <> gs.location_id))
     ORDER BY gs.created_at
     LIMIT :limit
    """
    hits = []
    for row in await _rows(session, sql, _base_params(window, cfg)):
        cross_org = (
            row["session_org"] != row["voucher_org"]
            or row["session_org"] != row["batch_org"]
        )
        hits.append(
            DetectionHit(
                rule="voucher_cross_org" if cross_org else "voucher_cross_venue",
                subject=str(row["voucher_id"]),
                priority=P1 if cross_org else P2,
                title=(
                    "Voucher redeemed in another organization"
                    if cross_org
                    else "Voucher redeemed at another venue"
                ),
                message=(
                    f"Session {row['session_id']} used voucher "
                    f"{row['voucher_id']} issued for "
                    + (
                        f"organization {row['batch_org']}"
                        if cross_org
                        else f"location {row['batch_location']}"
                    )
                    + "."
                ),
                organization_id=_s(row["session_org"]),
                details={
                    "session_id": _s(row["session_id"]),
                    "voucher_id": _s(row["voucher_id"]),
                    "voucher_organization_id": _s(row["voucher_org"]),
                    "batch_location_id": _s(row["batch_location"]),
                    "session_location_id": _s(row["session_location"]),
                    "router_id": _s(row["router_id"]),
                },
            )
        )
    return hits


# ============================================================================
# P2 rules (cheap ones from the report)
# ============================================================================


async def rule_role_self_assigned(
    session: Any, window: DetectionWindow, cfg: Thresholds
) -> list[DetectionHit]:
    """R3: a non-operator assigned a role to themselves."""
    sql = f"""
    WITH {_PLATFORM_OPS_CTE}
    SELECT a.id, a.actor_user_id, u.email, a.organization_id,
           a.metadata->>'role_id' AS role_id
      FROM audit_log_entries a
      LEFT JOIN users u ON u.id = a.actor_user_id
     WHERE a.created_at >= CAST(:since AS timestamptz)
       AND a.created_at < CAST(:now AS timestamptz)
       AND a.action = 'role_assigned'
       AND a.actor_user_id IS NOT NULL
       AND a.actor_user_id::text = a.metadata->>'target_user_id'
       AND a.actor_user_id NOT IN (SELECT user_id FROM platform_ops)
     LIMIT :limit
    """
    return [
        DetectionHit(
            rule="role_self_assigned",
            subject=f"{row['actor_user_id']}:{row['role_id']}",
            priority=P2,
            title="User assigned a role to themselves",
            message=(
                f"{_masked_email(row['email']) or row['actor_user_id']} assigned "
                f"role {row['role_id']} to themselves."
            ),
            organization_id=_s(row["organization_id"]),
            details={
                "audit_entry_id": _s(row["id"]),
                "actor_user_id": _s(row["actor_user_id"]),
                "actor": _masked_email(row["email"]),
                "role_id": row["role_id"],
            },
        )
        for row in await _rows(session, sql, _base_params(window, cfg))
    ]


async def rule_session_router_venue_mismatch(
    session: Any, window: DetectionWindow, cfg: Thresholds
) -> list[DetectionHit]:
    """R14 (H6): a guest session recorded at a location or organization the
    router does not belong to (cross-venue login)."""
    sql = """
    SELECT gs.id AS session_id, gs.router_id, gs.organization_id AS session_org,
           gs.location_id AS session_location, rt.organization_id AS router_org,
           rt.location_id AS router_location
      FROM guest_sessions gs
      JOIN routers rt ON rt.id = gs.router_id
     WHERE gs.created_at >= CAST(:since AS timestamptz)
       AND gs.created_at < CAST(:now AS timestamptz)
       AND (gs.location_id <> rt.location_id
            OR gs.organization_id <> rt.organization_id)
     LIMIT :limit
    """
    return [
        DetectionHit(
            rule="session_router_venue_mismatch",
            subject=str(row["router_id"]) + ":" + str(row["session_location"]),
            priority=P2,
            title="Guest session at a venue its router does not belong to",
            message=(
                f"Session {row['session_id']} on router {row['router_id']} is "
                f"recorded at location {row['session_location']}; the router "
                f"belongs to location {row['router_location']}."
            ),
            organization_id=_s(row["session_org"]),
            details={
                "session_id": _s(row["session_id"]),
                "router_id": _s(row["router_id"]),
                "session_location_id": _s(row["session_location"]),
                "router_location_id": _s(row["router_location"]),
                "router_organization_id": _s(row["router_org"]),
            },
        )
        for row in await _rows(session, sql, _base_params(window, cfg))
    ]


async def rule_otp_venue_volume(
    session: Any, window: DetectionWindow, cfg: Thresholds
) -> list[DetectionHit]:
    """R7 (per venue, P2): one location sending more SMS OTPs in an hour than
    any real lobby does."""
    sql = """
    SELECT location_id, organization_id, count(*) AS n
      FROM otp_requests
     WHERE channel = 'sms' AND location_id IS NOT NULL
       AND created_at >= CAST(:hour_ago AS timestamptz)
       AND created_at < CAST(:now AS timestamptz)
     GROUP BY location_id, organization_id
    HAVING count(*) > :max
     ORDER BY n DESC
     LIMIT :limit
    """
    params = {
        "now": window.now,
        "hour_ago": window.now - timedelta(hours=1),
        "max": cfg.venue_sms_hourly_max,
        "limit": cfg.max_hits_per_rule,
    }
    return [
        DetectionHit(
            rule="otp_venue_volume",
            subject=str(row["location_id"]),
            priority=P2,
            title="One venue's SMS OTP volume over threshold",
            message=(
                f"{row['n']} SMS OTPs in the last hour at location "
                f"{row['location_id']}."
            ),
            organization_id=_s(row["organization_id"]),
            details={
                "location_id": _s(row["location_id"]),
                "last_hour": int(row["n"]),
                "hourly_max": cfg.venue_sms_hourly_max,
            },
        )
        for row in await _rows(session, sql, params)
    ]


async def rule_otp_verify_ratio(
    session: Any, window: DetectionWindow, cfg: Thresholds
) -> list[DetectionHit]:
    """R8: share of OTPs that get verified collapses (codes sent to numbers
    nobody holds). The newest 10 minutes are left out: those codes may still
    be verified."""
    sql = """
    SELECT count(*) AS n, count(verified_at) AS verified
      FROM otp_requests
     WHERE created_at >= CAST(:start AS timestamptz)
       AND created_at < CAST(:end AS timestamptz)
    """
    params = {
        "start": window.now - timedelta(minutes=70),
        "end": window.now - timedelta(minutes=10),
    }
    row = (await _rows(session, sql, params))[0]
    n, verified = int(row["n"]), int(row["verified"])
    if n < cfg.otp_verify_ratio_min_sample or verified / n >= cfg.otp_verify_ratio_min:
        return []
    return [
        DetectionHit(
            rule="otp_verify_ratio",
            subject="platform",
            priority=P2,
            title="OTP verification ratio collapsed",
            message=f"Only {verified} of {n} OTPs in the last hour were verified.",
            details={
                "requested": n,
                "verified": verified,
                "min_ratio": cfg.otp_verify_ratio_min,
            },
        )
    ]


async def rule_billing_webhook_rejections(
    session: Any, window: DetectionWindow, cfg: Thresholds
) -> list[DetectionHit]:
    """R9: webhook signature failures (someone probing the endpoint)."""
    sql = """
    SELECT count(*) AS n FROM audit_log_entries
     WHERE action = 'billing_webhook_rejected'
       AND created_at >= CAST(:start AS timestamptz)
       AND created_at < CAST(:now AS timestamptz)
    """
    params = {"now": window.now, "start": window.now - timedelta(minutes=15)}
    n = int((await _rows(session, sql, params))[0]["n"])
    if n < cfg.webhook_rejected_max:
        return []
    return [
        DetectionHit(
            rule="billing_webhook_rejections",
            subject="platform",
            priority=P2,
            title="Billing webhook signature failures",
            message=f"{n} billing webhooks rejected in the last 15 minutes.",
            details={"last_15_min": n, "threshold": cfg.webhook_rejected_max},
        )
    ]


async def rule_dashboard_login_bruteforce(
    session: Any, window: DetectionWindow, cfg: Thresholds
) -> list[DetectionHit]:
    """R15: failed dashboard logins in the last 10 minutes, per email and
    platform-wide (credential stuffing)."""
    sql = """
    SELECT email, count(*) AS n
      FROM login_attempts
     WHERE NOT success
       AND created_at >= CAST(:start AS timestamptz)
       AND created_at < CAST(:now AS timestamptz)
     GROUP BY email
     ORDER BY n DESC
     LIMIT 1000
    """
    params = {"now": window.now, "start": window.now - timedelta(minutes=10)}
    rows = await _rows(session, sql, params)
    hits = [
        DetectionHit(
            rule="dashboard_login_bruteforce",
            subject=f"email:{row['email']}",
            priority=P2,
            title="Repeated failed dashboard logins for one account",
            message=(
                f"{row['n']} failed logins in 10 minutes for "
                f"{_masked_email(row['email'])}."
            ),
            details={
                "account": _masked_email(row["email"]),
                "failures": int(row["n"]),
            },
        )
        for row in rows
        if int(row["n"]) > cfg.login_failures_per_email_max
    ][: cfg.max_hits_per_rule]
    total = sum(int(row["n"]) for row in rows)
    if total > cfg.login_failures_total_max and len(rows) > (
        cfg.login_failures_distinct_emails
    ):
        hits.append(
            DetectionHit(
                rule="dashboard_login_stuffing",
                subject="platform",
                priority=P2,
                title="Failed dashboard logins across many accounts",
                message=(
                    f"{total} failed logins across {len(rows)} accounts in 10 minutes."
                ),
                details={"failures": total, "distinct_accounts": len(rows)},
            )
        )
    return hits


async def rule_voucher_guessing(
    session: Any, window: DetectionWindow, cfg: Thresholds
) -> list[DetectionHit]:
    """R17 (vouchers): failed voucher redemptions per location, 10 minutes."""
    sql = """
    SELECT location_id, organization_id, count(*) AS n
      FROM audit_log_entries
     WHERE action = 'voucher_redemption_failed'
       AND created_at >= CAST(:start AS timestamptz)
       AND created_at < CAST(:now AS timestamptz)
     GROUP BY location_id, organization_id
    HAVING count(*) > :max
     ORDER BY n DESC
     LIMIT :limit
    """
    params = {
        "now": window.now,
        "start": window.now - timedelta(minutes=10),
        "max": cfg.voucher_failures_per_location_max,
        "limit": cfg.max_hits_per_rule,
    }
    return [
        DetectionHit(
            rule="voucher_guessing",
            subject=str(row["location_id"]),
            priority=P3,
            title="Voucher code guessing",
            message=(
                f"{row['n']} failed voucher redemptions in 10 minutes at "
                f"location {row['location_id']}."
            ),
            organization_id=_s(row["organization_id"]),
            details={"location_id": _s(row["location_id"]), "failures": int(row["n"])},
        )
        for row in await _rows(session, sql, params)
    ]


async def rule_otp_guessing(
    session: Any, window: DetectionWindow, cfg: Thresholds
) -> list[DetectionHit]:
    """R17 (OTP): failed verifications against one OTP code, 10 minutes.
    Audit rows still accrue even where ``attempt_count`` undercounts."""
    sql = """
    SELECT entity_id, organization_id, location_id, count(*) AS n
      FROM audit_log_entries
     WHERE action = 'otp_verification_failed'
       AND entity_id IS NOT NULL
       AND created_at >= CAST(:start AS timestamptz)
       AND created_at < CAST(:now AS timestamptz)
     GROUP BY entity_id, organization_id, location_id
    HAVING count(*) > :max
     ORDER BY n DESC
     LIMIT :limit
    """
    params = {
        "now": window.now,
        "start": window.now - timedelta(minutes=10),
        "max": cfg.otp_failures_per_code_max,
        "limit": cfg.max_hits_per_rule,
    }
    return [
        DetectionHit(
            rule="otp_guessing",
            subject=str(row["entity_id"]),
            priority=P3,
            title="OTP code guessing",
            message=f"{row['n']} failed verifications against OTP {row['entity_id']}.",
            organization_id=_s(row["organization_id"]),
            details={
                "otp_request_id": _s(row["entity_id"]),
                "location_id": _s(row["location_id"]),
                "failures": int(row["n"]),
            },
        )
        for row in await _rows(session, sql, params)
    ]


RULES: tuple[DetectionRule, ...] = (
    # P1
    DetectionRule("tenant_role_platform_key", rule_tenant_role_platform_key),
    DetectionRule("tenant_role_global_scope", rule_tenant_role_global_scope),
    DetectionRule(
        "tenant_role_inherits_platform_role", rule_tenant_role_inherits_platform_role
    ),
    DetectionRule("tenant_override_platform_key", rule_tenant_override_platform_key),
    DetectionRule(
        "credential_reveal_by_non_operator", rule_credential_reveal_by_non_operator
    ),
    DetectionRule("platform_action_by_tenant", rule_platform_action_by_tenant),
    DetectionRule("otp_sms_volume", rule_otp_sms_volume, windowed=False),
    DetectionRule("otp_venueless_volume", rule_otp_venueless_volume, windowed=False),
    DetectionRule("billing_webhook_unmatched", rule_billing_webhook_unmatched),
    DetectionRule(
        "license_activated_without_payment", rule_license_activated_without_payment
    ),
    DetectionRule("voucher_cross_tenant", rule_voucher_cross_tenant),
    # P2 / P3
    DetectionRule("role_self_assigned", rule_role_self_assigned),
    DetectionRule("session_router_venue_mismatch", rule_session_router_venue_mismatch),
    DetectionRule("otp_venue_volume", rule_otp_venue_volume, windowed=False),
    DetectionRule("otp_verify_ratio", rule_otp_verify_ratio, windowed=False),
    DetectionRule(
        "billing_webhook_rejections", rule_billing_webhook_rejections, windowed=False
    ),
    DetectionRule(
        "dashboard_login_bruteforce", rule_dashboard_login_bruteforce, windowed=False
    ),
    DetectionRule("voucher_guessing", rule_voucher_guessing, windowed=False),
    DetectionRule("otp_guessing", rule_otp_guessing, windowed=False),
)


# ============================================================================
# Sweep engine
# ============================================================================


def _watermark_key(rule: str) -> str:
    return f"{REDIS_KEY_PREFIX}:watermark:{rule}"


def _dedup_key(hit: DetectionHit) -> str:
    return f"{REDIS_KEY_PREFIX}:dedup:{hit.rule}:{_hash(hit.subject)}"


_LOCK_KEY = f"{REDIS_KEY_PREFIX}:lock"


async def _window_for(
    redis: RedisLike, rule: DetectionRule, now: datetime, max_lookback_minutes: int
) -> DetectionWindow:
    floor = now - timedelta(minutes=max_lookback_minutes)
    if not rule.windowed:
        return DetectionWindow(since=floor, now=now)
    raw = await redis.get(_watermark_key(rule.name))
    since = now - timedelta(minutes=INITIAL_LOOKBACK_MINUTES)
    if raw:
        with contextlib.suppress(ValueError):
            since = datetime.fromisoformat(str(raw)) - timedelta(
                seconds=WATERMARK_OVERLAP_SECONDS
            )
    return DetectionWindow(since=max(since, floor), now=now)


@dataclass(slots=True)
class SweepResult:
    status: str = "ok"
    rules_run: int = 0
    rule_errors: dict[str, str] = field(default_factory=dict)
    hits: int = 0
    new_hits: int = 0
    events_written: int = 0
    emails_sent: int = 0

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "rules_run": self.rules_run,
            "rule_errors": dict(self.rule_errors),
            "hits": self.hits,
            "new_hits": self.new_hits,
            "events_written": self.events_written,
            "emails_sent": self.emails_sent,
        }


EmailSender = Callable[[str, str], Awaitable[int]]


def format_alert_email(hits: Sequence[DetectionHit]) -> tuple[str, str]:
    """One digest for every new hit of a sweep. Highest priority first."""
    ordered = sorted(hits, key=lambda h: (_PRIORITY_ORDER[h.priority], h.rule))
    top = ordered[0].priority
    subject = (
        f"[Wyfy security] {top}: {len(ordered)} new detection"
        f"{'s' if len(ordered) != 1 else ''} -- {ordered[0].title}"
    )
    lines = [
        "The security detection sweep found the following. Each is also a "
        "platform event (category 'security') in the Master console.",
        "",
    ]
    for hit in ordered:
        lines.append(f"[{hit.priority}] {hit.title}")
        lines.append(f"  {hit.message}")
        lines.append(f"  rule: {hit.event_type}")
        if hit.organization_id:
            lines.append(f"  organization_id: {hit.organization_id}")
        for key, value in hit.details.items():
            if value is not None:
                lines.append(f"  {key}: {value}")
        lines.append("")
    lines.append("Personal data is masked. Runbook: SOC report 2026-11-06, section 6.")
    return subject, "\n".join(lines)


async def run_security_detection_sweep(
    *,
    session_factory: Callable[[], Any],
    redis: RedisLike,
    settings: Any,
    send_email: EmailSender,
    rules: Sequence[DetectionRule] = RULES,
    now: datetime | None = None,
) -> SweepResult:
    result = SweepResult()
    if not settings.security_detection_enabled:
        result.status = "disabled"
        return result
    if not await redis.set(_LOCK_KEY, "1", nx=True, ex=SWEEP_LOCK_TTL_SECONDS):
        result.status = "locked"
        return result
    try:
        await _sweep(
            result,
            session_factory=session_factory,
            redis=redis,
            settings=settings,
            send_email=send_email,
            rules=rules,
            now=now or datetime.now(UTC),
        )
    finally:
        await redis.delete(_LOCK_KEY)
    return result


async def _sweep(
    result: SweepResult,
    *,
    session_factory: Callable[[], Any],
    redis: RedisLike,
    settings: Any,
    send_email: EmailSender,
    rules: Sequence[DetectionRule],
    now: datetime,
) -> None:
    cfg = Thresholds.from_settings(settings)
    timeout_ms = int(settings.security_detection_statement_timeout_ms)
    hits: list[DetectionHit] = []
    succeeded: list[DetectionRule] = []

    for rule in rules:
        window = await _window_for(
            redis, rule, now, settings.security_detection_max_lookback_minutes
        )
        try:
            async with session_factory() as session:
                # Both must be the first statements of the transaction.
                await session.execute(text("SET TRANSACTION READ ONLY"))
                await session.execute(
                    text(f"SET LOCAL statement_timeout = {timeout_ms}")
                )
                try:
                    rule_hits = await rule.run(session, window, cfg)
                finally:
                    await session.rollback()
        except Exception as exc:  # noqa: BLE001 -- one rule never stops the rest
            result.rule_errors[rule.name] = type(exc).__name__
            logger.warning(
                "security_detection_rule_failed",
                extra={"rule": rule.name, "error_type": type(exc).__name__},
            )
            continue
        result.rules_run += 1
        succeeded.append(rule)
        hits.extend(rule_hits[: cfg.max_hits_per_rule])

    result.hits = len(hits)
    dedup_ttl = int(settings.security_detection_dedup_hours) * 3600
    new_hits: list[DetectionHit] = []
    seen: set[str] = set()
    for hit in hits:
        key = _dedup_key(hit)
        if key in seen:
            continue
        seen.add(key)
        if await redis.set(key, now.isoformat(), nx=True, ex=dedup_ttl):
            new_hits.append(hit)
    result.new_hits = len(new_hits)

    if new_hits:
        try:
            await _write_events(session_factory, new_hits, now)
            result.events_written = len(new_hits)
        except Exception as exc:
            # Release the dedup claims so the next sweep reports them again.
            await redis.delete(*(_dedup_key(h) for h in new_hits))
            logger.error(
                "security_detection_event_write_failed",
                extra={"error_type": type(exc).__name__, "hits": len(new_hits)},
            )
            raise
        subject, body = format_alert_email(new_hits)
        result.emails_sent = await send_email(subject, body)
        for hit in new_hits:
            # The log line carries the same masked content as the email.
            logger.warning(
                "security_detection_hit",
                extra={
                    "rule": hit.rule,
                    "priority": hit.priority,
                    "detection_organization_id": hit.organization_id,
                },
            )

    for rule in succeeded:
        if rule.windowed:
            await redis.set(_watermark_key(rule.name), now.isoformat())

    logger.info("security_detection_sweep_completed", extra=result.as_dict())


async def _write_events(
    session_factory: Callable[[], Any], hits: Sequence[DetectionHit], now: datetime
) -> None:
    from .models import PlatformEvent

    async with session_factory() as session:
        for hit in hits:
            session.add(
                PlatformEvent(
                    category=EventCategory.SECURITY.value,
                    event_type=hit.event_type,
                    severity=hit.severity,
                    # NULL on purpose -- see module docstring, "What a tenant
                    # can see".
                    organization_id=None,
                    location_id=None,
                    router_id=None,
                    source_domain=SECURITY_EVENT_SOURCE_DOMAIN,
                    message=f"{hit.title}: {hit.message}",
                    event_metadata={
                        "rule": hit.rule,
                        "priority": hit.priority,
                        "subject_hash": _hash(hit.subject),
                        "organization_id": hit.organization_id,
                        **hit.details,
                    },
                    occurred_at=now,
                )
            )
        await session.commit()


async def send_platform_alert_email(subject: str, body: str) -> int:
    """Same destination and isolation as ``billing.tasks
    ._send_reconciliation_alert``: every address is tried; a failure is
    logged and never blocks the others."""
    from app.domains.otp.service import get_configured_email_provider

    settings = get_settings()
    recipients = settings.platform_alert_email_list
    if not recipients:
        logger.error(
            "security_detection_alert_unrouted",
            extra={"reason": "platform_alert_emails is empty"},
        )
        return 0
    provider = get_configured_email_provider(settings)
    sent = 0
    for address in recipients:
        try:
            await provider.send(address, subject, body)
            sent += 1
        except Exception as exc:  # noqa: BLE001 -- one address never blocks the rest
            logger.warning(
                "security_detection_alert_email_failed",
                extra={"error_type": type(exc).__name__},
            )
    return sent


# ============================================================================
# Celery task
# ============================================================================


async def _security_detection_sweep_async() -> dict[str, object]:
    redis = create_redis_client()
    try:
        result = await run_security_detection_sweep(
            session_factory=SessionLocal,
            redis=redis,
            settings=get_settings(),
            send_email=send_platform_alert_email,
        )
    finally:
        await redis.aclose()
    return result.as_dict()


@celery_app.task(
    name=TASK_SECURITY_DETECTION_SWEEP,
    # The worker shares one prefork pool across the celery, device_io and
    # marketing queues, so a hung sweep holds a slot the guest-facing tasks
    # need. Each rule is already capped by statement_timeout; this caps the
    # whole run, well inside the 5-minute interval.
    soft_time_limit=120,
    time_limit=150,
)
def security_detection_sweep() -> dict[str, object]:
    """Beat-scheduled every 5 minutes (``security-detection-sweep``)."""
    return run_celery_task(_security_detection_sweep_async())


__all__ = [
    "RULES",
    "DetectionHit",
    "DetectionRule",
    "DetectionWindow",
    "SweepResult",
    "Thresholds",
    "format_alert_email",
    "run_security_detection_sweep",
    "security_detection_sweep",
    "send_platform_alert_email",
]
