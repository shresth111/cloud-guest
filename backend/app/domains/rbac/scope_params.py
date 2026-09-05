"""Which request parameters name an organization, a location, or a router.

One table, shared by the thing that *enforces* scope
(``dependencies._current_scope_context``) and the thing that *audits* it
(``tests/unit/test_scope_parameter_coverage.py``). They must agree: a
parameter the resolver does not recognise is a parameter the permission check
silently ignores, and the coverage test exists to make that impossible to
introduce by accident.

## Why a table rather than a naming rule

``_current_scope_context`` used to look for path parameters spelled exactly
``organization_id``/``location_id``/``router_id``. ``GET
/customers/{customer_id}/features`` names an organization -- ``customer_id`` is
handed straight to ``LicenseService.get_entitlement_snapshot(organization_id)``
-- but it is not spelled that way, so the fallback did not fire, the check ran
against the caller's own ``X-Organization-Id`` header, and any tenant holding
``billing.read`` could read another tenant's plan, limits and support tier.

A convention ("anything ending ``_id``") would be worse than a table: most
``*_id`` parameters name a rule, a campaign, an invoice -- entities whose
tenancy the service layer resolves, not scope dimensions RBAC can compare. A
table is explicit about the small set that genuinely are scope, and the
coverage test fails when a new parameter name appears that is neither in the
table nor explicitly declared not-scope.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "NOT_SCOPE_BEARING_ID_PARAMS",
    "SCOPE_PARAM_ALIASES",
    "ScopeDimension",
    "scope_dimension_for",
]


class ScopeDimension(StrEnum):
    """The three tenancy dimensions ``ScopeContext`` carries."""

    ORGANIZATION = "organization"
    LOCATION = "location"
    ROUTER = "router"


# Parameter name -> the scope dimension it identifies. Keys are matched
# case-sensitively against FastAPI's own resolved path and query parameter
# names for the route.
SCOPE_PARAM_ALIASES: dict[str, ScopeDimension] = {
    # -- organization --------------------------------------------------------
    "organization_id": ScopeDimension.ORGANIZATION,
    # `/customers/{customer_id}/features` -- there is no separate "customer"
    # entity in this codebase; the value is an organization id. This is the
    # alias that motivated the whole table.
    "customer_id": ScopeDimension.ORGANIZATION,
    # `/billing/dashboard/failed-payments` -- an organization filter whose
    # name carries the report it belongs to.
    "failed_payments_organization_id": ScopeDimension.ORGANIZATION,
    # -- location ------------------------------------------------------------
    "location_id": ScopeDimension.LOCATION,
    # -- router --------------------------------------------------------------
    "router_id": ScopeDimension.ROUTER,
}


# ``*_id`` parameters that are deliberately **not** scope dimensions. Every one
# names an entity whose tenancy the service layer resolves by loading the row
# and comparing its owning organization -- RBAC cannot compare them, because a
# rule id says nothing about which tenant it belongs to until it is read.
#
# Listed explicitly rather than inferred, so that a genuinely new scope-bearing
# parameter cannot be introduced silently: the coverage test fails on any
# ``*_id`` parameter that is in neither this set nor ``SCOPE_PARAM_ALIASES``,
# which forces a decision instead of a default.
NOT_SCOPE_BEARING_ID_PARAMS: frozenset[str] = frozenset(
    {
        "actor_user_id",
        "agent_id",
        "alert_id",
        "api_key_id",
        "asset_id",
        "assignment_id",
        "backup_id",
        "batch_id",
        "booking_id",
        "campaign_id",
        "channel_id",
        "channel_partner_id",
        "config_id",
        "conversation_id",
        "coupon_id",
        "delivery_id",
        "demo_request_id",
        "device_id",
        "enrollment_id",
        "entry_id",
        "guest_id",
        "incident_id",
        "invoice_id",
        "job_id",
        "license_id",
        "link_id",
        "member_id",
        "nas_id",
        "other_version_id",
        "payment_id",
        "payment_method_id",
        "permission_group_id",
        "plan_id",
        "policy_id",
        "pool_id",
        "profile_id",
        "question_id",
        "quotation_id",
        "record_id",
        "role_assignment_id",
        "role_id",
        "rule_id",
        "run_id",
        "schedule_id",
        "series_id",
        "session_id",
        "snapshot_id",
        "subscription_id",
        "target_id",
        "target_version_id",
        "tax_rate_id",
        "team_id",
        "template_id",
        "ticket_id",
        "user_id",
        "variable_id",
        "version_id",
    }
)


def scope_dimension_for(param_name: str) -> ScopeDimension | None:
    """The scope dimension ``param_name`` identifies, or ``None``."""
    return SCOPE_PARAM_ALIASES.get(param_name)
