"""Pydantic request/response schemas for the Router Readiness Checklist
domain."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from .constants import ChecklistCategory, ChecklistItemStatus, DetectionMode

#: Keys stripped from ``ChecklistItemResponse.evidence`` before it leaves
#: the API.
#:
#: ``evidence`` is a free-form ``dict[str, Any]`` copied out of a JSONB
#: column, and ``GET /readiness/routers/{router_id}/checklist`` is gated on
#: a bare ``readiness.read``, which an organization-scoped Network
#: Administrator holds. So whatever a detection routine chose to record
#: about a device went straight to that device's venue admin, with no
#: schema in between deciding whether it should.
#:
#: For a MikroTik that is the whole point -- ``peer_status``,
#: ``unguarded_interfaces``, ``enabled_link_count`` are the evidence behind
#: a red tick, and the operator looking at them owns the router. For a
#: controller-managed row it is a different audience: the checks that run
#: are ``NOT_APPLICABLE`` plus ``CONTROLLER_INTEGRATION``, and between them
#: they were emitting the integration's primary key, its internal status
#: string, its enabled flag, the vocabulary of its unfinished controller
#: configuration, and the ``routers.vendor`` value naming the controller
#: product -- to a venue admin who, per this product's access decision, is
#: not shown the integration at all.
#:
#: **Inert for MikroTik by construction.** Every key below is written by
#: exactly one branch of ``ReadinessService._run_auto_detection``: the
#: ``not is_agent_managed(router)`` branch and the
#: ``_check_controller_integration`` call that only that branch makes.
#: Nothing on the agent-managed path emits any of them -- note in
#: particular that the two generic keys a MikroTik check *does* share the
#: shape of, ``lookup_available`` (rogue-DHCP) and
#: ``config_version_lookup_available`` (guest data path), are deliberately
#: NOT in this set. ``tests/unit/test_readiness.py`` pins that: a MikroTik
#: checklist's evidence must come back identical.
#:
#: ``integration_linked`` is deliberately kept. It is a bare boolean, it
#: names nothing, and the item's own ``detail`` already says the same thing
#: in a sentence written for a venue owner -- withholding it would make the
#: item's status unexplainable without making anything safer.
CUSTOMER_FORBIDDEN_EVIDENCE_KEYS: frozenset[str] = frozenset(
    {
        # The integration's primary key: the join from a router a venue
        # admin can see to the controller surface they cannot.
        "integration_id",
        # The internal IntegrationStatus vocabulary (AUTH_FAILED,
        # CONNECTING, SYNC_ERROR...) -- a statement about the platform's
        # connection to the controller, not about the venue's WiFi.
        "integration_status",
        # Whether the integration is switched on. A control the venue admin
        # does not have and a state they cannot act on.
        "is_enabled",
        # PortalReadinessGap values -- site_not_selected, ssid_not_selected,
        # guest_operator_missing. This is controller configuration named
        # field by field, which is precisely what is being withheld.
        "readiness_gaps",
        # routers.vendor, i.e. the controller product. The venue's own
        # equipment class is not a secret and RouterResponse still carries
        # it (see app.domains.router.schemas), but nothing on this
        # checklist reads it, so there is no reason for a second copy to
        # ride along inside a free-form blob nobody schema-checked.
        "vendor",
    }
)


def redact_customer_evidence(evidence: dict[str, Any] | None) -> dict[str, Any]:
    """``evidence`` with every controller-identifying key removed.

    A denylist, for the reason
    ``app.domains.router.schemas.redact_customer_router_settings`` gives
    for its own: ``evidence`` carries roughly two dozen legitimate
    MikroTik diagnostic keys today and will grow, and an allowlist would
    start withholding new ones from the operators they were written for.
    Every key it does name is emitted only on the controller-managed
    branch, so this takes nothing from a MikroTik venue.
    """
    if not evidence:
        return {}
    return {
        key: value
        for key, value in evidence.items()
        if key not in CUSTOMER_FORBIDDEN_EVIDENCE_KEYS
    }


class ChecklistItemResponse(BaseModel):
    item_key: str
    label: str
    description: str
    category: ChecklistCategory
    status: ChecklistItemStatus
    detection_mode: DetectionMode
    detail: str | None = None
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Raw detection evidence behind this item's status, minus every "
            "key in CUSTOMER_FORBIDDEN_EVIDENCE_KEYS -- see "
            "redact_customer_evidence."
        ),
    )
    last_checked_at: datetime | None = None
    checked_by_user_id: str | None = None


class ChecklistSummary(BaseModel):
    total: int
    passing: int
    failing: int
    not_checked: int
    # Checks that cannot apply to this device at all -- a controller-managed
    # fleet row (TP-Link Omada) has no agent, no WireGuard peer and no
    # RouterOS API to check. Defaulted so a caller reading an older response
    # shape, or a service that has not been redeployed, still validates.
    not_applicable: int = 0


class ChecklistResponse(BaseModel):
    router_id: str
    summary: ChecklistSummary
    items: list[ChecklistItemResponse]


class ConfirmChecklistItemRequest(BaseModel):
    status: ChecklistItemStatus = Field(
        ...,
        description=(
            "Must be manually_confirmed or manually_failed -- this endpoint "
            "records a human decision, it does not re-run auto-detection."
        ),
    )
    detail: str | None = Field(default=None, max_length=500)


__all__ = [
    "CUSTOMER_FORBIDDEN_EVIDENCE_KEYS",
    "redact_customer_evidence",
    "ChecklistItemResponse",
    "ChecklistSummary",
    "ChecklistResponse",
    "ConfirmChecklistItemRequest",
]
