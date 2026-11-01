"""DASH-1: the subscriber operations dashboard, pure part.

Every subscriber lands in exactly ONE bucket, so the buckets add up to
``total``. The bucket comes from JAZE-1's ``display_state`` (the single source
of truth, ``IspSubscriber360Service.display_state``), plus JAZE-3's KYC record
for "pending" and JAZE-3's churn threshold for "churned":

* ``blocked``: display state ``blocked`` or ``permanently_blocked``.
* ``frozen``: display state ``frozen``.
* ``suspended``: display state ``suspended`` (the customer's service is cut).
* ``pending``: display state ``scheduled`` (activation date in the future), or
  ``active`` / ``grace`` with a KYC record that is not verified yet or has no
  installation date (waiting on KYC or install).
* ``churned``: display state ``expired`` and expired longer than the ISP's
  ``churn_after_days`` (JAZE-3 compliance setting, default 60).
* ``expired``: display state ``expired``, within ``churn_after_days``.
* ``active``: display state ``active`` or ``grace``, not pending.
* ``other``: everything else (``disabled``, or any state a later lane adds).

Overlays are counted on top and never add to ``total``:

* ``expiring_7d``: ``active`` and ``valid_until`` within the next 7 days, on a
  prepaid (or package-less) plan: the subscriber has to recharge.
* ``scheduled_renewals``: ``active`` and ``valid_until`` within the next 7
  days on a postpaid package: the billing run renews it.
* ``new_in_period``: created inside the selected period.
* ``online``: has a live hotspot session or (PPPoE on) a live PPPoE session.

Open leads (JAZE-5) waiting on feasibility or install are reported next to
"pending" as ``pending_leads``. They are not subscribers, so they are not in
``total`` and not in the subscriber drill-down.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from typing import Any

BUCKETS: tuple[str, ...] = (
    "active",
    "pending",
    "suspended",
    "frozen",
    "blocked",
    "expired",
    "churned",
    "other",
)
OVERLAYS: tuple[str, ...] = (
    "online",
    "expiring_7d",
    "scheduled_renewals",
    "new_in_period",
)
#: Every key a tile (and so a drill-down) can carry.
TILE_KEYS: tuple[str, ...] = (*BUCKETS, *OVERLAYS, "total")

#: Open lead statuses (JAZE-5 ``LeadStatus``): not converted, dropped or
#: refused as not feasible.
OPEN_LEAD_STATUSES: tuple[str, ...] = (
    "new",
    "contacted",
    "feasibility_pending",
    "feasible",
    "install_scheduled",
)

DEFINITIONS: dict[str, str] = {
    "active": "Service on and valid (including a grace period), with nothing pending.",
    "pending": (
        "Activation is scheduled for later, or KYC is not verified yet, or "
        "installation is not recorded yet."
    ),
    "suspended": "The customer's service is suspended, so this subscriber is cut.",
    "frozen": "Validity is paused (frozen) by the ISP.",
    "blocked": "Blocked by the ISP, temporarily or permanently.",
    "expired": "Validity has ended, within the churn window.",
    "churned": "Validity ended longer ago than the churn window (Compliance settings).",
    "other": "Any other state, for example switched off (disabled).",
    "total": "Every subscriber in view. The eight states above add up to this.",
    "online": "Has a live hotspot session or a live PPPoE session right now.",
    "expiring_7d": "Active prepaid subscribers whose validity ends in the next 7 days.",
    "scheduled_renewals": (
        "Active postpaid subscribers whose period ends in the next 7 days; "
        "the billing run renews them."
    ),
    "new_in_period": "Subscribers created inside the selected period.",
    "pending_leads": (
        "Leads still waiting on feasibility or installation. Not subscribers yet, "
        "so not in the total."
    ),
}


def bucket_of(
    display_state: str,
    *,
    valid_until: datetime | None,
    now: datetime,
    churn_after: timedelta,
    kyc_pending: bool = False,
) -> str:
    if display_state in ("blocked", "permanently_blocked"):
        return "blocked"
    if display_state in ("frozen", "suspended"):
        return display_state
    if display_state == "scheduled":
        return "pending"
    if display_state == "expired":
        if valid_until is not None and now - valid_until > churn_after:
            return "churned"
        return "expired"
    if display_state in ("active", "grace"):
        return "pending" if kyc_pending else "active"
    return "other"


def overlays_of(
    bucket: str,
    *,
    valid_until: datetime | None,
    created_at: datetime | None,
    package_type: str | None,
    online: bool,
    now: datetime,
    period_start: datetime,
    period_end: datetime,
) -> set[str]:
    out: set[str] = set()
    if online:
        out.add("online")
    if (
        bucket == "active"
        and valid_until is not None
        and now < valid_until <= now + timedelta(days=7)
    ):
        out.add("scheduled_renewals" if package_type == "postpaid" else "expiring_7d")
    if created_at is not None and period_start <= created_at < period_end:
        out.add("new_in_period")
    return out


def tally(rows: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    """``rows``: dicts with ``bucket`` and ``overlays``. All TILE_KEYS present."""
    out = dict.fromkeys(TILE_KEYS, 0)
    for r in rows:
        out[r["bucket"]] += 1
        out["total"] += 1
        for o in r["overlays"]:
            out[o] += 1
    return out


def in_tile(key: str, row: Mapping[str, Any]) -> bool:
    """Exactly the rows a tile counted (the drill-down's filter)."""
    if key == "total":
        return True
    if key in BUCKETS:
        return row["bucket"] == key
    return key in row["overlays"]


__all__ = [
    "BUCKETS",
    "DEFINITIONS",
    "OPEN_LEAD_STATUSES",
    "OVERLAYS",
    "TILE_KEYS",
    "bucket_of",
    "in_tile",
    "overlays_of",
    "tally",
]
