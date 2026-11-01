"""REVENUE-HUB + CHURN-RISK, pure part (no I/O). Every rule the hub and the
churn-risk list apply lives here, so the definitions in ``DEFINITIONS`` and
the code cannot drift apart.

Subscriber states are the Overview's (DASH-1 ``dashboard_logic.bucket_of``
over JAZE-1 ``display_state``, plus JAZE-3 KYC and churn window); this module
never re-derives them:

* **active**: DASH-1 bucket ``active`` (active or grace, KYC + installation
  done). These are the paying subscribers. MRR and ARPU are taken over them.
* **pending**: DASH-1 bucket ``pending`` (activation scheduled, or KYC /
  installation outstanding). Not in MRR.
* **churned** / **expired**: DASH-1 buckets ``churned`` / ``expired``. The
  moment of churn is ``valid_until + churn_after_days``.
* **other**: DASH-1 buckets suspended, frozen, blocked, other.

Money is integer paise. MRR and billed revenue are GST-exclusive (taxable
value); dues and collections are what the subscriber owes / paid (GST
included), because that is the money that moves.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from .gst import compute_line

#: One month for MRR normalisation (package validity is counted in days).
MONTH_DAYS = 30

STATES: tuple[str, ...] = ("active", "pending", "expired", "churned", "other")

#: Dues ageing by days past the invoice's due date. ``not_due`` holds open
#: invoices whose due date has not come yet, so the five buckets add up to
#: all open dues.
AGEING: tuple[str, ...] = ("not_due", "d0_30", "d31_60", "d61_90", "d90_plus")

#: Drill-down keys a KPI tile opens (``GET /isp/revenue/list?metric=``).
SUBSCRIBER_METRICS: tuple[str, ...] = (
    "active",
    "pending",
    "expired",
    "churned",
    "other",
    "unpriced",
    "new",
    "lost",
)
INVOICE_METRICS: tuple[str, ...] = (*(f"dues_{a}" for a in AGEING), "uncollected")
LIST_METRICS: tuple[str, ...] = (*SUBSCRIBER_METRICS, *INVOICE_METRICS)

#: CHURN-RISK reasons, in display order.
RISK_REASONS: tuple[str, ...] = (
    "expired_recently",
    "expiring_no_payment",
    "late_payments",
    "tickets",
    "fup_hits",
    "long_offline",
)
#: Weight of each reason in the score. A subscriber's score is the sum of its
#: reasons' weights; the list is sorted by score, then by validity end.
RISK_WEIGHTS: dict[str, int] = {
    "expired_recently": 40,
    "expiring_no_payment": 30,
    "late_payments": 25,
    "tickets": 20,
    "fup_hits": 10,
    "long_offline": 15,
}


@dataclass(frozen=True)
class RiskRules:
    """Thresholds of the churn-risk rules (fixed; shown in ``definitions``)."""

    expiring_days: int = 7
    payment_lookback_days: int = 90
    late_lookback_days: int = 180
    late_min: int = 2
    ticket_lookback_days: int = 30
    ticket_repeat_min: int = 2
    fup_lookback_days: int = 30
    offline_days: int = 7


RULES = RiskRules()

DEFINITIONS: dict[str, str] = {
    "dso": (
        "Days sales outstanding: open subscriber dues / subscriber invoices "
        "billed in the last 90 days (GST included, less credit notes) x 90. "
        "Empty when nothing was billed."
    ),
    "mrr_history": (
        "Past months use the last daily snapshot taken in that month (whole "
        "ISP only). Without one, the month in progress shows today's MRR and "
        "older months show that month's billed value as a stand-in."
    ),
    "active": (
        "The Overview's Active: JAZE-1 state active or grace with KYC and "
        "installation done. MRR and ARPU are taken over them."
    ),
    "expired": (
        "State expired, but for no longer than the churn window (Compliance "
        "settings, default 60 days). Not churned yet: they can still renew."
    ),
    "churned": (
        "State expired for longer than the churn window. Churned on "
        "valid-until + churn window."
    ),
    "pending": (
        "The Overview's Pending: activation scheduled for later, or KYC / "
        "installation not done yet. Not in MRR."
    ),
    "other": "Blocked, frozen, suspended or switched off.",
    "mrr": (
        "Monthly recurring revenue: for every active subscriber, the price they "
        "renew at (the 360 override price, else the package price) without GST, "
        "scaled to 30 days (price x 30 / validity days). Active subscribers "
        "without a priced package add 0 and are counted as 'unpriced'."
    ),
    "arpu": "MRR divided by the number of active subscribers.",
    "unpriced": (
        "Active subscribers with no package, a free package or 0 validity days."
    ),
    "new": "Subscribers created in the month (ISP time zone).",
    "lost": (
        "Subscribers who churned in the month (valid-until + churn window "
        "falls in it)."
    ),
    "churn_rate": (
        "Lost in the month divided by the base at the start of the month: "
        "subscribers created before the month that had not churned before it. "
        "Deleted subscribers are not counted, and a subscriber who churned and "
        "later renewed counts as never lost (their validity moved on)."
    ),
    "billed": (
        "Subscriber invoices issued in the month (not cancelled): taxable value "
        "for 'billed', and total less credit notes for 'net billed'."
    ),
    "collected": "Amount paid so far on the subscriber invoices issued in the month.",
    "collection_rate": (
        "Collected divided by net billed, for invoices issued in the month, as of "
        "today. Customer (venue) and zone invoices are not part of the hub."
    ),
    "dues": (
        "Open subscriber invoices (issued or part paid) with a balance, by days "
        "past the due date: not due yet, 0-30, 31-60, 61-90, over 90."
    ),
    "uncollected": "Invoices issued in the month that still have a balance.",
    "zones": (
        "Each subscriber counts in its own zone, else its customer's zone; each "
        "invoice in the zone it was issued in, else its customer's zone. "
        "Wallet balance is the JAZE-4 zone ledger (shown only with the ledger "
        "switched on, and not to staff confined to some customers)."
    ),
    "packages": "Active subscribers and MRR per package (current package).",
    "churn_risk": (
        "Rule-based, no prediction. Each row lists the rules it matched with the "
        "measured values; the score is the sum of the rule weights."
    ),
    "expired_recently": (
        "Validity ended, not renewed yet, still inside the churn window: the best "
        "time to win them back."
    ),
    "expiring_no_payment": (
        f"Active, validity ends in the next {RULES.expiring_days} days, and no "
        f"confirmed payment in the last {RULES.payment_lookback_days} days."
    ),
    "late_payments": (
        f"At least {RULES.late_min} subscriber invoices from the last "
        f"{RULES.late_lookback_days} days were paid after their due date or are "
        "overdue now."
    ),
    "tickets": (
        "An open helpdesk ticket, or at least "
        f"{RULES.ticket_repeat_min} tickets raised in the last "
        f"{RULES.ticket_lookback_days} days (needs the Apps helpdesk switched on)."
    ),
    "fup_hits": (
        f"Throttled by the fair-usage policy in the last {RULES.fup_lookback_days} "
        "days (JAZE-2 enforcement events)."
    ),
    "long_offline": (
        f"Active, but no hotspot or PPPoE session seen for {RULES.offline_days} "
        "days or more (or never, when created that long ago)."
    ),
}


# --------------------------------------------------------------------------
# months
# --------------------------------------------------------------------------


def month_start(d: date) -> date:
    return d.replace(day=1)


def add_months(d: date, n: int) -> date:
    y, m = divmod(d.month - 1 + n, 12)
    return date(d.year + y, m + 1, 1)


def parse_month(raw: str | None, today: date) -> date:
    """``YYYY-MM`` -> first day; None -> this month. Raises ValueError."""
    if not raw:
        return month_start(today)
    y, m = raw.split("-")
    if len(y) != 4 or len(m) != 2:
        raise ValueError("month is YYYY-MM")
    return date(int(y), int(m), 1)


def month_bounds(first: date, tz: str) -> tuple[datetime, datetime]:
    """UTC instants [start, end) of the calendar month in the ISP time zone."""
    zone = ZoneInfo(tz or "Asia/Kolkata")
    start = datetime.combine(first, time.min, tzinfo=zone).astimezone(UTC)
    end = datetime.combine(add_months(first, 1), time.min, tzinfo=zone).astimezone(UTC)
    return start, end


def month_key(d: date) -> str:
    return f"{d.year:04d}-{d.month:02d}"


def local_date(dt: datetime, tz: str) -> date:
    return dt.astimezone(ZoneInfo(tz or "Asia/Kolkata")).date()


# --------------------------------------------------------------------------
# states, MRR
# --------------------------------------------------------------------------


def state_of(bucket: str) -> str:
    """Revenue state of a DASH-1 bucket (``dashboard_logic.bucket_of``, the
    single rule for "active"; the Overview and the hub never disagree)."""
    if bucket in ("active", "pending", "expired", "churned"):
        return bucket
    return "other"  # suspended, frozen, blocked, other


def churned_at(
    state: str, valid_until: datetime | None, churn_after: timedelta
) -> datetime | None:
    """When a churned subscriber crossed the churn window; None otherwise."""
    if state != "churned" or valid_until is None:
        return None
    return valid_until + churn_after


def monthly_paise(
    price_paise: int | None,
    validity_days: int | None,
    *,
    includes_gst: bool,
    gst_applied: bool,
    rate_bp: int,
) -> int | None:
    """The taxable value of one renewal scaled to 30 days; None = unpriced."""
    if not price_paise or price_paise <= 0 or not validity_days or validity_days <= 0:
        return None
    taxable = compute_line(
        int(price_paise),
        includes_gst=includes_gst,
        gst_applied=gst_applied,
        rate_bp=rate_bp,
        intra_state=True,
    ).taxable
    return (taxable * MONTH_DAYS + validity_days // 2) // validity_days


def ageing_bucket(due: date, today: date) -> str:
    days = (today - due).days
    if days < 0:
        return "not_due"
    if days <= 30:
        return "d0_30"
    if days <= 60:
        return "d31_60"
    if days <= 90:
        return "d61_90"
    return "d90_plus"


def rate(num: int, den: int) -> float | None:
    """A ratio rounded to 4 places; None when there is nothing to divide by."""
    return round(num / den, 4) if den > 0 else None


def base_at(
    created: Iterable[tuple[datetime | None, datetime | None]], at: datetime
) -> int:
    """Subscribers created before ``at`` that had not churned before it.
    ``created`` yields (created_at, churned_at)."""
    return sum(
        1 for c, ch in created if c is not None and c < at and (ch is None or ch >= at)
    )


# --------------------------------------------------------------------------
# churn risk
# --------------------------------------------------------------------------


@dataclass
class RiskFacts:
    """What we measured for one subscriber (all optional: a missing source
    means the rule simply cannot fire)."""

    state: str
    valid_until: datetime | None
    created_at: datetime | None
    last_payment_at: datetime | None = None
    late_invoices: int = 0
    open_tickets: int | None = None
    recent_tickets: int | None = None
    fup_hits: int = 0
    last_fup_at: datetime | None = None
    last_seen_at: datetime | None = None
    reasons: list[dict] = field(default_factory=list)


def _fmt(dt: datetime | None, tz: str) -> str:
    return local_date(dt, tz).strftime("%d %b %Y") if dt else "never"


def risk_reasons(
    f: RiskFacts, *, now: datetime, tz: str, rules: RiskRules = RULES
) -> list[dict]:
    """The rules ``f`` matches, each ``{code, weight, label, detail}``.
    ``detail`` states the measured values, so the row explains itself."""
    out: list[dict] = []

    def add(code: str, label: str, detail: str) -> None:
        out.append(
            {
                "code": code,
                "weight": RISK_WEIGHTS[code],
                "label": label,
                "detail": detail,
            }
        )

    if f.state == "expired" and f.valid_until is not None:
        days = (now - f.valid_until).days
        add(
            "expired_recently",
            "Expired, not renewed",
            f"Validity ended on {_fmt(f.valid_until, tz)} ({days} days ago) "
            "and there is no renewal since.",
        )
    if (
        f.state == "active"
        and f.valid_until is not None
        and now < f.valid_until <= now + timedelta(days=rules.expiring_days)
        and (
            f.last_payment_at is None
            or f.last_payment_at < now - timedelta(days=rules.payment_lookback_days)
        )
    ):
        left = max(0, (f.valid_until - now).days)
        add(
            "expiring_no_payment",
            "Expiring, no recent payment",
            f"Validity ends on {_fmt(f.valid_until, tz)} (in {left} days); last "
            f"confirmed payment: {_fmt(f.last_payment_at, tz)}.",
        )
    if f.late_invoices >= rules.late_min:
        add(
            "late_payments",
            "Pays late",
            f"{f.late_invoices} invoices from the last {rules.late_lookback_days} "
            "days were paid after the due date or are overdue now.",
        )
    if f.open_tickets is not None and (
        f.open_tickets > 0 or (f.recent_tickets or 0) >= rules.ticket_repeat_min
    ):
        parts = []
        if f.open_tickets:
            parts.append(f"{f.open_tickets} open")
        if f.recent_tickets:
            parts.append(
                f"{f.recent_tickets} raised in the last "
                f"{rules.ticket_lookback_days} days"
            )
        add("tickets", "Complaints", "Helpdesk tickets: " + ", ".join(parts) + ".")
    if f.fup_hits > 0:
        add(
            "fup_hits",
            "Hit the fair-usage limit",
            f"Throttled {f.fup_hits} times in the last {rules.fup_lookback_days} "
            f"days (last on {_fmt(f.last_fup_at, tz)}).",
        )
    if f.state == "active":
        cutoff = now - timedelta(days=rules.offline_days)
        never = f.last_seen_at is None
        if (never and f.created_at is not None and f.created_at < cutoff) or (
            not never and f.last_seen_at < cutoff
        ):
            add(
                "long_offline",
                "Not using the service",
                "No hotspot or PPPoE session ever."
                if never
                else f"Last online on {_fmt(f.last_seen_at, tz)} "
                f"({(now - f.last_seen_at).days} days ago).",
            )
    return out


def risk_score(reasons: list[dict]) -> int:
    return sum(r["weight"] for r in reasons)


__all__ = [
    "AGEING",
    "DEFINITIONS",
    "INVOICE_METRICS",
    "LIST_METRICS",
    "MONTH_DAYS",
    "RISK_REASONS",
    "RISK_WEIGHTS",
    "RULES",
    "STATES",
    "SUBSCRIBER_METRICS",
    "RiskFacts",
    "RiskRules",
    "add_months",
    "ageing_bucket",
    "base_at",
    "churned_at",
    "local_date",
    "month_bounds",
    "month_key",
    "month_start",
    "monthly_paise",
    "parse_month",
    "rate",
    "risk_reasons",
    "risk_score",
    "state_of",
]
