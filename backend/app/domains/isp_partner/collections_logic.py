"""COLLECTIONS-1 rules, as plain functions (no database), so every number on
the workbench can be explained and unit-tested.

**Risk score** (0-100, higher = less likely to pay without a push). Each rule
that fires adds its points and its reason text:

* oldest overdue invoice: 1-15 days +10, 16-30 +20, 31-60 +35, over 60 +50
* unpaid overdue invoices: 2 -> +8, 3 or more -> +15
* a promise to pay broken in the last 90 days: +20
* 2 or more invoices paid more than 7 days late in the last 180 days: +10
* no payment at all in the last 60 days: +10
* an open promise that is not due yet: -15

Band: high >= 50, medium >= 25, else low. The amount is NOT part of the
score; the list ranks by band first, then by overdue amount.

**Predicted collections this week** (Monday-Sunday in the ISP's time zone) =
cash already received this week + the expected value of:

* open promises due between today and Sunday x the ISP's promise keep rate
  (kept / (kept + broken) over 180 days; 0.6 until 10 promises resolved);
* invoices falling due between today and Sunday x the ISP's on-time rate
  (share of invoices due in the last 90 days paid in full within 3 days of
  the due date; 0.5 until 20 such invoices exist);
* overdue balances without an open promise x a fixed rate per band
  (low 0.25, medium 0.10, high 0.03).

Every component reports its base, its rate and whether the rate is measured
or the default.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta

HIGH_BAND = 50
MEDIUM_BAND = 25

DEFAULT_KEEP_RATE = 0.6
MIN_RESOLVED_PROMISES = 10
DEFAULT_ON_TIME_RATE = 0.5
MIN_DUE_INVOICES = 20
ON_TIME_SLACK_DAYS = 3
LATE_PAYMENT_DAYS = 7
BAND_RATES = {"low": 0.25, "medium": 0.10, "high": 0.03}

PROMISE_OPEN = "open"
PROMISE_KEPT = "kept"
PROMISE_BROKEN = "broken"
PROMISE_CANCELLED = "cancelled"
PROMISE_SUPERSEDED = "superseded"

NOTE_OUTCOMES = ("called", "no_answer", "visited", "promised", "disputed", "other")


@dataclass
class Reason:
    code: str
    points: int
    text: str

    def view(self) -> dict:
        return {"code": self.code, "points": self.points, "text": self.text}


@dataclass
class PartyFacts:
    """What the score reads about one party, already computed."""

    days_overdue: int
    overdue_invoices: int
    broken_promises_90d: int = 0
    late_payments_180d: int = 0
    days_since_last_payment: int | None = None
    has_billing_history: bool = True
    open_promise_on: date | None = None


@dataclass
class Risk:
    score: int
    band: str
    reasons: list[Reason] = field(default_factory=list)

    def view(self) -> dict:
        return {
            "score": self.score,
            "band": self.band,
            "reasons": [r.view() for r in self.reasons],
        }


def band_for(score: int) -> str:
    if score >= HIGH_BAND:
        return "high"
    if score >= MEDIUM_BAND:
        return "medium"
    return "low"


def score(f: PartyFacts, *, today: date) -> Risk:
    reasons: list[Reason] = []
    d = f.days_overdue
    if d > 60:
        reasons.append(Reason("age_60_plus", 50, f"Oldest bill {d} days overdue"))
    elif d > 30:
        reasons.append(Reason("age_31_60", 35, f"Oldest bill {d} days overdue"))
    elif d > 15:
        reasons.append(Reason("age_16_30", 20, f"Oldest bill {d} days overdue"))
    elif d > 0:
        reasons.append(Reason("age_1_15", 10, f"Oldest bill {d} days overdue"))
    if f.overdue_invoices >= 3:
        reasons.append(
            Reason("many_unpaid", 15, f"{f.overdue_invoices} overdue bills unpaid")
        )
    elif f.overdue_invoices == 2:
        reasons.append(Reason("two_unpaid", 8, "2 overdue bills unpaid"))
    if f.broken_promises_90d > 0:
        n = f.broken_promises_90d
        reasons.append(
            Reason(
                "broken_promise",
                20,
                f"Broke {n} promise{'s' if n > 1 else ''} to pay in 90 days",
            )
        )
    if f.late_payments_180d >= 2:
        reasons.append(
            Reason(
                "pays_late",
                10,
                f"Paid {f.late_payments_180d} bills over {LATE_PAYMENT_DAYS} days "
                "late in 180 days",
            )
        )
    if f.has_billing_history and (
        f.days_since_last_payment is None or f.days_since_last_payment > 60
    ):
        reasons.append(
            Reason(
                "no_recent_payment",
                10,
                "No payment ever"
                if f.days_since_last_payment is None
                else f"Last payment {f.days_since_last_payment} days ago",
            )
        )
    if f.open_promise_on is not None and f.open_promise_on >= today:
        reasons.append(
            Reason(
                "open_promise",
                -15,
                f"Promised to pay by {f.open_promise_on.isoformat()}",
            )
        )
    total = max(0, min(100, sum(r.points for r in reasons)))
    return Risk(score=total, band=band_for(total), reasons=reasons)


BAND_ORDER = {"high": 0, "medium": 1, "low": 2}


def sort_key(item: dict, sort: str) -> tuple:
    if sort == "amount":
        return (-item["overdue_paise"], -item["risk"]["score"])
    if sort == "age":
        return (-item["days_overdue"], -item["overdue_paise"])
    if sort == "score":
        return (-item["risk"]["score"], -item["overdue_paise"])
    # "priority": band, then amount
    return (BAND_ORDER[item["risk"]["band"]], -item["overdue_paise"])


# --------------------------------------------------------------------------
# promises
# --------------------------------------------------------------------------


def promise_status(
    *,
    stored: str,
    promised_on: date,
    target_paise: int,
    paid_by_deadline_paise: int,
    today: date,
) -> str:
    """The effective status of a promise. ``paid_by_deadline_paise`` is what
    the party paid from when the promise was made to the end of
    ``promised_on``. Only ``open`` moves."""
    if stored != PROMISE_OPEN:
        return stored
    if paid_by_deadline_paise >= target_paise:
        return PROMISE_KEPT
    if today > promised_on:
        return PROMISE_BROKEN
    return PROMISE_OPEN


def keep_rate(kept: int, broken: int) -> tuple[float, bool]:
    """(rate, measured). Needs MIN_RESOLVED_PROMISES resolved promises."""
    n = kept + broken
    if n < MIN_RESOLVED_PROMISES:
        return DEFAULT_KEEP_RATE, False
    return kept / n, True


def on_time_rate(on_time: int, total: int) -> tuple[float, bool]:
    if total < MIN_DUE_INVOICES:
        return DEFAULT_ON_TIME_RATE, False
    return on_time / total, True


def week_bounds(today: date) -> tuple[date, date]:
    start = today - timedelta(days=today.weekday())
    return start, start + timedelta(days=6)


@dataclass
class Component:
    key: str
    label: str
    base_paise: int
    rate: float
    measured: bool
    count: int
    basis: str

    @property
    def expected_paise(self) -> int:
        return int(round(self.base_paise * self.rate))

    def view(self) -> dict:
        return {
            "key": self.key,
            "label": self.label,
            "count": self.count,
            "base_paise": self.base_paise,
            "rate": round(self.rate, 4),
            "rate_measured": self.measured,
            "expected_paise": self.expected_paise,
            "basis": self.basis,
        }


def forecast(
    *,
    today: date,
    collected_so_far_paise: int,
    promises_due: list[int],
    keep: tuple[float, bool],
    invoices_due: list[int],
    on_time: tuple[float, bool],
    overdue_by_band: dict[str, list[int]],
) -> dict:
    start, end = week_bounds(today)
    comps = [
        Component(
            "promises",
            "Promises due this week",
            sum(promises_due),
            keep[0],
            keep[1],
            len(promises_due),
            "Your promise keep rate over 180 days"
            if keep[1]
            else f"Default rate: fewer than {MIN_RESOLVED_PROMISES} promises resolved",
        ),
        Component(
            "due_this_week",
            "Bills falling due this week",
            sum(invoices_due),
            on_time[0],
            on_time[1],
            len(invoices_due),
            f"Share of bills paid within {ON_TIME_SLACK_DAYS} days of due, last 90 days"
            if on_time[1]
            else f"Default rate: fewer than {MIN_DUE_INVOICES} bills due in 90 days",
        ),
    ]
    for band in ("low", "medium", "high"):
        amounts = overdue_by_band.get(band, [])
        comps.append(
            Component(
                f"overdue_{band}",
                f"Overdue, {band} risk, no promise",
                sum(amounts),
                BAND_RATES[band],
                False,
                len(amounts),
                "Fixed rule rate for this risk band",
            )
        )
    remaining = sum(c.expected_paise for c in comps)
    return {
        "week_start": start.isoformat(),
        "week_end": end.isoformat(),
        "as_of": today.isoformat(),
        "collected_so_far_paise": collected_so_far_paise,
        "predicted_remaining_paise": remaining,
        "predicted_total_paise": collected_so_far_paise + remaining,
        "components": [c.view() for c in comps],
        "method": (
            "Cash already received this week plus, for the days left: promises "
            "due x keep rate, bills due x on-time rate, other overdue balances x "
            "a fixed rate per risk band. Nothing is guessed beyond these rules."
        ),
    }


def day_bounds_utc(d: date, tz) -> tuple[datetime, datetime]:  # noqa: ANN001
    from datetime import UTC, time

    return (
        datetime.combine(d, time.min, tzinfo=tz).astimezone(UTC),
        datetime.combine(d + timedelta(days=1), time.min, tzinfo=tz).astimezone(UTC),
    )


__all__ = [
    "BAND_RATES",
    "NOTE_OUTCOMES",
    "PartyFacts",
    "Risk",
    "band_for",
    "day_bounds_utc",
    "forecast",
    "keep_rate",
    "on_time_rate",
    "promise_status",
    "score",
    "sort_key",
    "week_bounds",
]
