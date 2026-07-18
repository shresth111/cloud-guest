"""Peak-concurrent-sessions computation (BE-012 Part 2: Super Admin
Dashboard).

## The algorithm: a real sweep-line over session start/end events

"Peak concurrent sessions" means: at the single busiest moment within
``[window_start, window_end]``, how many :class:`~.models.guest.GuestSession`
rows were simultaneously alive? A naive approach ("sample every N minutes and
count how many sessions are active at each sample point") can miss the true
peak if it falls between samples, and gets more wrong the coarser the
sampling interval -- this module deliberately does not do that.

The correct approach is a classic interval-sweep: treat each session as two
events -- a ``+1`` at its start and a ``-1`` at its end (both clipped to the
window) -- sort all events chronologically, and walk them left to right
keeping a running total. The maximum value that running total ever reaches
*is* the peak concurrent count, by definition (at the moment just after the
running total hits its maximum, exactly that many sessions have started and
not yet ended).

**Half-open interval convention.** A session is considered "alive" during
``[started_at, ended_at)`` -- present at its start instant, absent at its end
instant. Two events at the exact same timestamp are therefore ordered
end-before-start (a session ending at ``t`` and a different session starting
at ``t`` do not count as briefly overlapping) -- see ``_event_sort_key``.

**Why this is a Python function, not a single SQL aggregate.** Expressing
"maximum of a running window-ordered sum" is possible in Postgres (a window
function: ``SUM(delta) OVER (ORDER BY ts)`` then ``MAX(...)`` of that), but
doing so in a way this codebase's own unit-test convention (hand-rolled
fakes, no live Postgres in unit tests -- see
``tests/unit/test_analytics.py``'s module docstring) can actually verify
against a hand-constructed overlapping-intervals fixture would mean either
mocking SQL execution results (not testing the real logic) or standing up a
real database in a unit test (a departure from every other test in this
suite). The chosen split keeps both halves honest and testable: **real SQL**
narrows the candidate set to only sessions whose interval could possibly
overlap the requested window (see
``AnalyticsRepository.list_session_intervals`` -- a bounded, indexed
``WHERE`` filter, never an unbounded table scan), and this **pure,
Postgres-independent function** computes the true peak over just the two
datetime columns of that already-filtered result set -- an O(n log n)
sort-and-scan over interval endpoints, not a full-row Python business-logic
loop of the kind this codebase's coding rules warn against.
"""

from __future__ import annotations

from datetime import datetime


def compute_peak_concurrent_sessions(
    intervals: list[tuple[datetime, datetime | None]],
    *,
    window_start: datetime,
    window_end: datetime,
) -> int:
    """Returns the true peak number of simultaneously-alive intervals within
    ``[window_start, window_end]``.

    ``intervals`` is a list of ``(started_at, ended_at)`` pairs -- ``ended_at
    is None`` means "still active as of now" (an ``ACTIVE`` session), treated
    as alive through ``window_end`` for the purposes of this window's peak
    (a session that is still open cannot be known to have ended before the
    window closes). Each interval is clipped to the window before being
    swept; intervals that clip to zero (or negative) width are dropped
    entirely -- they never touch the window.
    """
    events: list[tuple[datetime, int]] = []
    for started_at, ended_at in intervals:
        effective_end = ended_at if ended_at is not None else window_end
        clipped_start = max(started_at, window_start)
        clipped_end = min(effective_end, window_end)
        if clipped_start >= clipped_end:
            continue
        events.append((clipped_start, 1))
        events.append((clipped_end, -1))

    if not events:
        return 0

    # Half-open convention: at equal timestamps, process the -1 (end) before
    # the +1 (start) -- see module docstring. Sorting by (timestamp, delta)
    # achieves this since -1 < +1.
    events.sort(key=lambda event: (event[0], event[1]))

    running = 0
    peak = 0
    for _, delta in events:
        running += delta
        if running > peak:
            peak = running
    return peak


__all__ = ["compute_peak_concurrent_sessions"]
