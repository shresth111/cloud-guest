"""Per-NAS-session byte baselines for NAS-only (Aruba Instant On) accounting.

An Aruba AP's ``Acct-Input-Octets``/``Acct-Output-Octets`` are running totals
for ONE NAS session (one ``Acct-Session-Id``) and start again at 0 when the
guest reconnects. The platform maps that reconnect onto the same, reused
``GuestSession``. Converting the new NAS session's totals into deltas against
the ``GuestSession``'s lifetime bytes (``max(0, total - recorded)``) then
drops every byte of the new NAS session until its own total climbs past the
old one.

So, for NAS-only sessions that carry an ``Acct-Session-Id``, the delta is
taken against the CURRENT NAS session's own last-seen totals, kept on the
``GuestSession`` (``nas_counters``: ``{acct_session_id: [up, down]}``, the
few most recent NAS sessions, oldest dropped first):

* an unseen ``Acct-Session-Id`` starts from 0 (its counters just restarted);
* a seen one yields ``max(0, total - last_seen)``, so a retransmit (same id,
  same total) and a late, lower packet both add nothing;
* the very first id on a ``GuestSession`` with nothing tracked yet (a session
  in flight across this deploy) is assumed to be the NAS session the
  recorded bytes came from when its totals are at or above them -- exactly
  the old behaviour -- and a fresh restart from 0 when they are below.

Pure functions; the caller decides whether a row is NAS-only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: How many NAS sessions a ``GuestSession`` remembers (late packets of a
#: recent previous NAS session must still find their own baseline).
MAX_TRACKED_NAS_SESSIONS = 8
#: ``Acct-Session-Id`` is an opaque NAS string; keys are capped.
MAX_NAS_SESSION_ID_LENGTH = 64


def clean_nas_session_id(value: str | None) -> str | None:
    """``None`` for a missing or empty id (FreeRADIUS expands an absent
    attribute to ``""``), else the id capped at
    :data:`MAX_NAS_SESSION_ID_LENGTH`."""
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    return cleaned[:MAX_NAS_SESSION_ID_LENGTH]


@dataclass(frozen=True, slots=True)
class NasSessionDelta:
    bytes_uploaded_delta: int
    bytes_downloaded_delta: int
    counters: dict[str, list[int]]


def _normalized(counters: Any) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    if not isinstance(counters, dict):
        return out
    for key, value in counters.items():
        if (
            isinstance(key, str)
            and isinstance(value, list | tuple)
            and len(value) == 2
            and all(isinstance(v, int) and v >= 0 for v in value)
        ):
            out[key] = [int(value[0]), int(value[1])]
    return out


def _remember(
    counters: dict[str, list[int]], session_id: str, values: list[int]
) -> dict[str, list[int]]:
    counters.pop(session_id, None)
    counters[session_id] = values
    while len(counters) > MAX_TRACKED_NAS_SESSIONS:
        counters.pop(next(iter(counters)))
    return counters


def start_nas_session(counters: Any, session_id: str) -> dict[str, list[int]]:
    """Accounting-Start: the NAS session begins at 0. A retransmitted Start
    for an id already tracked changes nothing."""
    current = _normalized(counters)
    if session_id in current:
        return current
    return _remember(current, session_id, [0, 0])


def nas_session_delta(
    counters: Any,
    session_id: str,
    *,
    bytes_uploaded_total: int | None,
    bytes_downloaded_total: int | None,
    recorded_uploaded: int,
    recorded_downloaded: int,
) -> NasSessionDelta:
    """Deltas for one Interim-Update / Stop of NAS session ``session_id``."""
    current = _normalized(counters)
    previous = current.get(session_id)
    if previous is None:
        if current:
            previous = [0, 0]  # a new NAS session: AP counters restarted
        else:
            same_session = (
                bytes_uploaded_total is None
                or bytes_uploaded_total >= recorded_uploaded
            ) and (
                bytes_downloaded_total is None
                or bytes_downloaded_total >= recorded_downloaded
            )
            previous = (
                [recorded_uploaded, recorded_downloaded] if same_session else [0, 0]
            )
    up_prev, down_prev = previous
    up_delta = (
        max(0, bytes_uploaded_total - up_prev)
        if bytes_uploaded_total is not None
        else 0
    )
    down_delta = (
        max(0, bytes_downloaded_total - down_prev)
        if bytes_downloaded_total is not None
        else 0
    )
    seen = [
        max(up_prev, bytes_uploaded_total or 0),
        max(down_prev, bytes_downloaded_total or 0),
    ]
    return NasSessionDelta(up_delta, down_delta, _remember(current, session_id, seen))


__all__ = [
    "MAX_NAS_SESSION_ID_LENGTH",
    "MAX_TRACKED_NAS_SESSIONS",
    "NasSessionDelta",
    "clean_nas_session_id",
    "nas_session_delta",
    "start_nas_session",
]
