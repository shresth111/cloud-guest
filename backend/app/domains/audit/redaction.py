"""What may leave this domain when an audit entry's metadata is read.

## Why a second denylist

``app.domains.router.audit_changes`` already refuses to *write* secret-looking
keys into ``audit_log_entries.event_metadata``, and it is right to. This
module refuses to *read* them out, and the duplication is deliberate.

``event_metadata`` is a JSONB column that **every** domain writes: the router
service, system settings, network integrations, RBAC, and whatever is added
next month. Until now no read path passed it out at all, so a writer that put
a secret in it leaked nothing. The moment one does -- and
``GET /audit/entries`` is reachable by an organization owner, not only by a
platform operator -- the safety of that column becomes a property of every
writer, forever, including the ones nobody has written yet.

A read-side filter makes it a property of one file instead. The writer-side
redaction stays: it stops the secret being persisted in the first place, which
is strictly better and is what protects anyone reading the table directly. The
read-side one is what holds when a writer forgets.

## Why it does not import the router domain's list

The stems are restated rather than imported, which normally would be drift
waiting to happen. Here it is the point: this module must not depend on any
writer domain (``audit`` is read by all of them), and the two lists are
allowed to diverge in one direction only -- each may add stems the other
lacks, and the union is what is enforced end to end. A shared constant would
make removing a stem a one-line change that silently weakens both sides.
"""

from __future__ import annotations

from typing import Any

__all__ = ["REDACTED_PLACEHOLDER", "SECRET_KEY_STEMS", "redact_event_metadata"]

#: Substrings that make a key's value secret, matched case-insensitively
#: anywhere in the key. "Contains" rather than "equals" so
#: ``snmp_community_encrypted``, ``api_client_secret`` and
#: ``omada_operator_password`` are all caught without being enumerated.
SECRET_KEY_STEMS: tuple[str, ...] = (
    "secret",
    "password",
    "token",
    "credential",
    "community",
    "private_key",
    "api_key",
    "passphrase",
    "authorization",
    "cookie",
    "session_id",
)

#: What a redacted value is replaced with. A fixed string with no length, no
#: prefix and no type information -- each of those is an oracle, and an audit
#: reader learning "the value was 32 characters" has learned something about a
#: secret they were not shown.
REDACTED_PLACEHOLDER = "[redacted]"

#: How deep to walk before giving up and redacting wholesale. `event_metadata`
#: is free-form JSONB with no schema and no size limit; a hostile or merely
#: careless writer can nest it arbitrarily, and an unbounded recursive walk
#: over user-influenced data on a paginated list endpoint is a denial of
#: service. Bounded, and the bound fails closed.
_MAX_DEPTH = 8


def redact_event_metadata(value: Any, *, _depth: int = 0) -> Any:
    """``value`` with every secret-looking key's value replaced.

    Walks dicts and lists; scalars pass through. A key whose name matches any
    of :data:`SECRET_KEY_STEMS` is replaced wholesale -- the entire subtree,
    not just its scalar leaves -- because ``{"credentials": {"username": ...,
    "password": ...}}` should not be half-published on the strength of one
    innocuous-looking inner key.

    Beyond :data:`_MAX_DEPTH` the value is replaced rather than returned. That
    is the fail-closed direction: an audit line that reads ``[redacted]``
    costs a reader one query against the table; a leaked credential costs a
    rotation.
    """
    if _depth >= _MAX_DEPTH:
        return REDACTED_PLACEHOLDER
    if isinstance(value, dict):
        return {
            key: (
                REDACTED_PLACEHOLDER
                if _is_secret_key(str(key))
                else redact_event_metadata(item, _depth=_depth + 1)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_event_metadata(item, _depth=_depth + 1) for item in value]
    return value


def _is_secret_key(key: str) -> bool:
    folded = key.lower()
    return any(stem in folded for stem in SECRET_KEY_STEMS)
