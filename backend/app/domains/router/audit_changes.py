"""Field-level change sets for router audit entries.

## Why this module exists

``ROUTER_UPDATED`` entries used to read ``Router 'X' updated`` with ``{}``
metadata -- an event with no object. On 2026-09-10 a platform owner
relabelled seven live routers' ``vendor`` to ``tplink_omada`` through a
dropdown with no confirmation step, and the audit trail could not say
which field had moved, let alone what it moved *from*: the only way to
reconstruct the incident was to diff the ``routers`` table by hand against
a backup. ``vendor`` is not a cosmetic column either -- it is what
``vendor_capabilities`` reads to decide whether a row is agent-managed, so
seven healthy MikroTiks silently became "controller-managed" devices.

So an update now records *what changed*, from what, to what. That is the
whole job of this module: turn a before/after pair into a small, JSON-safe
change set for ``audit_log_entries.event_metadata`` and a one-line human
tail for the entry's description.

## Why it fails closed on secret-looking keys

An audit trail is read by more people, and kept for longer, than the rows
it describes. Writing ``api_secret`` values into it would take a
write-only, Fernet-encrypted-at-rest credential (see
``app.domains.router.crypto``) and copy it in plaintext into a table that
support staff can read -- strictly worse than not auditing the field at
all.

Redaction is therefore **not** an allowlist of known-safe fields but a
denylist that fails closed: a key is redacted if it is named in
:data:`REDACTED_ROUTER_FIELDS` **or** merely *contains* one of the secret
stems (``secret``, ``password``, ``token``, ``credentials``,
``community``). A column added later called ``radius_secret`` or
``omada_client_credentials`` is redacted on the day it is added, by
someone who never read this file and never had to. The cost of the
denylist being over-eager is a slightly vaguer audit line; the cost of an
allowlist missing an entry is a leaked credential, and those two mistakes
are not the same size. Nothing about a redacted value is recorded -- not
the value, not its length, not a prefix, not whether the old and new
values differed in shape -- because each of those is a usable oracle.

## Why ``settings`` is "opaque" rather than diffed

``routers.settings`` is free-form JSONB that any caller can put anything
into, including things that are secret-shaped but not secret-named. It is
also arbitrarily large. Recording that it changed, and nothing more, is
the honest answer: the reader learns an update touched it and can go look,
without this module promising a diff it cannot safely produce.
"""

from __future__ import annotations

__all__ = [
    "OPAQUE_ROUTER_FIELDS",
    "REDACTED_PLACEHOLDER",
    "REDACTED_ROUTER_FIELDS",
    "describe_router_changes",
    "router_field_changes",
]

# Keys whose VALUES must never reach an audit entry. This is the explicit
# floor; `_SECRET_KEY_STEMS` below is what makes the rule hold for columns
# nobody has written yet. Both the inbound (plaintext, write-only) request
# field names and the persisted `*_encrypted` column names are listed,
# because `RouterService.update_router` pops the former and writes the
# latter -- whichever spelling ends up in a change set, it is redacted.
REDACTED_ROUTER_FIELDS: frozenset[str] = frozenset(
    {
        "api_secret",
        "api_credentials_encrypted",
        "snmp_community",
        "snmp_community_encrypted",
        "token_hash",
        "password",
        "secret",
        "token",
    }
)

# Substring stems that make an *unknown* key redacted by default. Matching
# is "contains", not "ends with", so `snmp_community_encrypted` and
# `api_credentials_encrypted` are caught by their stems even though the
# secret-ish part is in the middle of the name.
_SECRET_KEY_STEMS: tuple[str, ...] = (
    "secret",
    "password",
    "token",
    "credentials",
    "community",
)

# Keys recorded as "this changed" with no values at all -- see the module
# docstring for why free-form JSONB gets this treatment rather than a diff.
OPAQUE_ROUTER_FIELDS: frozenset[str] = frozenset({"settings"})

# A stand-in for "a value arrived here", for callers that need to hand this
# module a sentinel rather than a real secret (``RouterService`` uses it to
# diff the inbound ``api_secret``/``snmp_community`` field names it has
# already popped off its update payload). It is never itself recorded: any
# key it is used with is redacted by definition, so the change set says
# ``{"redacted": True}`` and the placeholder never leaves this process.
REDACTED_PLACEHOLDER = "[redacted]"


def _is_redacted(key: str) -> bool:
    """True when ``key``'s value must never be recorded -- exact membership
    in :data:`REDACTED_ROUTER_FIELDS`, or any secret stem appearing anywhere
    in the (case-folded) key."""
    folded = key.lower()
    if folded in REDACTED_ROUTER_FIELDS:
        return True
    return any(stem in folded for stem in _SECRET_KEY_STEMS)


def _json_safe(value: object) -> object:
    """Normalises a value to something ``event_metadata`` (JSONB) can hold
    and two values can be compared by.

    ``str``/``int``/``bool``/``float``/``None`` pass through untouched;
    everything else -- ``uuid.UUID``, ``datetime``, ``Decimal``, enums,
    nested containers -- becomes ``str(value)``. Normalising *before*
    comparing is what makes "the caller sent the same UUID back as a
    string" correctly read as no change rather than as an edit.
    """
    if value is None or isinstance(value, str | bool | int | float):
        return value
    return str(value)


def router_field_changes(
    before: dict[str, object], after: dict[str, object]
) -> dict[str, dict[str, object]]:
    """Diffs a router update payload against the values it is replacing.

    Only keys present in ``after`` are considered -- ``after`` is the
    *effective* update payload, so a column the caller never mentioned is
    not a change and must not appear. Each changed key maps to exactly one
    of three shapes:

    * ``{"redacted": True}`` -- a secret-looking key (see module docstring).
      The key name is the entire record; no value, length or prefix.
    * ``{"changed": True}`` -- an :data:`OPAQUE_ROUTER_FIELDS` key.
    * ``{"from": old, "to": new}`` -- everything else, JSON-safe scalars.

    Returns ``{}`` when nothing actually moved, which is the signal callers
    use to keep a no-op update's description honest.
    """
    changes: dict[str, dict[str, object]] = {}
    for key, raw_new in after.items():
        old_value = _json_safe(before.get(key))
        new_value = _json_safe(raw_new)
        if old_value == new_value:
            continue
        if _is_redacted(key):
            changes[key] = {"redacted": True}
        elif key in OPAQUE_ROUTER_FIELDS:
            changes[key] = {"changed": True}
        else:
            changes[key] = {"from": old_value, "to": new_value}
    return changes


def _render(value: object) -> str:
    """Renders one side of a change for the human description.

    ``None`` reads as ``none`` (a bare empty string would be invisible in
    the middle of a sentence). Strings are single-quoted **only** when they
    contain a space, so ``vendor mikrotik -> tplink_omada`` stays clean
    while ``name 'Lobby AP' -> 'Office Guest'`` stays unambiguous about
    where one value ends and the next token begins.
    """
    if value is None:
        return "none"
    if isinstance(value, str) and " " in value:
        return f"'{value}'"
    return str(value)


def describe_router_changes(changes: dict[str, dict[str, object]]) -> str:
    """Renders a change set as the human tail of an audit description.

    Keys are emitted in alphabetical order rather than in payload order:
    the description is a stable, greppable string that two identical edits
    must produce identically, and ``dict`` order here would inherit
    whatever order the request body happened to serialise its fields in.

    Returns ``""`` for an empty change set so the caller can fall back to
    the plain ``Router 'X' updated`` wording instead of emitting a
    misleading empty field list.
    """
    parts: list[str] = []
    for key in sorted(changes):
        detail = changes[key]
        if detail.get("redacted"):
            # Says the field moved and explicitly says why there is no
            # value here, so a reader does not go looking for one.
            parts.append(f"{key} changed (value not recorded)")
        elif detail.get("changed"):
            parts.append(f"{key} changed")
        else:
            old = _render(detail.get("from"))
            new = _render(detail.get("to"))
            parts.append(f"{key} {old} -> {new}")
    return ", ".join(parts)
