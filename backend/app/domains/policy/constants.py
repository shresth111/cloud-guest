"""Enumerations and default rule payloads for the Policy domain.

See this module's own ``docs/policy/FLOW.md`` for the full write-up. Two
things worth knowing before reading the rest of this file:

## ``policy`` is a leaf module -- no imports from ``app.domains.guest``/
## ``app.domains.voucher``/``app.domains.otp``, not even for constants

``PLATFORM_DEFAULT_RULES`` below mirrors several already-existing, hardcoded
platform constants this session's own gap analysis found while auditing
``app.domains.guest.constants``/``app.domains.voucher.constants`` for real
per-organization-configurability candidates
(``DEFAULT_SESSION_TIMEOUT_MINUTES``, ``TERMINATION_RECONNECT_COOLDOWN_MINUTES``,
``RECONNECT_GRACE_MINUTES``, ``DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST`` --
the last of these even carries its own docstring in ``guest.constants``
explicitly deferring "full per-organization/location configurability" to
"the Policy Engine's job", confirming this module's own scope). Those values
are **duplicated here as literals, not imported** -- this codebase's own
``docs/ARCHITECTURE_DESIGN.md`` §4/§13 is explicit that ``policy`` must stay a
dependency-free leaf ("depends on nothing feature-specific") so that every
other domain can depend on it without ever creating an import cycle back into
a feature domain. Importing ``app.domains.guest.constants`` from here, even
just for a numeric literal, would be exactly the kind of coupling that rule
forbids. If ``guest``'s own constant is ever changed, this platform-default
mirror must be updated by hand -- an accepted, documented trade-off of
keeping ``policy`` acyclic, not an oversight.

## Rule types not yet seeded

``PolicyType`` covers every policy type ``docs/ARCHITECTURE_DESIGN.md`` §6.1
names (authN/session/bandwidth/FUP/business-hours/access/VLAN/QoS/routing),
plus two additive types this codebase's own Phase 1 BhaiFi-parity work
added: ``VOUCHER``/``DEVICE`` (see below). ``SESSION``/``AUTHN`` have a
seeded ``PLATFORM_DEFAULT_RULES`` entry *and* a typed Pydantic schema in
``schemas.py``'s ``POLICY_RULE_SCHEMAS`` registry, because those are the two
types this gap analysis found real, already-hardcoded platform constants
for. ``BANDWIDTH``/``QOS`` also gained a typed schema
(``schemas.BandwidthPolicyRules``/``QoSPolicyRules``) when
``app.domains.queue_management`` (the Queue Management Engine) was built --
that domain composes these two policy types for real, so their ``rules``
shape needed real validation -- but **no seeded platform default**: no
existing hardcoded constant anywhere in this codebase names a bandwidth cap
to mirror, so inventing one here would be a fake opinion, not a real
default (the same "real check without a fake opinion" discipline this
codebase already applies to e.g. Celery health's ``UNKNOWN`` status before a
worker was ever wired in). A ``BANDWIDTH``/``QOS`` policy with no assignment
at any scope resolves to an empty ``rules`` dict
(``PLATFORM_DEFAULT_RULES.get(policy_type, {})``) -- it is
``queue_management``'s own job to fall back to a sensible default
``QueueProfile`` (e.g. "Unlimited") when that happens, not this module's.

``FUP``/``BUSINESS_HOURS`` gained typed schemas
(``schemas.FUPPolicyRules``/``BusinessHoursPolicyRules``) for
``app.domains.guest``'s own quota-enforcement composition -- likewise no
seeded platform default (no existing hardcoded daily/weekly/monthly cap or
named time window to mirror). ``DEVICE`` gained a typed schema
(``schemas.DevicePolicyRules``) *and* a real seeded platform default,
mirroring ``app.domains.guest.constants.DEFAULT_MAX_DEVICES_PER_GUEST``
exactly (that constant's own docstring names this module as its intended
resolver, the identical "the seam this constant was always waiting for"
posture ``DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST`` established for
``SESSION`` before it). ``VOUCHER`` gained a typed schema
(``schemas.VoucherPolicyRules``) but **no seeded default** -- no existing
hardcoded "max active vouchers per guest" constant exists anywhere to
mirror. The rest (``ACCESS``/``VLAN``/``ROUTING``) remain fully functional --
a ``Policy``/``PolicyVersion`` of any of those types can be created,
versioned, published, and assigned today -- but have no seeded platform
default and validate their ``rules`` JSONB payload only as "a JSON object"
(see ``schemas.GenericPolicyRules``), honestly reflecting that no existing
hardcoded constant in this codebase justifies a specific default shape for
them yet.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class PolicyType(StrEnum):
    """Every policy type ``docs/ARCHITECTURE_DESIGN.md`` §6.1 names for the
    Policy Engine. Stored as a plain ``String`` column on
    ``models.Policy.policy_type`` -- never a native Postgres enum -- so a new
    type is a purely additive ``StrEnum`` member, no migration, mirroring
    every other domain's identical convention in this codebase."""

    AUTHN = "authn"
    SESSION = "session"
    BANDWIDTH = "bandwidth"
    FUP = "fup"
    BUSINESS_HOURS = "business_hours"
    ACCESS = "access"
    VLAN = "vlan"
    QOS = "qos"
    ROUTING = "routing"
    # Phase 1 BhaiFi-parity additions -- see module docstring's "Rule types
    # not yet seeded" section for the full write-up.
    VOUCHER = "voucher"
    DEVICE = "device"


class PolicyVersionStatus(StrEnum):
    """Lifecycle of a :class:`~.models.PolicyVersion`.

    ``DRAFT`` -> ``PUBLISHED`` is the only legal edge, and it is one-way and
    terminal: once published, a version's ``rules`` payload is immutable
    (see ``service.PolicyService.create_version``'s docstring) -- to change
    rules, create a *new* ``DRAFT`` version and publish that one instead.
    This mirrors ``app.domains.guest_teams.constants.GuestTeamStatus``'s/
    ``app.domains.voucher.constants.VoucherBatchStatus``'s identical
    "terminal states have no outgoing edges, not even to themselves"
    discipline: publishing an already-published version is rejected, not a
    silent no-op.
    """

    DRAFT = "draft"
    PUBLISHED = "published"


POLICY_VERSION_STATUS_TRANSITIONS: dict[
    PolicyVersionStatus, frozenset[PolicyVersionStatus]
] = {
    PolicyVersionStatus.DRAFT: frozenset({PolicyVersionStatus.PUBLISHED}),
    PolicyVersionStatus.PUBLISHED: frozenset(),
}


# ============================================================================
# Platform-default rule payloads -- see module docstring's "duplicated, not
# imported" write-up. Used by ``service.PolicyService.resolve_effective_policy``
# as the final fallback tier when no ``PolicyAssignment`` matches at any
# scope -- the exact "platform default" tier
# ``docs/ARCHITECTURE_DESIGN.md`` §13's resolution order names last.
# ============================================================================

PLATFORM_DEFAULT_RULES: dict[PolicyType, dict[str, Any]] = {
    PolicyType.SESSION: {
        # Mirrors app.domains.guest.constants.DEFAULT_SESSION_TIMEOUT_MINUTES.
        "session_timeout_minutes": 240,
        # Mirrors app.domains.guest.constants
        # .DEFAULT_MAX_CONCURRENT_SESSIONS_PER_GUEST -- that constant's own
        # docstring explicitly names this module as its intended successor.
        "max_concurrent_sessions_per_guest": 3,
        # Mirrors app.domains.guest.constants
        # .TERMINATION_RECONNECT_COOLDOWN_MINUTES.
        "termination_reconnect_cooldown_minutes": 60,
        # Mirrors app.domains.guest.constants.RECONNECT_GRACE_MINUTES.
        "reconnect_grace_minutes": 30,
    },
    PolicyType.AUTHN: {
        # Mirrors app.domains.voucher.constants
        # .DEFAULT_REDEMPTION_MAX_ATTEMPTS_PER_WINDOW /
        # .DEFAULT_REDEMPTION_WINDOW_MINUTES -- voucher redemption is an
        # authentication-adjacent, rate-limited action, the same category
        # this policy type is meant to govern.
        "max_attempts_per_window": 30,
        "window_minutes": 1,
    },
    PolicyType.DEVICE: {
        # Mirrors app.domains.guest.constants
        # .DEFAULT_MAX_DEVICES_PER_GUEST -- that constant's own docstring
        # explicitly names this module as its intended resolver, the
        # identical "the seam this constant was always waiting for"
        # posture PolicyType.SESSION's own entry above already
        # establishes.
        "max_devices_per_guest": 3,
        "require_known_device": False,
    },
}


__all__ = [
    "PolicyType",
    "PolicyVersionStatus",
    "POLICY_VERSION_STATUS_TRANSITIONS",
    "PLATFORM_DEFAULT_RULES",
]
