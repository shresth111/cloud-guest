"""Turn the RouterOS SNMP agent on (or off) for the platform's poller.

## Why this exists

The platform has had a working SNMP poller (``snmp_poller.py``) since
migration 0079, and no fleet router has ever answered it: RouterOS ships
``/snmp enabled=no`` and nothing in the product -- not the paste script, the
bootstrap renderer or any device writer -- ever turned it on. This module is
the one place that does, over the RouterOS API session the platform already
holds on 8728.

## What it owns on the device

* ``/snmp`` (one settings object): ``enabled=yes``.
* ONE ``/snmp community`` row, identified by ``comment=`` :data:`COMMUNITY_COMMENT`
  -- never by name, because on RouterOS the community *name* is the secret
  (v2c) or the USM user name (v3), and it changes when an operator rotates
  it. Read-only (``write-access=no``) and restricted to the poller's source
  address(es) (``addresses=``).
* The factory ``public`` community (``default=yes``). It ships readable from
  ``::/0`` -- every address, including every guest on the hotspot LAN, whose
  input traffic the platform firewall accepts (``cloudguest-fw-allow-lan``).
  It is inert while ``/snmp`` is disabled, which is exactly the state this
  module changes, so turning the agent on without also fencing ``public``
  would hand every guest the router's interface table. While its name is
  still ``public`` it is pinned to :data:`DEFAULT_COMMUNITY_FENCE`. A default
  community an operator has renamed is theirs and is left alone.

## The desired state is data, shared with the script renderer

:func:`desired_community_row` / :func:`desired_default_fence` return plain
dicts. This writer applies them field by field;
``app.domains.network_config.renderers.render_snmp_config`` renders the very
same dicts into RouterOS script. A parity test diffs the two, which is the
only thing that has ever stopped the generator and the writers drifting
(see that module's history of fixes that landed on one path only).

## Read back, always

Every write is followed by a fresh read, and :class:`SnmpApplyResult`
reports what the device *holds*, not what was sent. RouterOS has a long
record on this fleet of accepting a write and doing nothing visible
(``set`` against an empty ``find`` succeeds silently). Passwords are not
compared on read-back: whether RouterOS echoes them over the API is
model/version dependent, and a field that cannot be read is reported as
``unverified`` rather than assumed to match.

No hardware verification yet (2026-10-06). The owner's test steps live in
the PR description.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "COMMUNITY_COMMENT",
    "DEFAULT_COMMUNITY_FENCE",
    "SnmpDeviceConfig",
    "SnmpDeviceState",
    "SnmpApplyResult",
    "desired_community_row",
    "desired_default_fence",
    "read_snmp_state",
    "apply_snmp_config",
    "remove_snmp_config",
]

#: Marker on the one community row the platform owns.
COMMUNITY_COMMENT = "wyfy-snmp"

#: Where the factory ``public`` community is pinned once SNMP is on.
DEFAULT_COMMUNITY_FENCE = "127.0.0.1/32"

_PASSWORD_FIELDS = ("authentication-password", "encryption-password")


def _truthy(value: Any) -> bool:
    return str(value).lower() in {"true", "yes"}


@dataclass(frozen=True, slots=True)
class SnmpDeviceConfig:
    """What the platform wants on the device. ``name`` is the v2c community
    or the v3 user name. ``security``: ``none`` (v2c), ``authorized``
    (v3 authNoPriv) or ``private`` (v3 authPriv)."""

    name: str
    addresses: tuple[str, ...]
    security: str = "none"
    auth_protocol: str | None = None
    auth_password: str | None = None
    priv_protocol: str | None = None
    priv_password: str | None = None

    def __repr__(self) -> str:
        return (
            f"SnmpDeviceConfig(addresses={self.addresses!r}, "
            f"security={self.security!r})"
        )


def desired_community_row(config: SnmpDeviceConfig) -> dict[str, str]:
    """The platform's ``/snmp community`` row, as RouterOS field -> value."""
    if not config.name:
        raise ValueError("SNMP community/user name is empty")
    if not config.addresses:
        # An empty addresses= on RouterOS means "any address". Refuse
        # rather than silently publish the agent to the world.
        raise ValueError("SNMP allowed source addresses are empty")
    row = {
        "name": config.name,
        "addresses": ",".join(config.addresses),
        "read-access": "yes",
        "write-access": "no",
        "security": config.security,
        "comment": COMMUNITY_COMMENT,
    }
    if config.security in {"authorized", "private"}:
        row["authentication-protocol"] = config.auth_protocol or "SHA1"
        row["authentication-password"] = config.auth_password or ""
    if config.security == "private":
        row["encryption-protocol"] = config.priv_protocol or "AES"
        row["encryption-password"] = config.priv_password or ""
    return row


def desired_default_fence() -> dict[str, str]:
    """Fields set on the factory ``public`` community (see module docstring)."""
    return {"addresses": DEFAULT_COMMUNITY_FENCE}


@dataclass(frozen=True, slots=True)
class SnmpDeviceState:
    """What the device holds right now. No secret is ever carried here."""

    agent_enabled: bool
    community_present: bool
    community_disabled: bool
    community_addresses: str | None
    community_security: str | None
    community_read_only: bool | None
    default_public_open: bool
    other_communities: int


@dataclass(frozen=True, slots=True)
class SnmpApplyResult:
    """Outcome of an apply/remove: what was written, and the read-back.
    ``mismatches`` lists fields the device does NOT hold as desired after
    the write; ``unverified`` lists fields the API did not echo back."""

    changed: list[str] = field(default_factory=list)
    state: SnmpDeviceState | None = None
    mismatches: list[str] = field(default_factory=list)
    unverified: list[str] = field(default_factory=list)

    @property
    def verified(self) -> bool:
        return not self.mismatches


def _rows(api, *segments: str) -> list[dict[str, Any]]:  # noqa: ANN001
    return [dict(row) for row in api.path(*segments)]


def _ours(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in rows if str(r.get("comment", "")) == COMMUNITY_COMMENT]


def _default_public(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    for row in rows:
        if _truthy(row.get("default")) and str(row.get("name", "")) == "public":
            return row
    return None


def _agent_enabled(api) -> bool:  # noqa: ANN001
    for row in api.path("snmp"):
        return _truthy(dict(row).get("enabled"))
    return False


def read_snmp_state(api) -> SnmpDeviceState:  # noqa: ANN001
    """Read-only."""
    rows = _rows(api, "snmp", "community")
    ours = _ours(rows)
    mine = ours[0] if ours else None
    public = _default_public(rows)
    others = [
        r
        for r in rows
        if not _truthy(r.get("default"))
        and str(r.get("comment", "")) != COMMUNITY_COMMENT
    ]
    return SnmpDeviceState(
        agent_enabled=_agent_enabled(api),
        community_present=mine is not None,
        community_disabled=bool(mine and _truthy(mine.get("disabled"))),
        community_addresses=str(mine.get("addresses")) if mine else None,
        community_security=str(mine.get("security")) if mine else None,
        community_read_only=(
            (_truthy(mine.get("read-access")) and not _truthy(mine.get("write-access")))
            if mine
            else None
        ),
        default_public_open=bool(
            public and str(public.get("addresses", "")) != DEFAULT_COMMUNITY_FENCE
        ),
        other_communities=len(others),
    )


def _compare(
    desired: dict[str, str], actual: dict[str, Any] | None, prefix: str
) -> tuple[list[str], list[str]]:
    mismatches: list[str] = []
    unverified: list[str] = []
    if actual is None:
        return [f"{prefix}:missing"], []
    for key, value in desired.items():
        if key in _PASSWORD_FIELDS:
            if key not in actual:
                unverified.append(f"{prefix}:{key}")
            elif str(actual.get(key)) != value:
                mismatches.append(f"{prefix}:{key}")
            continue
        if str(actual.get(key, "")) != value:
            mismatches.append(f"{prefix}:{key}")
    if _truthy(actual.get("disabled")):
        mismatches.append(f"{prefix}:disabled")
    return mismatches, unverified


def apply_snmp_config(api, config: SnmpDeviceConfig) -> SnmpApplyResult:  # noqa: ANN001
    """Converge the device onto ``config``; then read back."""
    desired = desired_community_row(config)
    fence = desired_default_fence()
    changed: list[str] = []

    menu = api.path("snmp", "community")
    rows = _rows(api, "snmp", "community")
    ours = _ours(rows)
    if ours:
        row = ours[0]
        delta = {k: v for k, v in desired.items() if str(row.get(k, "")) != v}
        # Passwords may not be echoed; always (re)send them so a rotation
        # on the platform is never skipped by a read that could not see it.
        for key in _PASSWORD_FIELDS:
            if key in desired:
                delta[key] = desired[key]
        if _truthy(row.get("disabled")):
            delta["disabled"] = "no"
        if delta:
            menu.update(**{".id": row[".id"], **delta})
            changed.append("community")
        for extra in ours[1:]:  # a duplicate marker is never ours to keep
            menu.remove(extra[".id"])
            changed.append("community-duplicate-removed")
    else:
        menu.add(**desired)
        changed.append("community")

    public = _default_public(rows)
    if public is not None and any(
        str(public.get(k, "")) != v for k, v in fence.items()
    ):
        menu.update(**{".id": public[".id"], **fence})
        changed.append("default-public-fenced")

    if not _agent_enabled(api):
        api.path("snmp").update(enabled="yes")
        changed.append("agent-enabled")

    # Read back.
    after = _rows(api, "snmp", "community")
    mine = _ours(after)
    mismatches, unverified = _compare(desired, mine[0] if mine else None, "community")
    if len(mine) > 1:
        mismatches.append("community:duplicate")
    public_after = _default_public(after)
    if public_after is not None:
        m, _ = _compare(fence, public_after, "default-public")
        mismatches.extend(m)
    state = read_snmp_state(api)
    if not state.agent_enabled:
        mismatches.append("agent:enabled")
    return SnmpApplyResult(
        changed=changed, state=state, mismatches=mismatches, unverified=unverified
    )


def remove_snmp_config(api) -> SnmpApplyResult:  # noqa: ANN001
    """Remove the platform's community. Turns the agent off only when no
    other non-default community remains -- an operator's own SNMP setup
    is not ours to switch off. The ``public`` fence is left in place: it
    only ever made the device safer."""
    changed: list[str] = []
    menu = api.path("snmp", "community")
    for row in _ours(_rows(api, "snmp", "community")):
        menu.remove(row[".id"])
        changed.append("community-removed")
    state = read_snmp_state(api)
    if state.agent_enabled and state.other_communities == 0:
        api.path("snmp").update(enabled="no")
        changed.append("agent-disabled")
        state = read_snmp_state(api)
    mismatches: list[str] = []
    if state.community_present:
        mismatches.append("community:still-present")
    return SnmpApplyResult(changed=changed, state=state, mismatches=mismatches)
