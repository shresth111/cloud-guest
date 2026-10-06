"""RouterOS script for the platform's SNMP agent config -- the script twin of
the device writer ``wyfy_device_gateway.mikrotik_snmp.apply_snmp_config``.

## One desired state, two renderings

Both this renderer and the writer take their field values from
``mikrotik_snmp.desired_community_row`` / ``desired_default_fence``. Nothing
here restates a field name or value; ``tests/unit/test_router_snmp_parity.py``
parses the rendered lines and diffs them against those dicts, which is how
the generator-vs-writer drift that has bitten this codebase repeatedly
(content-filter order, ``/radius add`` duplicates, missing ``/radius
incoming``) is kept out of SNMP.

## Where this script is used -- and where it deliberately is not

* Served by ``GET /platform/routers/{id}/snmp/script`` (Master only) with
  secrets masked, so an operator can see exactly what "Apply to router"
  writes, line for line.
* **Not** part of ``render_network_config`` (the customer-reachable config
  push / ``ConfigVersion`` content) -- that would store the community in a
  config version an organization user can read -- and **not** part of the
  first-paste setup script. SNMP is opt-in per router and is turned on by
  the platform over the RouterOS API after enrollment; the paste script
  never touches ``/snmp``, so the two cannot fight over it.

## Ordering

The platform's community and the fence on the factory ``public`` community
are written *before* ``/snmp set enabled=yes``. RouterOS ships ``public``
readable from ``::/0``; enabling the agent first would expose it for the
length of the paste.
"""

from __future__ import annotations

from wyfy_device_gateway.mikrotik_snmp import (
    COMMUNITY_COMMENT,
    SnmpDeviceConfig,
    desired_community_row,
    desired_default_fence,
)

__all__ = ["SECRET_MASK", "render_snmp_config", "render_snmp_removal"]

#: What a masked secret renders as.
SECRET_MASK = "********"

_SECRET_KEYS = ("name", "authentication-password", "encryption-password")


def _args(fields: dict[str, str]) -> str:
    # Every value quoted: RouterOS accepts quoted values for every field
    # here, and the request schema already restricts secrets to an
    # alphabet with no quote, backslash or `$`.
    return " ".join(f'{key}="{value}"' for key, value in fields.items())


def render_snmp_config(
    config: SnmpDeviceConfig, *, mask_secrets: bool = True
) -> list[str]:
    row = desired_community_row(config)
    if mask_secrets:
        row = {k: (SECRET_MASK if k in _SECRET_KEYS else v) for k, v in row.items()}
    marker = f'comment="{COMMUNITY_COMMENT}"'
    fence = desired_default_fence()
    return [
        "# Wyfy Guest SNMP (read-only, platform poller only)",
        (
            f":if ([:len [/snmp community find where {marker}]] = 0) do={{ "
            f"/snmp community add {_args(row)} }} else={{ "
            f"/snmp community set [find where {marker}] {_args(row)} disabled=no }}"
        ),
        (
            ':foreach c in=[/snmp community find where default=yes name="public"] '
            f"do={{ /snmp community set $c {_args(fence)} }}"
        ),
        "/snmp set enabled=yes",
        # Read-back the operator can see.
        f"/snmp community print detail where {marker}",
        "/snmp print",
    ]


def render_snmp_removal() -> list[str]:
    marker = f'comment="{COMMUNITY_COMMENT}"'
    return [
        "# Remove the Wyfy Guest SNMP community",
        f"/snmp community remove [find where {marker}]",
        (
            ":if ([:len [/snmp community find where default=no]] = 0) do={ "
            "/snmp set enabled=no }"
        ),
        "/snmp print",
    ]
