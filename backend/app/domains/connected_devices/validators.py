"""Pure helpers for the Connected Device Management domain -- no I/O,
easy to unit-test in isolation (mirrors every other domain's own
``validators.py`` convention).

Unlike most other domains built in this batch, there is no user-facing
"create a connected device" input to validate -- rows only ever come into
existence via a real device sync (see ``device_adapters.py``). These
helpers are therefore lenient parsers of *real device output*
(RouterOS's own DHCP-lease/ARP/wireless-registration-table replies),
never raising on malformed input -- a router returning one odd row must
never abort an entire sync tick (mirrors
``app.domains.isp.device_adapters._parse_ping_rows``'s own "never crash
a health check that otherwise has a perfectly good tally" posture).
"""

from __future__ import annotations

import re

from .constants import OUI_VENDOR_PREFIXES

_MAC_ADDRESS_PATTERN = re.compile(
    r"^([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]"
    r"([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})$"
)


def normalize_mac_address(value: str | None) -> str | None:
    """Returns the canonical uppercase colon-separated form of ``value``,
    or ``None`` if it isn't a real six-octet MAC address at all --
    lenient by design (see module docstring), never raises."""
    if not value:
        return None
    match = _MAC_ADDRESS_PATTERN.match(value.strip())
    if match is None:
        return None
    return ":".join(octet.upper() for octet in match.groups())


def vendor_from_mac(mac_address: str) -> str | None:
    """Looks up ``mac_address``'s own OUI (first three octets) against
    :data:`~.constants.OUI_VENDOR_PREFIXES` -- returns ``None`` (genuinely
    unknown) for any prefix not in that intentionally small table, never
    a guessed vendor name."""
    prefix = mac_address[:8]
    return OUI_VENDOR_PREFIXES.get(prefix)


__all__ = ["normalize_mac_address", "vendor_from_mac"]
