"""Pure validation helpers for the Hotspot Settings domain -- no I/O,
easy to unit-test in isolation (mirrors every other domain's own
``validators.py`` convention).
"""

from __future__ import annotations

from .constants import MAX_WALLED_GARDEN_HOSTS
from .exceptions import InvalidWalledGardenHostError, TooManyWalledGardenHostsError


def validate_walled_garden_hosts(hosts: list[str]) -> None:
    """Raises :class:`~.exceptions.TooManyWalledGardenHostsError` past
    ``MAX_WALLED_GARDEN_HOSTS`` entries, or
    :class:`~.exceptions.InvalidWalledGardenHostError` for any blank entry
    or one containing whitespace. Deliberately permissive otherwise --
    RouterOS's own walled-garden ``dst-host`` matcher accepts plain
    hostnames, IPs, and ``*``-prefixed wildcard domains
    (``*.example.com``), so no stricter hostname grammar is enforced
    here."""
    if len(hosts) > MAX_WALLED_GARDEN_HOSTS:
        raise TooManyWalledGardenHostsError(MAX_WALLED_GARDEN_HOSTS)
    for host in hosts:
        if not host or host != host.strip() or any(ch.isspace() for ch in host):
            raise InvalidWalledGardenHostError(host)


__all__ = ["validate_walled_garden_hosts"]
