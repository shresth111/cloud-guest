"""Enumerations and small constants for the Content Filtering domain.

Every enum here is stored as a plain ``String`` column, never a native
PostgreSQL enum type -- the same reason every other domain in this
codebase documents: adding a new value never requires an ``ALTER TYPE``
migration, only a new additive ``StrEnum`` member.

## The two literal values shared with ``wyfy_device_gateway``

``CONTENT_FILTER_SINKHOLE_ADDRESS``/``CONTENT_FILTER_ADDRESS_LIST_NAME``
are also hard-coded (independently, not imported -- the vendor package
cannot depend on ``app.domains``, see its own module docstring) as
identical literals in ``wyfy_device_gateway.mikrotik_adapter``'s own
``configure_content_filter_rule``. Both describe the exact same real
RouterOS objects (a DNS sinkhole target address, an address-list name);
keeping the literal *values* identical across the two independent copies
is what keeps them describing the same device-side objects, not two
different ones -- see ``app.domains.network_config.renderers``'s own
"Content Filtering" module-docstring section for the full scope
write-up these constants implement.
"""

from __future__ import annotations

from enum import StrEnum

# A loopback address, deliberately -- see renderers.py's own "Content
# Filtering" section for why this, and not e.g. 0.0.0.0 or a "block page"
# LAN IP, is the real, honest sinkhole target: it always exists, needs no
# LAN host to actually be listening on it, and never ARPs a real device.
CONTENT_FILTER_SINKHOLE_ADDRESS = "127.0.0.1"

# RouterOS ``/ip firewall address-list`` list name every IP_CIDR rule's
# membership is added to, and the one, aggregate
# ``/ip firewall filter ... dst-address-list=`` DROP rule matches against
# -- see renderers.py's own docstring for why this is rendered once per
# router, not once per rule.
CONTENT_FILTER_ADDRESS_LIST_NAME = "wyfyguest-content-filter-blocked"


class ContentFilterValueType(StrEnum):
    """What ``ContentFilterRule.value`` actually holds, and therefore
    which real RouterOS enforcement mechanism a rule renders into -- see
    ``app.domains.network_config.renderers.render_content_filter_rule``.

    ``DOMAIN`` -- a bare hostname (``"facebook.com"``), DNS-sinkholed via
    ``/ip dns static``. ``IP_CIDR`` -- an IP address or CIDR block,
    dropped via ``/ip firewall address-list`` + one shared
    ``/ip firewall filter`` rule. There is deliberately no ``KEYWORD``/
    ``URL_PATH``/``REGEX`` value type: real URL-path or keyword matching
    needs Layer7/deep-packet-inspection (expensive on the low-power
    hardware this platform actually deploys) or a transparent HTTP proxy
    that is blind to HTTPS -- see that same renderers.py section for the
    full honest scope decision this domain deliberately does not
    implement."""

    DOMAIN = "domain"
    IP_CIDR = "ip_cidr"


class ContentFilterCategory(StrEnum):
    """A purely organizational/reporting label an admin attaches to a
    rule -- e.g. grouping "block facebook.com, instagram.com,
    tiktok.com" under ``SOCIAL_MEDIA`` in the dashboard. This is
    deliberately **not** a seeded, "complete" blocklist-per-category the
    way some commercial content filters ship one -- this platform has no
    real, maintained domain-category database to honestly back that
    claim with, and shipping a fabricated one that only *looks* complete
    would be exactly the kind of "looks wired up but isn't" shortcut this
    codebase's own conventions reject. An admin populates the actual
    domains/IPs themselves (one ``ContentFilterRule`` row per value,
    mirroring ``app.domains.mac_authorization``'s own "the org populates
    its own whitelist" precedent) and tags each with whichever category
    below best describes it, purely for their own dashboard filtering/
    reporting -- enforcement never depends on this field's value."""

    SOCIAL_MEDIA = "social_media"
    ADULT_CONTENT = "adult_content"
    GAMBLING = "gambling"
    STREAMING = "streaming"
    GAMING = "gaming"
    CUSTOM = "custom"


__all__ = [
    "CONTENT_FILTER_SINKHOLE_ADDRESS",
    "CONTENT_FILTER_ADDRESS_LIST_NAME",
    "ContentFilterValueType",
    "ContentFilterCategory",
]
