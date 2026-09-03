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


class ContentFilterDevicePushStatus(StrEnum):
    """Lifecycle of a :class:`~.models.ContentFilterRule`'s own device push.

    Distinct from ``is_enabled``, which is intent ("this site should be
    blocked"), and independent of ``network_config``'s ``ConfigVersion``
    status -- that pipeline renders a script and ships it over SSH on port
    22, which is filtered on the fleet; this is a direct RouterOS-API push
    on 8728. A rule can be enabled, rendered into a config version, and
    still never have reached a device -- which was the state of every row
    in this table before this domain had a push at all, and is exactly why
    a customer could block a site, be shown that it was blocked, and reach
    it from the guest network unchanged.

    * ``PENDING`` -- created, never pushed. The state every pre-existing
      row is backfilled to, truthfully: until now no code path could push
      one.
    * ``ACTIVE`` -- the real ``/ip dns static`` entries (a domain rule) or
      ``/ip firewall address-list`` membership (an IP/CIDR rule) for this
      row exist on the router. Stated exactly that narrowly on purpose:
      it is a claim about objects this platform wrote and can read back,
      not a claim that a packet was observed being dropped. Two known
      limits sit behind it, both documented where they live rather than
      hidden here -- a guest device that sets its own DNS resolver
      bypasses a domain rule's sinkhole entirely (see this package's
      ``__init__`` docstring), and an IP/CIDR rule's shared
      ``/ip firewall filter`` DROP rule has an unmanaged position in the
      ``forward`` chain, so a router carrying a broad accept ahead of it
      forwards the traffic regardless (see
      ``wyfy_device_gateway.mikrotik_adapter
      ._ensure_content_filter_enforcement_rule``).
    * ``FAILED`` -- the last push attempt raised; ``device_push_error``
      holds the device's own words.
    """

    PENDING = "pending"
    ACTIVE = "active"
    FAILED = "failed"


__all__ = [
    "CONTENT_FILTER_SINKHOLE_ADDRESS",
    "CONTENT_FILTER_ADDRESS_LIST_NAME",
    "ContentFilterValueType",
    "ContentFilterCategory",
    "ContentFilterDevicePushStatus",
    "DEVICE_CARRIED_FIELDS",
]


# The two columns ``ContentFilterService.push_rule_to_device`` actually
# puts on the router: ``value`` is the blocked domain or address itself,
# and ``value_type`` decides which mechanism realizes it (a DNS sinkhole
# or an address-list entry plus the shared DROP rule) -- a re-typed rule
# tears down the mechanism it stopped using. Changing either makes an
# ``ACTIVE`` row claim a site is blocked that is not. See
# ``app.common.device_push``.
#
# ``name`` is deliberately absent even though it *does* reach the device:
# it is carried as ``label``, the mutable tail of the RouterOS comment
# whose identity marker is the rule id (see
# ``mikrotik_adapter.configure_content_filter_rule``'s own "the comment is
# the rule's identity" section). A stale label on a comment blocks exactly
# what the customer asked for; demoting a live block to "not yet applied"
# over a rename would be the more misleading of the two. ``category``/
# ``comment`` never leave the database, and ``is_enabled`` is intent.
DEVICE_CARRIED_FIELDS = frozenset({"value", "value_type"})
