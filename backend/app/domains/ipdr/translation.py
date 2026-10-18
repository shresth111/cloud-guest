"""Translated IP / Translated Port: one small interface, so the source can
change without touching the builder.

RouterOS meters traffic-flow at the end of the forward chain, **before**
srcnat (~/wyfy-ops/ipdr/NAT-RESEARCH.md). A post-NAT value can only come from
conntrack: IPFIX NAT events (``nat-events=yes``, template 260 -- gated by
``traffic_flow_ipfix_nat_events``, unmeasured on our fleet) or a post-NAT
source the exporter filled. A post-NAT source *equal* to the source is not
a translation (router-originated traffic is not masqueraded, and an
un-snapshotted first-packet record carries the plain tuple).

``ExactOrRouterPublicIp`` -- today's resolver, sources:

1. ``nat_event``: the flow's own post-NAT source differs from its source.
2. ``derived``: the router's ``public_ip_address`` and the flow's own source
   port (masquerade keeps it when the reply tuple is unique).
3. ``ambiguous`` -- set by the builder on a ``derived`` row when masquerade
   would have had to remap (``join.mark_ambiguous``).
4. ``none``: no public address known; both cells blank.

The router's public address is a single typed-in value, not a history: a
per-router WAN-address time series (DHCP/PPPoE addresses change) is the
follow-up resolver, and ``at`` is already passed for it.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from .constants import (
    TRANSLATION_DERIVED,
    TRANSLATION_NAT_EVENT,
    TRANSLATION_NONE,
)
from .formatting import normalize_ip


@dataclass(frozen=True, slots=True)
class Translation:
    address: str | None
    port: int | None
    source: str


NO_TRANSLATION = Translation(None, None, TRANSLATION_NONE)


class TranslationResolver(Protocol):
    def translate(
        self,
        *,
        router_id: uuid.UUID,
        at: datetime,
        src_ip: str,
        src_port: int | None,
        nat_ip: str | None,
        nat_port: int | None,
    ) -> Translation: ...


class ExactOrRouterPublicIp:
    def __init__(self, public_ips: Mapping[uuid.UUID, str | None]) -> None:
        self._public = {k: normalize_ip(v) for k, v in public_ips.items()}

    def translate(
        self,
        *,
        router_id: uuid.UUID,
        at: datetime,
        src_ip: str,
        src_port: int | None,
        nat_ip: str | None,
        nat_port: int | None,
    ) -> Translation:
        nat = normalize_ip(nat_ip)
        if nat is not None and nat != normalize_ip(src_ip):
            return Translation(nat, nat_port, TRANSLATION_NAT_EVENT)
        public = self._public.get(router_id)
        if public is not None:
            return Translation(public, src_port, TRANSLATION_DERIVED)
        return NO_TRANSLATION
