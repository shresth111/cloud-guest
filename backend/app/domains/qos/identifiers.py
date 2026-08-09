"""The single source of truth for a :class:`~.models.QosTrafficRule` row's
own RouterOS packet-mark identifier.

## Why this lives here, not in ``network_config.renderers``

Two independent call sites must derive **the exact same string** for a
given rule, or the device-side pairing this fix exists to create breaks
silently:

1. ``app.domains.network_config.renderers.render_qos_traffic_rule`` emits
   the ``/ip firewall mangle ... new-packet-mark=<identifier>`` line.
2. ``app.domains.qos.device_adapters`` (via ``service.push_rule_to_device``)
   creates the paired ``/queue tree ... packet-mark=<identifier>`` entry
   that references that exact same mark.

The identifier logic used to live only in ``network_config.renderers`` as
a private ``_qos_identifier`` helper. Moving it here -- the domain that
actually owns ``QosTrafficRule`` -- rather than having ``app.domains.qos``
import it back out of ``network_config`` avoids a real import cycle:
``network_config.renderers`` already imports ``QosTrafficRule`` from this
domain (``from app.domains.qos.models import QosTrafficRule``), so the
dependency direction is already network_config -> qos; qos importing
anything back from network_config would cycle. ``network_config.renderers``
now imports :func:`qos_packet_mark_identifier` from here instead of
defining its own copy, so there remains exactly one implementation, not
two that could drift apart.
"""

from __future__ import annotations

from .models import QosTrafficRule


def qos_packet_mark_identifier(rule: QosTrafficRule) -> str:
    """``QosTrafficRule.name`` carries no uniqueness constraint -- suffixing
    with the row's own real, guaranteed-unique primary key avoids a
    RouterOS name collision between two differently-configured rules that
    happen to share a display name. Identical sanitization/suffixing
    discipline to every other ``_*_identifier`` helper in
    ``network_config.renderers`` (``_dhcp_identifier``/
    ``_hotspot_identifier``), duplicated here in miniature (not imported
    from that module) specifically to avoid the import-cycle problem this
    module's own docstring describes -- this one small, pure string
    function is cheap to keep in sync by inspection, unlike the identifier
    *value* itself, which absolutely must stay identical across both real
    call sites."""
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in rule.name)
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    cleaned = cleaned.strip("-") or "unnamed"
    return f"{cleaned}-{str(rule.id)[:8]}"


__all__ = ["qos_packet_mark_identifier"]
