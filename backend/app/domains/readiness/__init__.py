"""Router Readiness Checklist domain: a per-router, fourteen-item
production-readiness checklist -- "is this router actually ready to hand
to a customer", not a live monitoring/alerting system (that remains
``app.domains.monitoring``'s job).

## One table, one status per item

``RouterChecklistItem`` (one row per ``(router_id, item_key)``, updated in
place) is the entire persistence surface. There is no history table -- a
checklist reflects the *current* state of readiness, the same "one row per
subject" posture ``app.domains.router_agent.models.RouterAgentCredential``
already establishes for its own per-router status half.

## Two kinds of items, one schema

Five items (``constants.DetectionMode.AUTO``) are computed live on every
``GET`` by composing narrow reads against ``router``/``isp``/``wireguard``/
``router_agent`` -- zero new device I/O, using telemetry this platform
already collects. The other nine (``DetectionMode.MANUAL``) are set only by
an operator via the confirm endpoint. Both kinds share the exact same row
shape; ``detection_mode`` records how a given row's *current* status was
produced, not a fixed property of the item -- a human can override any auto
item (most usefully ``WIREGUARD``, where the auto-check honestly cannot
tell "not configured" from "broken" on its own).

## What's deliberately out of scope for this pass

Six manual items (LAN DHCP, Hotspot, Captive portal, DNS, Firewall rule
presence, reboot-persistence) could become auto-detected with one small new
read-only adapter call each -- left manual here rather than adding six new
adapter calls to ship the checklist itself. RADIUS live-auth testing and
DoH/DoT blocking have no supporting capability anywhere in the codebase
yet (no synthetic-auth harness; no config-generation to check DoH/DoT
blocking *against*) -- see ``constants.py``'s own module docstring.
"""
