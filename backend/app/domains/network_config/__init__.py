"""Network Configuration Management domain: renders a router's real
DHCP/VLAN/Port Forwarding rows into RouterOS script text and pushes it
through ``app.domains.router_provisioning``'s already-real config-version/
apply/rollback pipeline -- the "provisioning-integration mechanism" every
one of those three domains' own ``FLOW.md`` explicitly deferred real
device provisioning to.

## A thin renderer, not a fourth history table

This domain owns no table, no migration, no history of its own. Every
config version this domain creates lives in ``app.domains
.router_provisioning``'s own ``ConfigVersion`` table (via a new,
narrowly-scoped ``create_version_from_content`` method added to that
domain -- see its own docstring), and every version/diff/rollback read
this domain exposes delegates directly to that domain's own already-real,
already-tested methods. See ``docs/network_config/FLOW.md`` for the full
design write-up, including why this scope was chosen over an
NCM-owned push-run history table.

## What "push" means here

A push renders ONE combined RouterOS script covering every enabled
``DhcpPool``/``Vlan``/``PortForwardingRule`` row currently on the target
router (a full desired-state snapshot, mirroring how ``ConfigVersion``
already represents a router's whole config, not an incremental diff),
creates a new ``DRAFT`` version from that content, and immediately calls
``apply_version`` to queue it through the same real, already-established
pull-model provisioning queue every other config version already flows
through (a real router-side agent -- ``app.domains.router_agent`` --
polls for and completes these jobs; this domain fabricates no second
device-I/O mechanism).
"""

from __future__ import annotations
