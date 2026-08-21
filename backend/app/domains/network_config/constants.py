"""Constants for the Network Configuration Management domain."""

from __future__ import annotations

from enum import StrEnum


class BootstrapMode(StrEnum):
    """Which of the two Step 1 bootstrap-script renderings a caller wants
    -- see ``renderers.render_bootstrap_script``'s docstring for the full
    design write-up of each.

    * ``ONSITE`` -- fresh enrollment with a technician physically at the
      router (console/WinBox access in hand). Cleanup-first: any stale
      tunnel state is torn down *before* the platform is ever contacted,
      because nothing valuable exists yet and unknown prior state is the
      enemy. This is the default, and the only correct mode for a router
      that has never checked in.
    * ``REMOTE`` -- re-provision of a live, already-enrolled router whose
      existing WireGuard tunnel *is* the management path being used to
      reach it. Validate-first, then a detached, scheduler-staged cutover
      with a timed automatic revert -- nothing is destroyed until every
      replacement value is validated, and the teardown/recreate never runs
      inside the session that delivered it.

    Defined here (an import-free module) rather than in ``renderers`` so
    the router domain's API layer can import it without triggering
    ``renderers``'s heavy cross-domain import graph.
    """

    ONSITE = "onsite"
    REMOTE = "remote"


# Remote-mode timing (see ``renderers.render_bootstrap_script``'s remote
# section). The cutover fires one scheduler interval after staging --
# RouterOS auto-stamps ``start-time`` at add time and an interval-only
# entry first fires one interval later ("if the interval is set to value
# other than 0 scheduler will not run at startup", RouterOS Scheduler
# docs) -- long enough for the staging paste/import to finish, short
# enough that the freshly-minted check-in facts cannot go stale.
REMOTE_BOOTSTRAP_CUTOVER_DELAY_SECONDS = 30

# How long the previous tunnel's automatic restore stays armed before it
# fires (and its retry cadence if the restore itself fails). Matches the
# 10-minute scheduled-revert convention the fleet plan's §D3 safety-net
# design already fixed ("interval=10m comment=...safety-revert"): long
# enough to cover hub-side peer sync plus WireGuard handshake latency
# (persistent-keepalive is 25s, so a working tunnel proves itself within
# a minute or two), short enough to bound a fleet router's worst-case
# management outage after a failed cutover.
REMOTE_BOOTSTRAP_REVERT_WINDOW_MINUTES = 10

# The cutover's post-create confirmation loop: up to ATTEMPTS pings of the
# hub's tunnel address, DELAY seconds apart (~2 minutes total) -- decided
# well inside the revert window above, never racing it.
REMOTE_BOOTSTRAP_CONFIRM_ATTEMPTS = 20
REMOTE_BOOTSTRAP_CONFIRM_DELAY_SECONDS = 6

# How long a rendered WAN script waits for a DHCP lease / PPPoE dial to
# actually produce a gateway before giving up and aborting the import.
#
# Why this exists: the WAN script adds the ``/ip dhcp-client`` and then
# reads its ``gateway`` property a few lines later. Pasted chunk by chunk
# by a technician that gap is seconds and the lease has always bound; run
# as a single ``/import`` it is microseconds and the lease has not. The
# read then yields an unbound value, and a ``/ip route`` built from it
# lands with ``gateway=0.0.0.0`` flagged ``Is`` (Inactive) -- every ping
# says "no route to host" while the script sails on and builds a hotspot
# on a router with no internet. Confirmed live 2026-08-21.
#
# 30 x 1s: a normal ISP DHCP lease binds in under 5s and a PPPoE dial
# completes well inside 20s, so this clears both by a wide margin while
# bounding a genuinely-dead-WAN import to half a minute per link.
WAN_GATEWAY_WAIT_ATTEMPTS = 30
WAN_GATEWAY_WAIT_DELAY_SECONDS = 1

# The one value a RouterOS gateway property reports when a DHCP client
# exists but has not yet bound a lease. Must be rejected exactly like an
# empty string -- treating it as a real gateway is the bug above.
WAN_UNRESOLVED_GATEWAY = "0.0.0.0"

# Human-readable section headers written into the rendered RouterOS
# script ahead of each category's own commands -- purely cosmetic (a
# comment line, never parsed back), but real value for anyone reading a
# pushed ``ConfigVersion.rendered_content``/diff by hand.
DHCP_SECTION_HEADER = "# --- DHCP Pools (CloudGuest-managed) ---"
VLAN_SECTION_HEADER = "# --- VLANs (CloudGuest-managed) ---"
PORT_FORWARDING_SECTION_HEADER = "# --- Port Forwarding (CloudGuest-managed) ---"
HOTSPOT_SECTION_HEADER = "# --- Hotspot Profiles (CloudGuest-managed) ---"
QOS_SECTION_HEADER = "# --- QoS Traffic Rules (CloudGuest-managed) ---"
DNS_SECTION_HEADER = "# --- DNS Records (CloudGuest-managed) ---"
FIREWALL_SECTION_HEADER = "# --- Firewall Rules (CloudGuest-managed) ---"
WIREGUARD_SECTION_HEADER = "# --- WireGuard Peer (CloudGuest-managed) ---"
RADIUS_SECTION_HEADER = "# --- RADIUS Client (CloudGuest-managed) ---"
MAC_AUTHORIZATION_SECTION_HEADER = "# --- MAC Authorization (CloudGuest-managed) ---"
# ISP Link Netwatch -- see renderers.py's own "Netwatch" section for the
# full design write-up. A distinct, standalone push (never folded into
# render_network_config's own combined script -- see
# NetworkConfigService.push_isp_netwatch_config's own docstring for why).
NETWATCH_SECTION_HEADER = "# --- ISP Link Netwatch (CloudGuest-managed) ---"
CONTENT_FILTER_SECTION_HEADER = "# --- Content Filtering (CloudGuest-managed) ---"

__all__ = [
    "BootstrapMode",
    "REMOTE_BOOTSTRAP_CUTOVER_DELAY_SECONDS",
    "REMOTE_BOOTSTRAP_REVERT_WINDOW_MINUTES",
    "REMOTE_BOOTSTRAP_CONFIRM_ATTEMPTS",
    "REMOTE_BOOTSTRAP_CONFIRM_DELAY_SECONDS",
    "WAN_GATEWAY_WAIT_ATTEMPTS",
    "WAN_GATEWAY_WAIT_DELAY_SECONDS",
    "WAN_UNRESOLVED_GATEWAY",
    "DHCP_SECTION_HEADER",
    "VLAN_SECTION_HEADER",
    "PORT_FORWARDING_SECTION_HEADER",
    "HOTSPOT_SECTION_HEADER",
    "QOS_SECTION_HEADER",
    "DNS_SECTION_HEADER",
    "FIREWALL_SECTION_HEADER",
    "WIREGUARD_SECTION_HEADER",
    "RADIUS_SECTION_HEADER",
    "MAC_AUTHORIZATION_SECTION_HEADER",
    "NETWATCH_SECTION_HEADER",
    "CONTENT_FILTER_SECTION_HEADER",
]
