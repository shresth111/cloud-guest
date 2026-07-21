"""Constants for the Network Configuration Management domain."""

from __future__ import annotations

# Human-readable section headers written into the rendered RouterOS
# script ahead of each category's own commands -- purely cosmetic (a
# comment line, never parsed back), but real value for anyone reading a
# pushed ``ConfigVersion.rendered_content``/diff by hand.
DHCP_SECTION_HEADER = "# --- DHCP Pools (CloudGuest-managed) ---"
VLAN_SECTION_HEADER = "# --- VLANs (CloudGuest-managed) ---"
PORT_FORWARDING_SECTION_HEADER = "# --- Port Forwarding (CloudGuest-managed) ---"
HOTSPOT_SECTION_HEADER = "# --- Hotspot Profiles (CloudGuest-managed) ---"
QOS_SECTION_HEADER = "# --- QoS Traffic Rules (CloudGuest-managed) ---"

__all__ = [
    "DHCP_SECTION_HEADER",
    "VLAN_SECTION_HEADER",
    "PORT_FORWARDING_SECTION_HEADER",
    "HOTSPOT_SECTION_HEADER",
    "QOS_SECTION_HEADER",
]
