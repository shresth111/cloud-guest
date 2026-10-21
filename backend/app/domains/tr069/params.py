"""Curated TR-181 / TR-098 parameters (API_CONTRACT §6.3).

The resolver tries TR-181 (``Device.``) first, then TR-098
(``InternetGatewayDevice.``). **Passwords never leave GenieACS through us**:
``is_denied`` is enforced in the resolver (a denied path resolves to
``None``) *and* in ``refresh_parameter_names`` (a denied path is never asked
for), and ``curate`` only ever builds the fixed set of keys below -- there is
no code path that copies a raw subtree into ``params_cache``. Lesson from the
Omada SSID-list password leak.
"""

from __future__ import annotations

import re
from typing import Any

#: Any path segment matching this is never read, stored or requested.
_DENY = re.compile(
    r"(KeyPassphrase|PreSharedKey|WEPKey|Password|Passphrase|^X_.*Pass.*|Secret)",
    re.IGNORECASE,
)

WIFI_SLOTS = 4

TR181 = "Device."
TR098 = "InternetGatewayDevice."

#: logical name -> (TR-181 path, TR-098 path)
SCALARS: dict[str, tuple[str, str]] = {
    "manufacturer": ("Device.DeviceInfo.Manufacturer", "InternetGatewayDevice.DeviceInfo.Manufacturer"),
    "model": ("Device.DeviceInfo.ModelName", "InternetGatewayDevice.DeviceInfo.ModelName"),
    "serial_number": ("Device.DeviceInfo.SerialNumber", "InternetGatewayDevice.DeviceInfo.SerialNumber"),
    "software_version": (
        "Device.DeviceInfo.SoftwareVersion",
        "InternetGatewayDevice.DeviceInfo.SoftwareVersion",
    ),
    "hardware_version": (
        "Device.DeviceInfo.HardwareVersion",
        "InternetGatewayDevice.DeviceInfo.HardwareVersion",
    ),
    "uptime_s": ("Device.DeviceInfo.UpTime", "InternetGatewayDevice.DeviceInfo.UpTime"),
    "acs_username": (
        "Device.ManagementServer.Username",
        "InternetGatewayDevice.ManagementServer.Username",
    ),
    "periodic_inform_interval_s": (
        "Device.ManagementServer.PeriodicInformInterval",
        "InternetGatewayDevice.ManagementServer.PeriodicInformInterval",
    ),
    "lan_hosts": (
        "Device.Hosts.HostNumberOfEntries",
        "InternetGatewayDevice.LANDevice.1.Hosts.HostNumberOfEntries",
    ),
    "pppoe_username": (
        "Device.PPP.Interface.1.Username",
        "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.Username",
    ),
}

WAN_IP_PATHS: tuple[str, ...] = (
    "Device.IP.Interface.1.IPv4Address.1.IPAddress",
    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress",
    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress",
)
_TR098_PPP_IP = WAN_IP_PATHS[1]
_TR098_IP_TYPE = (
    "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.AddressingType"
)


def _wifi_paths(i: int) -> dict[str, tuple[str, ...]]:
    return {
        "ssid": (
            f"Device.WiFi.SSID.{i}.SSID",
            f"InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i}.SSID",
        ),
        "enabled": (
            f"Device.WiFi.SSID.{i}.Enable",
            f"InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i}.Enable",
        ),
        "clients": (
            f"Device.WiFi.AccessPoint.{i}.AssociatedDeviceNumberOfEntries",
            f"InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i}.TotalAssociations",
        ),
        "band": (
            f"Device.WiFi.Radio.{i}.OperatingFrequencyBand",
            f"InternetGatewayDevice.LANDevice.1.WLANConfiguration.{i}.OperatingFrequencyBand",
        ),
    }


def is_denied(path: str) -> bool:
    return any(_DENY.search(segment) for segment in path.split(".") if segment)


def resolve(doc: dict[str, Any], path: str) -> Any:
    """The ``_value`` at ``path`` in a GenieACS device document, or None.
    A denied path is always None, whatever the document holds."""
    if is_denied(path):
        return None
    node: Any = doc
    for segment in path.split("."):
        if not isinstance(node, dict) or segment not in node:
            return None
        node = node[segment]
    if isinstance(node, dict):
        return node.get("_value")
    return None


def first(doc: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        value = resolve(doc, path)
        if value not in (None, ""):
            return value
    return None


def data_model(doc: dict[str, Any]) -> str | None:
    if isinstance(doc.get("Device"), dict):
        return "tr181"
    if isinstance(doc.get("InternetGatewayDevice"), dict):
        return "tr098"
    return None


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "up"}
    if isinstance(value, int):
        return bool(value)
    return None


def _band(value: Any) -> str | None:
    text = str(value or "")
    if "5" in text:
        return "5GHz"
    if "2.4" in text or "2,4" in text:
        return "2.4GHz"
    return None


def scalar(doc: dict[str, Any], name: str) -> Any:
    return first(doc, *SCALARS[name])


def curate(doc: dict[str, Any]) -> dict[str, Any]:
    """The only shape ``params_cache`` ever holds."""
    wifi = []
    for i in range(1, WIFI_SLOTS + 1):
        paths = _wifi_paths(i)
        ssid = first(doc, *paths["ssid"])
        if ssid is None:
            continue
        wifi.append(
            {
                "index": i,
                "ssid": str(ssid),
                "band": _band(first(doc, *paths["band"])),
                "enabled": _bool(first(doc, *paths["enabled"])),
                "clients": _int(first(doc, *paths["clients"])),
            }
        )
    pppoe_username = scalar(doc, "pppoe_username")
    if resolve(doc, _TR098_PPP_IP) or pppoe_username:
        connection = "pppoe"
    elif str(resolve(doc, _TR098_IP_TYPE) or "").lower() == "static":
        connection = "static"
    elif resolve(doc, WAN_IP_PATHS[2]) or resolve(doc, WAN_IP_PATHS[0]):
        connection = "dhcp"
    else:
        connection = None
    return {
        "uptime_s": _int(scalar(doc, "uptime_s")),
        "wan_ip": first(doc, *WAN_IP_PATHS),
        "wan_connection_type": connection,
        "pppoe_username": pppoe_username,
        "wifi": wifi,
        "lan_hosts": _int(scalar(doc, "lan_hosts")),
        "hardware_version": scalar(doc, "hardware_version"),
        "software_version": scalar(doc, "software_version"),
    }


def refresh_parameter_names(model: str | None) -> list[str]:
    """Leaf paths for ``getParameterValues``. Leaves, not subtrees, so a
    password under a requested object can never be pulled in; filtered
    through the denylist anyway."""
    index = 0 if model != "tr098" else 1
    names = [pair[index] for pair in SCALARS.values()]
    names += [p for p in WAN_IP_PATHS if p.startswith(TR181 if index == 0 else TR098)]
    for i in range(1, WIFI_SLOTS + 1):
        names += [pair[index] for pair in _wifi_paths(i).values()]
    if index == 1:
        names.append(_TR098_IP_TYPE)
    return [n for n in names if not is_denied(n)]


def projection() -> list[str]:
    """NBI projection for sync: identity, inform state, and the curated
    leaves for both data models."""
    out = ["_id", "_lastInform", "_registered", "_deviceId", "_tags"]
    for tr181, tr098 in SCALARS.values():
        out += [tr181, tr098]
    out += list(WAN_IP_PATHS) + [_TR098_IP_TYPE]
    for i in range(1, WIFI_SLOTS + 1):
        for pair in _wifi_paths(i).values():
            out += list(pair)
    return [p for p in out if not is_denied(p)]
