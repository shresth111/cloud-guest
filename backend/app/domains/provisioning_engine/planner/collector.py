"""Pure collectors: ``ReadOnlyStateCapture`` → typed dicts for persistence.

No device I/O, no DB access. Every function is deterministic and
unit-testable against canned ``ReadOnlyStateCapture`` fixtures.

Safety rules applied here (defense in depth on top of
``ReadOnlyDeviceReader`` sanitization):

* Strip any residual secret-shaped keys (``password``, ``secret``,
  ``private-key``, ``on-event``, …) before a row is persisted.
* Firewall / NAT are reduced to **counts + wyfy_tagged_count** -- never
  full rule bodies that could embed secrets in ``comment`` / ``to-addresses``
  / ``content`` matchers.
* ``is_wyfy_managed`` is derived only from known comment prefixes
  (``WYFYGUEST-``, ``cloudguest-``).
"""

from __future__ import annotations

from typing import Any

from wyfy_device_gateway.read_only_reader import (
    SANITIZED_ROW_FIELDS,
    ReadOnlyStateCapture,
)

from .constants import MANAGED_COMMENT_PREFIXES, SnapshotStatus

# Extra keys that look secret even if the transport layer missed them.
_SECRET_KEY_FRAGMENTS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "private-key",
        "private_key",
        "preshared-key",
        "pre-shared-key",
        "passphrase",
        "wpa-passphrase",
        "wpa2-pre-shared-key",
        "on-event",
        "on_event",
        "api-key",
        "api_key",
        "token",
    }
)


def is_wyfy_managed(comment: str | None) -> bool:
    """True when ``comment`` starts with a known WyFy / cloudguest prefix."""
    if not comment:
        return False
    return any(comment.startswith(prefix) for prefix in MANAGED_COMMENT_PREFIXES)


def _looks_secret_key(key: str) -> bool:
    lowered = key.lower().replace("_", "-")
    if key in SANITIZED_ROW_FIELDS or lowered in SANITIZED_ROW_FIELDS:
        return True
    return any(fragment in lowered for fragment in _SECRET_KEY_FRAGMENTS)


def strip_secrets(row: dict[str, Any]) -> dict[str, Any]:
    """Defensive second-pass sanitization before persistence / API."""
    out: dict[str, Any] = {}
    for key, value in row.items():
        if _looks_secret_key(key):
            # Preserve presence booleans the transport already emitted.
            if key.startswith("has_"):
                out[key] = bool(value)
            else:
                out[f"has_{key.replace('-', '_')}"] = bool(value)
            continue
        if isinstance(value, dict):
            out[key] = strip_secrets(value)
        elif isinstance(value, list):
            out[key] = [
                strip_secrets(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            out[key] = value
    return out


def _as_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() not in {"false", "no", "0", ""}
    return bool(value)


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _first_row(sections: dict[str, list[dict[str, Any]]], name: str) -> dict[str, Any]:
    rows = sections.get(name) or []
    return rows[0] if rows else {}


def _comment(row: dict[str, Any]) -> str | None:
    raw = row.get("comment")
    return str(raw) if raw is not None and raw != "" else None


def collect_system_identity(
    capture: ReadOnlyStateCapture,
) -> dict[str, Any]:
    """Pull model / version / architecture / memory from system sections."""
    resource = _first_row(capture.sections, "system_resource")
    board = _first_row(capture.sections, "system_routerboard")

    model = (
        board.get("model")
        or board.get("board-name")
        or resource.get("board-name")
        or None
    )
    version = resource.get("version")
    architecture = resource.get("architecture-name") or resource.get("architecture")

    return {
        "model": str(model) if model else None,
        "routeros_version": str(version) if version else None,
        "architecture": str(architecture) if architecture else None,
        "total_memory_bytes": _as_int(resource.get("total-memory")),
        "free_memory_bytes": _as_int(resource.get("free-memory")),
        "free_storage_bytes": _as_int(resource.get("free-hdd-space")),
    }


def collect_interfaces(capture: ReadOnlyStateCapture) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in capture.sections.get("interfaces") or []:
        clean = strip_secrets(row)
        comment = _comment(clean)
        result.append(
            {
                "name": str(clean.get("name") or ""),
                "type": clean.get("type"),
                "running": _as_bool(clean.get("running")),
                "disabled": _as_bool(clean.get("disabled")),
                "comment": comment,
                "is_wyfy_managed": is_wyfy_managed(comment),
            }
        )
    return result


def collect_bridges(capture: ReadOnlyStateCapture) -> list[dict[str, Any]]:
    ports_by_bridge: dict[str, list[str]] = {}
    for port in capture.sections.get("bridge_ports") or []:
        bridge = str(port.get("bridge") or "")
        iface = str(port.get("interface") or "")
        if bridge and iface:
            ports_by_bridge.setdefault(bridge, []).append(iface)

    result: list[dict[str, Any]] = []
    for row in capture.sections.get("bridges") or []:
        clean = strip_secrets(row)
        name = str(clean.get("name") or "")
        comment = _comment(clean)
        result.append(
            {
                "name": name,
                "comment": comment,
                "is_wyfy_managed": is_wyfy_managed(comment),
                "ports": ports_by_bridge.get(name, []),
            }
        )
    return result


def collect_ip_addresses(capture: ReadOnlyStateCapture) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in capture.sections.get("ip_addresses") or []:
        clean = strip_secrets(row)
        comment = _comment(clean)
        result.append(
            {
                "address": clean.get("address"),
                "interface": clean.get("interface"),
                "comment": comment,
                "is_wyfy_managed": is_wyfy_managed(comment),
            }
        )
    return result


def collect_dhcp_clients(capture: ReadOnlyStateCapture) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in capture.sections.get("dhcp_clients") or []:
        clean = strip_secrets(row)
        comment = _comment(clean)
        entry: dict[str, Any] = {
            "interface": clean.get("interface"),
            "status": clean.get("status"),
            "comment": comment,
            "is_wyfy_managed": is_wyfy_managed(comment),
        }
        if "has_password" in clean:
            entry["has_password"] = bool(clean["has_password"])
        result.append(entry)
    # PPPoE clients also carry has_password from the transport layer.
    for row in capture.sections.get("pppoe_clients") or []:
        clean = strip_secrets(row)
        comment = _comment(clean)
        result.append(
            {
                "interface": clean.get("interface") or clean.get("name"),
                "status": clean.get("status") or "pppoe",
                "comment": comment,
                "is_wyfy_managed": is_wyfy_managed(comment),
                "has_password": bool(clean.get("has_password", False)),
            }
        )
    return result


def collect_dhcp_servers(capture: ReadOnlyStateCapture) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in capture.sections.get("dhcp_servers") or []:
        clean = strip_secrets(row)
        comment = _comment(clean)
        result.append(
            {
                "name": clean.get("name"),
                "interface": clean.get("interface"),
                "address_pool": clean.get("address-pool") or clean.get("address_pool"),
                "comment": comment,
                "is_wyfy_managed": is_wyfy_managed(comment),
            }
        )
    return result


def collect_routes(capture: ReadOnlyStateCapture) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in capture.sections.get("routes") or []:
        clean = strip_secrets(row)
        comment = _comment(clean)
        result.append(
            {
                "dst_address": clean.get("dst-address") or clean.get("dst_address"),
                "gateway": clean.get("gateway"),
                "distance": _as_int(clean.get("distance")),
                "active": _as_bool(clean.get("active")),
                "comment": comment,
                "is_wyfy_managed": is_wyfy_managed(comment),
            }
        )
    return result


def collect_dns_config(capture: ReadOnlyStateCapture) -> dict[str, Any]:
    row = strip_secrets(_first_row(capture.sections, "dns"))
    if not row:
        return {}
    return {
        "servers": row.get("servers"),
        "allow_remote_requests": _as_bool(
            row.get("allow-remote-requests") or row.get("allow_remote_requests")
        ),
        "dynamic_servers": row.get("dynamic-servers") or row.get("dynamic_servers"),
    }


def collect_rule_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts-only summary -- never persists full firewall/NAT rule bodies."""
    total = 0
    wyfy_tagged = 0
    disabled = 0
    for row in rows:
        total += 1
        comment = _comment(row)
        if is_wyfy_managed(comment):
            wyfy_tagged += 1
        if _as_bool(row.get("disabled")):
            disabled += 1
    return {
        "total_count": total,
        "wyfy_tagged_count": wyfy_tagged,
        "disabled_count": disabled,
    }


def collect_firewall_summary(capture: ReadOnlyStateCapture) -> dict[str, Any]:
    return collect_rule_summary(capture.sections.get("firewall_filter") or [])


def collect_nat_summary(capture: ReadOnlyStateCapture) -> dict[str, Any]:
    return collect_rule_summary(capture.sections.get("firewall_nat") or [])


def collect_hotspot_state(capture: ReadOnlyStateCapture) -> dict[str, Any]:
    servers_raw = capture.sections.get("hotspot_servers") or []
    profiles = capture.sections.get("hotspot_profiles") or []
    walled = capture.sections.get("hotspot_walled_garden") or []
    servers: list[dict[str, Any]] = []
    for row in servers_raw:
        clean = strip_secrets(row)
        comment = _comment(clean)
        servers.append(
            {
                "name": clean.get("name"),
                "interface": clean.get("interface"),
                "profile": clean.get("profile"),
                "disabled": _as_bool(clean.get("disabled")),
                "comment": comment,
                "is_wyfy_managed": is_wyfy_managed(comment),
            }
        )
    return {
        "server_count": len(servers_raw),
        "profile_count": len(profiles),
        "walled_garden_count": len(walled),
        "servers": servers,
    }


def collect_vlans(capture: ReadOnlyStateCapture) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in capture.sections.get("vlan_interfaces") or []:
        clean = strip_secrets(row)
        comment = _comment(clean)
        result.append(
            {
                "name": clean.get("name"),
                "vlan_id": _as_int(clean.get("vlan-id") or clean.get("vlan_id")),
                "interface": clean.get("interface"),
                "comment": comment,
                "is_wyfy_managed": is_wyfy_managed(comment),
            }
        )
    return result


def collect_services(capture: ReadOnlyStateCapture) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in capture.sections.get("ip_services") or []:
        clean = strip_secrets(row)
        result.append(
            {
                "name": clean.get("name"),
                "port": _as_int(clean.get("port")),
                "disabled": _as_bool(clean.get("disabled")),
            }
        )
    return result


def collect_packages(capture: ReadOnlyStateCapture) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in capture.sections.get("system_packages") or []:
        clean = strip_secrets(row)
        result.append(
            {
                "name": clean.get("name"),
                "version": clean.get("version"),
                "disabled": _as_bool(clean.get("disabled")),
            }
        )
    return result


def resolve_snapshot_status(capture: ReadOnlyStateCapture) -> SnapshotStatus:
    """``complete`` when no per-section errors; ``partial`` otherwise.

    Callers that never obtained a capture at all (connection failure)
    should persist ``failed`` themselves rather than calling this.
    """
    if capture.errors:
        return SnapshotStatus.PARTIAL
    return SnapshotStatus.COMPLETE


def collect_snapshot_fields(
    capture: ReadOnlyStateCapture,
) -> dict[str, Any]:
    """Build the full set of ORM column values from a capture.

    Returns a dict suitable for ``RouterSnapshotRepository.create`` /
    ``GenericRepository.create`` (section JSON + system identity fields +
    derived ``status``). Does **not** set ``router_id`` /
    ``organization_id`` / ``location_id`` / ``trigger`` / ``captured_at``
    -- those come from the service layer.
    """
    identity = collect_system_identity(capture)
    return {
        **identity,
        "status": resolve_snapshot_status(capture).value,
        "interfaces": collect_interfaces(capture),
        "bridges": collect_bridges(capture),
        "ip_addresses": collect_ip_addresses(capture),
        "dhcp_clients": collect_dhcp_clients(capture),
        "dhcp_servers": collect_dhcp_servers(capture),
        "routes": collect_routes(capture),
        "dns_config": collect_dns_config(capture),
        "firewall_summary": collect_firewall_summary(capture),
        "nat_summary": collect_nat_summary(capture),
        "hotspot_state": collect_hotspot_state(capture),
        "vlans": collect_vlans(capture),
        "services": collect_services(capture),
        "packages": collect_packages(capture),
        "error_detail": (
            "; ".join(f"{section}: {detail}" for section, detail in capture.errors.items())
            if capture.errors
            else None
        ),
    }


__all__ = [
    "is_wyfy_managed",
    "strip_secrets",
    "collect_system_identity",
    "collect_interfaces",
    "collect_bridges",
    "collect_ip_addresses",
    "collect_dhcp_clients",
    "collect_dhcp_servers",
    "collect_routes",
    "collect_dns_config",
    "collect_rule_summary",
    "collect_firewall_summary",
    "collect_nat_summary",
    "collect_hotspot_state",
    "collect_vlans",
    "collect_services",
    "collect_packages",
    "resolve_snapshot_status",
    "collect_snapshot_fields",
]
