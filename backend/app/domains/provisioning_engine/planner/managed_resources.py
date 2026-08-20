"""Derive ``managed_router_resources`` rows from a rendered plan or from a
read-only discovery snapshot (live-venue Phase B backfill)."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import Any

from wyfy_device_gateway.read_only_reader import ReadOnlyStateCapture

from app.domains.network_config.profiles.constants import wyfy_comment

from .collector import is_wyfy_managed, strip_secrets
from .constants import ManagedResourceOp, ManagedResourceStatus, PlanActionType
from .schemas import ConfigurationPlanResponse, PlanAction

_CAPTURE_SECTION_SPECS: tuple[tuple[str, str, str], ...] = (
    ("firewall_filter", "firewall_rule", "/ip/firewall/filter"),
    ("firewall_nat", "nat_rule", "/ip/firewall/nat"),
    ("wireguard_interfaces", "wireguard_interface", "/interface/wireguard"),
    ("wireguard_peers", "wireguard_peer", "/interface/wireguard/peers"),
    ("radius", "radius_client", "/radius"),
    ("netwatch", "netwatch", "/tool/netwatch"),
    ("system_schedulers", "scheduler", "/system/scheduler"),
)


def _comment(row: dict[str, Any]) -> str | None:
    raw = row.get("comment")
    if raw is None:
        return None
    text = str(raw).strip()
    return text or None


def _append_backfill_row(
    rows: list[dict[str, object]],
    *,
    router_id: uuid.UUID,
    organization_id: uuid.UUID,
    location_id: uuid.UUID,
    resource_kind: str,
    routeros_path: str,
    comment_tag: str,
    applied_at: datetime,
) -> None:
    payload = f"{resource_kind}:{routeros_path}:{comment_tag}"
    rows.append(
        {
            "router_id": router_id,
            "organization_id": organization_id,
            "location_id": location_id,
            "plan_id": None,
            "resource_kind": resource_kind,
            "routeros_path": routeros_path,
            "comment_tag": comment_tag,
            "desired_state_hash": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            "op": ManagedResourceOp.CREATED.value,
            "status": ManagedResourceStatus.APPLIED.value,
            "applied_at": applied_at,
        }
    )


def _append_from_managed_items(
    rows: list[dict[str, object]],
    *,
    items: list[dict[str, Any]],
    resource_kind: str,
    routeros_path: str,
    router_id: uuid.UUID,
    organization_id: uuid.UUID,
    location_id: uuid.UUID,
    applied_at: datetime,
) -> None:
    for item in items:
        if not item.get("is_wyfy_managed"):
            continue
        comment = item.get("comment")
        if not comment:
            continue
        _append_backfill_row(
            rows,
            router_id=router_id,
            organization_id=organization_id,
            location_id=location_id,
            resource_kind=resource_kind,
            routeros_path=routeros_path,
            comment_tag=str(comment),
            applied_at=applied_at,
        )


def build_managed_resource_backfill_rows(
    snapshot_fields: dict[str, Any],
    capture: ReadOnlyStateCapture,
    *,
    router_id: uuid.UUID,
    organization_id: uuid.UUID,
    location_id: uuid.UUID,
    applied_at: datetime,
) -> list[dict[str, object]]:
    """Mark existing ``cloudguest-*`` / ``WYFYGUEST-*`` resources as managed.

    Live-venue adoption Phase B: no device writes -- only DB rows with
    ``plan_id=NULL``, ``status=applied``, derived from the same discovery
    capture that produced ``snapshot_fields``. Firewall/NAT rows are scanned
    from the raw capture (snapshot persistence stores counts only).
    """
    rows: list[dict[str, object]] = []
    common = {
        "router_id": router_id,
        "organization_id": organization_id,
        "location_id": location_id,
        "applied_at": applied_at,
    }
    _append_from_managed_items(
        rows,
        items=list(snapshot_fields.get("interfaces") or []),
        resource_kind="interface",
        routeros_path="/interface",
        **common,
    )
    _append_from_managed_items(
        rows,
        items=list(snapshot_fields.get("bridges") or []),
        resource_kind="bridge",
        routeros_path="/interface/bridge",
        **common,
    )
    _append_from_managed_items(
        rows,
        items=list(snapshot_fields.get("vlans") or []),
        resource_kind="vlan_interface",
        routeros_path="/interface/vlan",
        **common,
    )
    _append_from_managed_items(
        rows,
        items=list(snapshot_fields.get("ip_addresses") or []),
        resource_kind="ip_address",
        routeros_path="/ip/address",
        **common,
    )
    _append_from_managed_items(
        rows,
        items=list(snapshot_fields.get("dhcp_servers") or []),
        resource_kind="dhcp_server",
        routeros_path="/ip/dhcp-server",
        **common,
    )
    _append_from_managed_items(
        rows,
        items=list(snapshot_fields.get("dhcp_clients") or []),
        resource_kind="dhcp_client",
        routeros_path="/ip/dhcp-client",
        **common,
    )
    _append_from_managed_items(
        rows,
        items=list(snapshot_fields.get("routes") or []),
        resource_kind="route",
        routeros_path="/ip/route",
        **common,
    )
    hotspot = snapshot_fields.get("hotspot_state") or {}
    _append_from_managed_items(
        rows,
        items=list(hotspot.get("servers") or []),
        resource_kind="hotspot_server",
        routeros_path="/ip/hotspot",
        **common,
    )
    for section, resource_kind, routeros_path in _CAPTURE_SECTION_SPECS:
        for raw in capture.sections.get(section) or []:
            clean = strip_secrets(dict(raw))
            comment = _comment(clean)
            if not comment or not is_wyfy_managed(comment):
                continue
            _append_backfill_row(
                rows,
                router_id=router_id,
                organization_id=organization_id,
                location_id=location_id,
                resource_kind=resource_kind,
                routeros_path=routeros_path,
                comment_tag=comment,
                applied_at=applied_at,
            )
    return rows


def _comment_tag_for_action(action: PlanAction) -> str | None:
    if action.action_type is PlanActionType.CREATE and action.resource_kind == "bridge":
        name = str(action.details.get("name") or action.resource_ref)
        return wyfy_comment("bridge", "guest") if "WYFYGUEST" in name else None
    if (
        action.action_type is PlanActionType.REMOVE
        and action.resource_kind == "bridge_port"
    ):
        bridge = str(action.details.get("bridge", ""))
        interface = str(action.details.get("interface", ""))
        if bridge and interface:
            return f"{bridge}:{interface}"
    return action.resource_ref or None


def _op_for_action(action: PlanAction) -> ManagedResourceOp | None:
    if action.action_type is PlanActionType.CREATE:
        return ManagedResourceOp.CREATED
    if action.action_type is PlanActionType.MODIFY:
        return ManagedResourceOp.MODIFIED
    if action.action_type is PlanActionType.REMOVE:
        return ManagedResourceOp.REMOVED
    return None


def build_managed_resource_rows(
    plan: ConfigurationPlanResponse,
    *,
    plan_id: uuid.UUID,
    router_id: uuid.UUID,
    organization_id: uuid.UUID,
    location_id: uuid.UUID,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for action in plan.actions:
        op = _op_for_action(action)
        comment_tag = _comment_tag_for_action(action)
        if op is None or not comment_tag:
            continue
        payload = f"{action.resource_kind}:{action.resource_ref}:{action.summary}"
        rows.append(
            {
                "router_id": router_id,
                "organization_id": organization_id,
                "location_id": location_id,
                "plan_id": plan_id,
                "resource_kind": action.resource_kind,
                "routeros_path": action.routeros_path,
                "comment_tag": comment_tag,
                "desired_state_hash": hashlib.sha256(
                    payload.encode("utf-8")
                ).hexdigest(),
                "op": op.value,
                "status": ManagedResourceStatus.PENDING.value,
            }
        )
    return rows


__all__ = ["build_managed_resource_backfill_rows", "build_managed_resource_rows"]
