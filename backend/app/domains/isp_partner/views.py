"""Response shapes for ``/isp`` (API_CONTRACT §4), as plain dicts.

The router never exposes tunnel IPs, keys, or the word WireGuard:
``cloud_link`` is derived from the router's heartbeat state only.
"""

from __future__ import annotations

import math
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from app.domains.monitoring.constants import ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES
from app.domains.router.enums import RouterStatus


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _id(value: uuid.UUID | None) -> str | None:
    return str(value) if value is not None else None


def page(items: list[Any], total: int, page_no: int, page_size: int) -> dict:
    return {
        "items": items,
        "total": total,
        "page": page_no,
        "page_size": page_size,
        "pages": math.ceil(total / page_size) if total else 0,
    }


def cloud_link(router: Any, *, now: datetime | None = None) -> str:
    """``up`` while the agent heartbeats within the platform's own offline
    threshold, ``down`` once it is stale, ``unknown`` before the first."""
    from app.domains.router.vendor_capabilities import is_agent_managed_row

    if not is_agent_managed_row(router):
        return "unknown"  # no agent, no heartbeat: not "down"
    seen = getattr(router, "last_seen_at", None)
    if seen is None:
        return "unknown"
    now = now or datetime.now(UTC)
    stale = timedelta(minutes=ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES)
    if router.status == RouterStatus.ONLINE.value and now - seen <= stale:
        return "up"
    return "down"


def cpe_online(device: Any, *, now: datetime | None = None) -> bool:
    """``last_inform_at > now - (2 * interval + 60)s`` (API_CONTRACT §5)."""
    if device.last_inform_at is None:
        return False
    now = now or datetime.now(UTC)
    interval = device.periodic_inform_interval_s or 300
    return device.last_inform_at > now - timedelta(seconds=2 * interval + 60)


def customer_view(
    org: Any,
    profile: Any,
    *,
    locations: list[Any],
    routers: list[Any],
    cpes: int,
    tr069_enabled: bool,
) -> dict:
    def p(name: str) -> Any:
        return getattr(profile, name, None) if profile is not None else None

    return {
        "id": str(org.id),
        "name": org.name,
        "slug": org.slug,
        "status": org.status,
        "legal_name": org.legal_name,
        "gstin": p("gstin"),
        "external_ref": p("external_ref"),
        "contact_name": p("contact_name"),
        "contact_email": org.contact_email,
        "contact_phone": org.contact_phone,
        "address_line1": p("address_line1"),
        "city": p("city"),
        "state_province": p("state_province"),
        "postal_code": p("postal_code"),
        "timezone": org.timezone,
        "notes": p("notes"),
        "counts": {
            "locations": len(locations),
            "routers_total": len(routers),
            "routers_online": sum(
                1 for r in routers if r.status == RouterStatus.ONLINE.value
            ),
            "cpes": cpes,
        },
        "tr069_enabled": tr069_enabled,
        "created_at": _iso(org.created_at),
        "updated_at": _iso(org.updated_at),
    }


def location_view(
    location: Any,
    *,
    customer_name: str | None,
    routers: list[Any],
    tr069_enabled: bool,
) -> dict:
    return {
        "id": str(location.id),
        "isp_customer_id": str(location.organization_id),
        "customer_name": customer_name,
        "name": location.name,
        "slug": location.slug,
        "location_code": location.location_code,
        "status": location.status,
        "property_type": location.property_type,
        "address_line1": location.address_line1,
        "city": location.city,
        "state_province": location.state_province,
        "postal_code": location.postal_code,
        "country": location.country,
        "timezone": location.timezone,
        "latitude": location.latitude,
        "longitude": location.longitude,
        "routers": {
            "total": len(routers),
            "online": sum(1 for r in routers if r.status == RouterStatus.ONLINE.value),
        },
        "tr069_enabled": tr069_enabled,
        "created_at": _iso(location.created_at),
    }


def router_view(
    router: Any,
    *,
    customer_name: str | None,
    location_name: str | None,
    cloud_link: str,
    tr069_enabled: bool,
    cpe_id: uuid.UUID | None,
) -> dict:
    return {
        "id": str(router.id),
        "isp_customer_id": str(router.organization_id),
        "customer_name": customer_name,
        "isp_location_id": str(router.location_id),
        "location_name": location_name,
        "name": router.name,
        "model": router.model,
        "serial_number": router.serial_number,
        "mac_address": router.mac_address,
        "vendor": router.vendor,
        "routeros_version": router.routeros_version,
        "status": router.status,
        "cloud_link": cloud_link,
        "last_seen_at": _iso(router.last_seen_at),
        "tr069": {"enabled": tr069_enabled, "cpe_id": _id(cpe_id)},
    }
