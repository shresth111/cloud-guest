"""Adding one Aruba Instant On site as one fleet row -- the one sequence both
Master entry points share.

Two callers, one rule set:

* ``POST /platform/routers/instant-on-sites`` (Router Fleet > "Add Instant On
  site", #328), for a customer and location that already exist.
* ``POST /locations/provision`` (the Add Customer wizard's Aruba option,
  PM_SPEC §5 Wave 2), which creates the customer, location and owner and
  then this row, in the same request transaction.

Both used to be able to drift: the refusal for an already-mapped site id
lived in the route body, and a second caller copying it would have been the
"generator vs writer" drift this codebase has been bitten by before. It
lives here now, and both callers go through it.

Writes are a ``routers`` row, its audit entry, and (when a site id is given)
an ``instant_on_sites`` mapping with polling and the customer view OFF. No
agent credential, provisioning token, WireGuard peer, RouterOS call, RADIUS
NAS or ``network_integrations`` row -- see
``RouterService.create_nas_only_site``. Every write is a flush on the
caller's session, so a failure anywhere rolls all of it back.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Protocol

from .exceptions import NasOnlySiteRefusedError

__all__ = [
    "InstantOnSiteMapper",
    "InstantOnSiteOnboarded",
    "NasOnlySiteCreator",
    "ensure_instant_on_site_id_free",
    "onboard_instant_on_site",
]


class NasOnlySiteCreator(Protocol):
    """``RouterService``'s side: the row, and a lookup ``configure_site``
    reads it back through."""

    async def create_nas_only_site(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        name: str,
        serial_number: str | None = None,
        mac_address: str | None = None,
    ) -> tuple[Any, bool, bool]: ...

    async def get_router(
        self,
        router_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> Any: ...


class InstantOnSiteMapper(Protocol):
    """``InstantOnReadService``'s side: the ``instant_on_sites`` mapping."""

    async def site_in_use(self, site_id: str) -> Any | None: ...

    async def configure_site(
        self,
        *,
        router_id: uuid.UUID,
        site_id: str,
        site_name: str | None,
        poll_enabled: bool,
        customer_visible: bool,
        router_lookup: Any,
        actor_user_id: uuid.UUID | None = None,
    ) -> Any: ...


@dataclass(frozen=True, slots=True)
class InstantOnSiteOnboarded:
    router: Any
    synthetic_serial_number: bool
    synthetic_mac_address: bool
    instant_on_site_id: str | None


async def ensure_instant_on_site_id_free(
    mapper: InstantOnSiteMapper, site_id: str | None
) -> None:
    """Refuse (409 ``site_already_onboarded``) when ``site_id`` is already
    mapped to a live fleet row. Read-only, so a caller can run it before its
    first write. A malformed id is ``InstantOnSiteNotConfigurableError``
    (``invalid_site_id``), raised by ``site_in_use`` itself."""
    if not site_id:
        return
    in_use = await mapper.site_in_use(site_id)
    if in_use is not None:
        raise NasOnlySiteRefusedError(
            f"Instant On site {site_id} is already mapped to another fleet "
            "device. One Instant On site is one fleet row.",
            reason="site_already_onboarded",
            existing_router_id=in_use.router_id,
        )


async def onboard_instant_on_site(
    *,
    router_service: NasOnlySiteCreator,
    instant_on_service: InstantOnSiteMapper,
    actor_user_id: uuid.UUID | None,
    organization_id: uuid.UUID,
    location_id: uuid.UUID,
    name: str,
    serial_number: str | None = None,
    mac_address: str | None = None,
    instant_on_site_id: str | None = None,
    instant_on_site_name: str | None = None,
) -> InstantOnSiteOnboarded:
    """The site-id check, the row (``create_nas_only_site``, which refuses a
    location of another customer, a second Instant On row and a mixed
    venue), then the site mapping. In that order, all on the caller's
    session."""
    await ensure_instant_on_site_id_free(instant_on_service, instant_on_site_id)
    (
        created,
        synthetic_serial,
        synthetic_mac,
    ) = await router_service.create_nas_only_site(
        actor_user_id=actor_user_id,
        organization_id=organization_id,
        location_id=location_id,
        name=name,
        serial_number=serial_number,
        mac_address=mac_address,
    )
    if instant_on_site_id:
        await instant_on_service.configure_site(
            router_id=created.id,
            site_id=instant_on_site_id,
            site_name=instant_on_site_name,
            # Both OFF: turning either on stays a deliberate Master action
            # (`PUT /platform/instant-on/routers/{router_id}/site`).
            poll_enabled=False,
            customer_visible=False,
            router_lookup=router_service,
            actor_user_id=actor_user_id,
        )
    return InstantOnSiteOnboarded(
        router=created,
        synthetic_serial_number=synthetic_serial,
        synthetic_mac_address=synthetic_mac,
        instant_on_site_id=instant_on_site_id,
    )
