"""Customer provisioning service.

Orchestrates onboarding a new customer: creates the organization, grants
the acting user ``organization-admin`` on it, and optionally creates the
first location. Composes existing organization, location and RBAC
services -- no new database tables.

This service used to also expose ``generate_script``, ``generate_nas``
and ``generate_wireguard``. All three were stubs: they fabricated
plausible-looking output (a bash installer for an agent that does not
exist, a random NAS id/IP/shared secret, a real X25519 keypair pointed
at a hostname that does not resolve), wrote nothing to the database,
pushed nothing to the hub, and returned a confident success message.
A fabricated RADIUS shared secret is worse than a 404: it hands an
operator a fourth value that matches neither the DB, the hub, nor the
device. They were removed rather than reimplemented -- the real paths
already exist and are the only ones that reach the hub:

* NAS registration -> ``POST /radius/nas/register-external/{router_id}``
  (``app.domains.guest.router.register_external_radius_nas``), which
  POSTs ``{tunnel_ip, nas_identifier, secret}`` to the FreeRADIUS hub
  agent via ``guest.radius_bridge.push_nas_client`` and raises 502 if
  the push fails -- the DB is only reconciled once the hub confirms.
* WireGuard peers -> ``POST /routers/{router_id}/wireguard-peer/
  allocate-external``, the one path that both reaches the live hub and
  writes a row (``wireguard.router`` POSTs to the hub agent, then calls
  ``WireGuardService.register_agent_allocated_peer``). It is gated at
  ``RequirePermission("wireguard.create", scope=ScopeType.GLOBAL)``,
  which is how this platform keeps tunnel internals off customer-
  reachable routes. The real endpoint is the hub's own
  ``hub.wyfyguest.com:51820``, not a constant in this domain.
* Device configuration -> ``network_config.renderers``, which emits
  RouterOS script text, applied through the ``router_provisioning``
  domain's adapters. Nothing here installs a bash agent.
"""

from __future__ import annotations

import logging
import uuid
from typing import Protocol

from app.domains.location.service import LocationService
from app.domains.organization.enums import OrganizationType
from app.domains.organization.service import OrganizationService
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.exceptions import RoleNotFoundError
from app.domains.rbac.service import RBACService

from .schemas import OnboardRequest, OnboardResponse

logger = logging.getLogger(__name__)


class DefaultAlertingProtocol(Protocol):
    """Give a newly onboarded customer the default alert rules, an email
    channel, and the link between them.

    Structurally satisfied by
    ``app.domains.monitoring.default_alerting.ensure_default_alerting``
    partially applied over its two services (see ``dependencies.py``). A
    narrow duck-typed protocol rather than a hard import, for the reason
    that module's own docstring gives: this domain has no business knowing
    what an alert is, and ``monitoring`` owns both services.

    ## Why this was missing and what it cost

    ``ensure_default_alerting`` had exactly one caller, ``POST
    /organizations``. This endpoint creates organizations too -- it is a
    path a master operator actually uses -- and did not call it, so a
    customer onboarded here had **no alert rules at all**. The 30s alert
    evaluation sweep had nothing to evaluate for them and their venue could
    go dark in silence. For an Omada venue it also meant the three
    ``network_controller*`` rules never existed, leaving the
    controller-health alerting inert for precisely the customers it was
    built for.
    """

    async def __call__(
        self, *, organization_id: uuid.UUID, contact_email: str | None
    ) -> object: ...


class _NoopDefaultAlerting:
    """Honest fallback when nothing real is wired -- logs rather than
    leaving an organization quietly unalerted. Never wired in production;
    see ``dependencies.py``."""

    async def __call__(
        self, *, organization_id: uuid.UUID, contact_email: str | None
    ) -> None:
        logger.info(
            "default_alerting_not_wired",
            extra={"organization_id": str(organization_id)},
        )


class CustomerProvisioningService:
    def __init__(
        self,
        organization_service: OrganizationService,
        location_service: LocationService,
        rbac_service: RBACService,
        default_alerting: DefaultAlertingProtocol | None = None,
    ) -> None:
        self.organization_service = organization_service
        self.location_service = location_service
        self.rbac_service = rbac_service
        self.default_alerting: DefaultAlertingProtocol = (
            default_alerting or _NoopDefaultAlerting()
        )

    async def onboard(
        self, request: OnboardRequest, actor_user_id: uuid.UUID
    ) -> OnboardResponse:
        org = await self.organization_service.create_organization(
            actor_user_id=actor_user_id,
            name=request.organization_name,
            slug=request.organization_slug,
            contact_email=request.admin_email,
            org_type=OrganizationType.STANDARD,
        )

        # Before the role grant and the location, so that an organization
        # that exists is an organization something is watching. Idempotent
        # and never raises by contract -- the try/except guards the layer
        # between here and it, because a customer must not fail to be
        # created over their default alert rules. See
        # `DefaultAlertingProtocol` for what was missing.
        try:
            await self.default_alerting(
                organization_id=org.id, contact_email=org.contact_email
            )
        except Exception:
            logger.exception(
                "default_alerting_failed_during_onboarding",
                extra={"organization_id": str(org.id)},
            )

        org_admin_role = await self.rbac_service.repository.get_role_by_slug(
            "organization-admin", None
        )
        if org_admin_role is None:
            raise RoleNotFoundError("organization-admin")

        await self.rbac_service.assign_role_to_user(
            actor_user_id=actor_user_id,
            target_user_id=actor_user_id,
            role_id=org_admin_role.id,
            scope_type=ScopeType.ORGANIZATION,
            requesting_organization_id=None,
            organization_id=org.id,
        )

        location_id: uuid.UUID | None = None
        if request.location_name:
            location = await self.location_service.create_location(
                actor_user_id=actor_user_id,
                organization_id=org.id,
                requesting_organization_id=None,
                name=request.location_name,
                slug=request.organization_slug,
                address_line1=request.location_address or "Not specified",
                city="Not specified",
                state_province="Not specified",
                postal_code="000000",
                country="IN",
            )
            location_id = location.id

        return OnboardResponse(
            organization_id=str(org.id),
            location_id=str(location_id) if location_id else None,
            admin_user_id=str(actor_user_id),
            message=f"Organization '{org.name}' onboarded",
        )
