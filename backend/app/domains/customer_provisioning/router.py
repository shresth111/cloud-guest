"""FastAPI routes for Customer Provisioning.

One route: create the organization (plus optional first location) for a
new customer, and grant the acting user ``organization-admin`` on it.

Three sibling routes were removed here rather than repaired --
``POST /customers/{customer_id}/generate-script``,
``.../generate-nas`` and ``.../wireguard``. Each returned a 200 with a
success message having written nothing: a bash installer for a
``cloudguest-agent`` binary that does not exist (this platform ships
RouterOS ``.rsc``), a randomly generated NAS id/IP/RADIUS shared secret
persisted nowhere, and a real X25519 keypair pointed at
``wg.cloudguest.io`` (NXDOMAIN; the real hub is
``hub.wyfyguest.com:51820``). See ``service.py``'s module docstring for
the real paths that replace them.

Scope mattered here as much as the fabrication. ``generate-nas`` was
gated on bare ``RequirePermission("guest_wifi.create")``, which eight
seeded roles hold -- six of them customer-scoped, down to
``guest-operator`` at LOCATION -- so a venue operator could be handed a
NAS id, IP and RADIUS shared secret that existed nowhere. ``wireguard``
was gated on bare ``RequirePermission("wireguard.create")``; every
other ``wireguard.*`` route in the codebase pins
``scope=ScopeType.GLOBAL`` precisely so tunnel internals stay off
customer-reachable routes (see ``app/domains/wireguard/router.py``),
making this the single route an org-scoped token could use to reach
them. The surviving ``onboard`` route mints no infrastructure
credential -- it creates an organization row -- so header-inferred
organization scope on ``organizations.create`` is appropriate for it,
and only ``super-admin``/``platform-admin``/``msp-owner``/``msp-admin``
hold that permission at all.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, status

from app.common.responses import ApiResponse, build_response
from app.core.config import Settings, get_settings
from app.domains.auth.models import AuthUser
from app.domains.notification.dependencies import get_onboarding_slack_notifier
from app.domains.notification.onboarding_slack import (
    OnboardingSlackNotifier,
    customer_created_notice,
)
from app.domains.notification.tasks import dispatch_onboarding_failure
from app.domains.rbac.dependencies import CurrentUser, RequirePermission

from .dependencies import get_customer_provisioning_service
from .schemas import OnboardRequest, OnboardResponse
from .service import CustomerProvisioningService

router = APIRouter(tags=["Customer Provisioning"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


@router.post(
    "/customers/onboard",
    response_model=ApiResponse[OnboardResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("organizations.create"))],
)
async def onboard_customer(
    request: Request,
    body: OnboardRequest,
    user: AuthUser = Depends(CurrentUser),
    service: CustomerProvisioningService = Depends(get_customer_provisioning_service),
    onboarding_slack: OnboardingSlackNotifier = Depends(get_onboarding_slack_notifier),
    settings: Settings = Depends(get_settings),
):
    """Composed at the router layer, not inside
    ``CustomerProvisioningService``: the Slack notice is an ops concern,
    the service has no business knowing what Slack is, and this is the
    same placement this domain already uses for ``ensure_default_alerting``
    (see ``dependencies.py``).

    Position matters in both branches. The success ``notify`` runs on the
    same request-scoped session as the onboarding, so the outbox row
    commits with the organization or is rolled back with it. The failure
    dispatch happens before the ``raise``, and goes to Celery precisely
    because the session it is standing in is about to be rolled back --
    see ``app.domains.notification.onboarding_slack``.
    """
    actor_user_id = uuid.UUID(user.id)
    try:
        payload = await service.onboard(body, actor_user_id)
    except Exception as exc:
        dispatch_onboarding_failure(
            settings=settings,
            stage="Customer creation",
            organization_name=body.organization_name,
            # Nothing was created, so there is no id to name. The
            # organization does not exist at either end of this branch.
            organization_id=None,
            error=exc,
            actor_user_id=actor_user_id,
            request_id=_request_id(request),
        )
        raise
    await onboarding_slack.notify(
        customer_created_notice(
            organization_id=uuid.UUID(payload.organization_id),
            organization_name=body.organization_name,
            organization_slug=body.organization_slug,
            location_created=payload.location_id is not None,
            actor_user_id=actor_user_id,
        )
    )
    return build_response(
        success=True,
        message=payload.message,
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )
