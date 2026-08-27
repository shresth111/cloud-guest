"""Operator-facing reconciliation endpoints.

Two verbs, both GLOBAL-scope only, for the same reason
``GET /wireguard/fleet-status`` is: these read and repair across the whole
fleet, and there is no organization for which "reconcile the hub" is a
sensible tenant-scoped question. (See also the standing product rule that
WireGuard internals never appear on a customer dashboard.)
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)
from app.domains.rbac.enums import ScopeType
from app.domains.wireguard.dependencies import get_wireguard_service
from app.domains.wireguard.service import WireGuardService

from .dependencies import get_hub_reconciliation_service
from .service import HubReconciliationService

router = APIRouter(tags=["WireGuard"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


class NasRebindResponse(BaseModel):
    router_id: str
    nas_identifier: str | None
    tunnel_ip_address: str
    pushed: bool
    reason: str | None = None


class ReconciliationResponse(BaseModel):
    """What one pass observed and changed.

    ``drift_public_keys`` is the deliberately-unresolved list: peers the
    pass could see were wrong but refused to guess about. Surfacing it as
    data (rather than only classifying it inside fleet-status) is what
    makes "nothing here needs a human" a claim the operator can check."""

    summary: dict[str, int]
    adopted_public_keys: list[str]
    nas_rebinds: list[NasRebindResponse]
    drift_public_keys: list[str]


class AdoptHubPeerRequest(BaseModel):
    router_id: uuid.UUID = Field(
        description=(
            "The router this hub peer belongs to. The operator supplies "
            "this because it is the one thing the platform cannot prove "
            "for a key with no issuance record -- everything else "
            "(that the hub holds the key, that no other router claims it, "
            "and which address the hub routes it to) is verified server-side."
        )
    )
    note: str | None = Field(
        default=None,
        max_length=500,
        description=(
            "Why this binding is correct. Stored on the issuance ledger and "
            "shown in fleet-status, so the next person to look at this peer "
            "reads an explanation instead of re-investigating it."
        ),
    )


@router.post(
    "/wireguard/reconcile",
    response_model=ApiResponse[ReconciliationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("wireguard.update", scope=ScopeType.GLOBAL))
    ],
)
async def reconcile_hub(
    request: Request,
    adopt: bool = True,
    service: HubReconciliationService = Depends(get_hub_reconciliation_service),
):
    """Runs one reconciliation pass: read the hub, adopt the identities the
    ledger can prove, and re-push every RADIUS client whose binding no
    longer matches the address its peer is on.

    ``wireguard.update`` rather than ``wireguard.read`` because this
    writes -- to this database and, through the RADIUS bridge, to the hub.
    Idempotent, so it is safe to run repeatedly and safe to schedule; see
    ``HubReconciliationService.reconcile``.

    ``adopt=false`` makes it a dry run of the WireGuard half (classify but
    change no identities) while still repairing stale RADIUS bindings,
    which are a pure catch-up with nothing to decide."""
    report = await service.reconcile(adopt=adopt)
    return build_response(
        success=True,
        message="Hub reconciliation complete",
        data=ReconciliationResponse(
            summary=report.summary,
            adopted_public_keys=report.adopted_public_keys,
            nas_rebinds=[
                NasRebindResponse(
                    router_id=str(rebind.router_id),
                    nas_identifier=rebind.nas_identifier,
                    tunnel_ip_address=rebind.tunnel_ip_address,
                    pushed=rebind.pushed,
                    reason=rebind.reason,
                )
                for rebind in report.nas_rebinds
            ],
            drift_public_keys=report.drift_public_keys,
        ).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/wireguard/hub-peers/{public_key:path}/adopt",
    response_model=ApiResponse[ReconciliationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(RequirePermission("wireguard.update", scope=ScopeType.GLOBAL))
    ],
)
async def adopt_hub_peer(
    request: Request,
    public_key: str,
    payload: AdoptHubPeerRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    wireguard_service: WireGuardService = Depends(get_wireguard_service),
    service: HubReconciliationService = Depends(get_hub_reconciliation_service),
):
    """Operator-confirmed adoption -- bind a router to the identity the hub
    is already holding, and move its RADIUS client to match.

    This is the repair path for the peers automatic adoption will not
    touch: anything with no issuance record (every peer allocated before
    the ledger existed, which on the production hub today is all seven),
    and the ambiguous case where a router has two live identities.

    ``{public_key:path}`` because WireGuard public keys are base64 and
    routinely contain ``/``. Without ``:path`` a key like
    ``7hu3t0FJ4t6B5X0vUx+YyPPD8LcurbKtxL8uoy+TZDg=`` splits into two path
    segments and 404s -- which would make this endpoint fail on roughly
    half of all real keys, intermittently, in a way that looks like the key
    being wrong.
    """
    peer = await wireguard_service.adopt_hub_peer(
        actor_user_id=uuid.UUID(user.id),
        router_id=payload.router_id,
        requesting_organization_id=requesting_organization_id,
        public_key=public_key,
        note=payload.note,
    )
    # The adoption already fired `peer_address_listener` if the address
    # moved, but that listener is only attached on the service THIS module
    # builds -- and `wireguard_service` here is the plain one. Rebinding
    # explicitly keeps the endpoint correct regardless of which service
    # instance FastAPI resolved, and it is idempotent, so a double push
    # cannot happen: `_rebind_if_stale` short-circuits once the recorded
    # synced address matches.
    rebind = await service.rebind_nas_for_router(
        router_id=payload.router_id,
        tunnel_ip_address=peer.tunnel_ip_address,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message=(
            f"Adopted {peer.tunnel_ip_address} for this router -- the platform "
            "now records the identity the device is demonstrably using"
        ),
        data=ReconciliationResponse(
            summary={},
            adopted_public_keys=[public_key],
            nas_rebinds=[
                NasRebindResponse(
                    router_id=str(rebind.router_id),
                    nas_identifier=rebind.nas_identifier,
                    tunnel_ip_address=rebind.tunnel_ip_address,
                    pushed=rebind.pushed,
                    reason=rebind.reason,
                )
            ],
            drift_public_keys=[],
        ).model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]
