"""FastAPI routes for the Voucher domain: admin-facing batch management
(create/list/get/approve/revoke/export/stats/list-vouchers, pre-printed
code import) plus guest-facing validate/redeem.

Every admin-facing endpoint is gated by RBAC's existing
``RequirePermission`` dependency against the already-seeded
``voucher.*`` permission keys (``app.domains.rbac.seed
.MODULE_ACTIONS[PermissionModule.VOUCHER]``) and resolves
``CurrentOrganization`` (``X-Organization-Id``), passed through to
``VoucherService`` as ``requesting_organization_id`` so tenant scoping is
enforced the same way every other domain's router enforces it.
Permission-key choices worth calling out:

* ``approve`` -> ``voucher.approve`` (seeded, and included in the
  ``OPERATE`` grant level -- see ``app.domains.rbac.seed
  .expand_grant_level`` -- so Location Manager/Reception Staff/Guest
  Operator system roles can approve batches without needing ``manage``).
* ``revoke`` -> ``voucher.update``: revoking is a lifecycle status change,
  not a destructive delete or a platform-admin-only "manage" action --
  ``update`` is, like ``approve``, included in ``OPERATE``, so the same
  front-line roles that can approve a batch can also cancel a misprinted
  one without needing ``voucher.manage``/``voucher.delete``.

**``POST /voucher-batches`` additionally resolves whether the caller holds
``voucher.manage``** (``dependencies.get_voucher_manage_bypass``, a
non-raising check distinct from the mandatory ``voucher.create``
``RequirePermission`` gate) to decide whether the new batch should skip the
approval queue -- see ``service.py``'s module docstring for the full
"fast path" reasoning.

**``POST /vouchers/validate``/``POST /vouchers/redeem`` carry no
``RequirePermission``/``CurrentUser`` dependency at all** -- mirrors
``app.domains.otp.router``'s identical justification: the caller is a guest
at a captive portal, with no platform-user identity RBAC could ever grant a
permission to. Abuse protection here comes entirely from this module's own
``VoucherRedemptionRateLimiter`` (Redis-backed, per-source throttling), not
from an authorization check that has no meaningful subject to authorize.
Both still use the standard ``ApiResponse`` envelope (consistent with
OTP's own guest-facing-but-still-enveloped precedent), since their real
caller is the captive-portal *frontend*.

**``GET .../export`` is the one deliberate deviation from the standard
envelope** -- it returns raw ``text/csv``, not ``ApiResponse``-wrapped
JSON. See ``service.py``'s module docstring: a downloadable CSV a print
vendor opens directly cannot usefully be JSON-wrapped; wrapping it would
defeat the endpoint's whole purpose.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, Response, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)

from .dependencies import (
    get_redemption_source,
    get_voucher_manage_bypass,
    get_voucher_service,
)
from .models import Voucher, VoucherBatch
from .schemas import (
    VoucherBatchCreate,
    VoucherBatchListResponse,
    VoucherBatchResponse,
    VoucherBatchRevokeRequest,
    VoucherBatchStatsResponse,
    VoucherImportRejection,
    VoucherImportRequest,
    VoucherImportResponse,
    VoucherListResponse,
    VoucherRedeemRequest,
    VoucherRedeemResponse,
    VoucherResponse,
    VoucherValidateRequest,
    VoucherValidateResponse,
)
from .service import VoucherService

router = APIRouter(tags=["Voucher"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _batch_response(batch: VoucherBatch) -> VoucherBatchResponse:
    return VoucherBatchResponse(
        id=str(batch.id),
        name=batch.name,
        organization_id=str(batch.organization_id),
        location_id=str(batch.location_id) if batch.location_id else None,
        quantity=batch.quantity,
        code_length=batch.code_length,
        code_prefix=batch.code_prefix,
        validity_minutes=batch.validity_minutes,
        batch_expires_at=batch.batch_expires_at,
        max_uses_per_voucher=batch.max_uses_per_voucher,
        data_limit_mb=batch.data_limit_mb,
        status=batch.status,
        created_by_user_id=str(batch.created_by_user_id)
        if batch.created_by_user_id
        else None,
        approved_by_user_id=str(batch.approved_by_user_id)
        if batch.approved_by_user_id
        else None,
        approved_at=batch.approved_at,
        notes=batch.notes,
        created_at=batch.created_at,
        updated_at=batch.updated_at,
    )


def _voucher_response(voucher: Voucher) -> VoucherResponse:
    return VoucherResponse(
        id=str(voucher.id),
        batch_id=str(voucher.batch_id),
        code=voucher.code,
        status=voucher.status,
        use_count=voucher.use_count,
        redeemed_at=voucher.redeemed_at,
        last_used_at=voucher.last_used_at,
        redeemed_identifier=voucher.redeemed_identifier,
        expires_at=voucher.expires_at,
        created_at=voucher.created_at,
    )


# ============================================================================
# Admin-facing batch management
# ============================================================================


@router.post(
    "/voucher-batches",
    response_model=ApiResponse[VoucherBatchResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("voucher.create"))],
)
async def create_voucher_batch(
    request: Request,
    payload: VoucherBatchCreate,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    has_manage_permission: bool = Depends(get_voucher_manage_bypass),
    service: VoucherService = Depends(get_voucher_service),
):
    batch = await service.create_batch(
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
        organization_id=payload.organization_id,
        location_id=payload.location_id,
        name=payload.name,
        quantity=payload.quantity,
        code_length=payload.code_length,
        code_prefix=payload.code_prefix,
        validity_minutes=payload.validity_minutes,
        batch_expires_at=payload.batch_expires_at,
        max_uses_per_voucher=payload.max_uses_per_voucher,
        data_limit_mb=payload.data_limit_mb,
        notes=payload.notes,
        has_manage_permission=has_manage_permission,
    )
    return build_response(
        success=True,
        message="Voucher batch created",
        data=_batch_response(batch).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/voucher-batches",
    response_model=ApiResponse[VoucherBatchListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("voucher.read"))],
)
async def list_voucher_batches(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: VoucherService = Depends(get_voucher_service),
):
    batches, meta = await service.list_batches(
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
    )
    payload = VoucherBatchListResponse(
        items=[_batch_response(batch) for batch in batches],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Voucher batches retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/voucher-batches/{batch_id}",
    response_model=ApiResponse[VoucherBatchResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("voucher.read"))],
)
async def get_voucher_batch(
    request: Request,
    batch_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: VoucherService = Depends(get_voucher_service),
):
    batch = await service.get_batch(
        batch_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Voucher batch retrieved",
        data=_batch_response(batch).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/voucher-batches/{batch_id}/approve",
    response_model=ApiResponse[VoucherBatchResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("voucher.approve"))],
)
async def approve_voucher_batch(
    request: Request,
    batch_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: VoucherService = Depends(get_voucher_service),
):
    batch = await service.approve_batch(
        batch_id=batch_id,
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Voucher batch approved and activated",
        data=_batch_response(batch).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/voucher-batches/{batch_id}/revoke",
    response_model=ApiResponse[VoucherBatchResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("voucher.update"))],
)
async def revoke_voucher_batch(
    request: Request,
    batch_id: uuid.UUID,
    payload: VoucherBatchRevokeRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: VoucherService = Depends(get_voucher_service),
):
    batch = await service.revoke_batch(
        batch_id=batch_id,
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
        reason=payload.reason,
    )
    return build_response(
        success=True,
        message="Voucher batch revoked",
        data=_batch_response(batch).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/voucher-batches/{batch_id}/vouchers",
    response_model=ApiResponse[VoucherListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("voucher.read"))],
)
async def list_batch_vouchers(
    request: Request,
    batch_id: uuid.UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: VoucherService = Depends(get_voucher_service),
):
    vouchers, meta = await service.list_vouchers(
        batch_id=batch_id,
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
    )
    payload = VoucherListResponse(
        items=[_voucher_response(voucher) for voucher in vouchers],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Batch vouchers retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/voucher-batches/{batch_id}/export",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("voucher.export"))],
)
async def export_voucher_batch(
    batch_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: VoucherService = Depends(get_voucher_service),
) -> Response:
    csv_text = await service.export_batch_csv(
        batch_id=batch_id, requesting_organization_id=requesting_organization_id
    )
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={
            "Content-Disposition": (
                f'attachment; filename="voucher_batch_{batch_id}.csv"'
            )
        },
    )


@router.get(
    "/voucher-batches/{batch_id}/stats",
    response_model=ApiResponse[VoucherBatchStatsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("voucher.read"))],
)
async def get_voucher_batch_stats(
    request: Request,
    batch_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: VoucherService = Depends(get_voucher_service),
):
    stats = await service.get_batch_stats(
        batch_id=batch_id, requesting_organization_id=requesting_organization_id
    )
    payload = VoucherBatchStatsResponse(
        batch_id=str(stats.batch_id),
        total=stats.total,
        unused=stats.unused,
        active=stats.active,
        exhausted=stats.exhausted,
        expired=stats.expired,
        revoked=stats.revoked,
        redemption_rate=stats.redemption_rate,
    )
    return build_response(
        success=True,
        message="Voucher batch stats retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Pre-printed code import
# ============================================================================


@router.post(
    "/vouchers/import",
    response_model=ApiResponse[VoucherImportResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("voucher.import"))],
)
async def import_vouchers(
    request: Request,
    payload: VoucherImportRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: VoucherService = Depends(get_voucher_service),
):
    result = await service.import_vouchers(
        batch_id=payload.batch_id,
        actor_user_id=uuid.UUID(user.id),
        requesting_organization_id=requesting_organization_id,
        codes=payload.codes,
    )
    response_payload = VoucherImportResponse(
        imported_count=len(result.imported),
        imported_codes=[voucher.code for voucher in result.imported],
        rejected=[
            VoucherImportRejection(code=code, reason=reason)
            for code, reason in result.rejected
        ],
    )
    return build_response(
        success=True,
        message=f"{len(result.imported)} voucher codes imported",
        data=response_payload.model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Guest-facing endpoints -- no RBAC, see module docstring
# ============================================================================


@router.post(
    "/vouchers/validate",
    response_model=ApiResponse[VoucherValidateResponse],
    status_code=status.HTTP_200_OK,
)
async def validate_voucher(
    request: Request,
    payload: VoucherValidateRequest,
    source: str = Depends(get_redemption_source),
    service: VoucherService = Depends(get_voucher_service),
):
    result = await service.validate_voucher(code=payload.code, source=source)
    response_payload = VoucherValidateResponse(
        code=result.voucher.code,
        is_first_use=result.is_first_use,
        uses_remaining=result.uses_remaining,
        max_uses_per_voucher=result.batch.max_uses_per_voucher,
        expires_at=result.voucher.expires_at,
        batch_status=result.batch.status,
    )
    return build_response(
        success=True,
        message="Voucher code is valid",
        data=response_payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/vouchers/redeem",
    response_model=ApiResponse[VoucherRedeemResponse],
    status_code=status.HTTP_200_OK,
)
async def redeem_voucher(
    request: Request,
    payload: VoucherRedeemRequest,
    source: str = Depends(get_redemption_source),
    service: VoucherService = Depends(get_voucher_service),
):
    voucher, batch = await service.redeem_voucher(
        code=payload.code, identifier=payload.identifier, source=source
    )
    response_payload = VoucherRedeemResponse(
        code=voucher.code,
        status=voucher.status,
        use_count=voucher.use_count,
        max_uses_per_voucher=batch.max_uses_per_voucher,
        redeemed_at=voucher.redeemed_at,
        expires_at=voucher.expires_at,
    )
    return build_response(
        success=True,
        message="Voucher redeemed",
        data=response_payload.model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]
