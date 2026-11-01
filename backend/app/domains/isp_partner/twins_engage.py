"""B3 (Engagement + location dashboard) venue twins.

Rows are derived from the original handlers' signatures by ``auto_twin``
(``twin_auto.py``) and checked by the same guard / gate-parity / body-id /
seam tests as every other row. What the partner console mounts:

- Login Page Offers: the customer ``CampaignsPage`` (unchanged) -- campaign
  create/update/schedule/pause/resume/end/delete, questions, assets.
- Vouchers: the customer ``VouchersPage`` (unchanged) -- venue voucher batches
  (front-desk passes) create/revoke/list vouchers/export/download/email and
  the redemption log. ``voucher_router`` is deliberately NOT on
  ``_PAID_WRITES`` upstream (it carries guest-facing redeem routes), and the
  gate-parity test keeps the twins equal to that.
- Location dashboard: ``/dashboard/location`` and ``/locations/{id}/overview``
  for the partner's own location dashboard panel.

Keys: reads ``isp_engage.read``; writes ``isp_engage.create/update/delete``
(ADDENDUM_04 §3), seeded by PR #436.
"""

from __future__ import annotations

from fastapi import Depends

from app.domains.campaigns import router as campaign_routes
from app.domains.guest import router as guest_routes
from app.domains.location import router as location_routes
from app.domains.rbac.authorization import AccessValidator
from app.domains.rbac.context import ScopeContext
from app.domains.rbac.dependencies import get_access_validator
from app.domains.rbac.enums import ScopeType
from app.domains.voucher import router as voucher_routes

from .constants import (
    ISP_ENGAGE_CREATE,
    ISP_ENGAGE_DELETE,
    ISP_ENGAGE_MANAGE,
    ISP_ENGAGE_READ,
    ISP_ENGAGE_UPDATE,
    ISP_PARTNER_READ,
)
from .dependencies import IspContext, RequireIspPartner
from .twin_auto import auto_twin
from .twin_body import BodyId
from .twins import TwinSpec

__all__ = ["ENGAGE_TWINS", "get_isp_voucher_manage_bypass"]


async def get_isp_voucher_manage_bypass(
    isp: IspContext = Depends(RequireIspPartner),
    access_validator: AccessValidator = Depends(get_access_validator),
) -> bool:
    """The ISP-side answer to voucher's ``get_voucher_manage_bypass``.

    The original asks "does the caller hold ``voucher.manage`` at the header
    scope?" -- on ``/isp`` that is the ISP org, where an ISP user never holds a
    customer key, so it would always say no and every ISP batch would wait for
    an approval nobody in the partner console can give. Here the same question
    is asked in ISP terms: ``isp_engage.manage`` on the ISP's own org.
    """
    return await access_validator.has_permission(
        isp.user_id,
        ISP_ENGAGE_MANAGE,
        scope_type=ScopeType.ORGANIZATION,
        scope_context=ScopeContext(organization_id=isp.isp_org_id, location_id=None),
    )


_C = "/venue/campaigns"
_V = "/venue/voucher-batches"

ENGAGE_TWINS: tuple[TwinSpec, ...] = (
    # -- Login Page Offers (campaigns) ---------------------------------------
    auto_twin(
        "POST",
        _C,
        campaign_routes.create_campaign,
        ISP_ENGAGE_CREATE,
        status_code=201,
        body_ids=(BodyId("location_id", "force_location"),),
    ),
    auto_twin(
        "GET", _C + "/{campaign_id}", campaign_routes.get_campaign, ISP_ENGAGE_READ
    ),
    auto_twin(
        "PUT",
        _C + "/{campaign_id}",
        campaign_routes.update_campaign,
        ISP_ENGAGE_UPDATE,
        body_ids=(BodyId("location_id", "force_location"),),
    ),
    auto_twin(
        "DELETE",
        _C + "/{campaign_id}",
        campaign_routes.delete_campaign,
        ISP_ENGAGE_DELETE,
    ),
    auto_twin(
        "POST",
        _C + "/{campaign_id}/schedule",
        campaign_routes.schedule_campaign,
        ISP_ENGAGE_UPDATE,
    ),
    auto_twin(
        "POST",
        _C + "/{campaign_id}/pause",
        campaign_routes.pause_campaign,
        ISP_ENGAGE_UPDATE,
    ),
    auto_twin(
        "POST",
        _C + "/{campaign_id}/resume",
        campaign_routes.resume_campaign,
        ISP_ENGAGE_UPDATE,
    ),
    auto_twin(
        "POST",
        _C + "/{campaign_id}/end",
        campaign_routes.end_campaign,
        ISP_ENGAGE_UPDATE,
    ),
    auto_twin(
        "POST",
        _C + "/{campaign_id}/questions",
        campaign_routes.add_campaign_question,
        ISP_ENGAGE_UPDATE,
        status_code=201,
    ),
    auto_twin(
        "GET",
        _C + "/{campaign_id}/questions",
        campaign_routes.list_campaign_questions,
        ISP_ENGAGE_READ,
    ),
    auto_twin(
        "PUT",
        _C + "/questions/{question_id}",
        campaign_routes.update_campaign_question,
        ISP_ENGAGE_UPDATE,
    ),
    auto_twin(
        "DELETE",
        _C + "/questions/{question_id}",
        campaign_routes.delete_campaign_question,
        ISP_ENGAGE_UPDATE,
    ),
    auto_twin(
        "POST",
        _C + "/{campaign_id}/assets",
        campaign_routes.add_campaign_asset,
        ISP_ENGAGE_UPDATE,
        status_code=201,
    ),
    auto_twin(
        "GET",
        _C + "/{campaign_id}/assets",
        campaign_routes.list_campaign_assets,
        ISP_ENGAGE_READ,
    ),
    auto_twin(
        "PUT",
        _C + "/assets/{asset_id}",
        campaign_routes.update_campaign_asset,
        ISP_ENGAGE_UPDATE,
    ),
    auto_twin(
        "DELETE",
        _C + "/assets/{asset_id}",
        campaign_routes.delete_campaign_asset,
        ISP_ENGAGE_UPDATE,
    ),
    # -- Vouchers (venue front-desk passes) ------------------------------------
    auto_twin(
        "POST",
        _V,
        voucher_routes.create_voucher_batch,
        ISP_ENGAGE_CREATE,
        paid_write=False,
        status_code=201,
        body_ids=(
            BodyId("organization_id", "force_org"),
            BodyId("location_id", "force_location"),
            BodyId(
                "plan_id",
                "service_checked",
                note="VoucherService.create_batch loads the plan with "
                "get_plan(plan_id, requesting_organization_id=...)",
            ),
            BodyId(
                "series_id",
                "service_checked",
                note="VoucherService.create_batch loads the series with "
                "get_series(series_id, requesting_organization_id=...)",
            ),
        ),
        deps_override={"has_manage_permission": get_isp_voucher_manage_bypass},
    ),
    auto_twin(
        "GET",
        _V + "/{batch_id}",
        voucher_routes.get_voucher_batch,
        ISP_ENGAGE_READ,
        paid_write=False,
    ),
    auto_twin(
        "POST",
        _V + "/{batch_id}/revoke",
        voucher_routes.revoke_voucher_batch,
        ISP_ENGAGE_UPDATE,
        paid_write=False,
    ),
    auto_twin(
        "GET",
        _V + "/{batch_id}/vouchers",
        voucher_routes.list_batch_vouchers,
        ISP_ENGAGE_READ,
        paid_write=False,
    ),
    auto_twin(
        "GET",
        _V + "/{batch_id}/export",
        voucher_routes.export_voucher_batch,
        ISP_ENGAGE_READ,
    ),
    auto_twin(
        "GET",
        _V + "/{batch_id}/download",
        voucher_routes.download_voucher_batch_pdf,
        ISP_ENGAGE_READ,
        paid_write=False,
    ),
    auto_twin(
        "POST",
        _V + "/{batch_id}/email",
        voucher_routes.email_voucher_batch_pdf,
        ISP_ENGAGE_UPDATE,
        paid_write=False,
    ),
    auto_twin(
        "GET",
        "/venue/voucher-redemptions",
        guest_routes.list_voucher_redemptions,
        ISP_ENGAGE_READ,
        redact_fields=("redeemed_identifier", "identifier"),
    ),
    # -- Location dashboard ----------------------------------------------------
    auto_twin(
        "GET",
        "/venue/locations/{isp_location_id}/overview",
        location_routes.get_location_overview,
        ISP_PARTNER_READ,
        target="location",
        resolve_param="isp_location_id",
        rename_path={"isp_location_id": "location_id"},
    ),
)
