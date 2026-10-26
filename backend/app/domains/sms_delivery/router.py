"""SMS delivery report + inbound DLR callback.

* ``GET /sms-delivery/report`` -- day-wise sent/failed/delivered/undelivered
  for exactly one organization, optionally one location.
* ``GET|POST /sms-delivery/dlr/{provider}`` -- provider delivery-report
  callback, authenticated by a shared secret.

## Report scoping

* Organization: ``RequireOrganization`` -- one tenant, always. A platform
  admin who asked for "all organizations" gets a 400, not a blended number
  (a blended count is invisible; see the Global-Super-Admin report defect).
* Location: the ``?location_id`` filter is checked against the location the
  permission ran at (``enforce_target_location``: header-vs-query) *and*
  against the caller's grant-derived confinement
  (``confine_location_filter``), so a site-scoped account cannot read a
  sibling site by naming it, nor read every site by naming none.
* Permission: ``otp.read`` -- the same key the existing "OTP Requests &
  Verification" report is gated on; this is that report's delivery half.

## Callback authentication

Ping4SMS documents no callback signature, so the callback is authenticated
the way this codebase authenticates other machine-to-machine pushes
(``device_logs`` ingest): a shared secret compared with
``secrets.compare_digest``, and the route answers 404 while no secret is
configured. The secret travels as ``?token=`` (providers can rarely set
headers on a callback) or the ``X-Wyfy-Dlr-Token`` header.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import date, timedelta
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.responses import build_response
from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.database.session import get_db_session
from app.domains.location.scoping import enforce_target_location
from app.domains.rbac.dependencies import (
    CurrentLocation,
    RequireOrganization,
    RequirePermission,
)
from app.domains.rbac.location_scope import (
    CallerLocationScope,
    LocationScope,
    confine_location_filter,
)

from .constants import (
    DLR_WEBHOOK_TOKEN_HEADER,
    REPORT_DEFAULT_TIMEZONE,
    REPORT_MAX_RANGE_DAYS,
    WEBHOOK_PROVIDERS,
    DlrSource,
    SmsPurpose,
)
from .dlr import MESSAGE_ID_FIELDS, STATUS_FIELDS, classify_dlr_status, first_field
from .exceptions import SmsDeliveryLocationAccessError
from .service import ReportScope, apply_dlr, build_report, delivery_reports_state

logger = get_logger(__name__)

router = APIRouter(prefix="/sms-delivery", tags=["SMS Delivery"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


@router.get(
    "/report",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("otp.read"))],
)
async def sms_delivery_report(
    request: Request,
    start_date: date = Query(...),
    end_date: date = Query(...),
    location_id: uuid.UUID | None = Query(default=None),
    purpose: SmsPurpose | None = Query(default=None),
    tz: str = Query(default=REPORT_DEFAULT_TIMEZONE, max_length=64),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    scope_location_id: uuid.UUID | None = Depends(CurrentLocation),
    caller_location_scope: LocationScope = Depends(CallerLocationScope),
    db: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    if end_date < start_date:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "end_date < start_date"
        )
    if (end_date - start_date) > timedelta(days=REPORT_MAX_RANGE_DAYS - 1):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Range is limited to {REPORT_MAX_RANGE_DAYS} days",
        )
    try:
        ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Unknown tz") from exc

    enforce_target_location(
        target_location_id=location_id,
        scope_location_id=scope_location_id,
        requesting_organization_id=organization_id,
    )
    location_filter = confine_location_filter(
        requested_location_id=location_id,
        caller_location_scope=caller_location_scope,
        error=SmsDeliveryLocationAccessError(),
    )
    report = await build_report(
        db,
        ReportScope(organization_id=organization_id, location_filter=location_filter),
        start=start_date,
        end=end_date,
        tz=tz,
        purpose=purpose.value if purpose else None,
    )
    report["delivery_reports"] = {
        **delivery_reports_state(settings),
        "received_in_range": report.pop("dlr_received"),
    }
    report["range"] = {
        "start_date": start_date.isoformat(),
        "end_date": end_date.isoformat(),
        "timezone": tz,
    }
    return build_response(
        success=True,
        message="SMS delivery report retrieved",
        data=report,
        request_id=_request_id(request),
    )


# ---------------------------------------------------------------------------
# Inbound DLR callback
# ---------------------------------------------------------------------------


async def _callback_fields(request: Request) -> dict[str, Any]:
    fields: dict[str, Any] = dict(request.query_params)
    if request.method == "POST":
        content_type = request.headers.get("content-type", "")
        try:
            if "json" in content_type:
                body = await request.json()
                if isinstance(body, dict):
                    fields.update(body)
                elif isinstance(body, list) and body and isinstance(body[0], dict):
                    fields.update(body[0])
            else:
                form = await request.form()
                fields.update({k: v for k, v in form.items() if isinstance(v, str)})
        except Exception as exc:  # noqa: BLE001 -- a malformed body is a 400
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unreadable body") from exc
    fields.pop("token", None)
    return fields


def _check_token(request: Request, settings: Settings) -> None:
    expected = settings.sms_dlr_webhook_token
    if not expected:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    supplied = request.headers.get(
        DLR_WEBHOOK_TOKEN_HEADER
    ) or request.query_params.get("token")
    if not supplied or not secrets.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
        )


@router.api_route("/dlr/{provider}", methods=["GET", "POST"])
async def sms_dlr_callback(
    provider: str,
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    _check_token(request, settings)
    provider = provider.lower()
    if provider not in WEBHOOK_PROVIDERS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    fields = await _callback_fields(request)
    message_id = first_field(fields, MESSAGE_ID_FIELDS)
    raw_status = first_field(fields, STATUS_FIELDS)
    if not message_id or not raw_status:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "message id and status are required"
        )
    outcome = await apply_dlr(
        db,
        provider=provider,
        provider_message_id=message_id[:100],
        status=classify_dlr_status(raw_status),
        source=DlrSource.WEBHOOK,
        raw=raw_status,
    )
    logger.info(
        "sms_dlr_callback",
        extra={
            "sms_provider": provider,
            "dlr_matched": outcome.matched,
            "dlr_applied": outcome.applied,
            "dlr_status": outcome.status,
        },
    )
    # 200 even when nothing matched: a provider retries non-2xx, and an
    # unknown id will never start matching.
    return {
        "matched": outcome.matched,
        "applied": outcome.applied,
        "status": outcome.status,
    }


__all__ = ["router"]
