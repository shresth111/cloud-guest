"""Venue twins for the customer app's OWN Portal page (``PortalPage.tsx``).

The founder asked for the exact customer Portal page in the partner console --
file uploads for the logo and background, colours, content picture, texts,
login methods and the phone-style live preview. The page is mounted unchanged
inside the partner venue scope; the request shim rewrites each of its calls to
the ``/isp/venue`` twin below. ``scripts/test-isp-partner-portal-shim.mjs`` on
the frontend greps every API path the page and its services call and fails on
one this module does not twin.

Gates (``twin_gates``): every ``/branding`` route carries
``RequireFeature(WHITE_LABEL)`` on the customer side, so the twins do too
(F4 default ``plan``: the CUSTOMER's plan decides; ``ISP_PARTNER_WHITE_LABEL=off``
refuses them outright). Writes on both routers are on ``_PAID_WRITES``.

Scoping: config ids resolve through ``IspScope.assert_portal_config`` (another
ISP's or an archived customer's config is a 404); ``/organizations/{id}`` takes
an ``isp_customer_id`` resolved through ``IspScope.assert_customer``; create
forces the body's ``organization_id``/``location_id`` to the venue.
"""

from __future__ import annotations

import inspect
import uuid

from fastapi import File, UploadFile

from app.database.session import get_db_session
from app.domains.billing.constants import PlanFeatureKey
from app.domains.branding import router as branding_routes
from app.domains.branding.dependencies import get_branding_service
from app.domains.branding.schemas import BrandingUpdateRequest
from app.domains.captive_portal import router as portal_routes
from app.domains.captive_portal.dependencies import get_captive_portal_service
from app.domains.captive_portal.schemas import (
    CaptivePortalConfigCreateRequest,
    CaptivePortalConfigUpdateRequest,
)
from app.domains.location import router as location_routes
from app.domains.location.dependencies import get_location_service
from app.domains.organization import router as organization_routes
from app.domains.organization.dependencies import get_organization_service

from .constants import ISP_PARTNER_READ, ISP_PARTNER_UPDATE
from .twin_body import BodyId
from .twins import Param, TwinSpec

__all__ = ["PORTAL_TWINS"]

_WL = (PlanFeatureKey.WHITE_LABEL,)
_ConfigId = Param("config_id", "path", uuid.UUID)
_File = Param("file", "body", UploadFile, File(...))
_Page = Param("page", "query", int, 1)
_PageSize = Param("page_size", "query", int, 25)
_Customer = Param("isp_customer_id", "path", uuid.UUID, forward="organization_id")
_ent_portal = portal_routes.get_entitlement_aware_captive_portal_service


def _branding(method: str, path: str, handler, *, key: str, **extra) -> TwinSpec:
    return TwinSpec(
        method=method,
        path=f"/venue/branding{path}",
        permission_key=key,
        handler=handler,
        target="header_customer",
        deps={"service": get_branding_service},
        inject={"organization_id": ("org",), "user": ("user",)},
        requires_features=_WL,
        **extra,
    )


def _config(method: str, path: str, handler, *, key: str, service=None, **extra):
    return TwinSpec(
        method=method,
        path=f"/venue/captive-portal-configs/{{config_id}}{path}",
        permission_key=key,
        handler=handler,
        target="portal_config",
        resolve_param="config_id",
        deps={"service": service or get_captive_portal_service},
        inject={
            "requesting_organization_id": ("org",),
            **({"user": ("user",)} if method != "GET" else {}),
        },
        **extra,
    )


PORTAL_TWINS: tuple[TwinSpec, ...] = (
    # -- branding (logo / background), org-level, WHITE_LABEL-gated ------------
    _branding("GET", "", branding_routes.get_branding, key=ISP_PARTNER_READ),
    _branding(
        "PUT",
        "",
        branding_routes.update_branding,
        key=ISP_PARTNER_UPDATE,
        params=(Param("body", "body", BrandingUpdateRequest),),
    ),
    _branding(
        "POST",
        "/logo",
        branding_routes.upload_logo,
        key=ISP_PARTNER_UPDATE,
        params=(_File,),
    ),
    _branding("DELETE", "/logo", branding_routes.delete_logo, key=ISP_PARTNER_UPDATE),
    _branding("GET", "/logo/raw", branding_routes.get_logo_raw, key=ISP_PARTNER_READ),
    _branding(
        "POST",
        "/background-image",
        branding_routes.upload_background_image,
        key=ISP_PARTNER_UPDATE,
        params=(_File,),
    ),
    _branding(
        "DELETE",
        "/background-image",
        branding_routes.delete_background_image,
        key=ISP_PARTNER_UPDATE,
    ),
    _branding(
        "GET",
        "/background-image/raw",
        branding_routes.get_background_image_raw,
        key=ISP_PARTNER_READ,
    ),
    # -- captive portal configs --------------------------------------------------
    TwinSpec(
        method="GET",
        path="/venue/captive-portal-configs",
        permission_key=ISP_PARTNER_READ,
        handler=portal_routes.list_captive_portal_configs,
        target="header_customer",
        params=(_Page, _PageSize),
        deps={"service": get_captive_portal_service},
        # The page lists the customer's configs and picks this location's (or
        # the customer default) itself, exactly as on the customer host.
        inject={"requesting_organization_id": ("org",), "location_id": ("const", None)},
    ),
    TwinSpec(
        method="POST",
        path="/venue/captive-portal-configs",
        permission_key=ISP_PARTNER_UPDATE,
        handler=portal_routes.create_captive_portal_config,
        target="header_location",
        params=(
            Param(
                "payload",
                "body",
                CaptivePortalConfigCreateRequest,
                inspect.Parameter.empty,
            ),
        ),
        body_ids=(
            BodyId("organization_id", "force_org"),
            BodyId("location_id", "force_location"),
        ),
        deps={"service": _ent_portal},
        inject={"requesting_organization_id": ("org",), "user": ("user",)},
        status_code=201,
    ),
    _config(
        "GET",
        "",
        portal_routes.get_captive_portal_config,
        key=ISP_PARTNER_READ,
        params=(_ConfigId,),
    ),
    _config(
        "PUT",
        "",
        portal_routes.update_captive_portal_config,
        key=ISP_PARTNER_UPDATE,
        service=_ent_portal,
        params=(
            _ConfigId,
            Param(
                "payload",
                "body",
                CaptivePortalConfigUpdateRequest,
                inspect.Parameter.empty,
            ),
        ),
    ),
    _config(
        "POST",
        "/activate",
        portal_routes.activate_captive_portal_config,
        key=ISP_PARTNER_UPDATE,
        params=(_ConfigId,),
    ),
    _config(
        "POST",
        "/deactivate",
        portal_routes.deactivate_captive_portal_config,
        key=ISP_PARTNER_UPDATE,
        params=(_ConfigId,),
    ),
    _config(
        "POST",
        "/content-image",
        portal_routes.upload_captive_portal_content_image,
        key=ISP_PARTNER_UPDATE,
        params=(_ConfigId, _File),
    ),
    _config(
        "DELETE",
        "/content-image",
        portal_routes.delete_captive_portal_content_image,
        key=ISP_PARTNER_UPDATE,
        params=(_ConfigId,),
    ),
    TwinSpec(
        method="GET",
        path="/venue/captive-portal/review-stats",
        permission_key=ISP_PARTNER_READ,
        handler=portal_routes.get_review_stats,
        target="header_location",
        params=(Param("days", "query", int, 30),),
        deps={"db": get_db_session},
        inject={
            "requesting_organization_id": ("org",),
            "location_id": ("location",),
            "header_location_id": ("location",),
        },
    ),
    # -- the page's org/location name lookups ----------------------------------
    TwinSpec(
        method="GET",
        path="/venue/organizations/{isp_customer_id}",
        permission_key=ISP_PARTNER_READ,
        handler=organization_routes.get_organization,
        target="customer",
        resolve_param="isp_customer_id",
        params=(_Customer,),
        deps={"organization_service": get_organization_service},
        inject={"requesting_organization_id": ("org",)},
    ),
    TwinSpec(
        method="GET",
        path="/venue/organizations/{isp_customer_id}/locations",
        permission_key=ISP_PARTNER_READ,
        handler=location_routes.list_locations,
        target="customer",
        resolve_param="isp_customer_id",
        params=(
            _Customer,
            _Page,
            _PageSize,
            Param("search", "query", str | None, None),
        ),
        deps={"location_service": get_location_service},
        inject={
            "requesting_organization_id": ("org",),
            "location_status": ("const", None),
        },
    ),
)
