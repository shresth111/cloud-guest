"""RBAC-FIX: every disconnect / KYC-CAF read / GSTR-1 route carries the
founder-approved key, and the role grants match the decision. The HTTP role
matrix on real data is ``test_isp_rbac_fix_postgres.py``."""

from __future__ import annotations

from functools import lru_cache

import pytest

from app.domains.isp_partner.rbac_roles import ROLES_BY_SLUG

DISCONNECT = "isp_subscribers.disconnect"
KYC = "isp_subscribers.kyc"
EXPECTED_KEY = {
    ("POST", "/subscribers/{subscriber_id}/disconnect"): DISCONNECT,
    ("POST", "/subscribers/{subscriber_id}/workbench/disconnect"): DISCONNECT,
    ("POST", "/subscribers/{subscriber_id}/pppoe/disconnect"): DISCONNECT,
    ("POST", "/pppoe/sessions/{pppoe_session_id}/disconnect"): DISCONNECT,
    ("GET", "/gst/gstr1"): "isp_billing.export",
    ("GET", "/compliance/subscribers/{subscriber_id}/kyc"): KYC,
    ("GET", "/compliance/subscribers/{subscriber_id}/documents/{document_id}"): KYC,
    ("GET", "/compliance/subscribers/{subscriber_id}/caf.pdf"): KYC,
    ("GET", "/caf/subscribers/{subscriber_id}"): KYC,
    ("GET", "/caf/subscribers/{subscriber_id}/caf.pdf"): KYC,
    ("GET", "/caf/leads/{lead_id}"): KYC,
    ("GET", "/caf/search"): KYC,
    ("POST", "/caf/export"): KYC,
}


@lru_cache(maxsize=1)
def _route_keys() -> dict[tuple[str, str], str | None]:
    from app.main import create_app

    out: dict[tuple[str, str], str | None] = {}
    for r in create_app().routes:
        path = getattr(r, "path", "")
        if not path.startswith("/api/v1/isp/") or not getattr(r, "methods", None):
            continue
        key = None
        for d in r.dependencies:
            call = d.dependency
            if getattr(call, "__qualname__", "").startswith("RequirePermission"):
                for cell in call.__closure__ or ():
                    v = cell.cell_contents
                    if isinstance(v, str) and "." in v:
                        key = v
        for m in r.methods:
            out[(m, path.removeprefix("/api/v1/isp"))] = key
    return out


@pytest.mark.parametrize(("route", "key"), sorted(EXPECTED_KEY.items()))
def test_route_uses_the_approved_key(route, key) -> None:
    assert _route_keys().get(route) == key, route


def test_no_other_isp_route_ends_a_session_with_the_update_key() -> None:
    for (method, path), key in _route_keys().items():
        if path.endswith("/disconnect") and path.startswith(("/subscribers", "/pppoe")):
            assert key == DISCONNECT, (method, path, key)


@pytest.mark.parametrize(
    ("slug", "disconnect", "kyc", "billing_export"),
    [
        ("isp-owner", True, True, True),
        ("isp-admin", True, True, True),
        ("isp-noc", True, False, False),
        ("isp-technician", True, True, False),
        ("isp-billing", False, True, True),
        ("isp-viewer", False, False, False),
    ],
)
def test_role_grants(slug, disconnect, kyc, billing_export) -> None:
    keys = set(ROLES_BY_SLUG[slug].permission_keys)
    assert (DISCONNECT in keys) is disconnect
    assert (KYC in keys) is kyc
    assert ("isp_billing.export" in keys) is billing_export
