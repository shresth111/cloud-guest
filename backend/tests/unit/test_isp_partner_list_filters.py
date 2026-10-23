"""QA-009: ISP list filters take a known value or are a 422, never a silently
empty list."""

from __future__ import annotations

import re

import pytest

from app.domains.location.enums import LocationStatus
from app.domains.organization.enums import OrganizationStatus
from app.domains.router.enums import RouterStatus

_CASES = {
    "/api/v1/isp/customers": ("status", OrganizationStatus),
    "/api/v1/isp/customers/{isp_customer_id}/locations": ("status", LocationStatus),
    "/api/v1/isp/locations": ("status", LocationStatus),
    "/api/v1/isp/routers": ("status", RouterStatus),
}


def _route(path: str):
    from app.main import create_app

    return next(
        r
        for r in create_app().routes
        if getattr(r, "path", "") == path
        and "GET" in (getattr(r, "methods", None) or ())
    )


def _pattern(route, alias: str) -> str:
    (param,) = [p for p in route.dependant.query_params if p.alias == alias]
    found = [
        getattr(m, "pattern", None)
        for m in param.field_info.metadata
        if getattr(m, "pattern", None)
    ]
    assert found, f"{route.path}?{alias} has no pattern"
    return found[0]


@pytest.mark.parametrize(("path", "case"), list(_CASES.items()))
def test_status_filter_accepts_exactly_the_enum(path, case) -> None:
    alias, enum = case
    pattern = re.compile(_pattern(_route(path), alias))
    for value in enum:
        assert pattern.fullmatch(value.value), (path, value)
    for bogus in ("bogus", "", "ACTIVE", "active;drop"):
        assert not pattern.fullmatch(bogus), (path, bogus)


def test_users_role_filter_is_an_isp_role() -> None:
    from app.domains.isp_partner.constants import ISP_ROLE_SLUGS

    pattern = re.compile(_pattern(_route("/api/v1/isp/users"), "role"))
    for slug in ISP_ROLE_SLUGS:
        assert pattern.fullmatch(slug)
    assert not pattern.fullmatch("organization-owner")
