"""Licence state gates customer writes, and never gates a guest.

Two changes are pinned here.

**A missing licence is a 402, not a 404.** ``RequireActiveLicense`` surfaced
``LicenseNotFoundError``'s 404 for an organization that has no ``License`` row
at all -- reachable in real data, since organizations predating the billing
domain have none. A gate answering "may this organization act?" must not
answer "that thing does not exist": a 404 from a write reads to a client as a
wrong URL and to an operator as a bug, and it is a completely different
remediation from "your plan lapsed".

**Writes are gated; reads and guest paths are not.** A customer whose plan
expired must still sign in, read their venues and their guest list, and reach
billing to pay. And no guest-facing path is ever gated -- cutting a venue's
WiFi over a billing state punishes the guests in its lobby for the owner's
lapsed card, turning a revenue problem into an outage.

The last test is the one that matters most: it walks the real mounted app and
asserts that nothing without its own permission gate (i.e. anything a guest
can reach) sits behind the licence gate on a state-changing method.
"""

from __future__ import annotations

import uuid

import pytest

from app.domains.billing.dependencies import _require_active_license
from app.domains.billing.exceptions import (
    LicenseNotActiveError,
    LicenseNotFoundError,
)


class _Snapshot:
    def __init__(self, *, is_active: bool, status: str) -> None:
        self.is_active = is_active
        self.license_status = status


class _Checker:
    def __init__(self, snapshot=None, raises: Exception | None = None) -> None:
        self._snapshot = snapshot
        self._raises = raises

    async def get_snapshot(self, organization_id):
        if self._raises is not None:
            raise self._raises
        return self._snapshot


class TestMissingLicenceIsCleanlyRefused:
    async def test_no_licence_row_is_a_402_not_a_404(self) -> None:
        org = uuid.uuid4()
        checker = _Checker(raises=LicenseNotFoundError(org))

        with pytest.raises(LicenseNotActiveError) as caught:
            await _require_active_license(org, checker)

        assert caught.value.status_code == 402

    async def test_the_message_says_which_problem_it_is(self) -> None:
        """"No licence assigned" and "your licence expired" need different
        fixes, so they must not read the same."""
        org = uuid.uuid4()

        with pytest.raises(LicenseNotActiveError) as caught:
            await _require_active_license(
                org, _Checker(raises=LicenseNotFoundError(org))
            )

        assert "no license has been assigned" in str(caught.value)

    async def test_an_expired_licence_is_still_refused(self) -> None:
        with pytest.raises(LicenseNotActiveError):
            await _require_active_license(
                uuid.uuid4(), _Checker(_Snapshot(is_active=False, status="expired"))
            )

    async def test_an_active_licence_passes(self) -> None:
        org = uuid.uuid4()

        result = await _require_active_license(
            org, _Checker(_Snapshot(is_active=True, status="active"))
        )

        assert result == org

    async def test_no_organization_context_passes_through(self) -> None:
        """A platform-level caller has no tenant to licence-check."""
        assert await _require_active_license(None, _Checker()) is None


# ---------------------------------------------------------------------------
# What is, and is not, actually gated in the mounted app
# ---------------------------------------------------------------------------


def _gated_routes():
    from app.main import create_app

    def calls(dependant):
        found = {d.call for d in dependant.dependencies}
        for d in dependant.dependencies:
            found |= calls(d)
        return found

    for route in create_app().routes:
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            continue
        names = {getattr(f, "__qualname__", "") for f in calls(dependant)}
        gated = any(n.startswith("RequireActiveLicenseForWrites") for n in names)
        yield route, names, gated


def test_no_guest_reachable_write_is_licence_gated() -> None:
    """The rule that must never be broken.

    Anything with no ``RequirePermission`` of its own is reachable without a
    dashboard login -- a guest path. None of those may sit behind a billing
    gate on a state-changing method. ``/vouchers/redeem`` is exactly this
    shape, which is why the whole voucher router is deliberately ungated.
    """
    offenders = []
    for route, names, gated in _gated_routes():
        if not gated:
            continue
        methods = set(getattr(route, "methods", set()))
        if methods <= {"GET", "HEAD", "OPTIONS"}:
            continue
        if not any(n.startswith("RequirePermission") for n in names):
            offenders.append((sorted(methods), getattr(route, "path", "")))

    assert offenders == [], (
        "these guest-reachable writes are behind the licence gate: "
        f"{offenders}. Cutting a guest off over the venue's billing state "
        "turns a revenue problem into an outage."
    )


def test_the_guest_login_and_portal_paths_are_not_gated() -> None:
    """Named explicitly, because these are the ones that would hurt most."""
    must_stay_open = {
        "/api/v1/captive-portal/resolve",
        "/api/v1/vouchers/redeem",
        "/api/v1/vouchers/validate",
        "/api/v1/guest-teams/join",
    }
    for route, _names, gated in _gated_routes():
        path = getattr(route, "path", "")
        if path in must_stay_open:
            methods = set(getattr(route, "methods", set()))
            if not methods <= {"GET", "HEAD", "OPTIONS"}:
                assert not gated, f"{path} must never be licence-gated"


def test_a_representative_customer_config_write_is_gated() -> None:
    """The gate has to actually be applied somewhere, or the whole change is
    decorative."""
    gated_paths = {
        getattr(route, "path", "")
        for route, _names, gated in _gated_routes()
        if gated and not set(getattr(route, "methods", set())) <= {"GET", "HEAD"}
    }
    assert any(p.startswith("/api/v1/campaigns") for p in gated_paths)
    assert any(p.startswith("/api/v1/vlans") for p in gated_paths)
