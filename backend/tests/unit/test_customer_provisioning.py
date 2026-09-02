"""Unit tests for the Customer Provisioning domain.

This domain previously shipped three endpoints that returned HTTP 200
with a confident success message having performed no work at all:

* ``POST /customers/{customer_id}/generate-script`` returned a bash
  script curling ``https://cloudguest.io/agent/install.sh`` and running
  a ``cloudguest-agent`` binary. Neither exists -- the domain does not
  resolve, and this platform provisions MikroTik devices with RouterOS
  ``.rsc`` via the ``router_provisioning`` domain.
* ``POST /customers/{customer_id}/generate-nas`` invented a NAS id, a
  ``10.0.x.y`` address and a ``secrets.token_hex(16)`` RADIUS shared
  secret, wrote none of it to the database, pushed none of it to the
  FreeRADIUS hub, and said "NAS device registered". Divergent RADIUS
  secrets between DB, hub and device are this platform's most expensive
  repeat incident; a fabricated fourth value that matches none of them
  is strictly worse than a 404.
* ``POST /customers/{customer_id}/wireguard`` generated a genuine
  X25519 keypair, registered the peer nowhere, and pointed it at
  ``wg.cloudguest.io:51820`` (NXDOMAIN).

All three are gone. The tests below are the regression guard: they
assert the routes stay gone, that the one surviving route really writes
before it reports success, and -- the check that would have caught this
in the first place -- that no module in this domain mints infrastructure
credentials locally instead of delegating to the domain that owns them.
"""

from __future__ import annotations

import pathlib
import uuid
from dataclasses import dataclass, field

import pytest

from app.domains.customer_provisioning.router import router as cp_router
from app.domains.customer_provisioning.schemas import OnboardRequest
from app.domains.customer_provisioning.service import CustomerProvisioningService
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.exceptions import RoleNotFoundError

DOMAIN_DIR = pathlib.Path("app/domains/customer_provisioning")


# --------------------------------------------------------------------
# Fakes: every write the service performs is recorded, so a test can
# assert a success response was preceded by an actual write.
# --------------------------------------------------------------------


@dataclass
class _FakeOrg:
    id: uuid.UUID
    name: str


@dataclass
class _FakeLocation:
    id: uuid.UUID


@dataclass
class _RecordingOrganizationService:
    writes: list[dict] = field(default_factory=list)
    raises: Exception | None = None
    #: id the "database" assigns to the row this write creates.
    next_id: uuid.UUID = field(default_factory=uuid.uuid4)

    async def create_organization(self, **kwargs):
        if self.raises is not None:
            raise self.raises
        self.writes.append(kwargs)
        return _FakeOrg(id=self.next_id, name=kwargs["name"])


@dataclass
class _RecordingLocationService:
    writes: list[dict] = field(default_factory=list)
    next_id: uuid.UUID = field(default_factory=uuid.uuid4)

    async def create_location(self, **kwargs):
        self.writes.append(kwargs)
        return _FakeLocation(id=self.next_id)


@dataclass
class _FakeRoleRepository:
    role_slug: str | None = "organization-admin"

    async def get_role_by_slug(self, slug: str, _scope):
        if self.role_slug is None:
            return None
        return _FakeOrg(id=uuid.uuid4(), name=slug)


@dataclass
class _RecordingRBACService:
    repository: _FakeRoleRepository = field(default_factory=_FakeRoleRepository)
    writes: list[dict] = field(default_factory=list)

    async def assign_role_to_user(self, **kwargs):
        self.writes.append(kwargs)


def _make_service(
    *,
    org_service: _RecordingOrganizationService | None = None,
    rbac_service: _RecordingRBACService | None = None,
) -> tuple[
    CustomerProvisioningService,
    _RecordingOrganizationService,
    _RecordingLocationService,
    _RecordingRBACService,
]:
    orgs = org_service or _RecordingOrganizationService()
    locations = _RecordingLocationService()
    rbac = rbac_service or _RecordingRBACService()
    service = CustomerProvisioningService(
        organization_service=orgs,  # type: ignore[arg-type]
        location_service=locations,  # type: ignore[arg-type]
        rbac_service=rbac,  # type: ignore[arg-type]
    )
    return service, orgs, locations, rbac


def _request(**overrides) -> OnboardRequest:
    payload = {
        "organization_name": "Blue Lagoon Resort",
        "organization_slug": "blue-lagoon",
        "admin_email": "owner@blue-lagoon.example",
    }
    payload.update(overrides)
    return OnboardRequest(**payload)


# --------------------------------------------------------------------
# The one surviving route really writes.
# --------------------------------------------------------------------


class TestOnboardActuallyWrites:
    async def test_success_response_is_backed_by_a_real_organization_write(
        self,
    ) -> None:
        service, orgs, _locations, rbac = _make_service()
        actor = uuid.uuid4()

        result = await service.onboard(_request(), actor)

        # The success message is only earned if a write happened.
        assert len(orgs.writes) == 1
        assert orgs.writes[0]["name"] == "Blue Lagoon Resort"
        assert len(rbac.writes) == 1
        assert rbac.writes[0]["scope_type"] is ScopeType.ORGANIZATION
        assert "onboarded" in result.message

    async def test_returned_id_comes_from_the_write_not_from_uuid4(self) -> None:
        """The precise failure mode of the deleted stubs: an identifier
        minted for the response rather than read back from a write.
        ``generate_nas`` returned ``str(uuid.uuid4())`` as its
        ``nas_id``; this asserts ``onboard`` cannot do the same."""
        known_id = uuid.uuid4()
        orgs = _RecordingOrganizationService()
        orgs.next_id = known_id  # type: ignore[attr-defined]
        service, orgs, _locations, _rbac = _make_service(org_service=orgs)

        result = await service.onboard(_request(), uuid.uuid4())

        assert result.organization_id == str(known_id), (
            "organization_id must be the id the organization service "
            "returned from its write, not a locally generated one"
        )

    async def test_returned_location_id_also_comes_from_the_write(self) -> None:
        known_id = uuid.uuid4()
        service, _orgs, locations, _rbac = _make_service()
        locations.next_id = known_id  # type: ignore[attr-defined]

        result = await service.onboard(
            _request(location_name="Poolside"), uuid.uuid4()
        )

        assert result.location_id == str(known_id)

    async def test_location_is_written_only_when_requested(self) -> None:
        service, _orgs, locations, _rbac = _make_service()

        without = await service.onboard(_request(), uuid.uuid4())
        assert without.location_id is None
        assert locations.writes == []

        with_location = await service.onboard(
            _request(location_name="Poolside"), uuid.uuid4()
        )
        assert with_location.location_id is not None
        assert len(locations.writes) == 1
        assert locations.writes[0]["name"] == "Poolside"

    async def test_failed_write_is_not_reported_as_success(self) -> None:
        boom = RuntimeError("organization slug already taken")
        service, _orgs, _locations, _rbac = _make_service(
            org_service=_RecordingOrganizationService(raises=boom)
        )

        with pytest.raises(RuntimeError):
            await service.onboard(_request(), uuid.uuid4())

    async def test_missing_seed_role_raises_rather_than_returning_success(
        self,
    ) -> None:
        service, _orgs, _locations, _rbac = _make_service(
            rbac_service=_RecordingRBACService(
                repository=_FakeRoleRepository(role_slug=None)
            )
        )

        with pytest.raises(RoleNotFoundError):
            await service.onboard(_request(), uuid.uuid4())


# --------------------------------------------------------------------
# The fabricated routes stay deleted.
# --------------------------------------------------------------------


class TestFabricatedRoutesAreGone:
    REMOVED_PATHS = (
        "/customers/{customer_id}/generate-script",
        "/customers/{customer_id}/generate-nas",
        "/customers/{customer_id}/wireguard",
    )

    def test_removed_from_this_domains_router(self) -> None:
        paths = {route.path for route in cp_router.routes}
        for removed in self.REMOVED_PATHS:
            assert removed not in paths, (
                f"{removed} is back. It fabricated infrastructure "
                "credentials and reported success without writing "
                "anything -- see this module's docstring."
            )

    def test_removed_from_the_mounted_openapi_surface(self) -> None:
        from app.main import create_app

        spec_paths = set(create_app().openapi()["paths"])
        for removed in self.REMOVED_PATHS:
            assert f"/api/v1{removed}" not in spec_paths

    def test_service_no_longer_exposes_the_stub_methods(self) -> None:
        for name in ("generate_script", "generate_nas", "generate_wireguard"):
            assert not hasattr(CustomerProvisioningService, name), (
                f"CustomerProvisioningService.{name} is back -- it "
                "returned success having written nothing."
            )

    def test_stub_response_schemas_are_gone(self) -> None:
        from app.domains.customer_provisioning import schemas

        for name in (
            "GenerateNasResponse",
            "GenerateScriptResponse",
            "GenerateScriptRequest",
            "WireguardConfigResponse",
        ):
            assert not hasattr(schemas, name)


# --------------------------------------------------------------------
# The guard that would have caught the original defect.
# --------------------------------------------------------------------


def _domain_sources() -> dict[str, str]:
    return {
        path.name: path.read_text()
        for path in sorted(DOMAIN_DIR.glob("*.py"))
    }


class TestNoFabricatedInfrastructureCredentials:
    """This domain composes other domains' services. It must never mint
    an infrastructure credential itself: the domain that owns the
    credential is the only one that can also push it to the hub and
    persist it, and a credential minted here is by construction one that
    matches nothing."""

    FORBIDDEN = {
        "secrets.token_hex": "RADIUS/NAS shared secrets belong to the guest domain",
        "secrets.token_urlsafe": "credential minting belongs to the owning domain",
        "X25519PrivateKey": "WireGuard keypairs belong to app.domains.wireguard",
        "wg.cloudguest.io": "fabricated hub endpoint -- this host does not resolve",
        "cloudguest.io/agent": "fabricated agent installer -- no such URL or binary",
        "cloudguest-agent": "no such binary; devices take RouterOS .rsc",
        "#!/bin/bash": "this platform provisions RouterOS, not bash hosts",
    }

    @pytest.mark.parametrize("needle", sorted(FORBIDDEN))
    def test_domain_source_is_free_of_credential_fabrication(
        self, needle: str
    ) -> None:
        offenders = [
            name
            for name, source in _domain_sources().items()
            # The prose in module docstrings names these on purpose, to
            # explain why they must not appear as code. Only flag a hit
            # that is not inside a docstring-only mention.
            if needle in _strip_docstrings(source)
        ]
        assert not offenders, (
            f"{needle!r} appears in {offenders} -- "
            f"{self.FORBIDDEN[needle]}."
        )


def _strip_docstrings(source: str) -> str:
    """Remove module/class/function docstrings so the guard checks code,
    not the comments explaining the guard."""
    import ast

    tree = ast.parse(source)
    spans: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if not isinstance(
            node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef
        ):
            continue
        body = getattr(node, "body", [])
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            spans.append((body[0].lineno, body[0].end_lineno or body[0].lineno))
    lines = source.splitlines()
    keep = [
        line
        for number, line in enumerate(lines, start=1)
        if not any(start <= number <= end for start, end in spans)
    ]
    return "\n".join(keep)


# --------------------------------------------------------------------
# Every route in this domain is accounted for.
# --------------------------------------------------------------------


class TestEveryRouteRequiresPermission:
    #: (method, path) -> the durable write that earns its success
    #: response. A new route in this domain must be added here with a
    #: real answer; "nothing" is not one.
    ROUTES_AND_THEIR_WRITES = {
        ("POST", "/customers/onboard"): (
            "organization row + organization-admin role assignment "
            "(+ optional location row)"
        ),
    }

    def test_route_inventory_is_exhaustive(self) -> None:
        actual = {
            (method, route.path)
            for route in cp_router.routes
            for method in getattr(route, "methods", set())
            if method != "HEAD"
        }
        assert actual == set(self.ROUTES_AND_THEIR_WRITES), (
            "A route in customer_provisioning is undocumented. Every "
            "route here must name the write that justifies its success "
            "response -- three routes in this domain once did not."
        )

    def test_every_route_has_a_permission_dependency(self) -> None:
        for route in cp_router.routes:
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
