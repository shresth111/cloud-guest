"""IspPartnerService: customers, locations, routers (BE-4) with fakes for
every composed service, and the request schemas' forbid-unknown rule."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.domains.isp_partner.exceptions import (
    IspCustomerLimitError,
    IspCustomerNotFoundError,
    IspCustomerSlugTakenError,
    IspExternalRefTakenError,
    IspImmutableFieldError,
    IspVendorNotSupportedError,
)
from app.domains.isp_partner.schemas import (
    CustomerCreateRequest,
    CustomerUpdateRequest,
    IspLocationCreateRequest,
    IspUserCreateRequest,
)
from app.domains.isp_partner.service import IspPartnerService
from app.domains.organization.exceptions import DuplicateSlugError
from tests.unit.isp_partner_fixtures import (
    CUST_A1,
    CUST_B1,
    ISP_A,
    LOC_A1,
    LOC_B1,
    NOW,
    PLAN,
    FakeIspRepository,
    context,
    estate,
    org,
)


class Repo(FakeIspRepository):
    added: list

    async def locations_for_organizations(self, ids):
        return [x for x in self.locations.values() if x.organization_id in ids]

    async def routers_for_organizations(self, ids):
        return [x for x in self.routers.values() if x.organization_id in ids]

    async def customer_profiles(self, ids):
        return {}

    async def credentials_for_isp(self, isp):
        return []

    async def cpes_for_isp(self, isp):
        return []

    async def count_customers(self, isp):
        return len(await self.child_ids(isp))

    async def external_ref_taken(self, isp, ref, except_customer_id=None):
        return ref == "TAKEN"

    async def add(self, row):
        self.__dict__.setdefault("added", []).append(row)
        return row

    async def flush(self):
        return None


def _repo() -> Repo:
    base = estate()
    repo = Repo(**{k: getattr(base, k) for k in base.__dataclass_fields__})
    for loc in repo.locations.values():
        loc.status = "active"
        loc.slug = "loc"
        loc.location_code = "L-1"
        loc.property_type = "cafe"
        loc.address_line1 = "1 Main"
        loc.city = "Noida"
        loc.state_province = "UP"
        loc.postal_code = "201301"
        loc.country = "IN"
        loc.timezone = "Asia/Kolkata"
        loc.latitude = None
        loc.longitude = None
        loc.created_at = NOW
    for r in repo.routers.values():
        r.status = "online"
    return repo


class FakeSession:
    class _Nested:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    def begin_nested(self):
        return self._Nested()

    async def execute(self, stmt):
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: []))


class Recorder:
    def __init__(self, repo: Repo, *, slug_taken: bool = False) -> None:
        self.repo = repo
        self.calls: list[tuple[str, dict]] = []
        self.slug_taken = slug_taken

    # organization service
    async def create_organization(self, **kw):
        self.calls.append(("create_organization", kw))
        if self.slug_taken:
            raise DuplicateSlugError(kw["slug"])
        new = org(
            uuid.uuid4(),
            parent=kw["parent_organization_id"],
            org_type=kw["org_type"].value,
        )
        new.name = kw["name"]
        new.slug = kw["slug"]
        new.settings = kw["settings"]
        self.repo.orgs[new.id] = new
        return new

    async def get_by_slug(self, slug, include_deleted=False):
        raise LookupError(slug)

    async def suspend_organization(self, **kw):
        self.calls.append(("suspend_organization", kw))
        o = self.repo.orgs[kw["organization_id"]]
        o.status = "suspended"
        return o

    async def activate_organization(self, **kw):
        self.calls.append(("activate_organization", kw))
        o = self.repo.orgs[kw["organization_id"]]
        o.status = "active"
        return o

    async def update_organization(self, **kw):
        self.calls.append(("update_organization", kw))
        o = self.repo.orgs[kw["organization_id"]]
        for k, v in kw["data"].items():
            setattr(o, k, v)
        return o

    # subscription service
    async def create_subscription(self, **kw):
        self.calls.append(("create_subscription", kw))

    # location service
    async def create_location(self, **kw):
        self.calls.append(("create_location", kw))
        loc = SimpleNamespace(
            id=uuid.uuid4(),
            organization_id=kw["organization_id"],
            name=kw["name"],
            slug=kw["slug"],
            status="active",
            location_code="L-2",
            property_type=None,
            address_line1=kw["address_line1"],
            city=kw["city"],
            state_province=kw["state_province"],
            postal_code=kw["postal_code"],
            country=kw["country"],
            timezone=kw["timezone"],
            latitude=None,
            longitude=None,
            created_at=NOW,
            is_deleted=False,
        )
        self.repo.locations[loc.id] = loc
        return loc

    # captive portal service
    async def create_config(self, **kw):
        self.calls.append(("create_config", kw))

    # router service
    async def create_router(self, **kw):
        self.calls.append(("create_router", kw))
        r = SimpleNamespace(
            id=uuid.uuid4(),
            organization_id=self.repo.locations[kw["location_id"]].organization_id,
            location_id=kw["location_id"],
            name=kw["name"],
            model=kw["model"],
            serial_number=kw["serial_number"],
            mac_address=kw["mac_address"],
            vendor=kw["vendor"],
            routeros_version=None,
            status="pending_provisioning",
            last_seen_at=None,
            is_deleted=False,
        )
        self.repo.routers[r.id] = r
        return r

    # audit
    async def create_audit_log_entry(self, **kw):
        self.calls.append(("audit", kw))

    def named(self, name):
        return [kw for n, kw in self.calls if n == name]


class Creds:
    def __init__(self) -> None:
        self.rows: dict = {}
        self.toggles: list = []

    async def get(self, isp, customer):
        return self.rows.get((isp, customer))

    async def set_enabled(self, isp, customer, enabled, *, actor_user_id):
        row = self.rows.get((isp, customer))
        if row is not None:
            row.enabled = enabled
            self.toggles.append((customer, enabled))
        return row


def _service(repo: Repo, rec: Recorder, creds: Creds | None = None, *, alerting=None):
    repo.session = FakeSession()
    service = IspPartnerService(
        repository=repo,
        organization_service=rec,
        location_service=rec,
        captive_portal_service=rec,
        subscription_service=rec,
        router_service=rec,
        audit=rec,
        credentials=creds or Creds(),
        default_alerting=alerting,
        clock=lambda: NOW,
    )

    async def _no_tr069(location_ids):
        return set()

    service._location_tr069 = _no_tr069  # type: ignore[method-assign]
    return service


_BODY = {"name": "Cafe X", "contact_email": "amit@example.com"}


class TestCreateCustomer:
    async def test_always_standard_child_of_the_isp_with_a_subscription(self) -> None:
        repo, alerted = _repo(), []
        rec = Recorder(repo)

        async def alerting(**kw):
            alerted.append(kw)

        service = _service(repo, rec, alerting=alerting)
        data = await service.create_customer(
            context(repo), dict(_BODY, external_ref="AIR-1")
        )
        (call,) = rec.named("create_organization")
        assert call["org_type"].value == "standard"
        assert call["parent_organization_id"] == ISP_A
        assert call["settings"] == {
            "onboarded_via": "isp_partner",
            "isp_organization_id": str(ISP_A),
        }
        (sub,) = rec.named("create_subscription")
        assert sub["plan_id"] == PLAN and sub["organization_id"] == uuid.UUID(
            data["id"]
        )
        assert alerted and alerted[0]["organization_id"] == uuid.UUID(data["id"])
        assert any(a["action"] == "isp_customer_created" for a in rec.named("audit"))
        assert data["status"] == "active" and data["tr069_enabled"] is False
        assert set(data) == {
            "id",
            "name",
            "slug",
            "status",
            "legal_name",
            "gstin",
            "external_ref",
            "contact_name",
            "contact_email",
            "contact_phone",
            "address_line1",
            "city",
            "state_province",
            "postal_code",
            "timezone",
            "notes",
            "counts",
            "tr069_enabled",
            "created_at",
            "updated_at",
        }
        assert set(data["counts"]) == {
            "locations",
            "routers_total",
            "routers_online",
            "cpes",
        }

    async def test_no_user_membership_or_role_is_ever_created(self) -> None:
        """BE-4: the service has no user/membership/role collaborator at all,
        and the only calls it makes are the ones listed here."""
        repo = _repo()
        rec = Recorder(repo)
        service = _service(repo, rec)
        created = await service.create_customer(context(repo), dict(_BODY))
        await service.create_location(
            context(repo),
            uuid.UUID(created["id"]),
            {
                "name": "Sector 18",
                "address_line1": "1 Main",
                "city": "Noida",
                "state_province": "UP",
                "postal_code": "201301",
                "country": "IN",
                "timezone": "Asia/Kolkata",
            },
        )
        names = {n for n, _ in rec.calls}
        assert names <= {
            "create_organization",
            "create_subscription",
            "audit",
            "create_location",
            "create_config",
        }
        assert not any("user" in n or "member" in n or "role" in n for n in names)

    async def test_alerting_failure_does_not_fail_creation(self) -> None:
        repo = _repo()

        async def boom(**kw):
            raise RuntimeError("smtp down")

        data = await _service(repo, Recorder(repo), alerting=boom).create_customer(
            context(repo), dict(_BODY)
        )
        assert data["id"]

    async def test_limit_slug_and_external_ref(self) -> None:
        repo = _repo()
        repo.profiles[ISP_A].max_customers = 2
        with pytest.raises(IspCustomerLimitError) as err:
            await _service(repo, Recorder(repo)).create_customer(
                context(repo), dict(_BODY)
            )
        assert err.value.status_code == 409
        repo.profiles[ISP_A].max_customers = None
        with pytest.raises(IspCustomerSlugTakenError):
            await _service(repo, Recorder(repo, slug_taken=True)).create_customer(
                context(repo), dict(_BODY, slug="cafe-x")
            )
        with pytest.raises(IspExternalRefTakenError):
            await _service(repo, Recorder(repo)).create_customer(
                context(repo), dict(_BODY, external_ref="TAKEN")
            )

    async def test_service_signature_has_no_org_type_or_parent(self) -> None:
        """BE-T 3: the service cannot be asked for anything but a STANDARD
        child of the caller's ISP -- there is no parameter to ask with, and
        a data dict naming one is ignored."""
        import inspect

        params = inspect.signature(IspPartnerService.create_customer).parameters
        assert set(params) == {"self", "isp", "data"}
        repo = _repo()
        rec = Recorder(repo)
        await _service(repo, rec).create_customer(
            context(repo),
            dict(_BODY, org_type="msp", parent_organization_id=str(CUST_A1)),
        )
        (call,) = rec.named("create_organization")
        assert (
            call["org_type"].value == "standard"
            and call["parent_organization_id"] == ISP_A
        )


class TestUpdateSuspend:
    async def test_slug_is_immutable(self) -> None:
        repo = _repo()
        with pytest.raises(IspImmutableFieldError) as err:
            await _service(repo, Recorder(repo)).update_customer(
                context(repo), CUST_A1, {"slug": "new"}
            )
        assert err.value.status_code == 422

    async def test_suspend_disables_tr069_only_and_activate_restores_it(self) -> None:
        repo = _repo()
        rec = Recorder(repo)
        creds = Creds()
        creds.rows[(ISP_A, CUST_A1)] = SimpleNamespace(enabled=True)
        service = _service(repo, rec, creds)
        data = await service.suspend_customer(context(repo), CUST_A1, reason="unpaid")
        assert data["status"] == "suspended"
        (suspend,) = rec.named("suspend_organization")
        assert (
            suspend["requesting_organization_id"] == CUST_A1
        )  # never None, never the ISP
        assert creds.toggles == [(CUST_A1, False)]
        # no guest/RADIUS/portal collaborator exists to touch
        assert {n for n, _ in rec.calls} <= {
            "suspend_organization",
            "update_organization",
            "audit",
        }
        await service.activate_customer(context(repo), CUST_A1)
        assert creds.toggles == [(CUST_A1, False), (CUST_A1, True)]

    async def test_activate_does_not_enable_tr069_the_isp_turned_off(self) -> None:
        repo = _repo()
        creds = Creds()
        creds.rows[(ISP_A, CUST_A1)] = SimpleNamespace(enabled=False)
        service = _service(repo, Recorder(repo), creds)
        await service.suspend_customer(context(repo), CUST_A1, reason=None)
        await service.activate_customer(context(repo), CUST_A1)
        assert creds.toggles == []

    async def test_other_isps_customer_is_404(self) -> None:
        repo = _repo()
        service = _service(repo, Recorder(repo))
        for call in (
            service.get_customer(context(repo), CUST_B1),
            service.suspend_customer(context(repo), CUST_B1, reason=None),
            service.update_customer(context(repo), CUST_B1, {"name": "x"}),
        ):
            with pytest.raises(IspCustomerNotFoundError):
                await call


class TestLocationsRouters:
    async def test_location_gets_the_default_portal_config(self) -> None:
        repo = _repo()
        rec = Recorder(repo)
        data = await _service(repo, rec).create_location(
            context(repo),
            CUST_A1,
            {
                "name": "Sector 18",
                "address_line1": "1 Main",
                "city": "Noida",
                "state_province": "UP",
                "postal_code": "201301",
                "country": "IN",
                "timezone": "Asia/Kolkata",
            },
        )
        (loc_call,) = rec.named("create_location")
        assert loc_call["organization_id"] == CUST_A1
        assert loc_call["requesting_organization_id"] == CUST_A1
        (cfg,) = rec.named("create_config")
        assert cfg["location_id"] == uuid.UUID(data["id"])
        assert cfg["organization_id"] == CUST_A1 and cfg["is_active"] is True
        assert cfg["requesting_organization_id"] == CUST_A1
        assert cfg["otp_email_enabled"] is True
        assert data["isp_customer_id"] == str(CUST_A1)

    async def test_router_is_mikrotik_only_and_scoped(self) -> None:
        repo = _repo()
        rec = Recorder(repo)
        service = _service(repo, rec)
        body = {
            "name": "hEX",
            "serial_number": "HG3X",
            "mac_address": "e4:8d:8c:00:00:01",
            "model": "RB750Gr3",
            "vendor": "mikrotik",
        }
        data = await service.create_router(context(repo), LOC_A1, body)
        assert data["cloud_link"] == "unknown" and data["vendor"] == "mikrotik"
        assert rec.named("create_router")[0]["requesting_organization_id"] == CUST_A1
        with pytest.raises(IspVendorNotSupportedError):
            await service.create_router(
                context(repo), LOC_A1, dict(body, vendor="aruba")
            )
        from app.domains.isp_partner.exceptions import IspLocationNotFoundError

        with pytest.raises(IspLocationNotFoundError):
            await service.create_router(context(repo), LOC_B1, body)


class TestSchemas:
    @pytest.mark.parametrize(
        "extra",
        [
            {"org_type": "msp"},
            {"parent_organization_id": str(uuid.uuid4())},
            {"organization_id": str(uuid.uuid4())},
            {"parent": "x"},
        ],
    )
    def test_customer_body_refuses_org_fields(self, extra) -> None:
        """BE-T 1, 2: 422 before any handler runs."""
        with pytest.raises(ValidationError):
            CustomerCreateRequest(**_BODY, **extra)
        with pytest.raises(ValidationError):
            CustomerUpdateRequest(**extra)

    def test_location_and_user_bodies_refuse_org_fields(self) -> None:
        with pytest.raises(ValidationError):
            IspLocationCreateRequest(
                name="x",
                address_line1="a",
                city="c",
                state_province="s",
                postal_code="1",
                organization_id=str(uuid.uuid4()),
            )
        for extra in ({"organization_id": str(uuid.uuid4())}, {"organization": "x"}):
            with pytest.raises(ValidationError):
                IspUserCreateRequest(
                    first_name="a",
                    last_name="b",
                    email="a@example.com",
                    role="isp-viewer",
                    **extra,
                )

    def test_contact_email_is_required_and_validated(self) -> None:
        with pytest.raises(ValidationError):
            CustomerCreateRequest(name="x")
        with pytest.raises(ValidationError):
            CustomerCreateRequest(name="x", contact_email="not-an-email")
