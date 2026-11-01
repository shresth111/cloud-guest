"""Per-location ACS credentials (0176): turning TR-069 off for a location
refuses that location's CPEs at the ACS edge on their next request, leaves the
customer's other locations alone, and works again when turned back on.

acs-auth runs against a fake session that answers the three reads
``_location_active`` makes (location setting, location row, the customer's
own credential) from mutable state, so a toggle between two requests is what
the next request sees. Nothing is cached across requests except the
password-hash verify (see #442).
"""

from __future__ import annotations

import base64
import uuid
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.domains.tr069 import credentials, internal_router
from app.domains.tr069.config import Tr069Settings

SECRET = "edge-s3cret"


def _basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


class _Result:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class FakeSession:
    """Answers the reads acs-auth makes, by table and bound parameters."""

    def __init__(self, state):
        self.state = state

    async def execute(self, stmt):
        from app.domains.tr069.models import Tr069AcsCredential, Tr069LocationSetting

        entity = stmt.column_descriptions[0]["entity"]
        params = stmt.compile().params
        if entity is Tr069LocationSetting:
            loc = next(v for k, v in params.items() if k.startswith("location_id"))
            enabled = self.state.settings.get(loc)
            return _Result(
                None if enabled is None else SimpleNamespace(enabled=enabled)
            )
        if entity is Tr069AcsCredential:
            cust = next(
                v for k, v in params.items() if k.startswith("customer_organization_id")
            )
            return _Result(self.state.customer_creds.get(cust))
        raise AssertionError(f"unexpected read: {entity}")

    async def get(self, model, ident):
        return self.state.locations.get(ident)

    def add(self, *a):
        raise AssertionError("acs-auth must not write")

    async def commit(self):
        return None

    async def rollback(self):
        return None


@pytest.fixture
def edge(monkeypatch):
    from functools import lru_cache

    from app.database.session import get_db_session
    from app.domains.isp_partner import config as isp_config
    from app.domains.tr069 import config as tr_config

    settings = Tr069Settings(enabled=True, edge_shared_secret=SECRET)
    monkeypatch.setattr(tr_config, "get_tr069_settings", lambda: settings)
    monkeypatch.setattr(internal_router, "get_tr069_settings", lambda: settings)
    monkeypatch.setattr(
        isp_config,
        "get_isp_partner_settings",
        lambda: isp_config.IspPartnerSettings(enabled=True),
    )
    isp_id, cust_id = uuid.uuid4(), uuid.uuid4()
    loc1, loc2 = uuid.uuid4(), uuid.uuid4()
    password = "AbcdEfgh1234IjklMnop5678"
    pw_hash = credentials.hash_password(password)

    def cred(username, location_id):
        return SimpleNamespace(
            username=username,
            password_hash=pw_hash,
            enabled=True,
            isp_organization_id=isp_id,
            customer_organization_id=cust_id,
            location_id=location_id,
        )

    state = SimpleNamespace(
        password=password,
        cust_id=cust_id,
        loc1=loc1,
        loc2=loc2,
        creds={
            "loc-11111111": cred("loc-11111111", loc1),
            "loc-22222222": cred("loc-22222222", loc2),
            "cust-33333333": cred("cust-33333333", None),
        },
        settings={loc1: True, loc2: True},
        locations={
            loc1: SimpleNamespace(organization_id=cust_id, is_deleted=False),
            loc2: SimpleNamespace(organization_id=cust_id, is_deleted=False),
        },
        customer_creds={},
    )
    # The customer's own credential, as the customer switch.
    state.customer_creds[cust_id] = state.creds["cust-33333333"]

    class Store:
        def __init__(self, session):
            pass

        async def get_by_username(self, username):
            return state.creds.get(username)

    async def owner_active(session, credential):
        return True

    monkeypatch.setattr(internal_router, "CredentialStore", Store)
    monkeypatch.setattr(internal_router, "_owner_active", owner_active)
    internal_router.positive_cache.clear()

    @lru_cache(maxsize=1)
    def app():
        from app.main import create_app

        return create_app()

    async def _db():
        yield FakeSession(state)

    application = app()
    application.dependency_overrides[get_db_session] = _db
    state.client = TestClient(application, raise_server_exceptions=False)
    yield state
    application.dependency_overrides.clear()
    internal_router.positive_cache.clear()


def _status(state, username: str) -> int:
    return state.client.get(
        "/api/v1/internal/tr069/acs-auth",
        headers={
            "X-Wyfy-Acs-Gate": SECRET,
            "Authorization": _basic(username, state.password),
        },
    ).status_code


def test_location_off_refuses_its_credential_on_the_next_request(edge) -> None:
    assert _status(edge, "loc-11111111") == 204  # positive answer now cached
    edge.settings[edge.loc1] = False  # PUT /isp/tr069/locations/{id} enabled=false
    assert _status(edge, "loc-11111111") == 401


def test_other_locations_of_the_same_customer_are_unaffected(edge) -> None:
    edge.settings[edge.loc1] = False
    assert _status(edge, "loc-11111111") == 401
    assert _status(edge, "loc-22222222") == 204
    assert _status(edge, "cust-33333333") == 204  # customer credential too


def test_location_back_on_is_accepted_again(edge) -> None:
    edge.settings[edge.loc1] = False
    assert _status(edge, "loc-11111111") == 401
    edge.settings[edge.loc1] = True
    assert _status(edge, "loc-11111111") == 204


def test_location_never_configured_refuses_its_credential(edge) -> None:
    del edge.settings[edge.loc1]
    assert _status(edge, "loc-11111111") == 401


def test_customer_switch_off_refuses_location_credentials(edge) -> None:
    assert _status(edge, "loc-11111111") == 204
    edge.creds["cust-33333333"].enabled = False  # customer TR-069 off
    assert _status(edge, "loc-11111111") == 401
    assert _status(edge, "loc-22222222") == 401


def test_location_credential_works_without_a_customer_credential(edge) -> None:
    """A customer whose TR-069 was only ever switched on per location."""
    edge.customer_creds.clear()
    assert _status(edge, "loc-11111111") == 204


def test_location_moved_to_another_customer_refuses_the_old_credential(edge) -> None:
    assert _status(edge, "loc-11111111") == 204
    edge.locations[edge.loc1] = SimpleNamespace(
        organization_id=uuid.uuid4(), is_deleted=False
    )
    assert _status(edge, "loc-11111111") == 401


def test_deleted_location_refuses_its_credential(edge) -> None:
    edge.locations[edge.loc1].is_deleted = True
    assert _status(edge, "loc-11111111") == 401


# -- task refusal for customer-credential CPEs at an OFF location ----------


class _Rows:
    def __init__(self, values):
        self._values = values

    def scalars(self):
        return SimpleNamespace(all=lambda: list(self._values))


class _BlocksSession:
    def __init__(self, creds, off_locations):
        self.creds = creds
        self.off_locations = off_locations

    async def execute(self, stmt):
        from app.domains.tr069.models import Tr069AcsCredential

        entity = stmt.column_descriptions[0]["entity"]
        if entity is Tr069AcsCredential:
            return _Rows(self.creds)
        return _Rows(self.off_locations)  # Tr069LocationSetting.location_id


def _service(creds, off_locations):
    from app.domains.tr069.service import Tr069Service

    svc = Tr069Service.__new__(Tr069Service)
    svc.session = _BlocksSession(creds, off_locations)
    return svc


def _device(**kw):
    base = dict(
        id=uuid.uuid4(),
        customer_organization_id=None,
        location_id=None,
        credential_id=None,
    )
    base.update(kw)
    return SimpleNamespace(**base)


async def test_management_blocks_reasons() -> None:
    isp = SimpleNamespace(isp_org_id=uuid.uuid4())
    cust, cust_off = uuid.uuid4(), uuid.uuid4()
    loc_on, loc_off = uuid.uuid4(), uuid.uuid4()
    cust_cred = SimpleNamespace(
        id=uuid.uuid4(), customer_organization_id=cust, location_id=None, enabled=True
    )
    off_cred = SimpleNamespace(
        id=uuid.uuid4(),
        customer_organization_id=cust_off,
        location_id=None,
        enabled=False,
    )
    loc_cred = SimpleNamespace(
        id=uuid.uuid4(),
        customer_organization_id=uuid.uuid4(),
        location_id=uuid.uuid4(),
        enabled=True,
    )
    isp_cred = SimpleNamespace(
        id=uuid.uuid4(), customer_organization_id=None, location_id=None, enabled=True
    )
    devices = {
        "cust@on": _device(customer_organization_id=cust, location_id=loc_on),
        "cust@off": _device(customer_organization_id=cust, location_id=loc_off),
        "cust@none": _device(customer_organization_id=cust),
        "custoff": _device(customer_organization_id=cust_off, location_id=loc_on),
        "loccred": _device(
            customer_organization_id=loc_cred.customer_organization_id,
            location_id=loc_cred.location_id,
            credential_id=loc_cred.id,
        ),
        "nocred": _device(customer_organization_id=uuid.uuid4()),
        "unassigned": _device(),
    }
    svc = _service([cust_cred, off_cred, loc_cred, isp_cred], [loc_off])
    blocks = await svc._management_blocks(isp, list(devices.values()))
    got = {k: blocks[d.id] for k, d in devices.items()}
    assert got == {
        "cust@on": None,
        "cust@off": "location_off",
        "cust@none": None,
        "custoff": "customer_off",
        "loccred": None,
        "nocred": "customer_off",
        "unassigned": None,
    }


async def test_queue_task_refuses_a_cpe_at_an_off_location(monkeypatch) -> None:
    from app.domains.tr069 import service as service_mod
    from app.domains.tr069.exceptions import Tr069DisabledForLocationError

    device = _device(customer_organization_id=None)
    svc = _service([], [])

    async def assert_cpe(isp, cpe_id):
        return device

    async def blocks(isp, devices):
        return {device.id: "location_off"}

    monkeypatch.setattr(service_mod.IspScope, "assert_cpe", assert_cpe)
    monkeypatch.setattr(svc, "_management_blocks", blocks)
    with pytest.raises(Tr069DisabledForLocationError):
        await svc.queue_task(
            SimpleNamespace(isp_org_id=uuid.uuid4()), device.id, "refresh_params"
        )


def test_location_username_prefix() -> None:
    assert credentials.generate_username("loc").startswith("loc-")


def test_customer_lookup_excludes_location_credentials() -> None:
    """``CredentialStore.get(isp, customer)`` must never return a location
    credential (both carry the customer id)."""
    import inspect

    src = inspect.getsource(credentials.CredentialStore.get)
    assert "location_id.is_(None)" in src
