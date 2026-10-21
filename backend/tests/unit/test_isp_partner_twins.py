"""BE-5: router setup twins and as-router-device.

Each twin is called over HTTP through the real ISP guard stack. The same
fakes (hub bridges mocked) are then handed straight to the ORIGINAL handler,
and the two ``data`` payloads must be identical -- same keys, same values.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.domains.guest import router as guest_routes
from app.domains.guest.dependencies import get_radius_service
from app.domains.isp_partner.rbac_roles import ROLES_BY_SLUG
from app.domains.router import router as router_routes
from app.domains.router.dependencies import get_router_service
from app.domains.router_agent.dependencies import get_router_agent_service
from app.domains.wireguard import router as wg_routes
from app.domains.wireguard.dependencies import get_wireguard_service
from tests.unit.isp_partner_fixtures import CUST_A1, CUST_A2, ISP_A, RTR_A1, RTR_B1
from tests.unit.test_isp_partner_hard_rules import STORE, _app, _h, client  # noqa: F401

NOW = datetime(2026, 10, 22, 6, 0, tzinfo=UTC)
TECH = uuid.UUID("00000000-0000-0000-0000-00000000ec01")
STORE.grant(
    TECH, "isp-technician", ROLES_BY_SLUG["isp-technician"].permission_keys, org=ISP_A
)


def _router():
    return SimpleNamespace(
        id=RTR_A1,
        location_id=uuid.UUID(int=11),
        organization_id=CUST_A1,
        name="hEX Cafe",
        serial_number="HG3X",
        mac_address="E4:8D:8C:00:00:01",
        model="RB750Gr3",
        vendor="mikrotik",
        routeros_version="7.18.2",
        management_ip_address=None,
        public_ip_address=None,
        status="pending_provisioning",
        last_seen_at=None,
        last_health_check_at=None,
        health_status=None,
        api_credentials_encrypted=None,
        settings={},
        snmp_enabled=False,
        snmp_community_encrypted=None,
        snmp_version=None,
        snmp_port=None,
        created_at=NOW,
        updated_at=NOW,
    )


class Fakes:
    def __init__(self) -> None:
        self.seen: list[tuple[str, object]] = []
        self.router = _router()
        self.peer = SimpleNamespace(
            id=uuid.UUID(int=21),
            router_id=RTR_A1,
            server_id=uuid.UUID(int=22),
            tunnel_ip_address="10.20.0.9",
            public_key="pk",
            status="active",
            rotation_count=0,
            last_handshake_at=None,
            created_at=NOW,
            updated_at=NOW,
        )
        self.nas = SimpleNamespace(
            id=uuid.UUID(int=31),
            nas_code="NAS-1",
            router_id=RTR_A1,
            organization_id=CUST_A1,
            location_id=uuid.UUID(int=11),
            nas_identifier="cg-abc",
            status="active",
            is_active=True,
            name="n",
            description=None,
            ip_address="10.20.0.9",
            hub_client_synced_ip="10.20.0.9",
            hub_client_synced_at=NOW,
            device_push_status="pending",
            device_push_error=None,
            device_pushed_at=None,
            vendor="mikrotik",
            created_at=NOW,
            updated_at=NOW,
        )

    # RouterService
    async def get_router(
        self, router_id, *, requesting_organization_id=None, include_deleted=False
    ):
        self.seen.append(("get_router", requesting_organization_id))
        return self.router

    async def controller_context(self, routers):
        return {
            r.id: SimpleNamespace(
                state=None,
                reason=None,
                last_contacted_at=None,
                vendor_claim_is_contradicted=False,
            )
            for r in routers
        }

    async def generate_provisioning_token(
        self, *, actor_user_id, router_id, requesting_organization_id
    ):
        self.seen.append(("token", requesting_organization_id))
        return SimpleNamespace(
            router_id=router_id, expires_at=NOW + timedelta(hours=1)
        ), "tok-plain"

    async def update_router(
        self, *, actor_user_id, router_id, requesting_organization_id, data
    ):
        self.seen.append(("update_router", requesting_organization_id))
        return self.router

    # RouterAgentService
    async def issue_credential_for_router(self, router):
        return SimpleNamespace(), "agent-plain"

    # WireGuardService
    async def allocate_tunnel_via_hub(self, **kw):
        self.seen.append(("allocate", kw["requesting_organization_id"], kw["force"]))
        return SimpleNamespace(
            peer=self.peer,
            peer_private_key="priv",
            reused=False,
            hub_public_key="hub",
            hub_endpoint_host="hub.example.com",
            hub_endpoint_port=51820,
            tunnel_network_cidr="10.20.0.0/24",
            hub_tunnel_ip_address="10.20.0.1",
            message="allocated",
        )

    def compute_health_status(self, peer):
        return "unknown"

    async def get_peer(self, *, router_id, requesting_organization_id):
        self.seen.append(("get_peer", requesting_organization_id))
        return self.peer

    # RadiusService
    async def list_nas_clients(self, **kw):
        return [], None

    async def register_nas(self, **kw):
        self.seen.append(("register_nas", kw["requesting_organization_id"]))
        return SimpleNamespace(nas_client=self.nas, shared_secret="s3")

    async def record_hub_client_sync(self, **kw):
        return self.nas


@pytest.fixture
def fakes(client, monkeypatch):  # noqa: F811
    f = Fakes()
    app = _app()
    for dep in (
        get_router_service,
        get_router_agent_service,
        get_wireguard_service,
        get_radius_service,
    ):
        app.dependency_overrides[dep] = lambda: f
    pushed: list = []

    async def _push(**kw):
        pushed.append(kw)

    monkeypatch.setattr(guest_routes, "push_nas_client", _push)
    f.pushed = pushed
    return f


def _request():
    from starlette.requests import Request

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [],
            "query_string": b"",
        }
    )


def _data(payload):
    payload = dict(payload)
    payload.pop("request_id", None)
    return payload


USER = SimpleNamespace(id=str(uuid.UUID(int=99)))


async def _originals(f: Fakes) -> dict[str, dict]:
    req = _request()
    return {
        "provisioning-token": await router_routes.generate_provisioning_token(
            req,
            router_id=RTR_A1,
            user=USER,
            requesting_organization_id=CUST_A1,
            router_service=f,
        ),
        "agent-credential/regenerate": await router_routes.regenerate_agent_credential(
            req,
            router_id=RTR_A1,
            requesting_organization_id=CUST_A1,
            router_service=f,
            agent_service=f,
        ),
        "wireguard-peer/allocate-external": await wg_routes.allocate_external_wireguard_peer(  # noqa: E501
            req,
            router_id=RTR_A1,
            rotate=False,
            force=False,
            user=USER,
            requesting_organization_id=CUST_A1,
            service=f,
        ),
        "radius-nas/register-external": await guest_routes.register_external_radius_nas(
            req,
            router_id=RTR_A1,
            user=USER,
            requesting_organization_id=CUST_A1,
            service=f,
            wireguard_service=f,
        ),
    }


@pytest.mark.parametrize(
    "action",
    [
        "provisioning-token",
        "agent-credential/regenerate",
        "wireguard-peer/allocate-external",
        "radius-nas/register-external",
    ],
)
async def test_twin_payload_equals_the_original(client, fakes, action) -> None:  # noqa: F811
    r = client.c.post(f"/api/v1/isp/routers/{RTR_A1}/{action}", headers=_h())
    assert r.status_code in (200, 201), r.text
    original = (await _originals(Fakes()))[action]
    from fastapi.encoders import jsonable_encoder

    def utc(v):
        # both go through the same app response class in production, which
        # renders UTC as "Z"; jsonable_encoder here renders "+00:00"
        if isinstance(v, dict):
            return {k: utc(x) for k, x in v.items()}
        if isinstance(v, list):
            return [utc(x) for x in v]
        return v.replace("+00:00", "Z") if isinstance(v, str) else v

    assert utc(_data(r.json())) == utc(jsonable_encoder(_data(original)))
    # every service call was scoped to the customer, never None or the ISP
    orgs = {entry[1] for entry in fakes.seen}
    assert orgs == {CUST_A1}


async def test_management_access_matches_the_platform_serializer(client, fakes) -> None:  # noqa: F811
    r = client.c.put(
        f"/api/v1/isp/routers/{RTR_A1}/management-access",
        json={"api_username": "wyfy"},
        headers=_h(),
    )
    assert r.status_code == 200, r.text
    expected = (await router_routes._one_platform(fakes.router, fakes)).model_dump(
        mode="json"
    )
    assert r.json()["data"] == expected
    assert ("update_router", CUST_A1) in fakes.seen


def test_force_true_is_422_and_never_reaches_the_hub(client, fakes) -> None:  # noqa: F811
    r = client.c.post(
        f"/api/v1/isp/routers/{RTR_A1}/wireguard-peer/allocate-external?force=true",
        headers=_h(),
    )
    assert r.status_code == 422
    assert r.json()["data"]["code"] == "ISP_FORCE_NOT_ALLOWED"
    assert not [s for s in fakes.seen if s[0] == "allocate"]


def test_router_of_isp_b_is_404(client, fakes) -> None:  # noqa: F811
    for action in ("provisioning-token", "radius-nas/register-external"):
        r = client.c.post(f"/api/v1/isp/routers/{RTR_B1}/{action}", headers=_h())
        assert r.status_code == 404
    assert fakes.seen == [] and fakes.pushed == []


def test_confined_technician_on_another_customers_router_is_404(client, fakes) -> None:  # noqa: F811
    client.repo.scopes[(ISP_A, TECH)] = {CUST_A2}
    client.user = TECH
    r = client.c.post(f"/api/v1/isp/routers/{RTR_A1}/provisioning-token", headers=_h())
    assert r.status_code == 404
    assert fakes.seen == []


def test_technician_on_own_customer_may_generate(client, fakes) -> None:  # noqa: F811
    """STATUS Q2 answered yes: technicians get the setup script for the
    customers they are confined to."""
    client.repo.scopes[(ISP_A, TECH)] = {CUST_A1}
    client.user = TECH
    r = client.c.post(f"/api/v1/isp/routers/{RTR_A1}/provisioning-token", headers=_h())
    assert r.status_code == 201, r.text


async def test_as_router_device_is_the_router_response_shape_plus_names(
    client,  # noqa: F811
    fakes,
) -> None:
    r = client.c.get(f"/api/v1/isp/routers/{RTR_A1}/as-router-device", headers=_h())
    assert r.status_code == 200, r.text
    data = r.json()["data"]
    original = (await router_routes._one(fakes.router, fakes)).model_dump(mode="json")
    assert {k: data[k] for k in original} == original
    assert set(data) - set(original) == {"organization_name", "location_name"}
    assert data["organization_name"] == client.repo.orgs[CUST_A1].name
    # the FE RouterDevice mapper reads these
    for key in (
        "id",
        "name",
        "status",
        "vendor",
        "location_id",
        "organization_id",
        "mac_address",
    ):
        assert key in data
