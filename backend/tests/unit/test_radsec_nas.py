"""RadSec (RADIUS over TLS) registration for NAS-only venues with no static IP.

Covers the three pieces a RadSec venue needs: the certificate-identity
validator in ``radius_bridge``, the ``register-radsec`` route plus the status
and switch-back behaviour of the existing routes, and the hub agent's
``/radius/radsec-client`` map writer.
"""

from __future__ import annotations

import importlib.util
import os
import stat
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.domains.guest.exceptions import PublicNasRegistrationRefusedError
from app.domains.guest.radius_bridge import (
    RadsecIdentityRejected,
    validate_radsec_identity,
)
from app.domains.guest.schemas import (
    PublicNasRegistrationRequest,
    RadsecNasRegistrationRequest,
)
from app.domains.rbac.enums import ScopeType
from app.domains.router.vendor_capabilities import ARUBA_INSTANT_ON_VENDOR

from .test_aruba_instant_on import (
    _ENC,
    _aruba_router,
    _data,
    _FakeRadiusService,
    _NasRow,
    _pinned,
    _request,
    _user,
)

_CN = "54:f0:b1:c8:a9:0a"
_ISSUER = "/C=US/O=Example/CN=Example Device CA"


class _RadsecFake(_FakeRadiusService):
    def __init__(self, *a, **kw) -> None:  # noqa: ANN002, ANN003
        super().__init__(*a, **kw)
        self.radsec_synced: list[dict] = []
        self.cleared: list = []

    async def record_radsec_sync(self, *, nas_id, cert_common_name, cert_issuer, **_):  # noqa: ANN001, ANN003, ANN201
        self.radsec_synced.append({"cn": cert_common_name, "issuer": cert_issuer})
        row = self._existing[0] if self._existing else self._row
        row.transport = "radsec"
        row.radsec_cert_cn = cert_common_name
        row.radsec_cert_issuer = cert_issuer
        row.ip_address = None
        row.hub_client_synced_ip = None
        row.hub_client_synced_at = "now"
        return row

    async def clear_radsec_identity(self, *, nas_id, **_):  # noqa: ANN001, ANN003, ANN201
        self.cleared.append(nas_id)
        row = self._existing[0] if self._existing else self._row
        row.transport = "udp"
        row.radsec_cert_cn = None
        row.radsec_cert_issuer = None
        return row


@pytest.fixture
def radsec(monkeypatch):  # noqa: ANN001, ANN201
    from app.domains.guest import router as guest_router

    calls: dict[str, list] = {"push": [], "remove": [], "dereg": [], "udp": []}

    async def _push(**kw: object) -> None:
        calls["push"].append(kw)

    async def _remove(**kw: object) -> None:
        calls["remove"].append(kw)

    async def _dereg(nas_identifier: str) -> int:
        calls["dereg"].append(nas_identifier)
        return 1

    async def _udp(**kw: object) -> str:
        calls["udp"].append(kw)
        return str(kw["controller_ip"])

    settings = SimpleNamespace(
        hub_radius_radsec_agent_url="http://agent:9092/radius/radsec-client",
        hub_radius_radsec_address="radsec.example.net",
        hub_radius_public_address="radius.example.net",
        api_public_base_url="https://api.wyfyguest.com",
    )
    monkeypatch.setattr(guest_router, "push_radsec_nas_client", _push)
    monkeypatch.setattr(guest_router, "remove_radsec_nas_client", _remove)
    monkeypatch.setattr(guest_router, "_deregister_nas_from_radius_bridge", _dereg)
    monkeypatch.setattr(guest_router, "push_controller_nas_client", _udp)
    monkeypatch.setattr(guest_router, "get_settings", lambda: settings)
    calls["settings"] = settings  # type: ignore[assignment]
    return calls


async def _register(router, service, cn: str = _CN, issuer: str = _ISSUER):  # noqa: ANN001, ANN202
    from app.domains.guest import router as guest_router

    return await guest_router.register_radsec_radius_nas(
        _request(),
        router.id,
        RadsecNasRegistrationRequest(cert_common_name=cn, cert_issuer=issuer),
        user=_user(),
        service=service,
    )


class TestValidateRadsecIdentity:
    def test_accepts_and_trims(self) -> None:
        assert validate_radsec_identity(f" {_CN} ", f" {_ISSUER} ") == (_CN, _ISSUER)

    @pytest.mark.parametrize(
        ("cn", "issuer"),
        [
            ("", _ISSUER),
            (_CN, ""),
            ("a|b", _ISSUER),
            (_CN, "/CN=x\n/CN=y"),
            # `openssl x509 -issuer` default form: would never match FreeRADIUS's.
            (_CN, "C = US, O = Example, CN = Example Device CA"),
        ],
    )
    def test_refuses(self, cn: str, issuer: str) -> None:
        with pytest.raises(RadsecIdentityRejected):
            validate_radsec_identity(cn, issuer)


class TestRegisterRadsecRoute:
    def test_pinned_to_global(self) -> None:
        assert (
            _pinned("/register-radsec/{router_id}", "POST")[ScopeType]
            == ScopeType.GLOBAL
        )

    async def test_non_nas_only_vendor_refused(self, radsec: dict) -> None:
        router = _aruba_router(vendor="mikrotik")
        with pytest.raises(PublicNasRegistrationRefusedError):
            await _register(router, _RadsecFake(router))
        assert radsec["push"] == []

    async def test_bad_identity_refused_before_any_write(self, radsec: dict) -> None:
        router = _aruba_router()
        service = _RadsecFake(router)
        with pytest.raises(PublicNasRegistrationRefusedError):
            await _register(router, service, issuer="CN = not compat")
        assert service.registered == [] and radsec["push"] == []

    async def test_not_configured_is_503_and_writes_nothing(self, radsec: dict) -> None:
        radsec["settings"].hub_radius_radsec_agent_url = ""
        router = _aruba_router()
        service = _RadsecFake(router)
        with pytest.raises(HTTPException) as exc:
            await _register(router, service)
        assert exc.value.status_code == 503
        assert service.registered == [] and radsec["push"] == []

    async def test_fresh_registration(self, radsec: dict) -> None:
        router = _aruba_router()
        service = _RadsecFake(router)
        data = _data(await _register(router, service))

        reg = service.registered[0]
        assert reg["ip_address"] is None
        secret = reg["shared_secret"]
        assert len(secret) == 32 and secret.isalnum()
        assert radsec["push"] == [
            {
                "nas_identifier": f"cg-aruba-{str(router.id)[:8]}",
                "secret": secret,
                "cert_common_name": _CN,
                "cert_issuer": _ISSUER,
            }
        ]
        assert service.radsec_synced == [{"cn": _CN, "issuer": _ISSUER}]
        # The backend secret never leaves the platform.
        assert "shared_secret" not in data and secret not in str(data)
        assert data["transport"] == "radsec"
        assert data["hub_confirmed"] is True and data["rotated"] is False
        assert data["radsec_server"] == {
            "host": "radsec.example.net",
            "port": 2083,
            "shared_secret": "radsec",
        }
        assert data["vendor"] == ARUBA_INSTANT_ON_VENDOR

    async def test_udp_row_moves_to_radsec_and_loses_its_stanza(
        self, radsec: dict
    ) -> None:
        router = _aruba_router()
        existing = _NasRow(
            id=uuid.uuid4(),
            router_id=router.id,
            nas_identifier="cg-aruba-0000abcd",
            hub_client_synced_ip="1.1.1.1",
            ip_address="1.1.1.1",
            transport="udp",
            shared_secret_encrypted=_ENC + "old",
        )
        service = _RadsecFake(router, existing=[existing])
        data = _data(await _register(router, service))

        assert service.registered == []
        secret = service.rotated[0]["secret"]
        assert radsec["push"][0]["secret"] == secret
        assert radsec["push"][0]["nas_identifier"] == "cg-aruba-0000abcd"
        assert radsec["dereg"] == ["cg-aruba-0000abcd"]
        assert data["rotated"] is True
        assert existing.ip_address is None and existing.transport == "radsec"


class TestStatusAndSwitchBack:
    async def _status(self, router, service):  # noqa: ANN001, ANN202
        from app.domains.guest import router as guest_router

        return _data(
            await guest_router.get_public_radius_nas_status(
                _request(), router.id, service=service
            )
        )

    def _radsec_row(self, router, synced: bool = True):  # noqa: ANN001, ANN202
        return _NasRow(
            id=uuid.uuid4(),
            router_id=router.id,
            nas_identifier="cg-aruba-0000abcd",
            hub_client_synced_ip=None,
            hub_client_synced_at="t" if synced else None,
            ip_address=None,
            status="active",
            transport="radsec",
            radsec_cert_cn=_CN,
            radsec_cert_issuer=_ISSUER,
            shared_secret_encrypted=_ENC + "S" * 32,
        )

    async def test_confirmed_radsec_row_has_no_gaps(self, radsec: dict) -> None:
        router = _aruba_router()
        data = await self._status(
            router, _RadsecFake(router, existing=[self._radsec_row(router)])
        )
        assert data["gaps"] == []
        assert data["transport"] == "radsec"
        assert data["nas_ip"] is None
        assert data["radius_server"] is None
        assert data["radsec_server"]["port"] == 2083
        assert data["radsec_cert_cn"] == _CN
        assert data["portal_url"] is not None

    async def test_unconfirmed_and_unconfigured_are_gaps(self, radsec: dict) -> None:
        radsec["settings"].hub_radius_radsec_address = ""
        router = _aruba_router()
        data = await self._status(
            router,
            _RadsecFake(router, existing=[self._radsec_row(router, synced=False)]),
        )
        assert set(data["gaps"]) == {
            "hub_not_confirmed",
            "radsec_server_address_not_configured",
        }
        assert data["portal_url"] is None

    async def test_register_public_on_a_radsec_row_revokes_the_enrolment(
        self, radsec: dict
    ) -> None:
        from app.domains.guest import router as guest_router

        router = _aruba_router()
        row = self._radsec_row(router)
        service = _RadsecFake(router, existing=[row])
        await guest_router.register_public_radius_nas(
            _request(),
            router.id,
            PublicNasRegistrationRequest(nas_ip="8.8.4.4"),
            user=_user(),
            service=service,
        )
        assert radsec["udp"][0]["controller_ip"] == "8.8.4.4"
        assert radsec["remove"] == [{"nas_identifier": "cg-aruba-0000abcd"}]
        assert service.cleared == [row.id]
        assert row.transport == "udp" and row.radsec_cert_cn is None


# ---------------------------------------------------------------------------
# Hub agent: /radius/radsec-client
# ---------------------------------------------------------------------------

_AGENT_PATH = (
    Path(__file__).resolve().parents[2] / "ops" / "hub-agents" / "radius_agent.py"
)


@pytest.fixture
def agent(tmp_path, monkeypatch):  # noqa: ANN001, ANN201
    spec = importlib.util.spec_from_file_location(
        "wyfy_radius_agent_radsec", _AGENT_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    m = tmp_path / "radsec-map"
    m.write_text("")
    os.chmod(m, 0o640)
    monkeypatch.setattr(mod, "RADSEC_MAP", str(m))
    monkeypatch.setattr(mod, "RADSEC_RELOAD_CMD", "")
    return mod, m


_S1 = "A" * 32
_S2 = "B" * 32


class TestAgentRadsecMap:
    def test_add_writes_the_line_the_passwd_module_reads(self, agent) -> None:  # noqa: ANN001
        mod, m = agent
        assert mod.add_radsec_client("cg-aruba-1", _S1, _CN, _ISSUER)["status"] == "ok"
        assert m.read_text() == f"{_CN}|cg-aruba-1|{_S1}|{_ISSUER}\n"
        assert stat.S_IMODE(m.stat().st_mode) == 0o640

    def test_re_enrolment_replaces_by_nas_and_by_cn(self, agent) -> None:  # noqa: ANN001
        mod, m = agent
        mod.add_radsec_client("cg-aruba-1", _S1, _CN, _ISSUER)
        mod.add_radsec_client("cg-aruba-2", _S2, "other-cn", _ISSUER)
        # NAS 1 moves to a new cert; NAS 2 claims NAS 1's old CN.
        r = mod.add_radsec_client("cg-aruba-1", _S1, "new-cn", _ISSUER)
        assert r["superseded"] == 1
        r = mod.add_radsec_client("cg-aruba-2", _S2, _CN, _ISSUER)
        lines = m.read_text().splitlines()
        assert lines == [
            f"new-cn|cg-aruba-1|{_S1}|{_ISSUER}",
            f"{_CN}|cg-aruba-2|{_S2}|{_ISSUER}",
        ]

    def test_remove(self, agent) -> None:  # noqa: ANN001
        mod, m = agent
        mod.add_radsec_client("cg-aruba-1", _S1, _CN, _ISSUER)
        assert mod.remove_radsec_client("cg-aruba-1")["removed"] == 1
        assert m.read_text() == ""
        assert mod.remove_radsec_client("cg-aruba-1")["removed"] == 0

    @pytest.mark.parametrize(
        ("nas", "secret", "cn", "issuer"),
        [
            ("bad id", _S1, _CN, _ISSUER),
            ("cg-1", "short", _CN, _ISSUER),
            ("cg-1", "x" * 31 + "|", _CN, _ISSUER),
            ("cg-1", _S1, "a|b", _ISSUER),
            ("cg-1", _S1, _CN, "CN = not compat"),
            ("cg-1", _S1, _CN, "/CN=a\n/CN=b"),
        ],
    )
    def test_rejects(self, agent, nas: str, secret: str, cn: str, issuer: str) -> None:  # noqa: ANN001
        mod, m = agent
        with pytest.raises(ValueError):
            mod.add_radsec_client(nas, secret, cn, issuer)
        assert m.read_text() == ""

    def test_not_configured(self, agent, monkeypatch) -> None:  # noqa: ANN001
        mod, _ = agent
        monkeypatch.setattr(mod, "RADSEC_MAP", "")
        with pytest.raises(NotImplementedError):
            mod.add_radsec_client("cg-1", _S1, _CN, _ISSUER)

    def test_reload_failure_is_an_error(self, agent, monkeypatch) -> None:  # noqa: ANN001
        mod, _ = agent
        monkeypatch.setattr(mod, "RADSEC_RELOAD_CMD", "false")
        with pytest.raises(RuntimeError):
            mod.add_radsec_client("cg-1", _S1, _CN, _ISSUER)

    def test_handler_routes_the_new_path(self, agent) -> None:  # noqa: ANN001
        mod, _ = agent
        assert "/radius/radsec-client" in mod._PATHS
        assert "/radius/client" in mod._PATHS
