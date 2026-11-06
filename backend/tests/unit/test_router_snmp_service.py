"""``app.domains.router.snmp`` -- per-vendor support, write-only config,
the real-read-back test, the device push, and the GLOBAL pin on every
``/platform/routers/{id}/snmp`` route.

Fakes sit at the boundaries only: the RouterService surface the SNMP service
uses, the SNMP poller, and the MikroTik adapter.
"""

from __future__ import annotations

import inspect
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import pytest
from wyfy_device_gateway.mikrotik_snmp import SnmpApplyResult, SnmpDeviceState
from wyfy_device_gateway.snmp_poller import (
    SnmpConnectionError,
    SnmpDeviceError,
    SnmpIdentity,
)

from app.domains.rbac.enums import ScopeType
from app.domains.router import snmp as snmp_module
from app.domains.router.crypto import decrypt_secret, encrypt_secret
from app.domains.router.models import Router
from app.domains.router.snmp import (
    RouterSnmpService,
    SnmpConfigInvalidError,
    SnmpNotConfiguredError,
    SnmpNotSupportedError,
    SnmpPollStatus,
    SnmpSupport,
    build_device_config,
    resolve_snmp_credentials,
    snmp_support_for,
)
from app.domains.router.snmp_router import router as snmp_api_router
from app.domains.router.snmp_router import snmp_status
from app.domains.router.snmp_schemas import RouterSnmpConfigRequest


@dataclass
class FakeSettings:
    snmp_default_community: str = ""
    snmp_default_version: str = "2c"
    snmp_default_port: int = 161
    snmp_poll_timeout_seconds: int = 5
    snmp_poller_source_addresses: str = "172.31.38.118/32"


def _router(**overrides: Any) -> Router:
    now = datetime.now(UTC)
    fields: dict[str, Any] = {
        "id": uuid.uuid4(),
        "created_at": now,
        "updated_at": now,
        "is_deleted": False,
        "version": 1,
        "organization_id": uuid.uuid4(),
        "location_id": uuid.uuid4(),
        "name": "Hall Router",
        "serial_number": "HJP0ATMRJ6X",
        "mac_address": "AA:BB:CC:DD:EE:01",
        "vendor": "mikrotik",
        "management_ip_address": "10.20.0.31",
        "status": "online",
        "api_username": "cloudguest-api",
        "api_credentials_encrypted": encrypt_secret("apisecret"),
        "snmp_enabled": False,
    }
    fields.update(overrides)
    return Router(**fields)


@dataclass
class _Repo:
    updates: list[dict[str, Any]] = field(default_factory=list)

    async def update_router(self, router: Router, data: dict[str, Any]) -> Router:
        self.updates.append(dict(data))
        for key, value in data.items():
            setattr(router, key, value)
        return router


@dataclass
class FakeRouterService:
    router: Router
    repository: _Repo = field(default_factory=_Repo)
    audits: list[dict[str, Any]] = field(default_factory=list)

    async def get_router(self, router_id: uuid.UUID, **_: Any) -> Router:
        assert router_id == self.router.id
        return self.router

    def get_decrypted_api_secret(self, router: Router) -> str | None:
        return (
            decrypt_secret(router.api_credentials_encrypted)
            if router.api_credentials_encrypted
            else None
        )

    async def _audit(self, actor, action, *, router, description, metadata=None):  # noqa: ANN001
        self.audits.append(
            {"action": action.value, "description": description, "metadata": metadata}
        )


@dataclass
class FakePoller:
    identity: SnmpIdentity | None = None
    exc: Exception | None = None
    calls: list[Any] = field(default_factory=list)

    async def read_identity(self, creds):  # noqa: ANN001
        self.calls.append(creds)
        if self.exc:
            raise self.exc
        return self.identity


_STATE = SnmpDeviceState(
    agent_enabled=True,
    community_present=True,
    community_disabled=False,
    community_addresses="172.31.38.118/32",
    community_security="none",
    community_read_only=True,
    default_public_open=False,
    other_communities=0,
)


@dataclass
class FakeAdapter:
    result: SnmpApplyResult = field(
        default_factory=lambda: SnmpApplyResult(changed=["community"], state=_STATE)
    )
    applied: list[Any] = field(default_factory=list)
    removed: int = 0

    async def apply_snmp_config(self, creds, config):  # noqa: ANN001
        self.applied.append((creds, config))
        return self.result

    async def remove_snmp_config(self, creds):  # noqa: ANN001
        self.removed += 1
        return self.result

    async def read_snmp_state(self, creds):  # noqa: ANN001
        return _STATE


@pytest.fixture(autouse=True)
def _settings(monkeypatch: pytest.MonkeyPatch) -> FakeSettings:
    settings = FakeSettings()
    monkeypatch.setattr(snmp_module, "get_settings", lambda: settings)
    return settings


def _service(router: Router, **kw: Any) -> tuple[RouterSnmpService, FakeRouterService]:
    rs = FakeRouterService(router)
    adapter = kw.pop("adapter", FakeAdapter())
    svc = RouterSnmpService(
        rs,  # type: ignore[arg-type]
        poller=kw.pop("poller", FakePoller()),
        device_adapter_resolver=lambda _vendor: adapter,
        settings=FakeSettings(**kw),  # type: ignore[arg-type]
    )
    return svc, rs


ACTOR = uuid.uuid4()


# ---------------------------------------------------------------------------
# per-vendor support
# ---------------------------------------------------------------------------


class TestVendorSupport:
    def test_mikrotik_supported(self) -> None:
        assert snmp_support_for("mikrotik").support is SnmpSupport.SUPPORTED

    def test_omada_has_agent_but_is_not_reachable(self) -> None:
        s = snmp_support_for("tplink_omada")
        assert s.support is SnmpSupport.NOT_REACHABLE
        assert s.metrics_via == "Omada controller API"

    def test_instant_on_has_no_snmp(self) -> None:
        s = snmp_support_for("aruba_instant_on")
        assert s.support is SnmpSupport.NOT_SUPPORTED
        assert s.metrics_via == "Instant On cloud"

    def test_unassessed_vendor_is_unknown_never_supported(self) -> None:
        assert snmp_support_for("ruckus").support is SnmpSupport.UNKNOWN

    @pytest.mark.parametrize("vendor", ["tplink_omada", "aruba_instant_on", "ruckus"])
    async def test_enabling_refused_for_non_mikrotik(self, vendor: str) -> None:
        svc, _ = _service(_router(vendor=vendor))
        with pytest.raises(SnmpNotSupportedError) as err:
            await svc.update_config(
                _router_id(svc),
                actor_user_id=ACTOR,
                data={"enabled": True, "community": "abcdef1"},
            )
        assert err.value.data["code"] == "SNMP_NOT_SUPPORTED_FOR_VENDOR"

    async def test_disabling_always_allowed(self) -> None:
        router = _router(vendor="tplink_omada", snmp_enabled=True)
        svc, _ = _service(router)
        await svc.update_config(router.id, actor_user_id=ACTOR, data={"enabled": False})
        assert router.snmp_enabled is False


def _router_id(svc: RouterSnmpService) -> uuid.UUID:
    return svc.router_service.router.id  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# configuration: write-only, encrypted, validated
# ---------------------------------------------------------------------------


class TestConfig:
    async def test_v2c_community_encrypted_and_never_in_status(self) -> None:
        router = _router()
        svc, rs = _service(router)
        await svc.update_config(
            router.id,
            actor_user_id=ACTOR,
            data={"enabled": True, "version": "2c", "community": "SuperSecret9"},
        )
        assert router.snmp_enabled is True
        assert router.snmp_community_encrypted is not None
        assert "SuperSecret9" not in router.snmp_community_encrypted
        assert decrypt_secret(router.snmp_community_encrypted) == "SuperSecret9"
        dumped = snmp_status(router, FakeSettings()).model_dump_json()  # type: ignore[arg-type]
        assert "SuperSecret9" not in dumped
        assert '"has_community":true' in dumped
        # Audit carries field names only.
        audit = rs.audits[-1]
        assert audit["action"] == "router_snmp_config_updated"
        assert "SuperSecret9" not in str(audit)
        assert "snmp_community" in audit["metadata"]["fields"]

    async def test_enable_without_any_community_refused(self) -> None:
        router = _router()
        svc, _ = _service(router)
        with pytest.raises(SnmpConfigInvalidError):
            await svc.update_config(
                router.id, actor_user_id=ACTOR, data={"enabled": True}
            )

    async def test_v3_needs_auth_passphrase(self) -> None:
        router = _router()
        svc, _ = _service(router)
        with pytest.raises(SnmpConfigInvalidError):
            await svc.update_config(
                router.id,
                actor_user_id=ACTOR,
                data={"enabled": True, "version": "3", "v3_username": "wyfy"},
            )

    async def test_v3_full_config_stored_encrypted(self) -> None:
        router = _router()
        svc, _ = _service(router)
        await svc.update_config(
            router.id,
            actor_user_id=ACTOR,
            data={
                "enabled": True,
                "version": "3",
                "v3_username": "wyfy",
                "v3_auth_protocol": "SHA1",
                "v3_auth_password": "authpass1",
                "v3_priv_protocol": "AES",
                "v3_priv_password": "privpass1",
            },
        )
        assert decrypt_secret(router.snmp_v3_auth_password_encrypted) == "authpass1"
        assert decrypt_secret(router.snmp_v3_priv_password_encrypted) == "privpass1"
        status = snmp_status(router, FakeSettings())  # type: ignore[arg-type]
        assert status.has_v3_auth_password and status.has_v3_priv_password
        assert "authpass1" not in status.model_dump_json()

    async def test_leaving_v3_drops_usm_secrets(self) -> None:
        router = _router(
            snmp_version="3",
            snmp_community_encrypted=encrypt_secret("wyfy"),
            snmp_v3_auth_password_encrypted=encrypt_secret("authpass1"),
        )
        svc, _ = _service(router)
        await svc.update_config(
            router.id,
            actor_user_id=ACTOR,
            data={"version": "2c", "community": "newcomm1"},
        )
        assert router.snmp_v3_auth_password_encrypted is None

    def test_schema_refuses_quotes_and_short_community(self) -> None:
        with pytest.raises(ValueError):
            RouterSnmpConfigRequest(community='bad"comm')
        with pytest.raises(ValueError):
            RouterSnmpConfigRequest(community="abc")
        with pytest.raises(ValueError):
            RouterSnmpConfigRequest(version="1")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            RouterSnmpConfigRequest(version="3", community="abcdefg")


# ---------------------------------------------------------------------------
# credential resolution
# ---------------------------------------------------------------------------


class TestResolve:
    def test_platform_default_applies_to_v2c_only(
        self, _settings: FakeSettings
    ) -> None:
        _settings.snmp_default_community = "fleetwide1"
        assert resolve_snmp_credentials(_router()).community == "fleetwide1"  # type: ignore[union-attr]
        assert resolve_snmp_credentials(_router(snmp_version="3")) is None

    def test_no_host_no_credentials(self) -> None:
        router = _router(
            management_ip_address=None,
            snmp_community_encrypted=encrypt_secret("x123456"),
        )
        assert resolve_snmp_credentials(router) is None

    def test_device_config_v3_security_follows_priv(self) -> None:
        creds = resolve_snmp_credentials(
            _router(
                snmp_version="3",
                snmp_community_encrypted=encrypt_secret("wyfy"),
                snmp_v3_auth_password_encrypted=encrypt_secret("authpass1"),
            )
        )
        assert creds is not None
        assert build_device_config(creds).security == "authorized"


# ---------------------------------------------------------------------------
# Test SNMP: a real read-back, reported truthfully
# ---------------------------------------------------------------------------


def _configured_router(**kw: Any) -> Router:
    return _router(
        snmp_enabled=True, snmp_community_encrypted=encrypt_secret("comm12345"), **kw
    )


class TestTest:
    async def test_ok_returns_what_the_device_said(self) -> None:
        router = _configured_router()
        poller = FakePoller(
            identity=SnmpIdentity(
                sys_name="hall", sys_descr="RouterOS", uptime_seconds=60
            )
        )
        svc, rs = _service(router, poller=poller)
        outcome = await svc.test(router.id, actor_user_id=ACTOR)
        assert outcome.ok and outcome.status is SnmpPollStatus.OK
        assert outcome.identity is not None and outcome.identity.sys_name == "hall"
        assert poller.calls[0].host == "10.20.0.31"
        assert rs.audits[-1]["action"] == "router_snmp_tested"

    async def test_timeout_is_no_response_and_says_what_it_cannot_tell(self) -> None:
        router = _configured_router()
        poller = FakePoller(exc=SnmpConnectionError("10.20.0.31", "timeout"))
        svc, _ = _service(router, poller=poller)
        outcome = await svc.test(router.id, actor_user_id=ACTOR)
        assert not outcome.ok
        assert outcome.status is SnmpPollStatus.NO_RESPONSE
        assert outcome.identity is None
        assert "wrong community" in (outcome.detail or "")

    async def test_agent_error_is_error(self) -> None:
        router = _configured_router()
        svc, _ = _service(
            router,
            poller=FakePoller(exc=SnmpDeviceError("10.20.0.31", "authorizationError")),
        )
        outcome = await svc.test(router.id, actor_user_id=ACTOR)
        assert outcome.status is SnmpPollStatus.ERROR

    async def test_nothing_to_test_with_is_refused(self) -> None:
        router = _router(snmp_enabled=True)
        svc, _ = _service(router)
        with pytest.raises(SnmpNotConfiguredError):
            await svc.test(router.id, actor_user_id=ACTOR)

    async def test_test_refused_for_instant_on(self) -> None:
        router = _configured_router(vendor="aruba_instant_on")
        svc, _ = _service(router)
        with pytest.raises(SnmpNotSupportedError):
            await svc.test(router.id, actor_user_id=ACTOR)


# ---------------------------------------------------------------------------
# Apply to router
# ---------------------------------------------------------------------------


class TestApply:
    async def test_enabled_pushes_restricted_community_and_stamps_verified(
        self,
    ) -> None:
        router = _configured_router()
        adapter = FakeAdapter()
        svc, rs = _service(router, adapter=adapter)
        outcome = await svc.apply_to_device(router.id, actor_user_id=ACTOR)
        assert outcome.verified and outcome.action == "apply"
        creds, config = adapter.applied[0]
        assert creds.host == "10.20.0.31" and creds.username == "cloudguest-api"
        assert creds.secret == "apisecret"
        assert config.name == "comm12345"
        assert config.addresses == ("172.31.38.118/32",)
        assert router.snmp_device_applied_at is not None
        assert rs.audits[-1]["metadata"]["verified"] is True
        assert "comm12345" not in str(rs.audits)

    async def test_unverified_write_clears_the_applied_stamp(self) -> None:
        router = _configured_router(snmp_device_applied_at=datetime.now(UTC))
        adapter = FakeAdapter(
            result=SnmpApplyResult(
                changed=["community"], state=_STATE, mismatches=["agent:enabled"]
            )
        )
        svc, _ = _service(router, adapter=adapter)
        outcome = await svc.apply_to_device(router.id, actor_user_id=ACTOR)
        assert not outcome.verified
        assert router.snmp_device_applied_at is None

    async def test_disabled_removes(self) -> None:
        router = _router(snmp_enabled=False)
        adapter = FakeAdapter()
        svc, _ = _service(router, adapter=adapter)
        outcome = await svc.apply_to_device(router.id, actor_user_id=ACTOR)
        assert outcome.action == "remove" and adapter.removed == 1

    async def test_empty_source_list_refused(self) -> None:
        router = _configured_router()
        svc, _ = _service(router, snmp_poller_source_addresses=" , ")
        with pytest.raises(SnmpConfigInvalidError):
            await svc.apply_to_device(router.id, actor_user_id=ACTOR)

    async def test_no_api_credentials_refused(self) -> None:
        router = _configured_router(api_credentials_encrypted=None)
        svc, _ = _service(router)
        with pytest.raises(SnmpNotConfiguredError):
            await svc.apply_to_device(router.id, actor_user_id=ACTOR)

    async def test_script_masks_every_secret(self) -> None:
        router = _configured_router()
        svc, _ = _service(router)
        action, lines = await svc.render_script(router.id)
        assert action == "apply"
        text = "\n".join(lines)
        assert "comm12345" not in text
        assert "********" in text


# ---------------------------------------------------------------------------
# RBAC: every SNMP route pinned GLOBAL
# ---------------------------------------------------------------------------


def test_every_snmp_route_is_pinned_global() -> None:
    routes = [r for r in snmp_api_router.routes if "/snmp" in getattr(r, "path", "")]
    assert len(routes) == 6
    for route in routes:
        pins = []
        for dep in route.dependencies:  # type: ignore[attr-defined]
            nonlocals = inspect.getclosurevars(dep.dependency).nonlocals
            pins.append(nonlocals.get("scope"))
        assert pins, route.path
        assert all(p == ScopeType.GLOBAL for p in pins), (route.path, pins)
