"""The router's local ``admin`` password: issue, push, prove, reveal."""

from __future__ import annotations

import inspect
import uuid
from dataclasses import dataclass, field

import pytest
from librouteros.exceptions import ConnectionClosed, FatalError, TrapError
from wyfy_device_gateway.mikrotik_local_users import (
    LocalUser,
    LocalUserNotFoundError,
    LoginProbeResult,
    list_users,
    probe_login,
    set_password,
)

from app.domains.rbac.enums import AuditAction, ScopeType
from app.domains.router.crypto import decrypt_secret, encrypt_secret
from app.domains.router.enums import RouterStatus
from app.domains.router.exceptions import (
    RouterLocalAdminDeviceError,
    RouterLocalAdminNotIssuedError,
    RouterLocalAdminUnavailableError,
)
from app.domains.router.local_admin import (
    LocalAdminDeviceError,
    generate_local_admin_password,
)
from app.domains.router.schemas import (
    CUSTOMER_FORBIDDEN_ROUTER_FIELDS,
    RouterResponse,
)
from tests.unit.test_router import make_router, make_service

ACTOR = uuid.uuid4()


@dataclass
class FakeDevice:
    """A router's account table. Logins succeed only with the current password."""

    admin_password: str | None = ""
    reachable: bool = True
    set_ignored: bool = False
    set_error: str | None = None
    users: list[LocalUser] = field(
        default_factory=lambda: [
            LocalUser("admin", "full", False),
            LocalUser("cloudguest-api", "full", False),
        ]
    )
    set_calls: list[dict[str, str]] = field(default_factory=list)

    async def probe_login(self, *, host, username, password):
        if not self.reachable:
            return LoginProbeResult.UNREACHABLE
        if username == "admin" and password == self.admin_password:
            return LoginProbeResult.ACCEPTED
        return LoginProbeResult.DENIED

    async def list_users(self, *, host, username, password):
        if not self.reachable:
            raise LocalAdminDeviceError("timed out")
        return list(self.users)

    async def set_password(
        self, *, host, username, password, target_username, new_password
    ):
        self.set_calls.append(
            {
                "login_as": username,
                "login_password": password,
                "target": target_username,
            }
        )
        if self.set_error:
            raise LocalAdminDeviceError(self.set_error)
        if not self.set_ignored:
            self.admin_password = new_password


async def _setup(device: FakeDevice | None = None, **router_fields):
    device = device or FakeDevice()
    service, repo, _loc, orgs, audit = make_service()
    service.local_admin_device = device
    router = await make_router(
        repo,
        location_id=uuid.uuid4(),
        organization_id=orgs.add().id,
        status=RouterStatus.ONLINE,
    )
    await repo.update_router(
        router,
        {
            "vendor": "mikrotik",
            "management_ip_address": "10.20.0.41",
            "api_username": "cloudguest-api",
            "api_credentials_encrypted": encrypt_secret("api-secret"),
            **router_fields,
        },
    )
    return service, repo, router, device, audit


def _actions(audit) -> list[str]:
    return [e["action"] for e in audit.entries]


class TestApply:
    async def test_blank_admin_gets_a_password_proven_by_login(self) -> None:
        service, _repo, router, device, _audit = await _setup()

        result = await service.apply_local_admin_password(
            actor_user_id=ACTOR, router_id=router.id
        )

        assert result.status == "active"
        assert result.device_changed is True
        assert result.verified_at is not None
        stored = decrypt_secret(router.local_admin_password_encrypted)
        assert device.admin_password == stored != ""
        assert router.local_admin_password_status == "active"

    async def test_push_authenticates_as_the_platform_not_as_admin(self) -> None:
        service, _repo, router, device, _audit = await _setup()

        await service.apply_local_admin_password(
            actor_user_id=ACTOR, router_id=router.id
        )

        assert device.set_calls == [
            {
                "login_as": "cloudguest-api",
                "login_password": "api-secret",
                "target": "admin",
            }
        ]

    async def test_password_is_committed_before_the_device_is_written(self) -> None:
        service, repo, router, device, _audit = await _setup()
        seen: list[int] = []
        original = device.set_password

        async def spy(**kwargs):
            seen.append(repo.commits)
            assert router.local_admin_password_encrypted is not None
            await original(**kwargs)

        device.set_password = spy
        await service.apply_local_admin_password(
            actor_user_id=ACTOR, router_id=router.id
        )
        assert seen == [1]

    async def test_a_device_that_ignores_the_write_stays_pending(self) -> None:
        service, _repo, router, device, audit = await _setup(
            FakeDevice(set_ignored=True)
        )

        with pytest.raises(RouterLocalAdminDeviceError):
            await service.apply_local_admin_password(
                actor_user_id=ACTOR, router_id=router.id
            )

        assert router.local_admin_password_status == "pending"
        assert router.local_admin_password_verified_at is None
        assert AuditAction.ROUTER_LOCAL_ADMIN_PASSWORD_APPLY_FAILED.value in _actions(
            audit
        )

    async def test_failure_is_committed_so_the_rollback_keeps_the_record(self) -> None:
        service, repo, router, _device, _audit = await _setup(
            FakeDevice(set_error="not enough permissions")
        )

        with pytest.raises(RouterLocalAdminDeviceError, match="not enough"):
            await service.apply_local_admin_password(
                actor_user_id=ACTOR, router_id=router.id
            )
        assert repo.commits == 2

    async def test_unreachable_router_is_never_written_to(self) -> None:
        service, _repo, router, device, _audit = await _setup(
            FakeDevice(reachable=False)
        )

        with pytest.raises(RouterLocalAdminDeviceError, match="reached"):
            await service.apply_local_admin_password(
                actor_user_id=ACTOR, router_id=router.id
            )

        assert device.set_calls == []
        assert router.local_admin_password_status == "pending"

    async def test_retry_reuses_the_same_password(self) -> None:
        service, _repo, router, device, _audit = await _setup(
            FakeDevice(reachable=False)
        )
        with pytest.raises(RouterLocalAdminDeviceError):
            await service.apply_local_admin_password(
                actor_user_id=ACTOR, router_id=router.id
            )
        first = decrypt_secret(router.local_admin_password_encrypted)

        device.reachable = True
        await service.apply_local_admin_password(
            actor_user_id=ACTOR, router_id=router.id
        )

        assert decrypt_secret(router.local_admin_password_encrypted) == first
        assert device.admin_password == first

    async def test_device_already_matching_is_not_written(self) -> None:
        """How a pasted setup script gets verified."""
        service, _repo, router, device, _audit = await _setup()
        issued = await service.issue_local_admin_password(
            actor_user_id=ACTOR, router_id=router.id
        )
        device.admin_password = issued.password

        result = await service.apply_local_admin_password(
            actor_user_id=ACTOR, router_id=router.id
        )

        assert result.device_changed is False
        assert result.status == "active"
        assert device.set_calls == []

    async def test_password_changed_on_the_device_is_put_back(self) -> None:
        service, _repo, router, device, _audit = await _setup()
        await service.apply_local_admin_password(
            actor_user_id=ACTOR, router_id=router.id
        )
        stored = device.admin_password
        device.admin_password = "changed-at-the-venue"

        result = await service.apply_local_admin_password(
            actor_user_id=ACTOR, router_id=router.id
        )

        assert result.device_changed is True
        assert device.admin_password == stored

    async def test_reports_other_full_access_accounts(self) -> None:
        device = FakeDevice()
        device.users += [
            LocalUser("installer", "full", False),
            LocalUser("old", "full", True),
            LocalUser("viewer", "read", False),
        ]
        service, _repo, router, _device, _audit = await _setup(device)

        result = await service.apply_local_admin_password(
            actor_user_id=ACTOR, router_id=router.id
        )

        assert result.other_full_access_users == ["installer"]


class TestRefusals:
    @pytest.mark.parametrize(
        "fields",
        [
            {"vendor": "aruba"},
            {"vendor": "omada"},
            {"api_credentials_encrypted": None},
            {"api_username": None},
            {"management_ip_address": None, "public_ip_address": None},
            {"api_username": "admin"},
        ],
    )
    async def test_cannot_apply(self, fields) -> None:
        service, _repo, router, device, _audit = await _setup(**fields)

        with pytest.raises(RouterLocalAdminUnavailableError):
            await service.apply_local_admin_password(
                actor_user_id=ACTOR, router_id=router.id
            )

        assert device.set_calls == []
        assert router.local_admin_password_encrypted is None

    async def test_issue_refuses_other_vendors(self) -> None:
        service, _repo, router, _device, _audit = await _setup(vendor="aruba")

        with pytest.raises(RouterLocalAdminUnavailableError):
            await service.issue_local_admin_password(
                actor_user_id=ACTOR, router_id=router.id
            )


class TestCheck:
    async def test_blank_admin_is_reported_and_nothing_changes(self) -> None:
        service, _repo, router, device, audit = await _setup()

        result = await service.check_local_admin_password(
            actor_user_id=ACTOR, router_id=router.id
        )

        assert result.admin_login == "blank"
        assert result.admin_exists is True
        assert result.stored_password_works is None
        assert device.set_calls == []
        assert device.admin_password == ""
        assert router.local_admin_password_encrypted is None
        assert AuditAction.ROUTER_LOCAL_ADMIN_PASSWORD_CHECKED.value in _actions(audit)

    async def test_password_set_by_someone_else(self) -> None:
        service, _repo, router, _device, _audit = await _setup(
            FakeDevice(admin_password="installer-chose-this")
        )

        result = await service.check_local_admin_password(
            actor_user_id=ACTOR, router_id=router.id
        )

        assert result.admin_login == "password_set"

    async def test_unreachable_is_an_error_not_a_verdict(self) -> None:
        service, _repo, router, _device, _audit = await _setup(
            FakeDevice(reachable=False)
        )

        with pytest.raises(RouterLocalAdminDeviceError):
            await service.check_local_admin_password(
                actor_user_id=ACTOR, router_id=router.id
            )


class TestRevealAndIssue:
    async def test_issue_is_stable_and_starts_pending(self) -> None:
        service, _repo, router, _device, _audit = await _setup()

        first = await service.issue_local_admin_password(
            actor_user_id=ACTOR, router_id=router.id
        )
        second = await service.issue_local_admin_password(
            actor_user_id=ACTOR, router_id=router.id
        )

        assert first.password == second.password
        assert first.status == "pending"
        assert router.local_admin_password_encrypted != first.password

    async def test_reveal_is_audited_without_the_password(self) -> None:
        service, _repo, router, _device, audit = await _setup()
        issued = await service.issue_local_admin_password(
            actor_user_id=ACTOR, router_id=router.id
        )

        revealed = await service.reveal_local_admin_password(
            actor_user_id=ACTOR, router_id=router.id
        )

        assert revealed.password == issued.password
        entry = audit.entries[-1]
        assert entry["action"] == AuditAction.ROUTER_LOCAL_ADMIN_PASSWORD_REVEALED.value
        assert entry["actor_user_id"] == ACTOR
        assert issued.password not in str(audit.entries)

    async def test_reveal_before_issue_says_so(self) -> None:
        service, _repo, router, _device, _audit = await _setup()

        with pytest.raises(RouterLocalAdminNotIssuedError):
            await service.reveal_local_admin_password(
                actor_user_id=ACTOR, router_id=router.id
            )

    async def test_passwords_differ_and_need_no_escaping(self) -> None:
        passwords = {generate_local_admin_password() for _ in range(50)}
        assert len(passwords) == 50
        assert all(len(p) == 20 and p.isalnum() for p in passwords)


class TestExposure:
    def test_customer_response_cannot_carry_these_fields(self) -> None:
        assert {
            "local_admin_password",
            "local_admin_password_encrypted",
            "local_admin_password_status",
            "local_admin_password_verified_at",
        } <= CUSTOMER_FORBIDDEN_ROUTER_FIELDS
        assert not set(RouterResponse.model_fields) & CUSTOMER_FORBIDDEN_ROUTER_FIELDS

    def test_every_route_requires_a_global_grant(self) -> None:
        from app.domains.router.router import router as api_router

        routes = [r for r in api_router.routes if "local-admin-password" in r.path]
        assert {r.path.rsplit("/", 1)[-1] for r in routes} == {
            "check",
            "issue",
            "apply",
            "reveal",
        }
        for route in routes:
            assert route.path.startswith("/platform/")
            closures = [
                inspect.getclosurevars(d.dependency).nonlocals
                for d in route.dependencies
            ]
            assert any(
                c.get("permission_key") == "routers.manage"
                and c.get("scope") is ScopeType.GLOBAL
                for c in closures
            ), route.path


class _FakeApi:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []
        self.closed = False

    def __call__(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        return iter(self.rows if cmd == "/user/print" else [])

    def close(self):
        self.closed = True


class TestGateway:
    def test_set_password_targets_the_row_id(self) -> None:
        api = _FakeApi([{".id": "*1", "name": "admin"}, {".id": "*2", "name": "x"}])
        set_password(api, username="admin", new_password="pw")
        assert api.calls[-1] == ("/user/set", {".id": "*1", "password": "pw"})

    def test_set_password_on_a_missing_account_writes_nothing(self) -> None:
        api = _FakeApi([{".id": "*2", "name": "x"}])
        with pytest.raises(LocalUserNotFoundError):
            set_password(api, username="admin", new_password="pw")
        assert [c[0] for c in api.calls] == ["/user/print"]

    def test_list_users_reads_disabled_either_way(self) -> None:
        api = _FakeApi(
            [
                {"name": "a", "group": "full", "disabled": True},
                {"name": "b", "group": "full", "disabled": "false"},
            ]
        )
        assert [u.disabled for u in list_users(api)] == [True, False]

    def test_probe_accepted_closes_the_connection(self) -> None:
        api = _FakeApi([])
        assert probe_login(lambda: api) is LoginProbeResult.ACCEPTED
        assert api.closed is True

    def test_probe_a_login_that_cannot_run_a_command_is_not_accepted(self) -> None:
        """RouterOS before 6.43: the login call succeeds for ANY password."""

        class PreLoginApi(_FakeApi):
            def __call__(self, cmd, **kwargs):
                raise FatalError("not logged in")

        api = PreLoginApi([])
        assert probe_login(lambda: api) is LoginProbeResult.UNREACHABLE
        assert api.closed is True

    @pytest.mark.parametrize(
        ("error", "expected"),
        [
            (
                TrapError("invalid user name or password (6)"),
                LoginProbeResult.DENIED,
            ),
            (TrapError("cannot log in"), LoginProbeResult.DENIED),
            (TimeoutError("timed out"), LoginProbeResult.UNREACHABLE),
            (ConnectionRefusedError(), LoginProbeResult.UNREACHABLE),
            (ConnectionClosed("socket closed"), LoginProbeResult.UNREACHABLE),
            (TrapError("something else"), LoginProbeResult.UNREACHABLE),
        ],
    )
    def test_probe_only_a_real_refusal_counts_as_denied(self, error, expected) -> None:
        def connect():
            raise error

        assert probe_login(connect) is expected
