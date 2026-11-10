"""master_operator_mfa_mode: the second-factor gate on GLOBAL-scope permission checks.

Pins: only a GLOBAL check that already passed is gated (customers and
tenant-scoped calls never are), 'log' never blocks, 'enforce' 403s with
mfa_setup_required, an MFA-enabled operator is never blocked, and a failed
permission check still reports the permission error, not the MFA one.
"""

from __future__ import annotations

import logging
import uuid
from types import SimpleNamespace

import pytest

from app.domains.auth.models import AuthUser
from app.domains.rbac import dependencies as deps
from app.domains.rbac.context import ScopeContext
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.exceptions import MfaSetupRequiredError, RoleNotHeldError

_EVENT = "master_operator_without_mfa"


class _Validator:
    def __init__(self, *, deny: bool = False) -> None:
        self.deny = deny
        self.calls: list[ScopeType] = []

    async def check(self, user_id, permission_key, *, scope_type, scope_context):
        self.calls.append(scope_type)
        if self.deny:
            raise RoleNotHeldError(permission_key)


def _user(*, mfa: bool) -> AuthUser:
    return AuthUser(id=str(uuid.uuid4()), email="op@example.com", mfa_enabled=mfa)


@pytest.fixture
def mode(monkeypatch):
    def _set(value: str) -> None:
        settings = SimpleNamespace(master_operator_mfa_mode=value)
        monkeypatch.setattr(deps, "get_settings", lambda: settings)

    deps._mfa_last_logged.clear()
    return _set


def _context(**kw) -> ScopeContext:
    return ScopeContext(**kw)


async def _run(monkeypatch, *, user, scope=None, context=None, validator=None):
    ctx = context or _context()

    async def _fake_context(request, db):
        return ctx

    monkeypatch.setattr(deps, "_current_scope_context", _fake_context)
    dependency = deps.RequirePermission("platform.manage", scope=scope)
    return await dependency(
        request=None, user=user, access_validator=validator or _Validator(), db=None
    )


async def test_enforce_blocks_global_operator_without_mfa(monkeypatch, mode):
    mode("enforce")
    with pytest.raises(MfaSetupRequiredError) as exc:
        await _run(monkeypatch, user=_user(mfa=False), scope=ScopeType.GLOBAL)
    assert exc.value.status_code == 403
    assert exc.value.data == {"code": "mfa_setup_required"}


async def test_enforce_allows_operator_with_mfa(monkeypatch, mode):
    mode("enforce")
    user = _user(mfa=True)
    assert await _run(monkeypatch, user=user, scope=ScopeType.GLOBAL) is user


async def test_inferred_global_scope_is_gated_too(monkeypatch, mode):
    mode("enforce")
    with pytest.raises(MfaSetupRequiredError):
        await _run(monkeypatch, user=_user(mfa=False))


async def test_tenant_scoped_calls_are_never_gated(monkeypatch, mode):
    mode("enforce")
    user = _user(mfa=False)
    ctx = _context(organization_id=uuid.uuid4())
    assert await _run(monkeypatch, user=user, context=ctx) is user
    assert (
        await _run(monkeypatch, user=user, scope=ScopeType.ORGANIZATION, context=ctx)
        is user
    )


async def test_failed_permission_check_reports_permission_not_mfa(monkeypatch, mode):
    mode("enforce")
    with pytest.raises(RoleNotHeldError):
        await _run(
            monkeypatch,
            user=_user(mfa=False),
            scope=ScopeType.GLOBAL,
            validator=_Validator(deny=True),
        )


async def test_log_mode_allows_and_logs_once_per_interval(monkeypatch, mode, caplog):
    mode("log")
    user = _user(mfa=False)
    with caplog.at_level(logging.WARNING, logger=deps.logger.name):
        assert await _run(monkeypatch, user=user, scope=ScopeType.GLOBAL) is user
        assert await _run(monkeypatch, user=user, scope=ScopeType.GLOBAL) is user
    hits = [r for r in caplog.records if r.getMessage() == _EVENT]
    assert len(hits) == 1
    assert hits[0].user_id == user.id


async def test_off_mode_neither_blocks_nor_logs(monkeypatch, mode, caplog):
    mode("off")
    user = _user(mfa=False)
    with caplog.at_level(logging.WARNING, logger=deps.logger.name):
        assert await _run(monkeypatch, user=user, scope=ScopeType.GLOBAL) is user
    assert not [r for r in caplog.records if r.getMessage() == _EVENT]


def test_shipped_default_is_log():
    from app.core.config import Settings

    assert Settings.model_fields["master_operator_mfa_mode"].default == "log"
