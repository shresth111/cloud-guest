"""Auth hardening from the 2026-11-06 security review: L1 (session revoke is
owner-only), L2 (a password reset ends outstanding access tokens) and L4
(uniform login answers, MFA failures count toward lockout)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from app.core.config import get_settings
from app.domains.auth.security import AccountLockedError, RateLimitError
from app.domains.auth.service import (
    InvalidCredentialsError,
    InvalidMfaCodeError,
    SessionNotFoundError,
)

from .test_auth import (
    STRONG_PASSWORD,
    TestAuthServicePasswordResetRoundTrip,
    make_device_info,
    make_service,
    make_service_with_notification_sender,
)


async def _verified_user(service, email: str, username: str):
    user, token = await service.register(
        first_name="Test",
        last_name="User",
        email=email,
        username=username,
        password=STRONG_PASSWORD,
    )
    await service.verify_email(token)
    return user


class TestRevokeSessionIsOwnerOnly:
    async def test_cannot_revoke_someone_elses_session(self) -> None:
        service, repository, _redis = make_service()
        await _verified_user(service, "alice@example.com", "alice")
        await _verified_user(service, "bob@example.com", "bob")
        _alice, _tokens, alice_session = await service.login(
            "alice@example.com", STRONG_PASSWORD, make_device_info()
        )
        bob = await repository.get_user_by_email("bob@example.com")

        with pytest.raises(SessionNotFoundError):
            await service.revoke_session(alice_session, owner_user_id=bob.id)
        alice_row = await repository.get_session_by_id(alice_session)
        assert alice_row.is_active is True

    async def test_owner_can_revoke_their_own(self) -> None:
        service, repository, _redis = make_service()
        await _verified_user(service, "carol@example.com", "carol")
        carol, _tokens, session_id = await service.login(
            "carol@example.com", STRONG_PASSWORD, make_device_info()
        )
        await service.revoke_session(session_id, owner_user_id=carol.id)
        assert (await repository.get_session_by_id(session_id)).is_active is False

    async def test_unknown_session_is_404(self) -> None:
        service, _repository, _redis = make_service()
        with pytest.raises(SessionNotFoundError) as caught:
            await service.revoke_session(uuid.uuid4(), owner_user_id=uuid.uuid4())
        assert caught.value.status_code == 404


class TestResetEndsAccessTokens:
    async def test_reset_sets_tokens_invalidated_at_to_the_second(self) -> None:
        service, repository, _redis, sender = make_service_with_notification_sender()
        await _verified_user(service, "dave@example.com", "dave")
        sender.enqueued.clear()
        before = datetime.now(UTC).replace(microsecond=0)

        await service.initiate_password_reset("dave@example.com")
        token = TestAuthServicePasswordResetRoundTrip._extract_token(
            sender.enqueued[0]["body"]
        )
        await service.reset_password(token, "AnotherSecurePass456!@#")

        user = await repository.get_user_by_email("dave@example.com")
        assert user.tokens_invalidated_at is not None
        assert user.tokens_invalidated_at >= before
        # Floored to whole seconds so a token minted right after (same
        # second, the user logging straight back in) is not rejected.
        assert user.tokens_invalidated_at.microsecond == 0


class TestUniformLoginAnswers:
    async def test_inactive_account_with_wrong_password_looks_like_wrong_password(
        self,
    ) -> None:
        service, repository, _redis = make_service()
        user = await _verified_user(service, "erin@example.com", "erin")
        user.is_active = False

        with pytest.raises(InvalidCredentialsError) as wrong:
            await service.login(
                "erin@example.com", "NotTheRightPass123!@#", make_device_info()
            )
        with pytest.raises(InvalidCredentialsError) as unknown:
            await service.login(
                "nobody@example.com", "NotTheRightPass123!@#", make_device_info()
            )
        assert str(wrong.value) == str(unknown.value)

    async def test_inactive_account_with_right_password_is_told(self) -> None:
        service, _repository, _redis = make_service()
        user = await _verified_user(service, "fay@example.com", "fay")
        user.is_active = False
        with pytest.raises(InvalidCredentialsError, match="inactive"):
            await service.login("fay@example.com", STRONG_PASSWORD, make_device_info())

    async def test_unknown_email_still_runs_a_password_verify(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        service, _repository, _redis = make_service()
        calls: list[str] = []
        original = service._verify_password_safe

        def counting(password, password_hash, **kwargs):  # noqa: ANN001
            calls.append(password_hash)
            return original(password, password_hash, **kwargs)

        monkeypatch.setattr(service, "_verify_password_safe", counting)
        with pytest.raises(InvalidCredentialsError):
            await service.login(
                "ghost@example.com", STRONG_PASSWORD, make_device_info()
            )
        assert len(calls) == 1 and calls[0].startswith("$argon2")


class TestMfaFailuresCountTowardLockout:
    async def test_wrong_codes_lock_the_account(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        service, _repository, _redis = make_service()
        user = await _verified_user(service, "hal@example.com", "hal")
        user.mfa_enabled = True

        async def never(_user_id, _code):  # noqa: ANN001
            return False

        monkeypatch.setattr(service, "_verify_mfa_or_recovery_code", never)
        attempts = get_settings().max_login_attempts
        for _ in range(attempts):
            with pytest.raises(InvalidMfaCodeError):
                await service.login(
                    "hal@example.com",
                    STRONG_PASSWORD,
                    make_device_info(),
                    mfa_code="000000",
                )
        assert user.failed_login_attempts == attempts
        assert user.locked_until is not None
        # Locked in the database; the per-IP limiter may answer first.
        with pytest.raises((AccountLockedError, RateLimitError)):
            await service.login(
                "hal@example.com", STRONG_PASSWORD, make_device_info(), mfa_code="1"
            )


# ============================================================================
# L8: an API key acts on its own organization only, however it is named
# ============================================================================


def _api_request(
    *,
    headers: dict[str, str] | None = None,
    path_params: dict[str, object] | None = None,
    query_string: str = "",
):
    from starlette.requests import Request

    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": raw,
            "path_params": path_params or {},
            "query_string": query_string.encode(),
        }
    )


class TestApiKeyOrganizationBinding:
    async def _setup(self):
        from .test_auth import FakeApiKeyService, FakeAuthRepository, _ResolvedApiKey

        repository = FakeAuthRepository()
        user = await repository.create_user(
            first_name="Api",
            last_name="Caller",
            email="key@example.com",
            username="keyuser",
            password_hash="hashed",
            is_active=True,
            is_verified=True,
        )
        key_org = uuid.uuid4()
        service = FakeApiKeyService(
            resolved=_ResolvedApiKey(organization_id=key_org, user_id=user.id)
        )
        return repository, service, key_org

    async def _call(self, request, repository, service):
        from app.domains.auth.dependencies import get_current_user

        return await get_current_user(
            request=request,
            credentials=None,
            repository=repository,
            api_key_service=service,
            db=None,
        )

    async def test_path_named_other_org_is_refused(self) -> None:
        from fastapi import HTTPException

        repository, service, key_org = await self._setup()
        other = uuid.uuid4()
        for request in (
            _api_request(
                headers={"X-API-Key": "k"},
                path_params={"organization_id": str(other)},
            ),
            _api_request(
                headers={"X-API-Key": "k", "X-Organization-Id": str(key_org)},
                query_string=f"organization_id={other}",
            ),
        ):
            with pytest.raises(HTTPException) as caught:
                await self._call(request, repository, service)
            assert caught.value.status_code == 403

    async def test_own_org_by_path_or_header_is_allowed(self) -> None:
        repository, service, key_org = await self._setup()
        for request in (
            _api_request(
                headers={"X-API-Key": "k"},
                path_params={"organization_id": str(key_org)},
            ),
            _api_request(headers={"X-API-Key": "k", "X-Organization-Id": str(key_org)}),
            _api_request(headers={"X-API-Key": "k"}),
        ):
            await self._call(request, repository, service)

    async def test_malformed_header_is_400_not_500(self) -> None:
        from fastapi import HTTPException

        repository, service, _key_org = await self._setup()
        request = _api_request(
            headers={"X-API-Key": "k", "X-Organization-Id": "not-a-uuid"}
        )
        with pytest.raises(HTTPException) as caught:
            await self._call(request, repository, service)
        assert caught.value.status_code == 400
