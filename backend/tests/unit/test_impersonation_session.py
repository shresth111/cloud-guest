"""What an impersonation SESSION is, once ``POST /users/{id}/impersonate``
has minted it -- the half ``test_user.py::TestImpersonation`` does not cover.

Measured on prod 2026-10-02: an operator's "View as this customer" session
rendered "No locations yet" because the frontend had to invent the session's
grants (one placeholder org-scoped role, the organization picked in the Master
drawer). The impersonate response now carries the target's REAL role
assignments and memberships, built by the same helpers ``POST /auth/login``
uses. These tests pin three properties:

1. The response's grants are the TARGET's, computed for the target's id --
   never the operator's (no staff grant can leak into the session).
2. A request on an impersonation token is authenticated as the target, and the
   operator is carried alongside in the request context.
3. Every audit row written during such a request names the operator in
   ``metadata.impersonated_by``; rows written by a normal session do not.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi.security import HTTPAuthorizationCredentials
from starlette.requests import Request

from app.domains.auth.dependencies import get_current_user
from app.domains.auth.jwt import JWTManager
from app.domains.auth.schemas import (
    OrganizationMembershipSummary,
    RoleAssignmentSummary,
)
from app.domains.rbac.models import AuditLogEntry, _stamp_impersonating_operator
from app.domains.user import router as user_router_module
from app.domains.user.schemas import ImpersonateUserRequest
from app.domains.user.service import ImpersonationResult
from app.middleware.request_context import (
    MaskingContext,
    current_impersonator,
    get_masking_context,
    masking_context,
)

from .test_user import _create_kwargs, make_service


def _request() -> Request:
    return Request({"type": "http", "method": "GET", "path": "/", "headers": []})


@pytest.fixture
def request_context():
    """A fresh per-request context, exactly as RequestContextMiddleware sets
    one before any dependency runs."""
    token = masking_context.set(MaskingContext())
    try:
        yield
    finally:
        masking_context.reset(token)


# ---------------------------------------------------------------------------
# 1. The response carries the target's grants, and only the target's
# ---------------------------------------------------------------------------


class TestImpersonateResponseCarriesTargetGrants:
    async def test_roles_and_organizations_are_computed_for_the_target(
        self, monkeypatch
    ) -> None:
        operator_id = uuid.uuid4()
        target_id = uuid.uuid4()
        org_id = uuid.uuid4()
        location_id = uuid.uuid4()
        asked_roles_for: list[uuid.UUID] = []
        asked_orgs_for: list[uuid.UUID] = []

        async def fake_roles(_resolver, user_id):
            asked_roles_for.append(user_id)
            return [
                RoleAssignmentSummary(
                    role_id=str(uuid.uuid4()),
                    role_name="Location Manager",
                    role_slug="location-manager",
                    scope_type="location",
                    organization_id=str(org_id),
                    location_id=str(location_id),
                    router_id=None,
                )
            ]

        async def fake_orgs(_org_service, _license_service, user_id):
            asked_orgs_for.append(user_id)
            return [
                OrganizationMembershipSummary(
                    organization_id=str(org_id),
                    organization_name="WyFy Guest",
                    organization_slug="wyfy-guest",
                    is_primary_contact=False,
                    enabled_features=["guest_wifi"],
                )
            ]

        monkeypatch.setattr(user_router_module, "_role_assignment_summaries", fake_roles)
        monkeypatch.setattr(
            user_router_module, "_organization_membership_summaries", fake_orgs
        )

        target = SimpleNamespace(
            id=target_id, full_name="Mohit Murari", email="owner@x.test", username="m"
        )

        class FakeUserService:
            async def impersonate_user(self, *, actor_user_id, actor_email, user_id, reason):
                assert actor_user_id == operator_id
                assert user_id == target_id
                return ImpersonationResult(
                    access_token="tok",
                    expires_at=datetime.now(UTC) + timedelta(minutes=30),
                    target_user=target,
                )

        operator = SimpleNamespace(id=str(operator_id), email="staff@x.test")
        response = await user_router_module.impersonate_user(
            request=_request(),
            user_id=target_id,
            payload=ImpersonateUserRequest(reason="ticket"),
            user=operator,
            user_service=FakeUserService(),
            role_resolver=object(),
            organization_service=object(),
            license_service=object(),
        )

        # Computed for the TARGET -- never for the operator who asked.
        assert asked_roles_for == [target_id]
        assert asked_orgs_for == [target_id]
        assert operator_id not in asked_roles_for + asked_orgs_for

        body = response.body.decode() if hasattr(response, "body") else str(response)
        assert "location-manager" in body
        assert str(location_id) in body
        assert "WyFy Guest" in body

    def test_response_defaults_to_no_grants_rather_than_inventing_any(self) -> None:
        result = ImpersonationResult(
            access_token="tok",
            expires_at=datetime.now(UTC),
            target_user=SimpleNamespace(
                id=uuid.uuid4(), full_name="A B", email="a@b.test", username="ab"
            ),
        )
        dumped = user_router_module._impersonation_response(result).model_dump()
        assert dumped["roles"] == []
        assert dumped["organizations"] == []


# ---------------------------------------------------------------------------
# 2. A request on an impersonation token is the target, with the operator
#    carried alongside
# ---------------------------------------------------------------------------


class TestImpersonationTokenIdentity:
    async def test_token_authenticates_as_target_and_records_operator(
        self, request_context
    ) -> None:
        service, identity, *_rest = make_service()
        target = await service.create_user(**_create_kwargs())
        operator_id = uuid.uuid4()
        result = await service.impersonate_user(
            actor_user_id=operator_id,
            actor_email="staff@x.test",
            user_id=target.id,
            reason=None,
        )

        user = await get_current_user(
            request=_request(),
            credentials=HTTPAuthorizationCredentials(
                scheme="Bearer", credentials=result.access_token
            ),
            repository=identity,
            api_key_service=None,
        )

        assert user.id == str(target.id)
        assert user.id != str(operator_id)
        impersonator = current_impersonator()
        assert impersonator is not None
        assert impersonator["actor_user_id"] == str(operator_id)
        assert impersonator["actor_email"] == "staff@x.test"
        # The masking context's user is the target too -- PII-access audit rows
        # are attributed to the identity the request was authorized as.
        assert get_masking_context().user_id == str(target.id)

    async def test_normal_login_token_has_no_impersonator(self, request_context) -> None:
        service, identity, *_rest = make_service()
        user = await service.create_user(**_create_kwargs())
        token, _jti = JWTManager.create_access_token(str(user.id), user.email)

        await get_current_user(
            request=_request(),
            credentials=HTTPAuthorizationCredentials(scheme="Bearer", credentials=token),
            repository=identity,
            api_key_service=None,
        )

        assert current_impersonator() is None

    def test_outside_a_request_there_is_no_impersonator(self) -> None:
        assert current_impersonator() is None


# ---------------------------------------------------------------------------
# 3. Audit rows written during an impersonated request name the operator
# ---------------------------------------------------------------------------


def _entry(metadata: dict | None = None) -> AuditLogEntry:
    return AuditLogEntry(
        actor_user_id=uuid.uuid4(),
        action="location_updated",
        entity_type="location",
        entity_id=uuid.uuid4(),
        description="changed",
        event_metadata=metadata if metadata is not None else {},
    )


class TestAuditRowsNameTheOperator:
    def test_row_written_while_impersonating_is_stamped(self, request_context) -> None:
        get_masking_context().impersonated_by = {
            "actor_user_id": "op-1",
            "actor_email": "staff@x.test",
            "started_at": "2026-10-02T00:00:00+00:00",
        }
        entry = _entry({"field": "name"})
        customer_actor = entry.actor_user_id

        _stamp_impersonating_operator(None, None, entry)

        assert entry.event_metadata["impersonated_by"]["actor_user_id"] == "op-1"
        assert entry.event_metadata["impersonated_by"]["actor_email"] == "staff@x.test"
        # Existing metadata is preserved, and the authorized actor is not
        # rewritten -- the row names both identities, it does not swap them.
        assert entry.event_metadata["field"] == "name"
        assert entry.actor_user_id == customer_actor

    def test_row_written_by_a_normal_session_is_untouched(self, request_context) -> None:
        entry = _entry({"field": "name"})
        _stamp_impersonating_operator(None, None, entry)
        assert entry.event_metadata == {"field": "name"}

    def test_listener_is_registered_on_insert(self) -> None:
        from sqlalchemy import event

        assert event.contains(AuditLogEntry, "before_insert", _stamp_impersonating_operator)
