"""Regression tests for NAS deregistration: a bridge call that did not
remove the NAS from the live RADIUS server must never be reported to the
caller as a completed delete.

The bug these close, observed live on 2026-08-22: deleting a NAS client
through the master console soft-deleted the row, then called
``DELETE http://<hub>:9092/radius/client``. The hub agent
(``ops/hub-agents/radius_agent.py``) implemented only ``do_POST``, so
Python's ``http.server`` answered every one of those with
``501 Unsupported method ('DELETE')``. ``_deregister_nas_from_radius_bridge``
caught the ``HTTPError``, logged a WARNING, and returned normally; the
endpoint returned ``200 {"success": true, "message": "RADIUS NAS client
deleted"}``. Result on the live hub: 21 ``client{}`` stanzas in
``clients.conf`` against 0 active NAS rows in the database -- including the
five an operator had "deleted" through the console minutes earlier, each
still holding a shared secret the RADIUS server would still accept.
Deleting a NAS is a credential revocation; there were no tests on this path
at all, which is how it shipped.

Everything here drives the real route through the real ASGI stack (the
pattern ``test_radius_wire_format_poc.py`` established). Only two things
are substituted: the DB-backed service (the same in-memory fake
``test_guest.py`` uses -- there is no live Postgres here) and the outbound
HTTP transport to the hub agent. The bridge stub returns REAL
``httpx.Response`` objects so ``raise_for_status()``/``json()`` raise the
real exceptions the production code catches by name.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient, Response

from app.common.exceptions import register_exception_handlers
from app.domains.auth.models import AuthUser
from app.domains.guest.dependencies import get_radius_service
from app.domains.guest.exceptions import RadiusNasBridgeDeregistrationError
from app.domains.guest.router import (
    _deregister_nas_from_radius_bridge,
    deregister_radius_nas_client,
    nas_router,
)
from app.domains.guest.service import RadiusService
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    get_access_validator,
    get_current_user,
)

from .test_guest import make_fixture

_NAS_IDENTIFIER = "nas-1"
_NAS_SECRET = "supersecret123"
_ACTOR = AuthUser(id=str(uuid.uuid4()), email="ops@wyfy.example")


# ---------------------------------------------------------------------------
# Bridge stub
# ---------------------------------------------------------------------------


class _BridgeStub:
    """Stands in for the hub's radius agent on the wire.

    Records every call so a test can assert the bridge was (or was not)
    contacted, and can be told to answer with any status/body -- including
    the literal ``501 Unsupported method ('DELETE')`` the real agent
    returned in production.
    """

    def __init__(self, responder: Any) -> None:
        self._responder = responder
        self.calls: list[dict[str, Any]] = []

    def __call__(self, *args: Any, **kwargs: Any) -> _BridgeStub:
        return self

    async def __aenter__(self) -> _BridgeStub:
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False

    async def request(self, method: str, url: str, **kwargs: Any) -> Response:
        self.calls.append({"method": method, "url": url, **kwargs})
        return self._respond(method, url)

    async def post(self, url: str, **kwargs: Any) -> Response:
        self.calls.append({"method": "POST", "url": url, **kwargs})
        return self._respond("POST", url)

    def _respond(self, method: str, url: str) -> Response:
        result = self._responder(method, url)
        if isinstance(result, Exception):
            raise result
        return result


def _response(status_code: int, *, json_body: Any = None, text: str | None = None):
    def _responder(method: str, url: str) -> Response:
        request = httpx.Request(method, url)
        if text is not None:
            return Response(status_code, text=text, request=request)
        return Response(status_code, json=json_body, request=request)

    return _responder


@contextmanager
def bridge(responder: Any):
    stub = _BridgeStub(responder)
    with patch.object(httpx, "AsyncClient", stub):
        yield stub


#  The exact wire response the real agent gave for months: Python's
#  http.server answers an unimplemented verb with a 501 and an HTML error
#  page, not JSON.
_AGENT_501 = _response(
    501,
    text="<html><body><h1>Error response</h1>"
    "<p>Error code: 501</p>"
    "<p>Message: Unsupported method ('DELETE').</p></body></html>",
)
_AGENT_OK_ONE_REMOVED = _response(200, json_body={"status": "ok", "removed": 1})
_AGENT_OK_NONE_REMOVED = _response(200, json_body={"status": "ok", "removed": 0})


# ---------------------------------------------------------------------------
# App harness
# ---------------------------------------------------------------------------


class _PermitAll:
    async def check(self, *args: Any, **kwargs: Any) -> None:
        return None


def _build_app(radius_service: RadiusService) -> FastAPI:
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(nas_router, prefix="/api/v1")
    app.dependency_overrides[get_radius_service] = lambda: radius_service
    app.dependency_overrides[get_current_user] = lambda: _ACTOR
    app.dependency_overrides[get_access_validator] = lambda: _PermitAll()
    app.dependency_overrides[CurrentOrganization] = lambda: None
    return app


async def _register_nas(fx: Any) -> Any:
    result = await fx.radius_service.register_nas(
        actor_user_id=uuid.uuid4(),
        router_id=fx.router.id,
        nas_identifier=_NAS_IDENTIFIER,
        shared_secret=_NAS_SECRET,
    )
    #  ``RadiusNasClient.vendor`` carries a SQLAlchemy column default that
    #  is applied at INSERT time. The in-memory repository these tests
    #  share with ``test_guest.py`` never flushes, so the attribute stays
    #  ``None`` and ``RadiusNasResponse`` (``vendor: str``) rejects it.
    #  A fake-fidelity gap, not a production one -- filled in here rather
    #  than changing the shared fake out from under every other suite.
    result.nas_client.vendor = "MikroTik"
    return result


async def _delete_via_http(app: FastAPI, nas_id: uuid.UUID) -> Response:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.delete(f"/api/v1/radius/nas/{nas_id}")


# ---------------------------------------------------------------------------
# The bridge helper itself
# ---------------------------------------------------------------------------


class TestDeregisterBridgeCall:
    async def test_agent_501_raises_instead_of_being_swallowed(self) -> None:
        """THE regression test. The real agent's 501 must not return
        normally -- returning normally is what made the delete look
        complete."""
        with (
            bridge(_AGENT_501) as stub,
            pytest.raises(RadiusNasBridgeDeregistrationError) as excinfo,
        ):
            await _deregister_nas_from_radius_bridge(_NAS_IDENTIFIER)
        assert stub.calls and stub.calls[0]["method"] == "DELETE"
        assert "502" not in str(excinfo.value)
        assert excinfo.value.status_code == 502
        assert "501" in str(excinfo.value)

    async def test_unreachable_agent_raises(self) -> None:
        def _boom(method: str, url: str) -> Exception:
            return httpx.ConnectError("connection refused")

        with bridge(_boom), pytest.raises(RadiusNasBridgeDeregistrationError):
            await _deregister_nas_from_radius_bridge(_NAS_IDENTIFIER)

    async def test_non_json_200_raises(self) -> None:
        """A 200 from something that is not the agent is not a confirmed
        removal."""
        with (
            bridge(_response(200, text="OK")),
            pytest.raises(RadiusNasBridgeDeregistrationError),
        ):
            await _deregister_nas_from_radius_bridge(_NAS_IDENTIFIER)

    async def test_200_without_a_removed_count_raises(self) -> None:
        """An older agent build answering 200 with no ``removed`` key has
        not told us it removed anything. Optimistically reading that as
        success is the exact assumption that produced this bug."""
        with (
            bridge(_response(200, json_body={"status": "ok"})),
            pytest.raises(RadiusNasBridgeDeregistrationError),
        ):
            await _deregister_nas_from_radius_bridge(_NAS_IDENTIFIER)

    async def test_confirmed_removal_returns_the_stanza_count(self) -> None:
        with bridge(_response(200, json_body={"status": "ok", "removed": 3})):
            assert await _deregister_nas_from_radius_bridge(_NAS_IDENTIFIER) == 3

    async def test_zero_removed_is_a_success_not_an_error(self) -> None:
        """"Not on the RADIUS server" is an honest, already-consistent
        state and must stay retry-able, not be turned into a failure."""
        with bridge(_AGENT_OK_NONE_REMOVED):
            assert await _deregister_nas_from_radius_bridge(_NAS_IDENTIFIER) == 0

    async def test_sends_the_nas_identifier_the_hub_keys_on(self) -> None:
        with bridge(_AGENT_OK_ONE_REMOVED) as stub:
            await _deregister_nas_from_radius_bridge(_NAS_IDENTIFIER)
        assert stub.calls[0]["json"] == {"nas_identifier": _NAS_IDENTIFIER}


# ---------------------------------------------------------------------------
# The composed delete
# ---------------------------------------------------------------------------


class TestDeregisterRadiusNasClient:
    async def test_bridge_failure_leaves_the_row_undeleted(self) -> None:
        """The database and the hub must not be allowed to disagree. If the
        credential is still live on the hub, the NAS is still a NAS here."""
        fx = make_fixture()
        result = await _register_nas(fx)
        nas_id = result.nas_client.id

        with bridge(_AGENT_501), pytest.raises(RadiusNasBridgeDeregistrationError):
            await deregister_radius_nas_client(
                fx.radius_service,
                nas_id=nas_id,
                requesting_organization_id=None,
                actor_user_id=uuid.uuid4(),
            )

        still_there = await fx.radius_service.get_nas_client(nas_id)
        assert still_there.is_deleted is False
        assert still_there.is_active is True

    async def test_success_deletes_and_reports_the_stanza_count(self) -> None:
        fx = make_fixture()
        result = await _register_nas(fx)
        nas_id = result.nas_client.id

        with bridge(_response(200, json_body={"status": "ok", "removed": 2})):
            nas_client, removed = await deregister_radius_nas_client(
                fx.radius_service,
                nas_id=nas_id,
                requesting_organization_id=None,
                actor_user_id=uuid.uuid4(),
            )

        assert removed == 2
        assert nas_client.is_deleted is True

    async def test_retry_after_a_bridge_failure_succeeds(self) -> None:
        """The operator's recovery path. Because nothing was mutated on the
        failed attempt, simply doing it again once the hub is reachable
        works -- no manual SSH, no orphaned row."""
        fx = make_fixture()
        result = await _register_nas(fx)
        nas_id = result.nas_client.id

        with bridge(_AGENT_501), pytest.raises(RadiusNasBridgeDeregistrationError):
            await deregister_radius_nas_client(
                fx.radius_service,
                nas_id=nas_id,
                requesting_organization_id=None,
                actor_user_id=uuid.uuid4(),
            )
        with bridge(_AGENT_OK_ONE_REMOVED):
            nas_client, removed = await deregister_radius_nas_client(
                fx.radius_service,
                nas_id=nas_id,
                requesting_organization_id=None,
                actor_user_id=uuid.uuid4(),
            )
        assert removed == 1
        assert nas_client.is_deleted is True


# ---------------------------------------------------------------------------
# What the master console actually sees
# ---------------------------------------------------------------------------


class TestDeleteNasEndpoint:
    async def test_bridge_failure_is_a_502_not_a_success_envelope(self) -> None:
        """The headline assertion: with the bridge failing exactly as it did
        in production, the caller learns about it."""
        fx = make_fixture()
        result = await _register_nas(fx)
        app = _build_app(fx.radius_service)

        with bridge(_AGENT_501):
            resp = await _delete_via_http(app, result.nas_client.id)

        assert resp.status_code == 502
        body = resp.json()
        assert body.get("success") is not True
        #  The operator is told the credential may still be live, and that
        #  retrying is the fix -- not left to discover 21 stale stanzas.
        rendered = str(body)
        assert "NOT be removed" in rendered or "NOT removed" in rendered

        #  And the row is still listed, so it is still deletable.
        still_there = await fx.radius_service.get_nas_client(result.nas_client.id)
        assert still_there.is_deleted is False

    async def test_successful_delete_says_what_happened_on_the_radius_server(
        self,
    ) -> None:
        fx = make_fixture()
        result = await _register_nas(fx)
        app = _build_app(fx.radius_service)

        with bridge(_AGENT_OK_ONE_REMOVED):
            resp = await _delete_via_http(app, result.nas_client.id)

        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is True
        assert "removed from the RADIUS server" in body["message"]

    async def test_delete_with_nothing_on_the_hub_does_not_claim_a_removal(
        self,
    ) -> None:
        fx = make_fixture()
        result = await _register_nas(fx)
        app = _build_app(fx.radius_service)

        with bridge(_AGENT_OK_NONE_REMOVED):
            resp = await _delete_via_http(app, result.nas_client.id)

        assert resp.status_code == 200
        message = resp.json()["message"]
        assert "no client stanza" in message
        assert "removed from the RADIUS server" not in message

    async def test_bridge_is_called_before_the_row_is_soft_deleted(self) -> None:
        """Ordering is the actual fix. Asserted directly rather than
        inferred: the bridge sees the delete while the row is still active,
        so a bridge failure cannot leave a half-done delete behind."""
        fx = make_fixture()
        result = await _register_nas(fx)
        nas_id = result.nas_client.id
        observed: list[bool] = []

        def _observing(method: str, url: str) -> Response:
            nas = fx.radius_service.repository.nas_clients[nas_id]
            observed.append(nas.is_deleted)
            return Response(
                200,
                json={"status": "ok", "removed": 1},
                request=httpx.Request(method, url),
            )

        with bridge(_observing):
            await deregister_radius_nas_client(
                fx.radius_service,
                nas_id=nas_id,
                requesting_organization_id=None,
                actor_user_id=uuid.uuid4(),
            )

        assert observed == [False]


# ---------------------------------------------------------------------------
# Router decommissioning composes the same call
# ---------------------------------------------------------------------------


class TestDecommissionRouterCleansUpRadius:
    """``decommission_router`` reuses ``deregister_radius_nas_client``, so it
    has to inherit the same guarantee rather than re-swallowing the failure
    one layer up -- which is exactly what it used to do, with a bare
    ``except Exception: logger.warning(...)`` wrapped around the whole
    thing.
    """

    @staticmethod
    def _fakes() -> tuple[Any, Any, Any]:
        class _FakeRequest:
            class state:  # noqa: N801 -- mirrors Starlette's request.state
                request_id = "test-request"

        class _FakeRouterService:
            def __init__(self) -> None:
                self.decommissioned: list[uuid.UUID] = []

            async def decommission_router(self, **kwargs: Any) -> None:
                self.decommissioned.append(kwargs["router_id"])

        class _FakeWireGuardService:
            def __init__(self) -> None:
                self.revoked: list[uuid.UUID] = []

            async def revoke_tunnel(self, **kwargs: Any) -> None:
                self.revoked.append(kwargs["router_id"])

        return _FakeRequest(), _FakeRouterService(), _FakeWireGuardService()

    async def test_bridge_failure_aborts_the_whole_decommission(self) -> None:
        from app.domains.router.router import decommission_router

        fx = make_fixture()
        await _register_nas(fx)
        request, router_service, wireguard_service = self._fakes()

        with bridge(_AGENT_501), pytest.raises(RadiusNasBridgeDeregistrationError):
            await decommission_router(
                request,
                fx.router.id,
                user=_ACTOR,
                requesting_organization_id=None,
                router_service=router_service,
                radius_service=fx.radius_service,
                wireguard_service=wireguard_service,
            )

        #  Nothing was mutated: the router is still there, the tunnel is
        #  still up, and the NAS row is still active. Retrying once the hub
        #  is reachable does the whole thing cleanly.
        assert router_service.decommissioned == []
        assert wireguard_service.revoked == []

    async def test_successful_decommission_revokes_the_nas_first(self) -> None:
        from app.domains.router.router import decommission_router

        fx = make_fixture()
        result = await _register_nas(fx)
        request, router_service, wireguard_service = self._fakes()

        with bridge(_AGENT_OK_ONE_REMOVED) as stub:
            await decommission_router(
                request,
                fx.router.id,
                user=_ACTOR,
                requesting_organization_id=None,
                router_service=router_service,
                radius_service=fx.radius_service,
                wireguard_service=wireguard_service,
            )

        assert stub.calls[0]["json"] == {"nas_identifier": _NAS_IDENTIFIER}
        assert router_service.decommissioned == [fx.router.id]
        assert result.nas_client.is_deleted is True

    async def test_a_router_that_never_had_a_nas_decommissions_normally(self) -> None:
        """Most routers never register a NAS. They must not touch the bridge
        at all, so a hub outage cannot block their decommission."""
        from app.domains.router.router import decommission_router

        fx = make_fixture()
        request, router_service, wireguard_service = self._fakes()

        with bridge(_AGENT_501) as stub:
            await decommission_router(
                request,
                fx.router.id,
                user=_ACTOR,
                requesting_organization_id=None,
                router_service=router_service,
                radius_service=fx.radius_service,
                wireguard_service=wireguard_service,
            )

        assert stub.calls == []
        assert router_service.decommissioned == [fx.router.id]
