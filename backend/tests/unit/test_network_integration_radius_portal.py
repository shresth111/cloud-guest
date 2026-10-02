"""Server-side RADIUS-mode portal authorization (Omada ``authType 2``).

The flow under test: a guest at a RADIUS-mode venue finishes OTP, the portal
page calls ``POST /network-integrations/portal/radius-authorize``, and **this
platform** form-POSTs the controller's ``/portal/radius/browserauth``. That
last leg used to be the guest's own browser and could not be made to work --
the target is the controller's self-signed HTTPS portal port and Android
refuses it.

What is actually worth asserting here, in the order the risk runs:

1. **The SSRF boundary.** The redirect tells the *guest's browser* where to
   submit, and those values come back to us on an unauthenticated body. The
   URL is built from the integration row; a claimed address that disagrees is
   refused with the same opaque 403 as everything else and nothing leaves the
   process. ``TestTheAddressBoundary``.
2. **The other contract is untouched.** A live venue runs on
   ``external_portal``, and no input to the new path may reach it.
   ``TestTheContractsDoNotMix``.
3. **Controller answers become renderable outcomes, never 500s** -- reject,
   RADIUS timeout, controller unreachable. ``TestWhatTheControllerAnswers``.
4. **The credential is resolved server-side**, not accepted from the body.
   ``TestTheCredentialIsNotTheCallers``.
5. **The wire body is what hardware accepted**, field for field, and the
   ``302``/``200`` reading is the corrected one. ``TestTheWireContract``.
"""

from __future__ import annotations

import uuid
from typing import Any

import httpx
import pytest

from app.domains.network_integration.constants import (
    ErrorCode,
    PortalAuthMode,
    RadiusPortalFailure,
)
from app.domains.network_integration.exceptions import (
    GuestSessionNotActiveError,
    ProviderConnectionFailedError,
    ProviderControllerAddressMismatchError,
    ProviderTimeoutError,
)
from app.domains.network_integration.providers.base import (
    ProviderConnectionConfig,
    ProviderRadiusAuthorizationResult,
    ProviderRadiusPortalContext,
)
from app.domains.network_integration.providers.omada import (
    _RADIUS_PORTAL_PORTS,
    OmadaProvider,
)

from .test_network_integration import (
    FakeGuestSession,
    FakeGuestSessionLookup,
    FakeProvider,
    FakeRepository,
    _integration,
    _service,
)

pytestmark = pytest.mark.asyncio

CLIENT_MAC = "AA-BB-CC-DD-EE-FF"
# `_integration()`'s own CONTROLLER_URL host, so the "claimed address agrees"
# cases are built from the same place the refusal cases contradict.
CONTROLLER_HOST = "controller.example.com"


def _radius_setup(
    *,
    provider: FakeProvider | None = None,
    portal_mode: str = PortalAuthMode.RADIUS.value,
    session: FakeGuestSession | None = None,
    **integration_overrides: Any,
):
    """A RADIUS-mode venue with one ACTIVE session on the MAC being
    authorized. Returns ``(service, repo, integration, session_id, provider)``."""
    org, location = uuid.uuid4(), uuid.uuid4()
    session_id = uuid.uuid4()
    repo = FakeRepository()
    integration = repo.add(
        _integration(
            organization_id=org,
            location_id=location,
            portal_mode=portal_mode,
            **integration_overrides,
        )
    )
    lookup = FakeGuestSessionLookup(
        {session_id: session or FakeGuestSession(session_id, org, location)}
    )
    fake = provider or FakeProvider()
    service = _service(repo, provider=fake, guest_lookup=lookup)
    return service, repo, integration, session_id, fake


async def _authorize(service, integration, session_id, **overrides):
    kwargs: dict[str, Any] = {
        "session_id": session_id,
        "organization_id": integration.organization_id,
        "location_id": integration.location_id,
        "provider": "omada",
        "client_mac": CLIENT_MAC,
        "client_ip": "192.168.1.121",
        "ap_mac": "B8-FB-B3-5D-64-3E",
        "ssid_name": "WyfyRadTest",
        "radio_id": 1,
        "origin_url": "https://portal.example.com/connected",
    }
    kwargs.update(overrides)
    return await service.authorize_portal_client_via_radius(**kwargs)


# ============================================================================
# 1. The SSRF boundary
# ============================================================================


class TestTheAddressBoundary:
    """The one property that makes this endpoint safe to expose at all.

    ``target``/``targetPort``/``scheme`` arrive on an unauthenticated body,
    having travelled through a guest's browser, and they name where this
    platform is about to open a connection carrying this integration's TLS
    trust decision. They must never be able to move it.
    """

    async def test_a_foreign_target_is_refused_and_nothing_is_sent(self) -> None:
        provider = FakeProvider()
        service, repo, integration, session_id, _ = _radius_setup(provider=provider)

        with pytest.raises(GuestSessionNotActiveError):
            await _authorize(
                service,
                integration,
                session_id,
                target="169.254.169.254",
                target_port=8843,
                scheme="https",
            )

        # Not "it connected to the right place anyway" -- it did not connect.
        # The address check raised before the provider recorded anything, so
        # an empty list here is a statement about the request, not a default.
        assert provider.radius_contexts == []
        # The operator's feed names the real reason; the caller got a 403
        # that is indistinguishable from a nonexistent session.
        event = repo.events[-1]
        assert event.error_code == ErrorCode.RADIUS_PORTAL_ADDRESS_MISMATCH.value
        assert event.context["claimed_target"] == "169.254.169.254"

    async def test_a_mismatched_port_is_refused(self) -> None:
        """8843 is right for this venue; 9999 is not, and a caller does not
        get to pick. The port comes from the integration or from the
        provider's documented default, never from the request."""
        service, repo, integration, session_id, _ = _radius_setup()

        with pytest.raises(GuestSessionNotActiveError):
            await _authorize(service, integration, session_id, target_port=9999)
        assert (
            repo.events[-1].error_code == ErrorCode.RADIUS_PORTAL_ADDRESS_MISMATCH.value
        )

    async def test_a_mismatched_scheme_is_refused(self) -> None:
        service, repo, integration, session_id, _ = _radius_setup()

        with pytest.raises(GuestSessionNotActiveError):
            await _authorize(service, integration, session_id, scheme="http")
        assert (
            repo.events[-1].error_code == ErrorCode.RADIUS_PORTAL_ADDRESS_MISMATCH.value
        )

    async def test_an_agreeing_claim_is_accepted(self) -> None:
        """The check is a comparison, not a ban: a redirect that names the
        address we already hold is the ordinary case and must work."""
        service, _repo, integration, session_id, provider = _radius_setup()

        outcome = await _authorize(
            service,
            integration,
            session_id,
            target=CONTROLLER_HOST,
            target_port=8843,
            scheme="https",
        )
        assert outcome.authorized is True
        assert len(provider.radius_contexts) == 1

    async def test_omitting_the_claim_changes_nothing_about_where_we_connect(
        self,
    ) -> None:
        """A caller that sends no claim is not thereby trusted more. The
        address is built from the row either way; the claim only ever adds a
        way to be refused."""
        service, _repo, integration, session_id, provider = _radius_setup()

        outcome = await _authorize(service, integration, session_id)
        assert outcome.authorized is True

        config = provider.radius_configs[0]
        context = provider.radius_contexts[0]
        base_url, _scheme, host, port = OmadaProvider._radius_portal_origin(
            config, context
        )
        assert host == CONTROLLER_HOST
        assert port == 8843
        assert base_url == f"https://{CONTROLLER_HOST}:8843"

    async def test_the_url_is_built_from_the_row_even_when_a_claim_agrees(
        self,
    ) -> None:
        """Belt and braces on the boundary itself, at the provider level: the
        context's claimed fields are inputs to a comparison and inputs to
        nothing else."""
        config = ProviderConnectionConfig(
            provider="omada",
            base_url="https://10.0.0.5:8043",
            auth_mode="legacy",
        )
        context = ProviderRadiusPortalContext(
            client_mac=CLIENT_MAC,
            advertised_target="10.0.0.5",
            advertised_port=8843,
            advertised_scheme="https",
        )
        assert OmadaProvider._radius_portal_origin(config, context) == (
            "https://10.0.0.5:8843",
            "https",
            "10.0.0.5",
            8843,
        )

    async def test_an_operator_port_override_wins_over_the_default(self) -> None:
        """And a caller claiming the *default* against an overridden venue is
        refused -- "matches what the integration holds" means the override,
        not whatever is conventional."""
        config = ProviderConnectionConfig(
            provider="omada", base_url="https://10.0.0.5:8043", auth_mode="legacy"
        )
        overridden = ProviderRadiusPortalContext(
            client_mac=CLIENT_MAC, portal_port=9443
        )
        assert OmadaProvider._radius_portal_origin(config, overridden)[3] == 9443

        with pytest.raises(ProviderControllerAddressMismatchError):
            OmadaProvider._radius_portal_origin(
                config,
                ProviderRadiusPortalContext(
                    client_mac=CLIENT_MAC,
                    portal_port=9443,
                    advertised_port=8843,
                ),
            )

    async def test_the_service_reads_the_override_off_the_integration(self) -> None:
        from app.domains.network_integration.constants import (
            RADIUS_PORTAL_METADATA_PORT_KEY,
        )

        service, _repo, integration, session_id, provider = _radius_setup(
            provider_metadata={RADIUS_PORTAL_METADATA_PORT_KEY: 9443}
        )
        await _authorize(service, integration, session_id, target_port=9443)
        assert provider.radius_contexts[0].portal_port == 9443

    async def test_a_junk_override_falls_back_rather_than_stranding_the_venue(
        self,
    ) -> None:
        """A bad value in a JSONB column should not refuse every guest at the
        venue; it should be ignored and the documented default used."""
        from app.domains.network_integration.constants import (
            RADIUS_PORTAL_METADATA_PORT_KEY,
        )

        service, _repo, integration, session_id, provider = _radius_setup(
            provider_metadata={RADIUS_PORTAL_METADATA_PORT_KEY: "not-a-port"}
        )
        outcome = await _authorize(service, integration, session_id)
        assert outcome.authorized is True
        assert provider.radius_contexts[0].portal_port is None


# ============================================================================
# 2. The two contracts do not mix
# ============================================================================


class TestTheContractsDoNotMix:
    async def test_a_radius_call_against_an_external_portal_venue_is_refused(
        self,
    ) -> None:
        """The mirror image of the refusal `authorize_portal_client` has
        carried since RADIUS mode existed. A live venue runs on this contract
        and no request may reach it through the new path."""
        provider = FakeProvider()
        service, repo, integration, session_id, _ = _radius_setup(
            provider=provider, portal_mode=PortalAuthMode.EXTERNAL_PORTAL.value
        )

        with pytest.raises(GuestSessionNotActiveError):
            await _authorize(service, integration, session_id)

        assert provider.radius_contexts == []
        assert "authorize_guest" not in provider.calls
        assert repo.events[-1].error_code == ErrorCode.PORTAL_MODE_MISMATCH.value

    async def test_the_external_portal_path_still_refuses_a_radius_venue(
        self,
    ) -> None:
        """Unchanged behaviour, asserted here too because this change is
        exactly the one that would be tempted to delete it."""
        service, repo, integration, session_id, provider = _radius_setup()

        with pytest.raises(GuestSessionNotActiveError):
            await service.authorize_portal_client(
                session_id=session_id,
                organization_id=integration.organization_id,
                location_id=integration.location_id,
                provider="omada",
                client_mac=CLIENT_MAC,
                site="site-1",
            )
        assert "authorize_guest" not in provider.calls
        assert repo.events[-1].error_code == ErrorCode.PORTAL_MODE_MISMATCH.value


# ============================================================================
# 3. Session proof, unchanged and shared
# ============================================================================


class TestTheSessionGate:
    async def test_a_terminated_session_is_refused(self) -> None:
        """The punitive kill an admin used to throw an abusive guest off.
        Honouring it here would hand them a fresh controller authorization --
        on a contract where this platform has no way to revoke it."""
        org, location = uuid.uuid4(), uuid.uuid4()
        session_id = uuid.uuid4()
        service, _repo, integration, _sid, provider = _radius_setup(
            session=FakeGuestSession(session_id, org, location, status="terminated")
        )
        with pytest.raises(GuestSessionNotActiveError):
            await service.authorize_portal_client_via_radius(
                session_id=session_id,
                organization_id=integration.organization_id,
                location_id=integration.location_id,
                provider="omada",
                client_mac=CLIENT_MAC,
            )
        assert provider.radius_contexts == []

    async def test_another_devices_mac_is_refused(self) -> None:
        """The session is honest and the MAC is somebody else's -- a guest
        putting a stranger's phone on the venue's WiFi after one OTP."""
        service, _repo, integration, session_id, provider = _radius_setup()
        with pytest.raises(GuestSessionNotActiveError):
            await _authorize(
                service, integration, session_id, client_mac="11-22-33-44-55-66"
            )
        assert provider.radius_contexts == []

    async def test_it_is_the_same_method_the_other_contract_uses(self) -> None:
        """Not a resemblance -- the same code. A second copy is a second
        place to forget the TERMINATED case."""
        import inspect

        from app.domains.network_integration.service import (
            NetworkIntegrationService,
        )

        for name in ("authorize_portal_client", "authorize_portal_client_via_radius"):
            source = inspect.getsource(getattr(NetworkIntegrationService, name))
            assert "await self._resolve_portal_session(" in source


# ============================================================================
# 4. The credential is not the caller's
# ============================================================================


class TestTheCredentialIsNotTheCallers:
    async def test_the_username_is_the_sessions_guest_identifier(self) -> None:
        """It is the whole credential on this contract -- our FreeRADIUS
        authorizes by session lookup on exactly this string -- so accepting
        it from the body would be authorizing an identity the caller never
        proved they hold."""
        service, _repo, integration, session_id, provider = _radius_setup()
        await _authorize(service, integration, session_id)
        assert provider.radius_contexts[0].username == "+919876543210"

    async def test_there_is_no_username_field_on_the_request_schema(self) -> None:
        from app.domains.network_integration.schemas import (
            PortalRadiusAuthorizeRequest,
        )

        fields = set(PortalRadiusAuthorizeRequest.model_fields)
        assert not fields & {"username", "password", "identifier"}

    async def test_a_session_whose_guest_is_gone_is_refused(self) -> None:
        """Refused rather than submitted with an empty username, which the
        controller would answer with a reject that reads to an operator as
        'our RADIUS said no'."""
        org, location = uuid.uuid4(), uuid.uuid4()
        session_id = uuid.uuid4()
        service, _repo, integration, _sid, provider = _radius_setup(
            session=FakeGuestSession(session_id, org, location, guest_identifier=None)
        )
        with pytest.raises(GuestSessionNotActiveError):
            await service.authorize_portal_client_via_radius(
                session_id=session_id,
                organization_id=integration.organization_id,
                location_id=integration.location_id,
                provider="omada",
                client_mac=CLIENT_MAC,
            )
        assert provider.radius_contexts == []


# ============================================================================
# 5. What the controller answers
# ============================================================================


class TestWhatTheControllerAnswers:
    async def test_success_returns_the_controllers_own_landing_url(self) -> None:
        provider = FakeProvider(
            radius_result=ProviderRadiusAuthorizationResult(
                authorized=True, landing_url="http://neverssl.com/"
            )
        )
        service, repo, integration, session_id, _ = _radius_setup(provider=provider)

        outcome = await _authorize(service, integration, session_id)
        assert outcome.authorized is True
        assert outcome.redirect_url == "http://neverssl.com/"
        assert outcome.failure is None
        assert repo.events[-1].error_code is None

    async def test_a_radius_reject_is_a_rendered_outcome_not_an_exception(
        self,
    ) -> None:
        """-41529 is a genuine Access-Reject. On this platform that means the
        session is gone, not that a guest mistyped."""
        provider = FakeProvider(
            radius_result=ProviderRadiusAuthorizationResult(
                authorized=False,
                failure=RadiusPortalFailure.REJECTED.value,
                provider_code=-41529,
            )
        )
        service, repo, integration, session_id, _ = _radius_setup(provider=provider)

        outcome = await _authorize(service, integration, session_id)
        assert outcome.authorized is False
        assert outcome.failure == RadiusPortalFailure.REJECTED.value
        # The vendor's number goes to the operator's feed and NOT to the
        # caller: the whole point of moving this server-side was that the
        # guest used to be shown the controller's raw JSON.
        assert outcome.redirect_url is None
        event = repo.events[-1]
        assert event.error_code == ErrorCode.RADIUS_PORTAL_NOT_AUTHORIZED.value
        assert event.context["provider_error_code"] == -41529

    async def test_a_controller_timeout_is_an_error_code_not_a_500(self) -> None:
        provider = FakeProvider(
            raise_on={"authorize_guest_via_radius_portal": ProviderTimeoutError()}
        )
        service, repo, integration, session_id, _ = _radius_setup(provider=provider)

        outcome = await _authorize(service, integration, session_id)
        assert outcome.authorized is False
        assert outcome.failure == RadiusPortalFailure.CONTROLLER_UNREACHABLE.value
        assert repo.events[-1].error_code == ErrorCode.TIMEOUT.value

    async def test_an_unreachable_controller_is_the_same_guest_facing_answer(
        self,
    ) -> None:
        """Different cause, same advice. The distinction that matters to an
        operator is kept exactly where an operator looks."""
        provider = FakeProvider(
            raise_on={
                "authorize_guest_via_radius_portal": ProviderConnectionFailedError()
            }
        )
        service, repo, integration, session_id, _ = _radius_setup(provider=provider)

        outcome = await _authorize(service, integration, session_id)
        assert outcome.failure == RadiusPortalFailure.CONTROLLER_UNREACHABLE.value
        assert repo.events[-1].error_code == ErrorCode.CONNECTION_FAILED.value

    async def test_the_failure_vocabulary_is_closed(self) -> None:
        """The portal renders one message per value, so a value it has never
        heard of renders nothing."""
        allowed = {member.value for member in RadiusPortalFailure}
        for code in (-41501, -41529, -41530, -99999, None):
            assert OmadaProvider._radius_failure(code, 200) in allowed
        assert (
            OmadaProvider._radius_failure(-41529, 400)
            == RadiusPortalFailure.BAD_REQUEST.value
        ), "HTTP 400 is our malformed body and must outrank the error code"

    async def test_an_unmapped_vendor_code_is_not_guessed_at(self) -> None:
        assert (
            OmadaProvider._radius_failure(-40000, 200)
            == RadiusPortalFailure.CONTROLLER_REFUSED.value
        )

    async def test_every_attempt_is_logged_with_something_greppable(
        self, caplog
    ) -> None:
        """There was nothing to grep before this, which is how the
        browser-side version could fail for every Android guest at a venue
        and leave no record anywhere."""
        import logging

        service, _repo, integration, session_id, _ = _radius_setup()
        with caplog.at_level(logging.INFO):
            await _authorize(service, integration, session_id)

        record = next(
            r
            for r in caplog.records
            if r.message == "network_integration_radius_portal_authorize"
        )
        assert record.integration_id == str(integration.id)
        assert record.client_mac == "AA:BB:CC:DD:EE:FF"
        assert record.outcome == "authorized"
        # The credential on this path is the guest's identifier. It is not
        # logged, and that is deliberate.
        assert "+919876543210" not in caplog.text

    async def test_no_authorization_row_is_written(self) -> None:
        """This platform did not issue this grant -- the controller did, off
        an Access-Accept -- and a row here would claim an expiry nobody
        agreed on. ``disconnect_guest``'s RADIUS branch promises no such row
        exists; a half-true one would make that promise false."""
        service, repo, integration, session_id, _ = _radius_setup()
        await _authorize(service, integration, session_id)
        assert repo.authorizations == []


# ============================================================================
# 6. The wire contract, against what hardware accepted
# ============================================================================


class TestTheWireContract:
    """Asserted against the request measured on Omada Software Controller
    5.15.24.19 on 2026-09-17, which returned ``302`` and moved the client to
    ``authStatus 2 / authType 2``."""

    def test_the_body_is_the_measured_one(self) -> None:
        from wyfy_device_gateway.omada.radius_portal import (
            RadiusPortalContext,
            build_browserauth_body,
        )

        body = build_browserauth_body(
            RadiusPortalContext(
                client_mac="26-79-94-B5-24-D9",
                client_ip="192.168.1.121",
                ap_mac="B8-FB-B3-5D-64-3E",
                gateway_mac="",
                ssid_name="WyfyRadTest",
                vid="",
                radio_id=1,
                origin_url="http://neverssl.com/",
            ),
            username="+919876543210",
            password="welcome123",
        )
        assert body == {
            "clientMac": "26-79-94-B5-24-D9",
            "clientIp": "192.168.1.121",
            "apMac": "B8-FB-B3-5D-64-3E",
            "ssidName": "WyfyRadTest",
            "radioId": "1",
            "authType": "2",
            "originUrl": "http://neverssl.com/",
            "username": "+919876543210",
            "password": "welcome123",
        }

    def test_an_absent_field_stays_absent(self) -> None:
        """Present-only, never defaulted: some firmware treats a missing
        optional field and an empty one differently and we have measured
        neither."""
        from wyfy_device_gateway.omada.radius_portal import (
            RadiusPortalContext,
            build_browserauth_body,
        )

        body = build_browserauth_body(
            RadiusPortalContext(client_mac=CLIENT_MAC),
            username="u",
            password="p",
        )
        assert set(body) == {"clientMac", "authType", "username", "password"}

    def test_the_port_tables_agree(self) -> None:
        """Three copies of the same fact exist -- gateway, provider, and the
        test fake's reuse of the provider's. Duplicated deliberately (the
        gateway is a lazy import that may be absent), so the agreement is
        asserted rather than assumed."""
        from wyfy_device_gateway.omada.radius_portal import DEFAULT_PORTAL_PORTS

        assert (
            _RADIUS_PORTAL_PORTS
            == DEFAULT_PORTAL_PORTS
            == {
                "https": 8843,
                "http": 8088,
            }
        )


class TestTheTransport:
    """The gateway leg, with ``httpx.MockTransport`` in place of a socket."""

    async def _submit(self, handler, **kwargs):
        from wyfy_device_gateway.controller_contract import (
            ControllerAuthMode,
            ControllerCredentials,
            ControllerVendor,
        )
        from wyfy_device_gateway.omada.radius_portal import (
            RadiusPortalContext,
            submit_browserauth,
        )

        creds = ControllerCredentials(
            vendor=ControllerVendor.TPLINK_OMADA,
            base_url="https://10.0.0.5:8843",
            auth_mode=ControllerAuthMode.LEGACY,
            timeout_seconds=1.0,
        )
        return await submit_browserauth(
            creds,
            RadiusPortalContext(client_mac=CLIENT_MAC),
            username="u",
            password="p",
            transport=httpx.MockTransport(handler),
            **kwargs,
        )

    async def test_a_302_is_success_and_the_redirect_is_not_followed(self) -> None:
        """An earlier measurement appeared to show 302 on a reject too -- a
        silent-success disaster, taken with accounting enabled. The corrected
        reading is what is encoded, and following the redirect would destroy
        the only success signal this endpoint has."""
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(302, headers={"location": "http://neverssl.com/"})

        result = await self._submit(handler)
        assert result.authorized is True
        assert result.landing_url == "http://neverssl.com/"
        assert len(seen) == 1
        assert seen[0].url.path == "/portal/radius/browserauth"
        assert seen[0].headers["content-type"] == ("application/x-www-form-urlencoded")

    async def test_a_200_with_json_is_a_refusal_carrying_the_code(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "errorCode": -41530,
                    "msg": "Connecting to the RADIUS server times out.",
                },
            )

        result = await self._submit(handler)
        assert result.authorized is False
        assert result.provider_code == -41530
        assert result.http_status == 200

    async def test_a_400_is_reported_as_itself(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, text="")

        result = await self._submit(handler)
        assert result.authorized is False
        assert result.http_status == 400

    async def test_a_timeout_retries_once_and_then_raises_a_timeout(self) -> None:
        """One retry, not none and not a loop: the controller's answer
        already costs a RADIUS round trip."""
        from wyfy_device_gateway.omada.errors import OmadaTimeoutError

        attempts: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            attempts.append(1)
            raise httpx.ReadTimeout("timed out", request=request)

        with pytest.raises(OmadaTimeoutError):
            await self._submit(handler)
        assert len(attempts) == 2

    async def test_an_answered_call_is_never_retried(self) -> None:
        """Re-sending after a reject asks a venue's RADIUS server to reject
        the same guest twice; after a 302 it authorizes them twice."""
        attempts: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            attempts.append(1)
            return httpx.Response(200, json={"errorCode": -41529})

        await self._submit(handler)
        assert len(attempts) == 1

    async def test_a_transport_failure_recovers_on_the_second_attempt(self) -> None:
        attempts: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            attempts.append(1)
            if len(attempts) == 1:
                raise httpx.ConnectError("refused", request=request)
            return httpx.Response(302, headers={"location": "/done"})

        result = await self._submit(handler)
        assert result.authorized is True
        assert len(attempts) == 2


class TestTlsTrustIsInherited:
    async def test_pinned_mode_still_pins_and_adds_no_bypass(self) -> None:
        """The integration's existing trust decision is reused, not
        re-decided. A pinned integration whose certificate does not match
        fails closed here exactly as it does on every other call -- there is
        deliberately no 'verify off for this one submit'."""
        from wyfy_device_gateway.controller_contract import (
            ControllerAuthMode,
            ControllerCredentials,
            ControllerTlsMode,
            ControllerVendor,
        )
        from wyfy_device_gateway.omada.errors import OmadaTlsPinMismatchError
        from wyfy_device_gateway.omada.radius_portal import (
            RadiusPortalContext,
            submit_browserauth,
        )

        creds = ControllerCredentials(
            vendor=ControllerVendor.TPLINK_OMADA,
            base_url="https://10.0.0.5:8843",
            auth_mode=ControllerAuthMode.LEGACY,
            tls_mode=ControllerTlsMode.PINNED,
            # Pinning with nothing to pin to is a lie told to whoever reads
            # the row, and it would be told at the moment the pin mattered.
            tls_pinned_sha256=None,
            timeout_seconds=1.0,
        )
        with pytest.raises(OmadaTlsPinMismatchError):
            await submit_browserauth(
                creds,
                RadiusPortalContext(client_mac=CLIENT_MAC),
                username="u",
                password="p",
                transport=httpx.MockTransport(
                    lambda request: httpx.Response(302, headers={"location": "/x"})
                ),
            )

    def test_the_module_has_no_verify_false_of_its_own(self) -> None:
        """A grep, because this is the kind of thing that gets added in a
        hurry against a self-signed controller and never removed."""
        import ast
        import inspect

        from wyfy_device_gateway.omada import radius_portal

        tree = ast.parse(inspect.getsource(radius_portal))
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "verify":
                assert isinstance(node.value, ast.Name), (
                    "verify= must come from ssl_verify_argument(creds), not "
                    "from a literal"
                )
