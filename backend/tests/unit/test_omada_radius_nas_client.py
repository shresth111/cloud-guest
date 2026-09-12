"""A NAS client keyed on a controller's public address.

Every ``client{}`` stanza on the live hub today is keyed on a WireGuard
tunnel address -- 19 of 19 in the 2026-08-22 capture. A controller in
RADIUS mode is the first NAS whose address this platform does not own and
whose source a stranger can spoof from the internet, so these tests pin the
two things that distinguish it from a router registration:

1. **what will be refused before a request is made** -- a hostname, a
   private address, the tunnel range, a prefix rather than a host. Each of
   those produces a stanza that either matches nothing (and FreeRADIUS
   drops an unmatched Access-Request silently, with no reply and no log
   line) or matches far more than intended;
2. **what is actually sent to the hub agent**, including the compatibility
   shim that exists only because nobody currently has shell on the hub to
   upgrade the agent running there.

The idempotence property -- one stanza per shortname -- is shared with the
router path and is tested where it is implemented, in
``test_hub_radius_agent.py``; the controller-specific half of it is
re-asserted here against the agent in this repository.
"""

from __future__ import annotations

import importlib.util
import uuid
from pathlib import Path

import httpx
import pytest

from app.domains.guest.radius_bridge import (
    RadiusClientAddressRejected,
    push_controller_nas_client,
    push_nas_client,
    validate_controller_nas_address,
)
from app.domains.network_integration.constants import PortalAuthMode
from app.domains.network_integration.validators import (
    EXTERNAL_PORTAL_MODE_PARAM,
    build_external_portal_url,
)

_AGENT_PATH = (
    Path(__file__).resolve().parents[2] / "ops" / "hub-agents" / "radius_agent.py"
)
_spec = importlib.util.spec_from_file_location("wyfy_radius_agent_ctl", _AGENT_PATH)
assert _spec is not None and _spec.loader is not None
radius_agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(radius_agent)


class TestControllerAddressIsRefusedEarly:
    def test_a_public_literal_is_accepted_and_normalized(self) -> None:
        assert validate_controller_nas_address(" 13.126.39.79 ") == "13.126.39.79"

    def test_a_hostname_is_refused_with_the_reason(self) -> None:
        """``clients.conf`` resolves a hostname once, at FreeRADIUS
        start-up, and never again. A venue on a dynamic address would
        authenticate until the next restart and then stop, with the stanza
        still looking correct in the file."""
        with pytest.raises(RadiusClientAddressRejected) as exc:
            validate_controller_nas_address("controller.example.com")
        assert "start-up" in str(exc.value)

    @pytest.mark.parametrize(
        "address",
        ["192.168.1.5", "127.0.0.1", "169.254.169.254", "172.31.44.217"],
    )
    def test_a_private_or_reserved_address_is_refused(self, address: str) -> None:
        """An Access-Request from a venue arrives from its *public* NAT
        address. A private address here is somebody reading the
        controller's LAN address off its own settings page."""
        with pytest.raises(RadiusClientAddressRejected):
            validate_controller_nas_address(address)

    def test_the_tunnel_range_is_refused_by_name(self) -> None:
        """A controller address inside 10.20.0.0/24 is a copy-paste of a
        router's, and keying a stanza on it would hand an internet-facing
        secret to whatever peer currently holds that tunnel IP."""
        with pytest.raises(RadiusClientAddressRejected) as exc:
            validate_controller_nas_address("10.20.0.19")
        assert "WireGuard" in str(exc.value)

    def test_a_prefix_is_refused(self) -> None:
        """The agent writes ``ipaddr = <what we sent>/32``. A prefix here
        widens the client, which is the ``0.0.0.0/0`` catch-all defect this
        platform is removing, not adding to."""
        with pytest.raises(RadiusClientAddressRejected):
            validate_controller_nas_address("1.2.3.0/24")


class TestWhatIsSentToTheHub:
    @staticmethod
    def _capture(monkeypatch) -> list[dict]:  # noqa: ANN001
        sent: list[dict] = []

        class _Client:
            def __init__(self, *a, **k) -> None:  # noqa: ANN002, ANN003
                pass

            async def __aenter__(self):  # noqa: ANN204
                return self

            async def __aexit__(self, *a) -> bool:  # noqa: ANN002
                return False

            async def post(self, url, *, headers, json):  # noqa: ANN001, ANN204
                sent.append(json)
                return httpx.Response(200, json={"status": "ok"})

        monkeypatch.setattr(httpx, "AsyncClient", _Client)
        return sent

    async def test_the_address_is_sent_under_both_keys(self, monkeypatch) -> None:  # noqa: ANN001
        """A compatibility shim with an expiry date, not a naming opinion.

        The agent deployed on the hub reads ``payload["tunnel_ip"]`` and
        raises ``KeyError`` without it; the agent in this repository reads
        ``address``. Both are sent so the two can be upgraded in either
        order -- which matters here more than usual, because nobody
        currently has shell on that host to upgrade it at all.
        """
        sent = self._capture(monkeypatch)
        written = await push_controller_nas_client(
            controller_ip="13.126.39.79",
            nas_identifier="cg-omada-abcd1234",
            secret="a-secret-value",
        )
        assert written == "13.126.39.79"
        assert sent[0]["address"] == "13.126.39.79"
        assert sent[0]["tunnel_ip"] == "13.126.39.79"

    async def test_a_controller_client_asks_for_message_authenticator(
        self, monkeypatch
    ) -> None:  # noqa: ANN001
        """Omada sends a Message-Authenticator on every Access-Request --
        measured on the wire, PAP and CHAP alike -- so demanding it costs
        the venue nothing and closes BlastRADIUS (CVE-2024-3596) on the one
        client of ours whose source address is reachable from the
        internet."""
        sent = self._capture(monkeypatch)
        await push_controller_nas_client(
            controller_ip="13.126.39.79",
            nas_identifier="cg-omada-abcd1234",
            secret="a-secret-value",
        )
        assert sent[0]["require_message_authenticator"] is True

    async def test_a_router_push_is_unchanged_on_the_wire(self, monkeypatch) -> None:  # noqa: ANN001
        """The router path must not start sending a flag the deployed agent
        would ignore and a future agent would act on. Its stanzas keep the
        established default."""
        sent = self._capture(monkeypatch)
        await push_nas_client(
            tunnel_ip="10.20.0.19",
            nas_identifier="cg-5d3a509e",
            secret="a-secret-value",
        )
        assert "require_message_authenticator" not in sent[0]
        assert sent[0]["tunnel_ip"] == "10.20.0.19"

    async def test_a_refused_address_never_reaches_the_hub(self, monkeypatch) -> None:  # noqa: ANN001
        sent = self._capture(monkeypatch)
        with pytest.raises(RadiusClientAddressRejected):
            await push_controller_nas_client(
                controller_ip="10.20.0.19",
                nas_identifier="cg-omada-abcd1234",
                secret="a-secret-value",
            )
        assert sent == []


class TestTheAgentWritesAControllerStanza:
    @pytest.fixture
    def conf(self, tmp_path: Path, monkeypatch) -> Path:  # noqa: ANN001
        path = tmp_path / "clients.conf"
        path.write_text("client localhost {\n\tipaddr = 127.0.0.1\n}\n")
        monkeypatch.setattr(radius_agent, "CLIENTS_CONF", str(path))
        monkeypatch.setattr(radius_agent, "BACKUP_DIR", str(tmp_path / "bak"))
        monkeypatch.setattr(radius_agent, "_validate_and_restart", lambda _b: None)
        return path

    def test_a_public_address_is_keyed_as_a_host(self, conf: Path) -> None:
        radius_agent.add_client(
            "13.126.39.79", "cg-omada-abcd1234", "a-secret-value", True
        )
        text = conf.read_text()
        assert "ipaddr = 13.126.39.79/32" in text
        assert "shortname = cg-omada-abcd1234" in text
        assert "backend_secret = a-secret-value" in text

    def test_the_explicit_flag_hardens_a_new_client(self, conf: Path) -> None:
        radius_agent.add_client(
            "13.126.39.79", "cg-omada-abcd1234", "a-secret-value", True
        )
        assert "require_message_authenticator = yes" in conf.read_text()

    def test_the_flag_can_only_harden(self, conf: Path) -> None:
        """There is no way to ask this agent to turn the requirement off,
        so a request cannot silently downgrade a client somebody
        deliberately hardened."""
        conf.write_text(
            "client cg-x {\n\tipaddr = 13.126.39.79/32\n\tsecret = s\n"
            "\tshortname = cg-omada-abcd1234\n"
            "\trequire_message_authenticator = yes\n}\n"
        )
        radius_agent.add_client(
            "13.126.39.79", "cg-omada-abcd1234", "a-secret-value", None
        )
        assert "require_message_authenticator = yes" in conf.read_text()

    def test_one_stanza_per_shortname_still_holds(self, conf: Path) -> None:
        """The property the whole write path rests on, re-asserted for a
        controller: a venue whose public address moves converges on a
        re-push instead of leaving a second stanza behind holding a
        still-valid secret."""
        radius_agent.add_client(
            "13.126.39.79", "cg-omada-abcd1234", "secret-one", True
        )
        result = radius_agent.add_client(
            "13.126.39.80", "cg-omada-abcd1234", "secret-two", True
        )
        assert result["superseded"] == 1
        text = conf.read_text()
        assert "secret-one" not in text
        assert "13.126.39.79" not in text


class TestThePastedUrlCarriesTheMode:
    def test_an_external_portal_url_is_byte_for_byte_unchanged(self) -> None:
        """No operator has to re-paste anything, and no already-configured
        controller changes behaviour, because the new parameter is only
        emitted for the mode that needs it."""
        url = build_external_portal_url(
            organization_id=uuid.UUID(int=1),
            location_id=uuid.UUID(int=2),
            router_id=uuid.UUID(int=3),
            provider="omada",
        )
        assert url is not None
        assert EXTERNAL_PORTAL_MODE_PARAM not in url.host_and_query

    def test_a_radius_url_names_the_mode(self) -> None:
        url = build_external_portal_url(
            organization_id=uuid.UUID(int=1),
            location_id=uuid.UUID(int=2),
            router_id=uuid.UUID(int=3),
            provider="omada",
            portal_mode=PortalAuthMode.RADIUS.value,
        )
        assert url is not None
        assert f"{EXTERNAL_PORTAL_MODE_PARAM}=radius" in url.host_and_query

    def test_the_query_still_follows_a_path_segment(self) -> None:
        """``ExternalRadiusSetting.externalUrl`` carries the same published
        regex as ``ExternalServerPortalSetting.serverUrl`` (re-read off the
        live controller's own /v3/api-docs, 2026-09-12): ``?`` and ``&``
        are inside the PATH character class, so a query string is legal
        only after a ``/``. A host-plus-query with no path is rejected by
        the controller outright."""
        url = build_external_portal_url(
            organization_id=uuid.UUID(int=1),
            location_id=uuid.UUID(int=2),
            router_id=uuid.UUID(int=3),
            provider="omada",
            portal_mode=PortalAuthMode.RADIUS.value,
        )
        assert url is not None
        host, _, query = url.host_and_query.partition("?")
        assert "/" in host
        assert query
