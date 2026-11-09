"""Notification webhooks cannot be aimed at internal addresses (security
review 2026-11-06, M3)."""

from __future__ import annotations

import httpx
import pytest

from app.common import outbound_http
from app.common.outbound_http import (
    BlockedDestinationError,
    PublicOnlyTransport,
    host_is_literal_non_public,
    is_public_address,
)
from app.domains.monitoring.constants import NotificationChannelType
from app.domains.monitoring.exceptions import InvalidNotificationChannelConfigError
from app.domains.monitoring.service import (
    NotificationDeliveryError,
    WebhookNotifier,
    _post_json,
)
from app.domains.monitoring.validators import validate_notification_channel_config


class TestAddressClassification:
    @pytest.mark.parametrize(
        "address",
        [
            "127.0.0.1",
            "10.0.0.5",
            "172.18.0.1",
            "192.168.88.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "224.0.0.1",
        ],
    )
    def test_internal_addresses_are_not_public(self, address: str) -> None:
        assert is_public_address(address) is False

    @pytest.mark.parametrize("address", ["8.8.8.8", "13.204.31.11", "2606:4700::1"])
    def test_public_addresses(self, address: str) -> None:
        assert is_public_address(address) is True

    def test_literal_hosts(self) -> None:
        assert host_is_literal_non_public("localhost")
        assert host_is_literal_non_public("[::1]")
        assert host_is_literal_non_public("169.254.169.254")
        assert not host_is_literal_non_public("hooks.slack.com")
        assert not host_is_literal_non_public("8.8.8.8")


class TestValidatorAtSave:
    def test_generic_webhook_requires_https(self) -> None:
        with pytest.raises(InvalidNotificationChannelConfigError):
            validate_notification_channel_config(
                NotificationChannelType.WEBHOOK, {"url": "http://example.com/hook"}
            )
        validate_notification_channel_config(
            NotificationChannelType.WEBHOOK, {"url": "https://example.com/hook"}
        )

    @pytest.mark.parametrize(
        ("channel_type", "key"),
        [
            (NotificationChannelType.WEBHOOK, "url"),
            (NotificationChannelType.SLACK, "webhook_url"),
        ],
    )
    @pytest.mark.parametrize(
        "url",
        [
            "https://127.0.0.1/x",
            "https://169.254.169.254/latest/meta-data",
            "https://localhost:8000/api/v1/x",
            "https://[::1]/x",
            "https://10.1.2.3/x",
        ],
    )
    def test_internal_literals_refused(
        self, channel_type: NotificationChannelType, key: str, url: str
    ) -> None:
        with pytest.raises(InvalidNotificationChannelConfigError):
            validate_notification_channel_config(channel_type, {key: url})


def _patch_resolver(monkeypatch: pytest.MonkeyPatch, answers: dict[str, list[str]]):
    async def fake_resolve(host: str, port: int) -> list[str]:
        return answers[host]

    monkeypatch.setattr(outbound_http, "_resolve", fake_resolve)


class TestTransportAtSend:
    async def test_hostname_resolving_inside_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_resolver(monkeypatch, {"evil.example": ["10.0.0.7"]})
        reached: list[str] = []

        async def fake_parent(self, request):  # noqa: ANN001
            reached.append(str(request.url))
            return httpx.Response(200)

        monkeypatch.setattr(
            httpx.AsyncHTTPTransport, "handle_async_request", fake_parent
        )
        async with httpx.AsyncClient(transport=PublicOnlyTransport()) as client:
            with pytest.raises(BlockedDestinationError):
                await client.post("https://evil.example/hook", json={})
        assert reached == []

    async def test_public_and_trusted_hosts_pass(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_resolver(
            monkeypatch,
            {"hooks.example.com": ["93.184.216.34"], "internal.n8n": ["172.18.0.9"]},
        )

        async def fake_parent(self, request):  # noqa: ANN001
            return httpx.Response(204)

        monkeypatch.setattr(
            httpx.AsyncHTTPTransport, "handle_async_request", fake_parent
        )
        transport = PublicOnlyTransport(trusted_hosts=["internal.n8n"])
        async with httpx.AsyncClient(transport=transport) as client:
            assert (await client.post("https://hooks.example.com/x")).status_code == 204
            assert (await client.post("https://internal.n8n/x")).status_code == 204

    async def test_mixed_answers_are_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A name that resolves to one public and one private address is
        refused: the connection could land on either."""
        _patch_resolver(monkeypatch, {"split.example": ["8.8.8.8", "127.0.0.1"]})
        async with httpx.AsyncClient(transport=PublicOnlyTransport()) as client:
            with pytest.raises(BlockedDestinationError):
                await client.get("https://split.example/")


class TestNoResponseEcho:
    async def test_error_body_is_not_returned(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="root:x:0:0 secret internal page")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        with pytest.raises(NotificationDeliveryError) as caught:
            await _post_json(client, "https://hooks.example.com/x", {})
        assert "secret" not in str(caught.value)
        assert "HTTP 500" in str(caught.value)

        notifier = WebhookNotifier(client)
        with pytest.raises(NotificationDeliveryError) as caught:
            await notifier.send_test(text="t", config={"url": "https://h.example/x"})
        assert "secret" not in str(caught.value)

    async def test_blocked_destination_message_is_plain(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise BlockedDestinationError("blocked", request=request)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        with pytest.raises(NotificationDeliveryError) as caught:
            await _post_json(client, "https://h.example/x", {})
        assert "private or internal" in str(caught.value)
