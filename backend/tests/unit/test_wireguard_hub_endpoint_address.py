"""``resolve_hub_endpoint_address``: the raw-IP fallback the setup-script
generator uses when a router cannot resolve the hub's name at paste time."""

from __future__ import annotations

import asyncio
import socket

import pytest

from app.domains.wireguard import validators
from app.domains.wireguard.schemas import WireGuardTunnelCreateResponse
from app.domains.wireguard.validators import resolve_hub_endpoint_address

pytestmark = pytest.mark.asyncio


async def test_ipv4_literal_is_returned_unchanged() -> None:
    assert await resolve_hub_endpoint_address("13.201.253.36") == "13.201.253.36"


async def test_ipv6_literal_is_not_offered() -> None:
    # The generator's fallback is IPv4 only; hand it nothing rather than v6.
    assert await resolve_hub_endpoint_address("2001:db8::1") is None


async def test_blank_host_returns_none() -> None:
    assert await resolve_hub_endpoint_address("  ") is None


async def test_hostname_resolves_to_first_ipv4(monkeypatch) -> None:
    async def fake_getaddrinfo(host, port, *, family, type):  # noqa: A002
        assert host == "hub.example.test"
        assert family == socket.AF_INET
        return [(socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("203.0.113.7", 0))]

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
    assert await resolve_hub_endpoint_address("hub.example.test") == "203.0.113.7"


async def test_lookup_failure_returns_none(monkeypatch) -> None:
    async def failing(*_args, **_kwargs):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", failing)
    assert await resolve_hub_endpoint_address("hub.example.test") is None


async def test_slow_resolver_times_out_to_none(monkeypatch) -> None:
    async def slow(*_args, **_kwargs):
        await asyncio.sleep(5)
        return []

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", slow)
    result = await resolve_hub_endpoint_address(
        "hub.example.test", timeout_seconds=0.05
    )
    assert result is None


async def test_response_field_is_optional() -> None:
    # Older callers and tests build the response without it.
    fields = WireGuardTunnelCreateResponse.model_fields
    assert "hub_endpoint_address" in fields
    assert fields["hub_endpoint_address"].is_required() is False
    assert validators.resolve_hub_endpoint_address is resolve_hub_endpoint_address
