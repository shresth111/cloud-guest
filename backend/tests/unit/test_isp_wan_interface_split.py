"""Unit tests for Wave 1 Step 4: WAN physical/routing interface split."""

from __future__ import annotations

import uuid

import pytest

from app.domains.isp.constants import IspConnectionMode, IspLinkRole
from app.domains.isp.exceptions import IspLinkInterfaceInvariantError
from app.domains.isp.models import IspLink
from app.domains.isp.service import (
    _has_pppoe_password,
    get_decrypted_pppoe_password,
)
from app.domains.isp.validators import (
    derive_pppoe_routing_interface,
    normalize_isp_link_interfaces,
)
from app.domains.router.crypto import encrypt_secret
from tests.unit.test_isp import FakeIspRepository, FakeRouterLookup, _make_router


def test_derive_pppoe_routing_interface() -> None:
    assert derive_pppoe_routing_interface(wan_slot=1) == "pppoe-wan1"
    assert derive_pppoe_routing_interface(wan_slot=3) == "pppoe-wan3"


def test_static_normalizes_physical_equals_routing() -> None:
    physical, routing, legacy = normalize_isp_link_interfaces(
        connection_mode=IspConnectionMode.STATIC.value,
        physical_interface="ether1",
        is_create=True,
    )
    assert physical == routing == legacy == "ether1"


def test_static_rejects_mismatched_routing() -> None:
    with pytest.raises(IspLinkInterfaceInvariantError, match="equal to"):
        normalize_isp_link_interfaces(
            connection_mode=IspConnectionMode.STATIC.value,
            physical_interface="ether1",
            routing_interface="ether2",
            is_create=True,
        )


def test_dhcp_accepts_legacy_interface_field() -> None:
    physical, routing, legacy = normalize_isp_link_interfaces(
        connection_mode=IspConnectionMode.DHCP.value,
        interface="ether2",
        is_create=True,
    )
    assert physical == routing == legacy == "ether2"


def test_pppoe_requires_both_credentials_when_either_supplied() -> None:
    with pytest.raises(IspLinkInterfaceInvariantError, match="pppoe_password"):
        normalize_isp_link_interfaces(
            connection_mode=IspConnectionMode.PPPOE.value,
            physical_interface="ether1",
            pppoe_username="user@isp",
            has_pppoe_password=False,
            is_create=True,
        )


def test_pppoe_without_credentials_allows_legacy_device_configured_links() -> None:
    physical, routing, legacy = normalize_isp_link_interfaces(
        connection_mode=IspConnectionMode.PPPOE.value,
        interface="pppoe-out1",
        is_create=True,
    )
    assert physical is None
    assert routing == legacy == "pppoe-out1"


def test_pppoe_with_physical_interface_uses_wan_slot_routing() -> None:
    physical, routing, legacy = normalize_isp_link_interfaces(
        connection_mode=IspConnectionMode.PPPOE.value,
        physical_interface="ether1",
        is_create=True,
    )
    assert physical == "ether1"
    assert routing == legacy == "pppoe-wan1"


def test_pppoe_derives_routing_interface() -> None:
    physical, routing, legacy = normalize_isp_link_interfaces(
        connection_mode=IspConnectionMode.PPPOE.value,
        physical_interface="ether1",
        pppoe_username="user@isp",
        has_pppoe_password=True,
        wan_slot=2,
        is_create=True,
    )
    assert physical == "ether1"
    assert routing == legacy == "pppoe-wan2"


def test_has_pppoe_credentials_and_decrypt_roundtrip() -> None:
    encrypted = encrypt_secret("secret-pass")
    link = IspLink(
        id=uuid.uuid4(),
        router_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        location_id=uuid.uuid4(),
        provider_name="ISP",
        link_type="fiber",
        connection_mode=IspConnectionMode.PPPOE.value,
        role=IspLinkRole.PRIMARY.value,
        is_active_uplink=True,
        auto_failback=True,
        is_enabled=True,
        priority=0,
        health_status="unknown",
        health_status_source="automated",
        consecutive_unhealthy_count=0,
        pppoe_password_encrypted=encrypted,
    )
    assert _has_pppoe_password(link) is True
    assert get_decrypted_pppoe_password(link) == "secret-pass"


@pytest.mark.asyncio
async def test_create_pppoe_link_persists_split_and_encrypted_password() -> None:
    from app.domains.isp.service import IspService

    router = _make_router()
    repo = FakeIspRepository()
    service = IspService(
        repository=repo,
        router_lookup=FakeRouterLookup({router.id: router}),
        audit_writer=None,
        redis=None,
    )
    link = await service.create_link(
        actor_user_id=None,
        requesting_organization_id=router.organization_id,
        router_id=router.id,
        provider_name="Fiber ISP",
        link_type="fiber",
        connection_mode=IspConnectionMode.PPPOE.value,
        role=IspLinkRole.PRIMARY,
        physical_interface="ether1",
        pppoe_username="user@isp",
        pppoe_password="hunter2",
        dns_override=["8.8.8.8"],
    )
    assert link.physical_interface == "ether1"
    assert link.routing_interface == "pppoe-wan1"
    assert link.interface == "pppoe-wan1"
    assert link.pppoe_username == "user@isp"
    assert link.dns_override == ["8.8.8.8"]
    assert get_decrypted_pppoe_password(link) == "hunter2"
