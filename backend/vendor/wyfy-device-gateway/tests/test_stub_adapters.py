"""Every stub vendor adapter must fully implement the
``DeviceGatewayAdapter`` Protocol shape (checkable via ``isinstance``
against the ``@runtime_checkable`` Protocol) and raise ``NotImplementedError``
from every operation, with ``capabilities()`` reporting nothing as
supported."""

from __future__ import annotations

import inspect

import pytest

from wyfy_device_gateway.contract import (
    DeviceCredentials,
    DeviceGatewayAdapter,
    DeviceVendor,
    DhcpPoolConfig,
    PortForwardConfig,
    RadiusClientConfig,
    VlanConfig,
)
from wyfy_device_gateway.stub_adapters import (
    ArubaAdapter,
    CiscoMerakiAdapter,
    RuckusAdapter,
    TpLinkAdapter,
    UnifiAdapter,
)

STUB_ADAPTER_CLASSES = [
    TpLinkAdapter,
    RuckusAdapter,
    UnifiAdapter,
    ArubaAdapter,
    CiscoMerakiAdapter,
]


def _fake_creds(vendor: DeviceVendor) -> DeviceCredentials:
    return DeviceCredentials(vendor=vendor, host="10.0.0.2", username="u", secret="s")


@pytest.mark.parametrize("adapter_cls", STUB_ADAPTER_CLASSES)
def test_stub_adapter_satisfies_protocol_shape(adapter_cls):
    adapter = adapter_cls()
    assert isinstance(adapter, DeviceGatewayAdapter)


@pytest.mark.parametrize("adapter_cls", STUB_ADAPTER_CLASSES)
def test_stub_adapter_reports_no_capabilities(adapter_cls):
    adapter = adapter_cls()
    capabilities = adapter.capabilities()
    assert capabilities  # non-empty
    assert all(value is False for value in capabilities.values())


@pytest.mark.parametrize("adapter_cls", STUB_ADAPTER_CLASSES)
@pytest.mark.asyncio
async def test_stub_adapter_every_method_raises_not_implemented(adapter_cls):
    adapter = adapter_cls()
    creds = _fake_creds(adapter.vendor)

    with pytest.raises(NotImplementedError):
        await adapter.get_interface_list(creds)
    with pytest.raises(NotImplementedError):
        await adapter.get_wan_health(creds, target_ip="1.1.1.1")
    with pytest.raises(NotImplementedError):
        await adapter.list_connected_devices(creds)
    with pytest.raises(NotImplementedError):
        await adapter.provision_device(creds, rendered_config="x", content_type="text")
    with pytest.raises(NotImplementedError):
        await adapter.reboot_device(creds)
    with pytest.raises(NotImplementedError):
        await adapter.configure_vlan(
            creds, vlan=VlanConfig(vlan_id=1, name="x", interface="eth0", ip_cidr=None)
        )
    with pytest.raises(NotImplementedError):
        await adapter.configure_dhcp_pool(
            creds,
            pool=DhcpPoolConfig(
                interface="eth0",
                range_start="10.0.0.2",
                range_end="10.0.0.10",
                gateway="10.0.0.1",
                dns_servers=[],
                lease_time_seconds=60,
            ),
        )
    with pytest.raises(NotImplementedError):
        await adapter.configure_port_forward(
            creds,
            rule=PortForwardConfig(
                rule_id="pf-1",
                protocol="tcp",
                external_port=80,
                internal_ip="10.0.0.5",
                internal_port=8080,
            ),
        )
    with pytest.raises(NotImplementedError):
        await adapter.set_radius_client_config(
            creds, config=RadiusClientConfig(radius_server_host="10.0.0.9", radius_secret="s")
        )
    with pytest.raises(NotImplementedError):
        await adapter.disconnect_device(creds, mac_address="AA:BB:CC:DD:EE:FF", interface=None)


@pytest.mark.parametrize("adapter_cls", STUB_ADAPTER_CLASSES)
@pytest.mark.asyncio
async def test_stub_adapter_diagnostics_and_isp_methods_raise_not_implemented(adapter_cls):
    """The previous test only covered the first 10 of the Protocol's 33
    methods. These 6 (diagnostics + isp-style WAN telemetry) are just as
    real a call surface (PRD section 2.1, items 2 and 6) and must fail the
    same honest way -- a caller reaching a non-MikroTik vendor here should
    get a clean NotImplementedError, never an AttributeError from a
    genuinely missing method."""
    adapter = adapter_cls()
    creds = _fake_creds(adapter.vendor)

    with pytest.raises(NotImplementedError):
        await adapter.ping(creds, target="1.1.1.1", count=4, timeout_seconds=5)
    with pytest.raises(NotImplementedError):
        await adapter.traceroute(creds, target="1.1.1.1", max_hops=10, timeout_seconds=5)
    with pytest.raises(NotImplementedError):
        await adapter.get_active_default_gateway(creds)
    with pytest.raises(NotImplementedError):
        await adapter.get_pppoe_interface_status(creds, interface_name="pppoe-out1")
    with pytest.raises(NotImplementedError):
        await adapter.get_interface_traffic_counters(creds, interface_name="ether1")
    with pytest.raises(NotImplementedError):
        await adapter.run_speed_test(creds, download_url="https://example.com/10MB.bin")


@pytest.mark.parametrize("adapter_cls", STUB_ADAPTER_CLASSES)
@pytest.mark.asyncio
async def test_stub_adapter_queue_management_methods_raise_not_implemented(adapter_cls):
    """QoS/bandwidth-shaping methods (PRD section 2.1 item 5) -- same
    coverage gap as the diagnostics test above."""
    adapter = adapter_cls()
    creds = _fake_creds(adapter.vendor)

    with pytest.raises(NotImplementedError):
        await adapter.create_simple_queue(
            creds,
            name="q1",
            target="10.0.0.5/32",
            download_rate_kbps=1000,
            upload_rate_kbps=1000,
        )
    with pytest.raises(NotImplementedError):
        await adapter.update_simple_queue(
            creds, device_queue_id="*1", download_rate_kbps=1000, upload_rate_kbps=1000
        )
    with pytest.raises(NotImplementedError):
        await adapter.delete_simple_queue(creds, device_queue_id="*1")
    with pytest.raises(NotImplementedError):
        await adapter.create_queue_tree(
            creds, name="t1", parent="global", packet_mark=None, max_limit_kbps=1000
        )
    with pytest.raises(NotImplementedError):
        await adapter.apply_pcq(creds, name="pcq1", rate_kbps=1000)
    with pytest.raises(NotImplementedError):
        await adapter.set_priority(creds, device_queue_id="*1", priority=4)
    with pytest.raises(NotImplementedError):
        await adapter.assign_queue_to_target(creds, device_queue_id="*1", target="10.0.0.6/32")
    with pytest.raises(NotImplementedError):
        await adapter.remove_queue(creds, device_queue_id="*1")
    with pytest.raises(NotImplementedError):
        await adapter.read_queue_status(creds, device_queue_id="*1")


@pytest.mark.parametrize("adapter_cls", STUB_ADAPTER_CLASSES)
@pytest.mark.asyncio
async def test_stub_adapter_provisioning_engine_methods_raise_not_implemented(adapter_cls):
    """Discovery/push/verify/health/backup/restore/raw-command (PRD section
    2.1 item 4) -- same coverage gap as the diagnostics test above."""
    adapter = adapter_cls()
    creds = _fake_creds(adapter.vendor)

    with pytest.raises(NotImplementedError):
        await adapter.discover(creds)
    with pytest.raises(NotImplementedError):
        await adapter.push_config(creds, config_content="/ip address add ...")
    with pytest.raises(NotImplementedError):
        await adapter.verify_config(creds, expected_content="/ip address add ...")
    with pytest.raises(NotImplementedError):
        await adapter.health_check(creds)
    with pytest.raises(NotImplementedError):
        await adapter.backup(creds)
    with pytest.raises(NotImplementedError):
        await adapter.restore(creds, backup_content=b"\x00\x01")
    with pytest.raises(NotImplementedError):
        await adapter.upload_file(creds, filename="x.rsc", content=b"data")
    with pytest.raises(NotImplementedError):
        await adapter.execute_raw_command(creds, command="/system/resource/print")


@pytest.mark.parametrize("adapter_cls", STUB_ADAPTER_CLASSES)
def test_stub_adapter_error_message_mentions_prd(adapter_cls):
    adapter = adapter_cls()
    err = adapter._not_implemented()
    assert "PRD section 3" in str(err)
    assert "not yet implemented" in str(err)


@pytest.mark.parametrize("adapter_cls", STUB_ADAPTER_CLASSES)
@pytest.mark.asyncio
async def test_every_protocol_method_raises_not_implemented(adapter_cls):
    """The hand-written tests above name methods one by one, so a method
    added to the Protocol later is covered by none of them -- which is how
    the stubs went nineteen methods short of the Protocol without a single
    failure. This walks the Protocol itself instead. The stubs ignore their
    arguments, so every keyword-only parameter is passed as ``None``."""
    adapter = adapter_cls()
    creds = _fake_creds(adapter.vendor)
    for name in sorted(DeviceGatewayAdapter.__protocol_attrs__):
        if name == "capabilities":
            continue
        method = getattr(adapter, name)
        if not inspect.iscoroutinefunction(method):
            continue
        kwargs = {
            param.name: None
            for param in inspect.signature(method).parameters.values()
            if param.kind is inspect.Parameter.KEYWORD_ONLY
        }
        with pytest.raises(NotImplementedError):
            await method(creds, **kwargs)
