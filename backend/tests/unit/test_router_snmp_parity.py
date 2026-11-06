"""Generator-vs-writer parity for SNMP.

The device writer (``wyfy_device_gateway.mikrotik_snmp.apply_snmp_config``)
and the script renderer (``app.domains.network_config.snmp_renderer``) must
put the same object on the router. Substring checks have let this codebase
drift before (rule *content* asserted, rule *position* not), so this test
parses the rendered command back into field=value pairs and diffs it against
the writer's desired dicts, checks ordering, and checks that every rendered
line is structurally balanced.

It also pins the third path: the first-paste setup script in the frontend
never touches ``/snmp`` (checked on that side), and the customer-reachable
``render_network_config`` never renders SNMP (checked here).
"""

from __future__ import annotations

import inspect
import re

import pytest
from wyfy_device_gateway.mikrotik_snmp import (
    COMMUNITY_COMMENT,
    SnmpDeviceConfig,
    desired_community_row,
    desired_default_fence,
)

from app.domains.network_config import renderers
from app.domains.network_config.snmp_renderer import (
    SECRET_MASK,
    render_snmp_config,
    render_snmp_removal,
)

_PAIR = re.compile(r'([a-z-]+)="([^"]*)"')

CONFIGS = [
    SnmpDeviceConfig(name="comm12345", addresses=("172.31.38.118/32",)),
    SnmpDeviceConfig(
        name="monitor-user",
        addresses=("172.31.38.118/32", "172.31.45.127/32"),
        security="private",
        auth_protocol="SHA1",
        auth_password="authpass1",
        priv_protocol="AES",
        priv_password="privpass1",
    ),
]


def _segment(line: str, start: str, end: str) -> str:
    return line[line.index(start) + len(start) : line.index(end, line.index(start))]


@pytest.mark.parametrize("config", CONFIGS)
def test_rendered_community_equals_writer_desired_row(config: SnmpDeviceConfig) -> None:
    lines = render_snmp_config(config, mask_secrets=False)
    upsert = next(line for line in lines if "/snmp community add" in line)
    desired = desired_community_row(config)
    add_part = _segment(upsert, "/snmp community add ", "}")
    set_part = _segment(upsert, f'[find where comment="{COMMUNITY_COMMENT}"] ', "}")
    assert dict(_PAIR.findall(add_part)) == desired
    set_pairs = dict(_PAIR.findall(set_part))
    assert {k: set_pairs[k] for k in desired} == desired


def test_rendered_fence_equals_writer_fence() -> None:
    lines = render_snmp_config(CONFIGS[0], mask_secrets=False)
    fence_line = next(line for line in lines if "default=yes" in line)
    assert (
        dict(_PAIR.findall(_segment(fence_line, "set $c ", "}")))
        == desired_default_fence()
    )


def test_agent_enabled_only_after_community_and_fence() -> None:
    lines = render_snmp_config(CONFIGS[0], mask_secrets=False)
    enable = lines.index("/snmp set enabled=yes")
    assert any("/snmp community add" in line for line in lines[:enable])
    assert any("default=yes" in line for line in lines[:enable])


@pytest.mark.parametrize("config", CONFIGS)
def test_masked_render_leaks_no_secret(config: SnmpDeviceConfig) -> None:
    text = "\n".join(render_snmp_config(config))
    for secret in (config.name, config.auth_password, config.priv_password):
        if secret:
            assert secret not in text
    assert SECRET_MASK in text


@pytest.mark.parametrize(
    "lines",
    [render_snmp_config(c, mask_secrets=False) for c in CONFIGS]
    + [render_snmp_removal()],
)
def test_every_line_structurally_balanced(lines: list[str]) -> None:
    for line in lines:
        assert line.count("{") == line.count("}"), line
        assert line.count("[") == line.count("]"), line
        assert line.count('"') % 2 == 0, line
        assert line.count("(") == line.count(")"), line


def test_customer_reachable_network_config_never_renders_snmp() -> None:
    source = inspect.getsource(renderers.render_network_config)
    assert "snmp" not in source.lower()
