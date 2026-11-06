# ruff: noqa: E501 -- golden RouterOS lines are compared verbatim, unwrapped.
"""RouterOS script injection through tenant-named rules (security review
2026-11-06, M1).

Two halves, and the first is the one live routers depend on:

* **Golden output.** Ordinary names render byte-for-byte what they rendered
  before the escaper was strengthened, so no router sees a config diff from
  this change. The expected strings below were captured from the renderers
  on ``origin/main`` before the fix.
* **Hostile names.** ``$``, ``[``, ``"``, ``;`` and newlines can neither run
  a substitution nor end the quoted string, and the API refuses them at the
  schema in the first place.
"""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from app.domains.content_filtering.schemas import ContentFilterRuleCreateRequest
from app.domains.dns.schemas import DnsRecordCreateRequest
from app.domains.firewall.schemas import FirewallRuleUpdateRequest
from app.domains.hotspot.schemas import HotspotProfileCreateRequest
from app.domains.network_config.profiles.constants import (
    escape_routeros_string,
    routeros_value,
)
from app.domains.network_config.renderers import (
    render_content_filter_rule,
    render_dns_record,
    render_firewall_rule,
    render_hotspot_profile,
    render_port_forwarding_rule,
    render_qos_traffic_rule,
)
from app.domains.port_forwarding.schemas import (
    PortForwardingRuleCreateRequest,
    PortForwardingRuleUpdateRequest,
)
from app.domains.qos.schemas import QosTrafficRuleCreateRequest

from .test_network_config import (
    _make_content_filter_rule,
    _make_dns_record,
    _make_firewall_rule,
    _make_hotspot_profile,
    _make_qos_rule,
    _make_rule,
)

_HOTSPOT_ID = uuid.UUID("11111111-2222-4333-8444-555555555555")
_QOS_ID = uuid.UUID("66666666-7777-4888-9999-aaaaaaaaaaaa")


class TestGoldenOutputUnchanged:
    def test_port_forwarding(self) -> None:
        assert render_port_forwarding_rule(
            _make_rule(name="CCTV NVR (front gate) #2")
        ) == [
            '/ip firewall nat add chain=dstnat protocol=tcp dst-port=8080 action=dst-nat to-addresses=192.168.1.10 to-ports=80 comment="CCTV NVR (front gate) #2"',
        ]

    def test_hotspot_profile(self) -> None:
        assert render_hotspot_profile(
            _make_hotspot_profile(
                id=_HOTSPOT_ID,
                name="Guest Café 2-hr",
                walled_garden_hosts=["*.example.com", "pay.razorpay.com"],
            )
        ) == [
            ':if ([:len [/ip hotspot user profile find where name="guest-café-2-hr-11111111"]] = 0) do={ /ip hotspot user profile add name=guest-café-2-hr-11111111 session-timeout=240m idle-timeout=15m rate-limit=1024k/4096k } else={ /ip hotspot user profile set [/ip hotspot user profile find where name="guest-café-2-hr-11111111"] session-timeout=240m idle-timeout=15m rate-limit=1024k/4096k }',
            ':if ([:len [/ip hotspot walled-garden find where dst-host="*.example.com" && comment="Guest Café 2-hr"]] = 0) do={ /ip hotspot walled-garden add dst-host=*.example.com action=allow comment="Guest Café 2-hr" }',
            ':if ([:len [/ip hotspot walled-garden find where dst-host="pay.razorpay.com" && comment="Guest Café 2-hr"]] = 0) do={ /ip hotspot walled-garden add dst-host=pay.razorpay.com action=allow comment="Guest Café 2-hr" }',
        ]

    def test_qos(self) -> None:
        assert render_qos_traffic_rule(
            _make_qos_rule(id=_QOS_ID, name="Zoom / Teams calls")
        ) == [
            '/ip firewall mangle add chain=prerouting protocol=udp dst-port=5060-5061 action=mark-packet new-packet-mark=zoom-teams-calls-66666666 passthrough=no comment="Zoom / Teams calls (priority=1)"',
        ]

    def test_dns(self) -> None:
        assert render_dns_record(_make_dns_record(comment="Printer, 2nd floor")) == [
            '/ip dns static add name=printer.local ttl=3600s address=192.168.1.50 comment="Printer, 2nd floor"',
        ]

    def test_firewall(self) -> None:
        assert render_firewall_rule(
            _make_firewall_rule(name="Block SMB", comment="Staff LAN - no SMB")
        ) == [
            '/ip firewall filter add chain=input protocol=tcp dst-port=23 action=drop comment="Staff LAN - no SMB (priority=10)"',
        ]

    def test_content_filter(self) -> None:
        assert render_content_filter_rule(
            _make_content_filter_rule(name="Owner's blocklist")
        ) == [
            '/ip dns static add name=facebook.com type=A address=127.0.0.1 comment="social_media: Owner\'s blocklist"',
            '/ip dns static add regexp="^.*\\.facebook\\.com$" type=A address=127.0.0.1 comment="social_media: Owner\'s blocklist (subdomains)"',
        ]


class TestEscaper:
    def test_plain_text_is_untouched(self) -> None:
        for value in ["Web Server", "Café (2nd floor) #2", "a-b_c.d/e:f@g", ""]:
            assert escape_routeros_string(value) == value

    def test_every_special_character_is_escaped(self) -> None:
        assert escape_routeros_string('a\\b"c$d?e') == 'a\\\\b\\"c\\$d\\?e'
        assert escape_routeros_string("x\ny\rz\tw") == "x\\ny\\rz\\tw"
        assert escape_routeros_string("bell\x07") == "bell\\07"

    def test_bare_value_quotes_only_when_needed(self) -> None:
        assert routeros_value("*.example.com") == "*.example.com"
        assert routeros_value("10.0.0.1") == "10.0.0.1"
        assert routeros_value("x.com;/system reboot") == '"x.com;/system reboot"'
        assert routeros_value('a" b') == '"a\\" b"'


_HOSTILE = 'x" ; /system reboot ; :put "$[/user print]\n/ip service enable api'


def _no_breakout(line: str) -> None:
    """Every ``$`` is escaped and the line is still one line."""
    assert "\n" not in line
    for index, ch in enumerate(line):
        if ch == "$":
            assert line[index - 1] == "\\", line


class TestHostileNamesCannotBreakOut:
    def test_port_forward_comment(self) -> None:
        (line,) = render_port_forwarding_rule(_make_rule(name=_HOSTILE))
        _no_breakout(line)
        assert line.endswith(
            'comment="x\\" ; /system reboot ; :put '
            '\\"\\$[/user print]\\n/ip service enable api"'
        )

    def test_hotspot_profile_and_hosts(self) -> None:
        lines = render_hotspot_profile(
            _make_hotspot_profile(name=_HOSTILE, walled_garden_hosts=["a.com;/x"])
        )
        for line in lines:
            _no_breakout(line)
        assert 'dst-host="a.com;/x"' in lines[1]
        assert "dst-host=a.com;/x" not in lines[1]

    def test_qos_dns_firewall_content_filter(self) -> None:
        rendered = [
            *render_qos_traffic_rule(_make_qos_rule(name=_HOSTILE)),
            *render_dns_record(_make_dns_record(comment=_HOSTILE)),
            *render_firewall_rule(_make_firewall_rule(comment=_HOSTILE)),
            *render_content_filter_rule(_make_content_filter_rule(name=_HOSTILE)),
        ]
        for line in rendered:
            if "regexp=" in line:
                line = line.split("regexp=", 1)[0] + line.split(" type=A", 1)[1]
            _no_breakout(line)


class TestSchemaRefusesScriptCharacters:
    @pytest.mark.parametrize(
        "bad", ['a"b', "a$b", "a[b]", "a;b", "a\\b", "a?b", "a\nb", "a{b}", "a`b"]
    )
    def test_port_forward_name(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            PortForwardingRuleCreateRequest(
                router_id="r",
                name=bad,
                destination_port=80,
                internal_address="10.0.0.2",
                internal_port=80,
            )
        with pytest.raises(ValidationError):
            PortForwardingRuleUpdateRequest(name=bad)

    def test_other_rule_types(self) -> None:
        with pytest.raises(ValidationError):
            QosTrafficRuleCreateRequest.model_validate(
                {"router_id": "r", "name": "$x", "priority": 1}
            )
        with pytest.raises(ValidationError):
            DnsRecordCreateRequest.model_validate(
                {
                    "router_id": "r",
                    "name": "a.local",
                    "address": "1.1.1.1",
                    "record_type": "a",
                    "comment": "x;y",
                }
            )
        with pytest.raises(ValidationError):
            HotspotProfileCreateRequest.model_validate(
                {"router_id": "r", "name": "a[b]"}
            )
        with pytest.raises(ValidationError):
            FirewallRuleUpdateRequest(comment='"')
        with pytest.raises(ValidationError):
            ContentFilterRuleCreateRequest.model_validate(
                {
                    "router_id": "r",
                    "name": "a$b",
                    "value_type": "domain",
                    "value": "x.com",
                }
            )

    def test_ordinary_names_still_accepted(self) -> None:
        for good in [
            "Web Server",
            "CCTV (front) #2",
            "Café 2nd-floor",
            "John's PC",
            "Zoom / Teams, 50%",
            "गेस्ट वाईफाई",
        ]:
            assert PortForwardingRuleUpdateRequest(name=good).name == good
            assert FirewallRuleUpdateRequest(comment=good).comment == good
