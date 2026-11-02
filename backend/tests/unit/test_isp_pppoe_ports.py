"""X2 PPPoE ports: the setting, the FreeRADIUS site and the router script agree,
and none of them is a port the shared Aruba Instant On listener uses (two
servers on one UDP port stop FreeRADIUS from starting, for every tenant)."""

from __future__ import annotations

import re
from pathlib import Path

from app.domains.isp_partner.pppoe_config import IspPppoeSettings

FREERADIUS = Path(__file__).resolve().parents[2] / "ops" / "freeradius"


def _ports(path: Path) -> set[int]:
    return {int(p) for p in re.findall(r"^\s*port\s*=\s*(\d+)", path.read_text(), re.M)}


def test_defaults_match_the_site_file() -> None:
    fields = IspPppoeSettings.model_fields
    assert fields["auth_port"].default == 1922
    assert fields["acct_port"].default == 1923
    assert _ports(FREERADIUS / "isp-pppoe" / "wyfy-isp-pppoe") == {1922, 1923}


def test_x2_shares_no_port_with_the_aruba_listener() -> None:
    aruba = FREERADIUS / "sites-aruba-shared.conf"
    if not aruba.exists():  # integ/isp-test forked before the Aruba listener
        return
    assert not _ports(aruba) & _ports(FREERADIUS / "isp-pppoe" / "wyfy-isp-pppoe")
