"""An environment that does not set the hub agent URLs must not reach any hub.

The defaults used to be the production hub's private address, so staging and
local runs were silently wired to the live hub (2026-10-02).
"""

import pytest

from app.core.config import Settings

HUB_URL_FIELDS = ("hub_wg_agent_url", "hub_wg_agent_peers_url", "hub_radius_agent_url")


@pytest.mark.parametrize("field", HUB_URL_FIELDS)
def test_hub_agent_url_has_no_infrastructure_default(field, monkeypatch) -> None:
    monkeypatch.delenv(f"CLOUDGUEST_{field.upper()}", raising=False)

    assert getattr(Settings(_env_file=None), field) == ""


@pytest.mark.parametrize("field", HUB_URL_FIELDS)
def test_hub_agent_url_still_comes_from_env(field, monkeypatch) -> None:
    monkeypatch.setenv(f"CLOUDGUEST_{field.upper()}", "http://10.0.0.5:9091/x")

    assert getattr(Settings(_env_file=None), field) == "http://10.0.0.5:9091/x"
