"""RAKESH-FS: ``/isp/workflow`` flag + the MB<->GB boundary helpers.

The console enters/shows GB; the database keeps whole MB unchanged
(``data_cap_mb``, ``fup_limit_mb``). Route-table rules (guards, no
scope-alias path names) are walked for every isp_partner route by
``test_isp_partner_guards``.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.domains.isp_partner import workflow_config as wc


async def test_flag_defaults_off() -> None:
    wc.get_workflow_settings.cache_clear()
    assert wc.get_workflow_settings().enabled is False
    assert wc.franchisee_logins_on() is False
    with pytest.raises(HTTPException) as exc:
        await wc.RequireWorkflowEnabled()
    assert exc.value.status_code == 404


def test_flag_on(monkeypatch) -> None:
    monkeypatch.setenv("ISP_WORKFLOW_ENABLED", "true")
    wc.get_workflow_settings.cache_clear()
    try:
        assert wc.get_workflow_settings().enabled is True
    finally:
        monkeypatch.delenv("ISP_WORKFLOW_ENABLED")
        wc.get_workflow_settings.cache_clear()


@pytest.mark.parametrize(
    ("gb", "mb"),
    [
        (3000, 3_072_000),
        (1.5, 1536),
        (0.5, 512),
        (0.001, 1),  # never rounds a positive limit to 0
        (1.0005, 1025),
        (1_000_000, 1_024_000_000),
        (0, 0),
        (None, None),
    ],
)
def test_gb_to_mb(gb, mb) -> None:
    assert wc.gb_to_mb(gb) == mb


def test_gb_to_mb_refuses_negative() -> None:
    with pytest.raises(ValueError):
        wc.gb_to_mb(-1)


@pytest.mark.parametrize(
    ("mb", "gb"),
    [(3_072_000, 3000.0), (1536, 1.5), (500, 0.488), (None, None), (1, 0.001)],
)
def test_mb_to_gb(mb, gb) -> None:
    assert wc.mb_to_gb(mb) == gb


def test_round_trip_whole_gb_is_exact() -> None:
    for g in (1, 10, 999, 3000, 50_000, 1_000_000):
        assert wc.mb_to_gb(wc.gb_to_mb(g)) == g


def test_largest_form_value_fits_existing_int_column() -> None:
    # isp_packages.data_cap_mb is INTEGER (int4); the console caps at 1e6 GB.
    assert wc.gb_to_mb(1_000_000) < 2**31 - 1
