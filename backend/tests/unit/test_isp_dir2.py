"""DIR-2: flag, selection rules and the read-only eligibility checks that the
dry run reports (mirroring the single actions' own guard clauses). Real-DB
behaviour is in ``test_isp_dir2_postgres.py``."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.domains.isp_partner import directory_bulk_router as d

NOW = datetime(2026, 11, 1, 6, tzinfo=UTC)


def _s(**kw):
    base = {
        "status": "active",
        "package_id": uuid.uuid4(),
        "valid_until": NOW + timedelta(days=5),
        "customer_organization_id": uuid.uuid4(),
    }
    base.update(kw)
    return SimpleNamespace(**base)


def _p(**kw):
    base = {"block_kind": None, "frozen_at": None}
    base.update(kw)
    return SimpleNamespace(**base)


async def test_flag_defaults_off() -> None:
    d.get_dir2_settings.cache_clear()
    assert d.get_dir2_settings().enabled is False
    with pytest.raises(HTTPException) as exc:
        await d.RequireDir2Enabled()
    assert exc.value.status_code == 404


def test_selection_rules() -> None:
    ids = [uuid.uuid4()]
    d.BulkStatusRequest(action="block", subscriber_ids=ids)  # dry run by default
    d.BulkStatusRequest(action="block", filter=d.DirectoryFilter(state="active"))
    with pytest.raises(ValidationError):  # neither
        d.BulkStatusRequest(action="block")
    with pytest.raises(ValidationError):  # both
        d.BulkStatusRequest(
            action="block", subscriber_ids=ids, filter=d.DirectoryFilter()
        )
    with pytest.raises(ValidationError):  # apply without a bulk_key
        d.BulkStatusRequest(action="block", subscriber_ids=ids, dry_run=False)
    d.BulkStatusRequest(
        action="block", subscriber_ids=ids, dry_run=False, bulk_key="k" * 8
    )
    with pytest.raises(ValidationError):  # permanent blocks are not offered in bulk
        d.BulkStatusRequest(action="permanent", subscriber_ids=ids)
    with pytest.raises(ValidationError):
        d.BulkStatusRequest(
            action="block", subscriber_ids=[uuid.uuid4()] * (d.MAX_BULK + 1)
        )


def test_renew_skip() -> None:
    assert d.renew_skip(_s(), _p()) is None
    assert d.renew_skip(_s(), None) is None
    assert d.renew_skip(_s(), _p(block_kind="temporary")) == "blocked"
    assert d.renew_skip(_s(), _p(frozen_at=NOW)) == "frozen"
    assert d.renew_skip(_s(status="disabled"), _p()) == "disabled"
    assert d.renew_skip(_s(package_id=None), _p()) == "no_package"


@pytest.mark.parametrize(
    ("action", "s", "p", "role", "want"),
    [
        ("block", _s(), _p(), "isp-noc", None),
        ("block", _s(), _p(block_kind="temporary"), "isp-noc", "already_blocked"),
        ("unblock", _s(), _p(), "isp-noc", "not_blocked"),
        ("unblock", _s(), _p(block_kind="temporary"), "isp-noc", None),
        (
            "unblock",
            _s(),
            _p(block_kind="permanent"),
            "isp-noc",
            "permanent_owner_only",
        ),
        ("unblock", _s(), _p(block_kind="permanent"), "isp-owner", None),
        ("freeze", _s(), _p(), "isp-noc", None),
        (
            "freeze",
            _s(valid_until=NOW - timedelta(days=1)),
            _p(),
            "isp-noc",
            "no_validity_left",
        ),
        ("freeze", _s(), _p(frozen_at=NOW), "isp-noc", "already_frozen"),
        ("freeze", _s(), _p(block_kind="temporary"), "isp-noc", "blocked"),
        ("unfreeze", _s(), _p(), "isp-noc", "not_frozen"),
        ("unfreeze", _s(), _p(frozen_at=NOW), "isp-noc", None),
    ],
)
def test_status_skip(action, s, p, role, want) -> None:
    assert d.status_skip(action, s, p, role_slug=role, now=NOW) == want


def test_move_skip() -> None:
    s = _s()
    assert d.move_skip(s, s.customer_organization_id) == "already_there"
    assert d.move_skip(s, uuid.uuid4()) is None
