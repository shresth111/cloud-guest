"""0173: ``portal_impressions`` + ``guest_sessions.internet_confirmed_*``.

No database in CI, so the revision's ``op`` calls are recorded and checked:
it chains on the previous head, creates exactly what the models declare,
and its downgrade undoes every one of its upgrade's objects.
"""

from __future__ import annotations

import contextlib
import importlib.util
import pathlib
from typing import Any

import pytest
import sqlalchemy as sa

from app.domains.analytics.models import PortalImpression
from app.domains.guest.models import GuestSession

FILE = pathlib.Path("alembic/versions/0173_login_funnel_stage_tracking.py")


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("rev0173", FILE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _MigrationContext:
    @contextlib.contextmanager
    def autocommit_block(self):
        yield


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple, dict]] = []

    def get_context(self) -> _MigrationContext:
        return _MigrationContext()

    def __getattr__(self, name: str):
        def _call(*args, **kwargs):
            self.calls.append((name, args, kwargs))

        return _call


def _run(monkeypatch: pytest.MonkeyPatch, fn: str) -> _Recorder:
    module = _load()
    recorder = _Recorder()
    monkeypatch.setattr(module, "op", recorder)
    getattr(module, fn)()
    return recorder


def test_chains_on_the_previous_head() -> None:
    module = _load()
    assert module.revision == "0173_login_funnel_stage_tracking"
    assert module.down_revision == "0172_add_otp_sms_usage_index"


def test_creates_exactly_the_model_columns(monkeypatch) -> None:
    rec = _run(monkeypatch, "upgrade")
    (create,) = [c for c in rec.calls if c[0] == "create_table"]
    name, *columns = create[1]
    assert name == "portal_impressions"
    created = {c.name for c in columns if isinstance(c, sa.Column)}
    assert created == set(PortalImpression.__table__.c.keys())
    # Never a column that could hold personal data.
    assert not created & {"mac_address", "ip_address", "user_agent", "identifier"}


def test_indexes_match_the_models(monkeypatch) -> None:
    rec = _run(monkeypatch, "upgrade")
    created = {c[1][0] for c in rec.calls if c[0] == "create_index"}
    model_indexes = {i.name for i in PortalImpression.__table__.indexes} | {
        "ix_guest_sessions_internet_confirmed"
    }
    assert created == model_indexes
    assert "ix_guest_sessions_internet_confirmed" in {
        i.name for i in GuestSession.__table__.indexes
    }


def test_guest_session_columns_are_nullable_without_default(monkeypatch) -> None:
    rec = _run(monkeypatch, "upgrade")
    added = {c[1][1].name: c[1][1] for c in rec.calls if c[0] == "add_column"}
    assert set(added) == {"internet_confirmed_at", "internet_confirmed_source"}
    for column in added.values():
        assert column.nullable is True
        assert column.server_default is None  # catalog-only ALTER, no rewrite
        assert column.name in GuestSession.__table__.c


def test_downgrade_undoes_upgrade(monkeypatch) -> None:
    up = _run(monkeypatch, "upgrade")
    down = _run(monkeypatch, "downgrade")
    assert {c[1][0] for c in up.calls if c[0] == "create_index"} == {
        c[1][0] for c in down.calls if c[0] == "drop_index"
    }
    assert {c[1][1].name for c in up.calls if c[0] == "add_column"} == {
        c[1][1] for c in down.calls if c[0] == "drop_column"
    }
    assert [c[1][0] for c in down.calls if c[0] == "drop_table"] == [
        "portal_impressions"
    ]
    # Indexes go before their table.
    names = [c[0] for c in down.calls]
    assert names.index("drop_table") == len(names) - 1


def test_guest_sessions_index_is_built_concurrently(monkeypatch) -> None:
    # guest_sessions takes a write on every sign-in; a plain CREATE INDEX
    # would block those for the length of the build.
    rec = _run(monkeypatch, "upgrade")
    idx = [
        kw
        for name, args, kw in rec.calls
        if name == "create_index" and args and args[1] == "guest_sessions"
    ]
    assert idx and all(kw.get("postgresql_concurrently") is True for kw in idx)
