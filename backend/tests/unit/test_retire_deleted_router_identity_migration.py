"""0183: free the serial/MAC held by already soft-deleted ``routers`` rows.

No database in CI, so the revision is run against a recording bind: what it
selects, what it updates, and that its derivation is the service's.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from app.domains.router.service import retired_router_identity

FILE = pathlib.Path("alembic/versions/0183_retire_deleted_router_identity.py")


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("rev0183", FILE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _row(serial: str, mac: str, *, deleted_at: datetime | None = None) -> Any:
    return SimpleNamespace(
        id=uuid.uuid4(), serial_number=serial, mac_address=mac, deleted_at=deleted_at
    )


class _Bind:
    def __init__(self, rows: list[Any]) -> None:
        self.rows = rows
        self.executed: list[tuple[str, dict[str, Any] | None]] = []

    def execute(self, statement: Any, params: dict[str, Any] | None = None) -> Any:
        self.executed.append((str(statement), params))
        return self.rows if params is None else None


def _run_upgrade(monkeypatch: pytest.MonkeyPatch, rows: list[Any]) -> _Bind:
    module = _load()
    bind = _Bind(rows)
    monkeypatch.setattr(module, "op", SimpleNamespace(get_bind=lambda: bind))
    module.upgrade()
    return bind


def test_chains_on_the_previous_head() -> None:
    module = _load()
    assert module.revision == "0183_retire_deleted_router_identity"
    assert module.down_revision == "0181_add_router_local_admin_password"


def test_reads_and_writes_deleted_rows_only(monkeypatch) -> None:
    deleted = _row("VNV5M1K1M6", "54:F0:B1:C8:A9:0A")
    bind = _run_upgrade(monkeypatch, [deleted])

    select_sql, _ = bind.executed[0]
    assert "WHERE is_deleted = true" in select_sql
    assert "NOT LIKE '%-deleted-%'" in select_sql
    updates = [(sql, p) for sql, p in bind.executed if p is not None]
    assert len(updates) == 1
    sql, params = updates[0]
    assert sql.startswith("UPDATE routers SET serial_number = :serial")
    # The UPDATE re-checks the soft delete itself: a row restored between the
    # SELECT and the UPDATE is not touched.
    assert "WHERE id = :id AND is_deleted = true" in sql
    assert params["id"] == deleted.id


def test_matches_the_service_derivation_and_keeps_the_real_values(
    monkeypatch,
) -> None:
    deleted_at = datetime(2026, 11, 2, 9, 30, tzinfo=UTC)
    deleted = _row("VNV5M1K1M6", "54:F0:B1:C8:A9:0A", deleted_at=deleted_at)
    bind = _run_upgrade(monkeypatch, [deleted])

    (params,) = [p for _sql, p in bind.executed if p is not None]
    assert (params["serial"], params["mac"]) == retired_router_identity(
        deleted.id, "VNV5M1K1M6", deleted_at
    )
    assert params["serial"].startswith("VNV5M1K1M6-deleted-20261102-")
    kept = json.loads(params["retired"])["retired_identity"]
    assert kept["serial_number"] == "VNV5M1K1M6"
    assert kept["mac_address"] == "54:F0:B1:C8:A9:0A"


def test_already_retired_rows_are_skipped_so_a_rerun_is_a_no_op(monkeypatch) -> None:
    # The row freed by hand on prod 2026-11-12, and one the service retired.
    by_hand = _row("VNV5M1K1M6-deleted-20261112", "DE:1E:7E:37:FE:E5")
    by_service = _row("HB31090ABCD-deleted-20261112-0a1b2c3d", "02:00:00:00:00:01")
    bind = _run_upgrade(monkeypatch, [by_hand, by_service])
    assert [p for _sql, p in bind.executed if p is not None] == []


def test_downgrade_writes_nothing(monkeypatch) -> None:
    module = _load()
    bind = _Bind([])
    monkeypatch.setattr(module, "op", SimpleNamespace(get_bind=lambda: bind))
    module.downgrade()
    assert bind.executed == []
