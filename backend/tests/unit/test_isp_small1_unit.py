"""SMALL-1: the per-subscriber discount classifier for bulk renew (pure)."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

from app.domains.isp_partner import bulk_discount as bd


def _code(**kw):  # noqa: ANN003, ANN202
    base = {
        "id": uuid.uuid4(),
        "code": "X",
        "kind": "flat",
        "value": 5000,
        "active": True,
        "is_deleted": False,
        "valid_from": None,
        "valid_until": None,
        "max_uses": None,
        "used_count": 0,
        "min_amount_paise": None,
        "max_discount_paise": None,
        "package_ids": None,
    }
    base.update(kw)
    return SimpleNamespace(**base)


def test_reasons_in_order() -> None:
    p1, p2 = uuid.uuid4(), uuid.uuid4()
    d = _code(package_ids=[str(p1)], min_amount_paise=10000)
    assert bd.classify(d, gross_paise=50000, package_id=p2, remaining=None)[1] == (
        bd.SKIP_NOT_FOR_PACKAGE
    )
    assert bd.classify(d, gross_paise=0, package_id=p1, remaining=None)[1] == (
        bd.SKIP_NOTHING
    )
    assert bd.classify(d, gross_paise=9999, package_id=p1, remaining=None)[1] == (
        bd.SKIP_BELOW_MINIMUM
    )
    assert bd.classify(d, gross_paise=50000, package_id=p1, remaining=0)[1] == (
        bd.SKIP_USED_UP
    )
    q, reason = bd.classify(d, gross_paise=50000, package_id=p1, remaining=1)
    assert reason is None and q.amount_paise == 5000


def test_percent_half_up_and_real_counter() -> None:
    d = _code(kind="percent", value=1000)  # 10 %
    q, _ = bd.classify(d, gross_paise=12345, package_id=None, remaining=None)
    assert q.amount_paise == 1235
    used = _code(max_uses=1, used_count=1)
    assert bd.classify(used, gross_paise=100, package_id=None, remaining=None)[1] == (
        bd.SKIP_USED_UP
    )


def test_bulk_key_matches_dir2() -> None:
    sid = uuid.UUID(int=0xABCDEF)
    assert bd.bulk_idempotency_key("k" * 8, sid) == f"bulk-{'k' * 8}-{sid.hex[:12]}"
