"""SCOPE-FIX: the ``pppoe_session_id`` path id resolves inside the caller's ISP
and customer scope before any disconnect is sent. (The PG scenario in
``test_isp_scope_fix_postgres.py`` covers the other ids; a live PPPoE session
needs a NAS client + router, so this one is checked at the service.)"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.domains.isp_partner.pppoe_service import IspPppoeService
from app.domains.rbac.scope_params import (
    NOT_SCOPE_BEARING_ID_PARAMS,
    SCOPE_PARAM_ALIASES,
)

ISP, OTHER_ISP = uuid.uuid4(), uuid.uuid4()
C1, C2 = uuid.uuid4(), uuid.uuid4()


class _Session:
    def __init__(self, row):
        self.row = row

    async def get(self, _model, _id):
        return self.row


class _Repo:
    async def get_organization(self, org_id):
        return SimpleNamespace(
            id=org_id,
            is_deleted=False,
            status="active",
            org_type="standard",
            parent_organization_id=ISP,
        )


def _isp(confined):
    return SimpleNamespace(
        isp_org_id=ISP, confined_customer_ids=confined, repository=_Repo()
    )


def _row(isp, customer):
    return SimpleNamespace(
        id=uuid.uuid4(), isp_organization_id=isp, customer_organization_id=customer
    )


async def _scoped(isp, row):
    return await IspPppoeService(session=_Session(row))._session_scoped(
        isp, uuid.uuid4()
    )


async def test_own_session_resolves() -> None:
    row = _row(ISP, C1)
    assert await _scoped(_isp(None), row) is row
    assert await _scoped(_isp(frozenset({C1})), row) is row


@pytest.mark.parametrize(
    ("row", "confined"),
    [
        (None, None),  # unknown id
        (_row(OTHER_ISP, C1), None),  # another ISP's session
        (_row(ISP, C2), frozenset({C1})),  # outside a confined caller's list
    ],
)
async def test_foreign_session_is_not_found(row, confined) -> None:
    with pytest.raises(Exception) as exc:  # noqa: PT011
        await _scoped(_isp(confined), row)
    assert type(exc.value).__name__ == "IspPppoeSessionNotFoundError"


def test_isp_path_ids_are_not_scope_aliases() -> None:
    fixed = {
        "announcement_id", "assignee_user_id", "binding_id", "checkout_id",
        "discount_id", "document_id", "fiber_node_id", "item_id", "lead_id",
        "lease_id", "parent_id", "pppoe_session_id", "product_id",
        "stock_location_id", "subject_id", "task_id", "type_id", "unit_id",
        "vendor_id",
    }  # fmt: skip
    assert fixed <= NOT_SCOPE_BEARING_ID_PARAMS
    assert not fixed & set(SCOPE_PARAM_ALIASES)
