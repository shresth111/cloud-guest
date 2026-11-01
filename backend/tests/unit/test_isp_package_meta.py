"""PKG-2: package type + connection type (``/isp/package-meta``).

Flag default OFF -> 404; another ISP's package -> 404 before anything is
written; only the listed labels are accepted. The route table rules (guard
stack, no scope-alias names, permission coverage) are walked for every
isp_partner route by ``test_isp_partner_guards`` and
``test_route_permission_coverage``.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.domains.isp_partner import package_meta_router as pm
from app.domains.isp_partner.package_meta_models import (
    CONNECTION_TYPES,
    PACKAGE_TYPES,
    IspPackageMeta,
)
from app.domains.isp_partner.plans_service import IspPackageNotFoundError

ISP, OTHER = uuid.uuid4(), uuid.uuid4()


class _Db:
    """get() from a dict; nothing may be added for a refused request."""

    def __init__(self, *rows):
        self.rows = {r.id: r for r in rows}
        self.added = []

    async def get(self, _model, key):
        return self.rows.get(key)

    def add(self, row):  # pragma: no cover - must not happen here
        self.added.append(row)


def _isp():
    return SimpleNamespace(isp_org_id=ISP, user_id=uuid.uuid4())


async def test_flag_defaults_off() -> None:
    pm.get_package_meta_settings.cache_clear()
    assert pm.get_package_meta_settings().enabled is False
    with pytest.raises(HTTPException) as exc:
        await pm.RequirePackageMetaEnabled()
    assert exc.value.status_code == 404


@pytest.mark.parametrize(
    "pkg",
    [
        SimpleNamespace(id=uuid.uuid4(), is_deleted=False, isp_organization_id=OTHER),
        SimpleNamespace(id=uuid.uuid4(), is_deleted=True, isp_organization_id=ISP),
    ],
)
async def test_other_isp_or_deleted_package_is_404(pkg) -> None:
    db = _Db(pkg)
    with pytest.raises(IspPackageNotFoundError):
        await pm._package(db, _isp(), pkg.id)
    assert db.added == []


async def test_unknown_package_is_404() -> None:
    with pytest.raises(IspPackageNotFoundError):
        await pm._package(_Db(), _isp(), uuid.uuid4())


def test_only_listed_labels_are_accepted() -> None:
    for t in PACKAGE_TYPES:
        pm.IspPackageMetaRequest(package_type=t)
    for c in CONNECTION_TYPES:
        pm.IspPackageMetaRequest(connection_type=c)
    pm.IspPackageMetaRequest()  # both may be cleared
    with pytest.raises(ValidationError):
        pm.IspPackageMetaRequest(package_type="residential")
    with pytest.raises(ValidationError):
        pm.IspPackageMetaRequest(connection_type="dsl")
    with pytest.raises(ValidationError):
        pm.IspPackageMetaRequest(package_type="home", speed="x")


def test_check_constraints_match_the_labels() -> None:
    sql = " ".join(
        str(c.sqltext)
        for c in IspPackageMeta.__table__.constraints
        if hasattr(c, "sqltext")
    )
    for v in (*PACKAGE_TYPES, *CONNECTION_TYPES):
        assert f"'{v}'" in sql


def test_view_shape() -> None:
    pid = uuid.uuid4()
    assert pm._view(pid, None) == {
        "package_id": str(pid),
        "package_type": None,
        "connection_type": None,
    }
