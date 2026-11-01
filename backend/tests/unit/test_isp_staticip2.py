"""STATICIP-2: flag default off, lease invoice key prefix, release body.
Real-DB behaviour (ledger, CSV, invoices, release frees the IP and stops
billing, isolation) is in ``test_isp_staticip2_postgres.py``."""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.domains.isp_partner import staticip_router as sr


async def test_flag_defaults_off() -> None:
    sr.get_staticip2_settings.cache_clear()
    assert sr.get_staticip2_settings().enabled is False
    with pytest.raises(HTTPException) as exc:
        await sr.RequireStaticIp2Enabled()
    assert exc.value.status_code == 404


def test_lease_key_prefix_matches_bill_leases() -> None:
    lid = uuid.uuid4()
    # finance_service.bill_leases writes f"sip:{lease.id}:{start.isoformat()}"
    key = f"sip:{lid}:2026-11-01"
    assert key.startswith(sr.lease_key_prefix(lid))
    assert not f"sip:{uuid.uuid4()}:2026-11-01".startswith(sr.lease_key_prefix(lid))


def test_release_body() -> None:
    b = sr.IspStaticIpReleaseRequest()
    assert b.release_binding is True and b.until is None
    sr.IspStaticIpReleaseRequest(reason="moved", until="2026-11-30")
    with pytest.raises(ValidationError):
        sr.IspStaticIpReleaseRequest(reason="because")
    with pytest.raises(ValidationError):
        sr.IspStaticIpReleaseRequest(extra=1)


def test_routes_use_existing_billing_keys() -> None:
    from app.domains.isp_partner.rbac_roles import all_permission_keys

    keys = set(all_permission_keys())
    seen = set()
    for r in sr.staticip_router.routes:
        for d in r.dependencies:
            call = d.dependency
            if getattr(call, "__qualname__", "").startswith("RequirePermission"):
                for cell in call.__closure__ or ():
                    v = cell.cell_contents
                    if isinstance(v, str) and "." in v:
                        seen.add(v)
    assert seen == {"isp_billing.read", "isp_billing.export", "isp_billing.manage"}
    assert seen <= keys
