"""ONBOARD-1 ``/isp/onboarding`` without a database (runs in CI).

The real-PostgreSQL rollback scenario is in
``test_isp_onboarding_postgres.py``; this file pins the pieces that make the
one-transaction promise hold:

* ``_FlushOnCommit`` turns a lane handler's ``commit`` into ``flush``;
* ``IspOnboardStepError`` keeps the lane's status/message/``data.code`` and
  adds ``data.step``;
* the request model (extra=forbid, MAC normalisation, KYC key allow-list);
* the orchestrator: a step that fails part-way raises with that step and
  the session is never committed; the static-queue push stays off unless
  ``ISP_STATIC_QUEUE_PUSH`` is on.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.domains.isp_partner import onboarding_router as m
from app.domains.isp_partner.exceptions import IspBadRequestError


class FakeSession:
    def __init__(self) -> None:
        self.flushes = 0
        self.commits = 0
        self.items: list[Any] = []

    async def flush(self) -> None:
        self.flushes += 1

    async def commit(self) -> None:
        self.commits += 1

    def add(self, obj: Any) -> None:
        self.items.append(obj)

    def __contains__(self, obj: object) -> bool:
        return obj in self.items


# --- _FlushOnCommit ---------------------------------------------------------------


async def test_flush_on_commit_never_commits() -> None:
    s = FakeSession()
    tx = m._FlushOnCommit(s)  # type: ignore[arg-type]
    tx.add("row")
    await tx.commit()
    await tx.flush()
    assert (s.commits, s.flushes) == (0, 2)
    assert "row" in tx and s.items == ["row"]


# --- IspOnboardStepError --------------------------------------------------------


def test_step_error_keeps_lane_code_and_status() -> None:
    from app.domains.isp_partner.pppoe_service import IspPppoeUsernameTakenError

    e = m.IspOnboardStepError("pppoe", IspPppoeUsernameTakenError())
    assert e.status_code == 409
    assert e.data["code"] == "ISP_PPPOE_USERNAME_TAKEN"
    assert e.data["step"] == "pppoe"
    assert "already used" in e.message


def test_step_error_keeps_field() -> None:
    e = m.IspOnboardStepError(
        "caf", IspBadRequestError("Give the CAF number", field="caf")
    )
    assert (e.status_code, e.data["field"], e.data["step"]) == (422, "caf", "caf")


def test_step_error_http_and_unknown() -> None:
    e = m.IspOnboardStepError("static_ip", HTTPException(404, "Not Found"))
    assert (e.status_code, e.message, e.data["code"]) == (
        404,
        "Not Found",
        "ISP_ONBOARD_STEP_FAILED",
    )
    boom = m.IspOnboardStepError("kyc", RuntimeError("db password=hunter2"))
    assert boom.status_code == 500
    assert "hunter2" not in boom.message  # internals never reach the client


# --- request model ---------------------------------------------------------------


def _sub(**kw: Any) -> dict:
    return {
        "isp_customer_id": str(uuid.uuid4()),
        "identifier": "flat-101",
        "package_id": str(uuid.uuid4()),
        **kw,
    }


def test_request_normalises_macs_and_forbids_extra() -> None:
    r = m.OnboardingRequest.model_validate(
        {"subscriber": _sub(), "macs": ["aa-bb-cc-dd-ee-ff", "AA:BB:CC:DD:EE:FF"]}
    )
    assert r.macs == ["AA:BB:CC:DD:EE:FF"]
    with pytest.raises(ValidationError):
        m.OnboardingRequest.model_validate({"subscriber": _sub(), "sms": True})
    with pytest.raises(ValidationError):
        m.OnboardingRequest.model_validate({"subscriber": _sub(), "macs": ["nope"]})
    with pytest.raises(ValidationError):
        m.OnboardingRequest.model_validate({"subscriber": _sub(stb_serial_x=1)})


def test_request_kyc_allow_list_and_limits() -> None:
    ok = m.OnboardingRequest.model_validate(
        {
            "subscriber": _sub(),
            "kyc": {"full_name": "A", "id_proof_type": "aadhaar", "id_number": "7865"},
        }
    )
    assert ok.kyc and ok.kyc["id_number"] == "7865"
    with pytest.raises(ValidationError):
        m.OnboardingRequest.model_validate(
            {"subscriber": _sub(), "kyc": {"aadhaar_full": "x"}}
        )
    row = {"isp_location_id": str(uuid.uuid4()), "pool_id": str(uuid.uuid4())}
    with pytest.raises(ValidationError):
        m.OnboardingRequest.model_validate(
            {"subscriber": _sub(), "static_ips": [row] * 5}
        )


# --- orchestrator, with fakes ------------------------------------------------------


class FakePlans:
    def __init__(self, sub: Any, pkg: Any) -> None:
        self.sub, self.pkg = sub, pkg

    async def subscriber(self, isp: Any, sid: uuid.UUID) -> Any:
        return self.sub

    async def package(self, isp: Any, pid: Any) -> Any:
        return self.pkg

    def _billing(self) -> Any:
        raise AssertionError("billing must not run in these scenarios")


class Fake360:
    def __init__(self, plans: FakePlans) -> None:
        self.plans = plans
        self.events: list[str] = []

    async def onboard(self, isp: Any, data: dict) -> dict:
        return {"id": str(self.plans.sub.id), "profile": {}, "welcome": None}

    async def event(self, isp: Any, s: Any, kind: str, summary: str, **kw: Any) -> None:
        self.events.append(summary)

    async def view_360(self, isp: Any, sid: uuid.UUID) -> dict:
        return {"id": str(sid)}


class FakeAudit:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def create_audit_log_entry(self, **kw: Any) -> None:
        self.rows.append(kw)


def _ctx(monkeypatch: pytest.MonkeyPatch, *, perms: set[str], pppoe_on: bool = True):
    sub = SimpleNamespace(
        id=uuid.uuid4(),
        circuit_id=7,
        customer_organization_id=uuid.uuid4(),
        package_id=uuid.uuid4(),
        valid_until=datetime.now(UTC) + timedelta(days=30),
    )
    plans = FakePlans(sub, SimpleNamespace(price_paise=0, validity_days=30))
    svc = Fake360(plans)

    async def held(isp: Any, av: Any) -> set[str]:
        return perms

    monkeypatch.setattr(m, "_held", held)
    # Apps off by default here; the APPS-2 install-task cases switch it on
    monkeypatch.setattr(m, "_apps_on", lambda: False)
    monkeypatch.setattr(
        m, "get_isp_pppoe_settings", lambda: SimpleNamespace(enabled=pppoe_on)
    )
    isp = SimpleNamespace(isp_org_id=uuid.uuid4(), user_id=uuid.uuid4())
    return svc, isp, FakeSession(), FakeAudit()


ALL = {m.SUBS_UPDATE, m.KYC_UPDATE, m.INVOICES_CREATE, m.BILLING_EXECUTE}


async def _call(svc, isp, db, audit, body: dict) -> dict:
    return await m.onboard(
        request=SimpleNamespace(headers={}, state=SimpleNamespace(request_id="t")),  # type: ignore[arg-type]
        payload=m.OnboardingRequest.model_validate(body),
        isp=isp,
        db=db,  # type: ignore[arg-type]
        svc=svc,  # type: ignore[arg-type]
        av=None,  # type: ignore[arg-type]
        audit=audit,
        queue_service=None,
    )


async def test_failure_midway_names_step_and_never_commits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    svc, isp, db, audit = _ctx(monkeypatch, perms=ALL)
    from app.domains.isp_partner.pppoe_service import IspPppoeUsernameTakenError

    class BoomPppoe:
        def __init__(self, **kw: Any) -> None:
            pass

        async def set_credential(self, *a: Any) -> dict:
            raise IspPppoeUsernameTakenError()

    macs_called: list[str] = []

    async def mac(*a: Any, **kw: Any) -> dict:
        macs_called.append("x")
        return {"data": {}}

    monkeypatch.setattr(m, "IspPppoeService", BoomPppoe)
    monkeypatch.setattr(m, "add_mac_binding", mac)
    with pytest.raises(m.IspOnboardStepError) as ei:
        await _call(
            svc,
            isp,
            db,
            audit,
            {
                "subscriber": _sub(),
                "pppoe": {"generate_password": True},
                "macs": ["AABBCCDDEEFF"],
            },
        )
    assert ei.value.data["step"] == "pppoe"
    assert ei.value.data["code"] == "ISP_PPPOE_USERNAME_TAKEN"
    assert db.commits == 0  # the request session rolls back the subscriber
    assert macs_called == []  # later steps never ran
    assert audit.rows == []


async def test_pppoe_refused_before_anything_when_flag_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    svc, isp, db, audit = _ctx(monkeypatch, perms=ALL, pppoe_on=False)
    with pytest.raises(m.IspOnboardStepError) as ei:
        await _call(svc, isp, db, audit, {"subscriber": _sub(), "pppoe": {}})
    assert ei.value.data["step"] == "pppoe" and db.commits == 0


async def test_permissions_checked_before_the_transaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.domains.rbac.exceptions import PermissionDeniedError

    svc, isp, db, audit = _ctx(monkeypatch, perms={m.SUBS_UPDATE})
    with pytest.raises(PermissionDeniedError):
        await _call(
            svc,
            isp,
            db,
            audit,
            {"subscriber": _sub(), "billing": {"issue_invoice": True}},
        )
    with pytest.raises(PermissionDeniedError):
        await _call(
            svc, isp, db, audit, {"subscriber": _sub(), "kyc": {"full_name": "A"}}
        )
    assert db.commits == 0


async def test_static_queue_recorded_not_pushed_while_flag_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    svc, isp, db, audit = _ctx(monkeypatch, perms=ALL)
    seen: list[Any] = []

    async def ip(request: Any, sid: Any, payload: Any, **kw: Any) -> dict:
        seen.append((payload.static_queue, type(kw["db"]).__name__))
        return {"data": {"ip": "10.0.0.9"}}

    monkeypatch.setattr(m, "add_ip_binding", ip)
    monkeypatch.setattr(
        m, "get_onboard_settings", lambda: SimpleNamespace(static_queue_push=False)
    )
    row = {
        "isp_location_id": str(uuid.uuid4()),
        "pool_id": str(uuid.uuid4()),
        "static_queue": True,
    }
    out = await _call(svc, isp, db, audit, {"subscriber": _sub(), "static_ips": [row]})
    data = out["data"]
    assert seen == [(False, "_FlushOnCommit")]  # handler got the no-commit session
    assert data["static_queue_recorded"] is True
    assert any("recorded; router push is off" in e for e in svc.events)
    assert db.commits == 1  # one commit, at the very end
    assert [s["step"] for s in data["steps"] if s["status"] == "done"] == [
        "subscriber",
        "static_ip",
    ]
    assert audit.rows and audit.rows[0]["action"] == m.AUDIT_ONBOARDED

    seen.clear()
    monkeypatch.setattr(
        m, "get_onboard_settings", lambda: SimpleNamespace(static_queue_push=True)
    )
    out = await _call(
        svc,
        isp,
        FakeSession(),
        FakeAudit(),
        {"subscriber": _sub(), "static_ips": [row]},
    )
    assert seen == [(True, "_FlushOnCommit")]
    assert out["data"]["static_queue_recorded"] is False


async def test_free_package_skips_invoice(monkeypatch: pytest.MonkeyPatch) -> None:
    svc, isp, db, audit = _ctx(monkeypatch, perms=ALL)
    out = await _call(
        svc, isp, db, audit, {"subscriber": _sub(), "billing": {"issue_invoice": True}}
    )
    inv = next(s for s in out["data"]["steps"] if s["step"] == "invoice")
    assert inv["status"] == "skipped" and "free" in inv["detail"]
    assert out["data"]["invoice"] is None


# --- APPS-2: the install task ---------------------------------------------------


async def test_install_task_created_when_apps_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.domains.isp_partner import apps_tasks

    svc, isp, db, audit = _ctx(monkeypatch, perms=ALL)
    monkeypatch.setattr(m, "_apps_on", lambda: True)
    svc.plans.sub.first_name, svc.plans.sub.last_name = "Asha", None
    svc.plans.sub.identifier, svc.plans.sub.address = "flat-101", "12 Lane"
    seen: list[dict] = []

    async def create(self, isp, data, **kw):  # noqa: ANN001, ANN202
        seen.append(data)
        return {
            "id": "t1",
            "status": "unclaimed",
            "subscriber_id": str(data["subscriber_id"]),
        }

    monkeypatch.setattr(apps_tasks.FieldTaskService, "create", create)
    out = (await _call(svc, isp, db, audit, {"subscriber": _sub()}))["data"]
    assert out["task"]["status"] == "unclaimed"
    assert seen[0]["kind"] == "install" and seen[0]["subscriber_id"] == svc.plans.sub.id
    assert next(s for s in out["steps"] if s["step"] == "task")["status"] == "done"
    assert db.commits == 1


async def test_install_task_failure_rolls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.domains.isp_partner import apps_tasks

    svc, isp, db, audit = _ctx(monkeypatch, perms=ALL)
    monkeypatch.setattr(m, "_apps_on", lambda: True)
    svc.plans.sub.first_name = svc.plans.sub.last_name = None
    svc.plans.sub.identifier, svc.plans.sub.address = "flat-101", None

    async def boom(self, isp, data, **kw):  # noqa: ANN001, ANN202
        raise IspBadRequestError("task store down")

    monkeypatch.setattr(apps_tasks.FieldTaskService, "create", boom)
    with pytest.raises(m.IspOnboardStepError) as ei:
        await _call(svc, isp, db, audit, {"subscriber": _sub()})
    assert ei.value.data["step"] == "task" and db.commits == 0


async def test_install_task_skipped_on_request(monkeypatch: pytest.MonkeyPatch) -> None:
    svc, isp, db, audit = _ctx(monkeypatch, perms=ALL)
    monkeypatch.setattr(m, "_apps_on", lambda: True)
    out = (
        await _call(
            svc, isp, db, audit, {"subscriber": _sub(), "create_install_task": False}
        )
    )["data"]
    assert out["task"] is None
    assert next(s for s in out["steps"] if s["step"] == "task")["status"] == "skipped"
