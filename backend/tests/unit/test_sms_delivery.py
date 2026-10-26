"""SMS delivery log: send-site logging, DLR parsing, the DLR callback, and the
report's tenant scoping. No database -- the SQL-level guarantees
(forward-only UPDATE, the aggregation) are also exercised against a real
Postgres in ``test_sms_delivery_postgres.py``.
"""

from __future__ import annotations

import uuid
from datetime import date
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy.dialects import postgresql

from app.core.config import Settings, get_settings
from app.database.session import get_db_session
from app.domains.location.exceptions import CrossLocationScopeAccessError
from app.domains.marketing.constants import Channel
from app.domains.marketing.senders import ProviderResult, SendError
from app.domains.marketing.service import MarketingService
from app.domains.otp.constants import OtpChannel, OtpPurpose
from app.domains.otp.service import (
    LoggingSmsProvider,
    OtpService,
    Ping4SmsProvider,
)
from app.domains.sms_delivery import router as sms_router
from app.domains.sms_delivery import service as sms_service
from app.domains.sms_delivery.constants import (
    DlrSource,
    SmsDeliveryStatus,
    SmsPurpose,
)
from app.domains.sms_delivery.dlr import (
    classify_dlr_status,
    error_code_for,
    parse_poll_answer,
    scrub,
)
from app.domains.sms_delivery.exceptions import SmsDeliveryLocationAccessError
from app.domains.sms_delivery.recorder import (
    SmsDeliveryRecorder,
    send_sms_and_record,
)
from app.domains.sms_delivery.service import (
    DlrOutcome,
    ReportScope,
    build_report_query,
    delivery_reports_state,
    fold_report_rows,
)

ORG_A = uuid.UUID("00000000-0000-0000-0000-00000000000a")
ORG_B = uuid.UUID("00000000-0000-0000-0000-00000000000b")
LOC_A1 = uuid.UUID("00000000-0000-0000-0000-0000000000a1")
LOC_A2 = uuid.UUID("00000000-0000-0000-0000-0000000000a2")
PHONE = "+919876543210"
SECRET_KEY = "SECRETKEY1234567890"


class FakeRecorder:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    async def record(self, **fields: Any) -> None:
        self.rows.append(fields)


class FakeProvider:
    provider_name = "ping4sms"

    def __init__(self, result: Any = "32961147", exc: Exception | None = None):
        self.result = result
        self.exc = exc
        self.calls: list[tuple[str, str]] = []

    async def send(self, phone_number: str, message: str) -> str | None:
        self.calls.append((phone_number, message))
        if self.exc is not None:
            raise self.exc
        return self.result


def _http_error(status_code: int = 400) -> httpx.HTTPStatusError:
    request = httpx.Request(
        "GET",
        "https://site.ping4sms.com/api/smsapi",
        params={"key": SECRET_KEY, "number": PHONE, "sms": "123456 is your code"},
    )
    response = httpx.Response(status_code, request=request, text="bad")
    return httpx.HTTPStatusError(
        f"Client error '{status_code}' for url '{request.url}'",
        request=request,
        response=response,
    )


# ---------------------------------------------------------------------------
# send_sms_and_record
# ---------------------------------------------------------------------------


class TestSendAndRecord:
    async def test_success_records_sent_with_provider_message_id(self) -> None:
        recorder = FakeRecorder()
        provider = FakeProvider("32961147")
        ref = uuid.uuid4()

        message_id = await send_sms_and_record(
            provider,
            PHONE,
            "Your code is 123456",
            recorder=recorder,
            purpose=SmsPurpose.GUEST_OTP.value,
            organization_id=ORG_A,
            location_id=LOC_A1,
            reference_id=ref,
        )

        assert message_id == "32961147"
        assert provider.calls == [(PHONE, "Your code is 123456")]
        [row] = recorder.rows
        assert row["status"] == SmsDeliveryStatus.SENT.value
        assert row["provider"] == "ping4sms"
        assert row["provider_message_id"] == "32961147"
        assert row["organization_id"] == ORG_A
        assert row["location_id"] == LOC_A1
        assert row["reference_id"] == ref
        assert row["purpose"] == "guest_otp"

    async def test_failure_records_failed_and_reraises(self) -> None:
        recorder = FakeRecorder()
        error = _http_error(400)
        provider = FakeProvider(exc=error)

        with pytest.raises(httpx.HTTPStatusError):
            await send_sms_and_record(
                provider,
                PHONE,
                "Your code is 123456",
                recorder=recorder,
                purpose=SmsPurpose.GUEST_OTP.value,
                organization_id=ORG_A,
            )

        [row] = recorder.rows
        assert row["status"] == SmsDeliveryStatus.FAILED.value
        assert row["error_code"] == "http_400"
        assert row.get("provider_message_id") is None

    async def test_no_recorder_is_a_plain_send(self) -> None:
        provider = FakeProvider("1")
        assert (
            await send_sms_and_record(
                provider, PHONE, "x", recorder=None, purpose="guest_otp"
            )
            == "1"
        )


# ---------------------------------------------------------------------------
# SmsDeliveryRecorder: PII + secrets never persisted, never raises
# ---------------------------------------------------------------------------


class _CapturingSession:
    def __init__(self, sink: list[Any], *, fail: bool = False) -> None:
        self.sink = sink
        self.fail = fail

    async def __aenter__(self) -> _CapturingSession:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    def add(self, row: Any) -> None:
        self.sink.append(row)

    async def commit(self) -> None:
        if self.fail:
            raise RuntimeError("db down")


class TestRecorder:
    async def test_row_masks_number_and_scrubs_error(self) -> None:
        sink: list[Any] = []
        recorder = SmsDeliveryRecorder(lambda: _CapturingSession(sink))
        error = _http_error(400)

        await recorder.record(
            purpose="guest_otp",
            provider="ping4sms",
            phone_number=PHONE,
            status="failed",
            organization_id=ORG_A,
            error_code=error_code_for(error),
            error_message=str(error),
        )

        [row] = sink
        assert row.recipient_masked == "+91******3210"
        stored = " ".join(
            str(getattr(row, column.key))
            for column in row.__table__.columns
            if getattr(row, column.key, None) is not None
        )
        assert SECRET_KEY not in stored
        assert "9876543210" not in stored
        assert "123456" not in stored
        assert row.error_code == "http_400"

    async def test_logging_provider_writes_no_row(self) -> None:
        sink: list[Any] = []
        recorder = SmsDeliveryRecorder(lambda: _CapturingSession(sink))
        await send_sms_and_record(
            LoggingSmsProvider(),
            PHONE,
            "x",
            recorder=recorder,
            purpose="guest_otp",
        )
        assert sink == []

    async def test_db_failure_never_breaks_the_send(self) -> None:
        recorder = SmsDeliveryRecorder(lambda: _CapturingSession([], fail=True))
        provider = FakeProvider("77")
        assert (
            await send_sms_and_record(
                provider, PHONE, "x", recorder=recorder, purpose="guest_otp"
            )
            == "77"
        )


# ---------------------------------------------------------------------------
# Real send sites
# ---------------------------------------------------------------------------


class TestOtpSendSite:
    def _service(self, provider: Any, recorder: FakeRecorder) -> OtpService:
        return OtpService(
            repository=SimpleNamespace(),  # type: ignore[arg-type]
            redis=SimpleNamespace(),  # type: ignore[arg-type]
            sms_provider=provider,
            sms_delivery_recorder=recorder,
            sms_message_template="{#num#} is your Wyfy code",
        )

    def _otp_request(self) -> SimpleNamespace:
        return SimpleNamespace(
            id=uuid.uuid4(),
            identifier=PHONE,
            organization_id=ORG_A,
            location_id=LOC_A1,
        )

    async def test_guest_otp_sms_logged_with_venue(self) -> None:
        recorder = FakeRecorder()
        otp_request = self._otp_request()
        await self._service(FakeProvider("555"), recorder)._dispatch(
            otp_request,  # type: ignore[arg-type]
            code="482913",
            channel=OtpChannel.SMS,
            purpose=OtpPurpose.GUEST_LOGIN,
        )
        [row] = recorder.rows
        assert row["purpose"] == "guest_otp"
        assert row["status"] == "sent"
        assert row["provider_message_id"] == "555"
        assert (row["organization_id"], row["location_id"]) == (ORG_A, LOC_A1)
        assert row["reference_id"] == otp_request.id
        assert "482913" not in str(row)

    async def test_guest_otp_send_failure_logged_then_raised(self) -> None:
        recorder = FakeRecorder()
        provider = FakeProvider(exc=RuntimeError("ping4sms send failed: Low credits"))
        with pytest.raises(RuntimeError):
            await self._service(provider, recorder)._dispatch(
                self._otp_request(),  # type: ignore[arg-type]
                code="482913",
                channel=OtpChannel.SMS,
                purpose=OtpPurpose.GUEST_LOGIN,
            )
        [row] = recorder.rows
        assert row["status"] == "failed"
        assert row["error_code"] == "RuntimeError"
        assert "Low credits" in row["error_message"]

    async def test_account_otp_purpose(self) -> None:
        recorder = FakeRecorder()
        await self._service(FakeProvider("1"), recorder)._dispatch(
            self._otp_request(),  # type: ignore[arg-type]
            code="1",
            channel=OtpChannel.SMS,
            purpose=OtpPurpose.ACCOUNT_DATA_MASKING,
        )
        assert recorder.rows[0]["purpose"] == "account_otp"


class TestPing4ProviderReturnsMessageId:
    async def test_numeric_body_is_the_message_id(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_get(self, url, *, params=None):  # noqa: ANN001
            return httpx.Response(
                200, text="32961147\n", request=httpx.Request("GET", url)
            )

        monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
        provider = Ping4SmsProvider(api_key="k", route="2", sender_id="WYFYG")
        assert await provider.send(PHONE, "hi") == "32961147"
        assert provider.provider_name == "ping4sms"

    async def test_documented_error_code_still_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_get(self, url, *, params=None):  # noqa: ANN001
            return httpx.Response(200, text="108", request=httpx.Request("GET", url))

        monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
        provider = Ping4SmsProvider(api_key="k", route="2", sender_id="WYFYG")
        with pytest.raises(RuntimeError, match="Low credits"):
            await provider.send(PHONE, "hi")


class TestMarketingSendSite:
    def _self(self, recorder: FakeRecorder, sms_sender: Any) -> SimpleNamespace:
        return SimpleNamespace(
            sms_delivery_recorder=recorder,
            senders=SimpleNamespace(sms=sms_sender),
        )

    async def test_campaign_sms_success_logged(self) -> None:
        recorder = FakeRecorder()
        fake = self._self(recorder, SimpleNamespace(provider="ping4sms"))
        recipient_id = uuid.uuid4()
        await MarketingService._record_sms(
            fake,  # type: ignore[arg-type]
            Channel.SMS,
            own=None,
            purpose=SmsPurpose.MARKETING,
            address=PHONE,
            organization_id=ORG_A,
            location_id=LOC_A2,
            reference_id=recipient_id,
            result=ProviderResult(provider="ping4sms", message_id="900"),
        )
        [row] = recorder.rows
        assert row["status"] == "sent"
        assert row["provider_source"] == "wyfy"
        assert row["provider_message_id"] == "900"
        assert row["location_id"] == LOC_A2

    async def test_campaign_sms_failure_logged_as_own(self) -> None:
        recorder = FakeRecorder()
        own_sender = SimpleNamespace(provider="exotel")
        fake = self._self(recorder, None)
        await MarketingService._record_sms(
            fake,  # type: ignore[arg-type]
            Channel.SMS,
            own=SimpleNamespace(sms=own_sender),  # type: ignore[arg-type]
            purpose=SmsPurpose.MARKETING,
            address=PHONE,
            organization_id=ORG_A,
            location_id=None,
            reference_id=uuid.uuid4(),
            error=SendError("low_credits", "ping4sms error 108", permanent=True),
        )
        [row] = recorder.rows
        assert row["status"] == "failed"
        assert row["provider"] == "exotel"
        assert row["provider_source"] == "own"
        assert row["error_code"] == "low_credits"

    async def test_non_sms_channel_and_unconfigured_sender_write_nothing(
        self,
    ) -> None:
        recorder = FakeRecorder()
        for channel, sender in ((Channel.EMAIL, object()), (Channel.SMS, None)):
            await MarketingService._record_sms(
                self._self(recorder, sender),  # type: ignore[arg-type]
                channel,
                own=None,
                purpose=SmsPurpose.MARKETING,
                address=PHONE,
                organization_id=ORG_A,
                location_id=None,
                reference_id=uuid.uuid4(),
                result=ProviderResult(provider="x", message_id="1"),
            )
        assert recorder.rows == []


# ---------------------------------------------------------------------------
# DLR parsing -- "delivered" only from a recognised provider status
# ---------------------------------------------------------------------------


class TestDlrParsing:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("DELIVRD", SmsDeliveryStatus.DELIVERED),
            ("delivered", SmsDeliveryStatus.DELIVERED),
            ("UNDELIV", SmsDeliveryStatus.UNDELIVERED),
            ("undelivered", SmsDeliveryStatus.UNDELIVERED),
            ("EXPIRED", SmsDeliveryStatus.UNDELIVERED),
            ("REJECTD", SmsDeliveryStatus.UNDELIVERED),
            ("failed", SmsDeliveryStatus.UNDELIVERED),
            ("PENDING", None),
            ("sent", None),
            ("queued", None),
            ("", None),
            (None, None),
            ("110", None),
        ],
    )
    def test_status_field_values(
        self, value: str | None, expected: SmsDeliveryStatus | None
    ) -> None:
        assert classify_dlr_status(value) == expected

    @pytest.mark.parametrize(
        ("body", "expected"),
        [
            ("DELIVRD", SmsDeliveryStatus.DELIVERED),
            ("32961147 DELIVRD 2026-10-26 10:00:01", SmsDeliveryStatus.DELIVERED),
            ("UNDELIV", SmsDeliveryStatus.UNDELIVERED),
            # A numeric code, the answer the real dlrapi gave for an unknown
            # id on prod (2026-10-26): never a status.
            ("110", None),
            ("101", None),
            # Plain English in free text is not a delivery report.
            ("Request failed, try later", None),
            ("Message delivered to operator queue", None),
            ('{"status": "DELIVRD", "msgid": "1"}', SmsDeliveryStatus.DELIVERED),
            ('{"data": {"status": "UNDELIV"}}', SmsDeliveryStatus.UNDELIVERED),
            ('[{"status": "PENDING"}]', None),
            # A JSON body is read by field, never by scanning values.
            ('{"note": "DELIVRD", "status": "PENDING"}', None),
            ("{not json", None),
            ("", None),
        ],
    )
    def test_poll_answers(self, body: str, expected: SmsDeliveryStatus | None) -> None:
        assert parse_poll_answer(body) == expected

    def test_scrub_removes_query_strings_secrets_and_numbers(self) -> None:
        text = (
            f"Client error for url 'https://site.ping4sms.com/api/smsapi?key="
            f"{SECRET_KEY}&number=919876543210&sms=482913' key={SECRET_KEY} "
            "to 919876543210"
        )
        cleaned = scrub(text) or ""
        assert SECRET_KEY not in cleaned
        assert "9876543210" not in cleaned
        assert "482913" not in cleaned
        assert "site.ping4sms.com" in cleaned


# ---------------------------------------------------------------------------
# DLR callback
# ---------------------------------------------------------------------------


class _NoopSession:
    async def commit(self) -> None:  # pragma: no cover - not reached
        return None


def _callback_app(token: str, calls: list[dict[str, Any]], outcome: DlrOutcome):
    app = FastAPI()
    app.include_router(sms_router.router, prefix="/api/v1")

    async def _db():
        yield _NoopSession()

    app.dependency_overrides[get_db_session] = _db
    app.dependency_overrides[get_settings] = lambda: Settings(
        sms_dlr_webhook_token=token
    )
    return app


@pytest.fixture
def callback(monkeypatch: pytest.MonkeyPatch):
    calls: list[dict[str, Any]] = []
    holder = {"outcome": DlrOutcome(matched=True, applied=True, status="delivered")}

    async def fake_apply(session, **kwargs):  # noqa: ANN001
        calls.append(kwargs)
        return holder["outcome"]

    monkeypatch.setattr(sms_router, "apply_dlr", fake_apply)

    def make(token: str = "s3cret-token"):
        app = _callback_app(token, calls, holder["outcome"])
        transport = httpx.ASGITransport(app=app)
        return httpx.AsyncClient(transport=transport, base_url="http://test")

    return SimpleNamespace(make=make, calls=calls, holder=holder)


class TestDlrCallback:
    async def test_valid_callback_applies_classified_status(self, callback) -> None:
        async with callback.make() as client:
            response = await client.post(
                "/api/v1/sms-delivery/dlr/ping4sms?token=s3cret-token",
                data={"msgid": "32961147", "status": "DELIVRD"},
            )
        assert response.status_code == 200
        assert response.json() == {
            "matched": True,
            "applied": True,
            "status": "delivered",
        }
        [call] = callback.calls
        assert call["provider"] == "ping4sms"
        assert call["provider_message_id"] == "32961147"
        assert call["status"] == SmsDeliveryStatus.DELIVERED
        assert call["source"] == DlrSource.WEBHOOK

    async def test_header_token_and_json_body(self, callback) -> None:
        async with callback.make() as client:
            response = await client.post(
                "/api/v1/sms-delivery/dlr/twilio",
                headers={"X-Wyfy-Dlr-Token": "s3cret-token"},
                json={"MessageSid": "SM1", "MessageStatus": "undelivered"},
            )
        assert response.status_code == 200
        assert callback.calls[0]["status"] == SmsDeliveryStatus.UNDELIVERED

    async def test_duplicate_callback_is_idempotent(self, callback) -> None:
        callback.holder["outcome"] = DlrOutcome(
            matched=True, applied=False, status="delivered"
        )
        async with callback.make() as client:
            response = await client.get(
                "/api/v1/sms-delivery/dlr/ping4sms",
                params={"token": "s3cret-token", "msgid": "1", "status": "DELIVRD"},
            )
        assert response.status_code == 200
        assert response.json()["applied"] is False

    async def test_pending_status_is_passed_as_no_status(self, callback) -> None:
        async with callback.make() as client:
            await client.get(
                "/api/v1/sms-delivery/dlr/ping4sms",
                params={"token": "s3cret-token", "msgid": "1", "status": "PENDING"},
            )
        assert callback.calls[0]["status"] is None

    @pytest.mark.parametrize("token", ["wrong", ""])
    async def test_invalid_token_is_401_and_touches_nothing(
        self, callback, token: str
    ) -> None:
        async with callback.make() as client:
            response = await client.post(
                f"/api/v1/sms-delivery/dlr/ping4sms?token={token}",
                data={"msgid": "1", "status": "DELIVRD"},
            )
        assert response.status_code == 401
        assert callback.calls == []

    async def test_disabled_when_no_token_configured(self, callback) -> None:
        async with callback.make(token="") as client:
            response = await client.post(
                "/api/v1/sms-delivery/dlr/ping4sms?token=anything",
                data={"msgid": "1", "status": "DELIVRD"},
            )
        assert response.status_code == 404
        assert callback.calls == []

    async def test_unknown_provider_and_missing_fields(self, callback) -> None:
        async with callback.make() as client:
            unknown = await client.post(
                "/api/v1/sms-delivery/dlr/acme?token=s3cret-token",
                data={"msgid": "1", "status": "DELIVRD"},
            )
            missing = await client.post(
                "/api/v1/sms-delivery/dlr/ping4sms?token=s3cret-token",
                data={"status": "DELIVRD"},
            )
        assert unknown.status_code == 404
        assert missing.status_code == 400
        assert callback.calls == []


# ---------------------------------------------------------------------------
# apply_dlr is forward-only at the SQL level
# ---------------------------------------------------------------------------


class _RecordingSession:
    def __init__(self) -> None:
        self.statements: list[Any] = []

    async def execute(self, statement: Any) -> Any:
        self.statements.append(statement)
        return SimpleNamespace(first=lambda: None, scalar_one_or_none=lambda: None)


class TestApplyDlrStatement:
    async def test_update_is_conditional_on_sent_and_wyfy_account(self) -> None:
        session = _RecordingSession()
        outcome = await sms_service.apply_dlr(
            session,  # type: ignore[arg-type]
            provider="ping4sms",
            provider_message_id="1",
            status=SmsDeliveryStatus.DELIVERED,
            source=DlrSource.WEBHOOK,
            raw="DELIVRD",
        )
        assert outcome == DlrOutcome(matched=False, applied=False, status=None)
        sql = str(
            session.statements[0].compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )
        assert "sms_delivery_logs.status = 'sent'" in sql
        assert "sms_delivery_logs.provider_source = 'wyfy'" in sql


# ---------------------------------------------------------------------------
# Report: aggregation + tenant scoping
# ---------------------------------------------------------------------------


def _row(day: str, loc: uuid.UUID | None, purpose: str, **counts: int):
    base = dict.fromkeys(
        (
            "attempted",
            "sent",
            "failed",
            "delivered",
            "undelivered",
            "awaiting_dlr",
            "dlr_received",
        ),
        0,
    )
    base.update(counts)
    return {
        "day": date.fromisoformat(day),
        "location_id": loc,
        "purpose": purpose,
        **base,
    }


class TestReportAggregation:
    def test_zero_fills_days_and_totals_by_location_and_purpose(self) -> None:
        rows = [
            _row(
                "2026-10-24",
                LOC_A1,
                "guest_otp",
                attempted=3,
                sent=2,
                failed=1,
                delivered=1,
                awaiting_dlr=1,
                dlr_received=1,
            ),
            _row(
                "2026-10-24",
                LOC_A2,
                "marketing",
                attempted=2,
                sent=2,
                undelivered=1,
                awaiting_dlr=1,
                dlr_received=1,
            ),
            _row(
                "2026-10-26", LOC_A1, "guest_otp", attempted=1, sent=1, awaiting_dlr=1
            ),
        ]
        report = fold_report_rows(
            rows, start=date(2026, 10, 23), end=date(2026, 10, 26)
        )
        assert [d["date"] for d in report["days"]] == [
            "2026-10-23",
            "2026-10-24",
            "2026-10-25",
            "2026-10-26",
        ]
        assert report["days"][0]["attempted"] == 0
        assert report["days"][1] == {
            "date": "2026-10-24",
            "attempted": 5,
            "sent": 4,
            "failed": 1,
            "delivered": 1,
            "undelivered": 1,
            "awaiting_dlr": 2,
        }
        assert report["totals"]["attempted"] == 6
        by_loc = {r["location_id"]: r for r in report["by_location"]}
        assert by_loc[str(LOC_A1)]["attempted"] == 4
        by_purpose = {r["purpose"]: r for r in report["by_purpose"]}
        assert by_purpose["marketing"]["undelivered"] == 1
        assert report["dlr_received"] == 2

    def _sql(self, scope: ReportScope, **kw: Any) -> str:
        query = build_report_query(
            scope,
            start=date(2026, 10, 1),
            end=date(2026, 10, 31),
            tz="Asia/Kolkata",
            **kw,
        )
        return str(
            query.compile(
                dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
            )
        )

    def test_query_always_filters_the_one_organization(self) -> None:
        sql = self._sql(ReportScope(organization_id=ORG_A, location_filter=None))
        assert f"sms_delivery_logs.organization_id = '{ORG_A}'" in sql
        assert str(ORG_B) not in sql

    def test_query_applies_location_confinement(self) -> None:
        one = self._sql(ReportScope(organization_id=ORG_A, location_filter=LOC_A1))
        assert f"sms_delivery_logs.location_id = '{LOC_A1}'" in one
        many = self._sql(
            ReportScope(organization_id=ORG_A, location_filter=[LOC_A1, LOC_A2])
        )
        assert "sms_delivery_logs.location_id IN" in many

    async def test_empty_confinement_reads_nothing(self) -> None:
        session = _RecordingSession()
        report = await sms_service.build_report(
            session,  # type: ignore[arg-type]
            ReportScope(organization_id=ORG_A, location_filter=[]),
            start=date(2026, 10, 1),
            end=date(2026, 10, 2),
            tz="Asia/Kolkata",
        )
        assert session.statements == []
        assert report["totals"]["attempted"] == 0


class TestReportEndpointScoping:
    @pytest.fixture
    def captured(self, monkeypatch: pytest.MonkeyPatch) -> list[ReportScope]:
        scopes: list[ReportScope] = []

        async def fake_build_report(session, scope, **kwargs):  # noqa: ANN001
            scopes.append(scope)
            return fold_report_rows([], start=kwargs["start"], end=kwargs["end"])

        monkeypatch.setattr(sms_router, "build_report", fake_build_report)
        return scopes

    async def _call(self, **overrides: Any) -> dict[str, Any]:
        request = SimpleNamespace(state=SimpleNamespace(request_id="r1"))
        args: dict[str, Any] = {
            "request": request,
            "start_date": date(2026, 10, 1),
            "end_date": date(2026, 10, 7),
            "location_id": None,
            "purpose": None,
            "tz": "Asia/Kolkata",
            "organization_id": ORG_A,
            "scope_location_id": None,
            "caller_location_scope": None,
            "db": object(),
            "settings": Settings(sms_delivery_provider="logging"),
        }
        args.update(overrides)
        return await sms_router.sms_delivery_report(**args)

    async def test_org_caller_reads_whole_org(self, captured) -> None:
        response = await self._call()
        assert captured == [ReportScope(organization_id=ORG_A, location_filter=None)]
        assert response["data"]["delivery_reports"]["enabled"] is False

    async def test_site_confined_caller_without_filter_gets_own_sites(
        self, captured
    ) -> None:
        await self._call(
            scope_location_id=LOC_A1, caller_location_scope=frozenset({LOC_A1})
        )
        assert captured[0].location_filter == [LOC_A1]

    async def test_site_confined_caller_cannot_name_sibling_site(
        self, captured
    ) -> None:
        with pytest.raises(SmsDeliveryLocationAccessError):
            await self._call(
                location_id=LOC_A2, caller_location_scope=frozenset({LOC_A1})
            )
        assert captured == []

    async def test_header_location_must_match_query_location(self, captured) -> None:
        with pytest.raises(CrossLocationScopeAccessError):
            await self._call(location_id=LOC_A2, scope_location_id=LOC_A1)
        assert captured == []

    async def test_range_and_tz_validated(self, captured) -> None:
        from fastapi import HTTPException

        with pytest.raises(HTTPException):
            await self._call(start_date=date(2026, 1, 1), end_date=date(2026, 12, 31))
        with pytest.raises(HTTPException):
            await self._call(tz="Mars/Olympus")
        with pytest.raises(HTTPException):
            await self._call(start_date=date(2026, 10, 7), end_date=date(2026, 10, 1))

    def test_route_requires_otp_read_and_a_single_organization(self) -> None:
        route = next(r for r in sms_router.router.routes if r.path.endswith("/report"))
        closures = [
            cell.cell_contents
            for dep in route.dependencies
            for cell in (dep.dependency.__closure__ or ())
        ]
        assert "otp.read" in closures
        from app.domains.rbac.dependencies import RequireOrganization

        assert any(
            dep.call is RequireOrganization for dep in route.dependant.dependencies
        )


class TestDeliveryReportsState:
    def test_poll_needs_ping4sms_flag_and_key(self) -> None:
        on = delivery_reports_state(
            Settings(sms_delivery_provider="ping4sms", ping4sms_api_key="k")
        )
        assert on == {"enabled": True, "mechanisms": ["poll"], "provider": "ping4sms"}
        off = delivery_reports_state(
            Settings(
                sms_delivery_provider="ping4sms",
                ping4sms_api_key="k",
                sms_dlr_poll_enabled=False,
            )
        )
        assert off["enabled"] is False
        webhook = delivery_reports_state(
            Settings(sms_delivery_provider="twilio", sms_dlr_webhook_token="t")
        )
        assert webhook["mechanisms"] == ["webhook"]
