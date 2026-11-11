"""First name + mobile required on the console's subscriber writes (unit).
The route scenario is ``test_isp_subscriber_contact_postgres.py``."""

from __future__ import annotations

import inspect

import pytest

from app.domains.isp_partner import subscriber_contact as sc


@pytest.fixture
def on(monkeypatch: pytest.MonkeyPatch):  # noqa: ANN201
    monkeypatch.setenv("ISP_SUBSCRIBER_CONTACT_REQUIRED", "true")
    sc.get_subscriber_contact_settings.cache_clear()
    yield
    sc.get_subscriber_contact_settings.cache_clear()


def test_flag_off_is_a_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ISP_SUBSCRIBER_CONTACT_REQUIRED", raising=False)
    sc.get_subscriber_contact_settings.cache_clear()
    sc.check_contact_on_create({})
    sc.check_contact_on_patch({"first_name": "", "phone": "x"})
    sc.get_subscriber_contact_settings.cache_clear()


@pytest.mark.parametrize(
    ("v", "ok"),
    [
        ("9876543210", True),
        ("+91 98765-43210", True),
        ("09876543210", True),
        ("919876543210", True),
        ("5876543210", False),
        ("12345", False),
        ("", False),
        (None, False),
        ("98765432101", False),
    ],
)
def test_is_mobile(v, ok: bool) -> None:  # noqa: ANN001
    assert sc.is_mobile(v) is ok


def test_create_rules(on) -> None:  # noqa: ANN001
    with pytest.raises(sc.IspSubscriberFirstNameRequiredError):
        sc.check_contact_on_create({"phone": "9876543210"})
    with pytest.raises(sc.IspSubscriberFirstNameRequiredError):
        sc.check_contact_on_create({"first_name": "  ", "phone": "9876543210"})
    with pytest.raises(sc.IspSubscriberMobileRequiredError):
        sc.check_contact_on_create({"first_name": "Asha"})
    with pytest.raises(sc.IspSubscriberMobileRequiredError):
        sc.check_contact_on_create({"first_name": "Asha", "phone": "12"})
    sc.check_contact_on_create({"first_name": "Asha", "phone": "9876543210"})
    assert (
        sc.IspSubscriberFirstNameRequiredError.code
        == "ISP_SUBSCRIBER_FIRST_NAME_REQUIRED"
    )
    assert sc.IspSubscriberMobileRequiredError.status_code_default == 422


def test_patch_checks_only_sent_keys(on) -> None:  # noqa: ANN001
    sc.check_contact_on_patch({})
    sc.check_contact_on_patch({"zone_id": None, "last_name": None})
    with pytest.raises(sc.IspSubscriberFirstNameRequiredError):
        sc.check_contact_on_patch({"first_name": None})
    with pytest.raises(sc.IspSubscriberMobileRequiredError):
        sc.check_contact_on_patch({"phone": None})
    sc.check_contact_on_patch({"first_name": "A", "phone": "9876543210"})


def test_wired_only_into_the_console_routes() -> None:
    from app.domains.isp_partner import (
        apps_leads,
        onboarding_router,
        plans_router,
        plans_service,
        subscriber360_router,
    )

    assert "check_contact_on_create(data)" in inspect.getsource(
        plans_router.create_subscriber
    )
    assert "check_contact_on_patch(data)" in inspect.getsource(
        plans_router.patch_subscriber
    )
    assert "check_contact_on_create(data)" in inspect.getsource(
        subscriber360_router.onboard_subscriber
    )
    assert "check_contact_on_create(" in inspect.getsource(onboarding_router.onboard)
    # coupon sync, the service layer and lead conversion are untouched
    for mod in (plans_service, apps_leads):
        assert "subscriber_contact" not in inspect.getsource(mod)
