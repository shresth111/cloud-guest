"""``MikroTikAdapter.push_hotspot_certificate`` -- the API-only replacement
for the ``scp`` + ``ssh`` hotspot-certificate push.

## What these tests can and cannot prove

No real MikroTik device exists in this sandbox (see ``mikrotik_adapter.py``'s
own module docstring), and the fleet's own firewall means nobody could reach
one over SSH to compare against even if there were. So what is proven here is
exactly this: the *command sequence and its ordering*, the fail-closed gates,
and the read-back verification -- against a fake transport whose certificate
store behaves the way RouterOS's does (an import of ``x.pem`` creates
``x.pem_0``, ``x.pem_1``, ...; a private-key import pairs onto the matching
certificate).

Three things these tests deliberately do NOT prove, because only hardware
can, and each is called out again where it is exercised:

1. whether ``/certificate import`` is callable over the API on this fleet's
   RouterOS build, and whether it reports counters (``test_import_counters_
   are_recorded_but_never_gated_on`` is why an absent reply is survivable);
2. whether a router can reach an HTTP URL on the app server at all -- the
   tunnel has only ever carried app-server-to-router traffic
   (``test_fetch_failure_...`` covers the failure being legible, not the
   success);
3. that RouterOS names imported objects ``<file>_0``/``<file>_1`` on this
   build. That naming is taken from the shell script that ran successfully
   against real hardware on 2026-08-18, not from documentation.

``test_intermediate_survives_the_push`` is the regression test for that
2026-08-18 incident and is the single most important test in this file.
"""

from __future__ import annotations

from typing import Any

import pytest
from fake_write_transport import FakeRouterOSApi
from wyfy_device_gateway.contract import HotspotCertificatePush
from wyfy_device_gateway.mikrotik_adapter import (
    MikroTikAdapter,
    MikroTikDeviceError,
    _dns_name_covered,
)

CERT_NAME = "wyfy-hotspot-fleet"
PROFILE = "hsprof1"
UPLOAD_FULLCHAIN = f"{CERT_NAME}.fullchain.pem"
UPLOAD_PRIVKEY = f"{CERT_NAME}.privkey.pem"

# The leaf names its issuer by authority-key-id; the intermediate claims that
# id as its own subject-key-id. That link, not an object count, is what makes
# the chain RouterOS serves complete -- see the incident write-up in
# ``_verify_hotspot_certificate``.
LEAF_AKID = "aa:bb:cc:dd"
INTERMEDIATE_SKID = LEAF_AKID
ROOT_SKID = "11:22:33:44"

PUSH = HotspotCertificatePush(
    cert_name=CERT_NAME,
    hotspot_profile=PROFILE,
    fullchain_url="http://10.20.0.1:8443/tok-fullchain",
    privkey_url="http://10.20.0.1:8443/tok-privkey",
    expected_dns_names=("wifi.wyfyguest.com", "*.portal.wyfyguest.com"),
)


def _fetch_reply(status: str = "finished") -> list[dict[str, Any]]:
    return [{"status": "downloading", "downloaded": "0"}, {"status": status}]


def _make_api(
    *,
    existing_certificates: list[dict[str, Any]] | None = None,
    profile: dict[str, Any] | None = None,
    fetch_status: str = "finished",
    import_counters: dict[str, Any] | None = None,
    import_creates_leaf: bool = True,
    import_creates_intermediate: bool = True,
    rebind_is_a_no_op: bool = False,
) -> FakeRouterOSApi:
    """A fake router whose ``/certificate import`` really imports.

    Defaults model the fleet as it stands today: one bound, about-to-expire
    leaf under the stable name plus the intermediate that was preserved under
    ``-chain-1`` by the previous round.
    """
    certificates = existing_certificates
    if certificates is None:
        certificates = [
            {
                ".id": "*1",
                "name": CERT_NAME,
                "trusted": True,
                "private-key": True,
                "akid": LEAF_AKID,
                "skid": "old-leaf-skid",
                "invalid-after": "nov/16/2026 12:00:00",
            },
            {
                ".id": "*2",
                "name": f"{CERT_NAME}-chain-1",
                "trusted": True,
                "private-key": False,
                "akid": ROOT_SKID,
                "skid": INTERMEDIATE_SKID,
            },
        ]

    profile_row = profile
    if profile_row is None:
        profile_row = {
            ".id": "*10",
            "name": PROFILE,
            "dns-name": "wifi.wyfyguest.com",
            "ssl-certificate": CERT_NAME,
            "login-by": "https,http-pap",
        }

    menus: dict[tuple[str, ...], list[dict[str, Any]]] = {
        ("certificate",): certificates,
        ("ip", "hotspot", "profile"): [profile_row],
        ("file",): [],
    }

    def _fetch(api: FakeRouterOSApi, kwargs: dict[str, Any]):
        if fetch_status == "finished":
            rows = api.path("file")._rows
            rows.append({".id": f"*f{len(rows) + 1}", "name": kwargs["dst-path"]})
        return _fetch_reply(fetch_status)

    def _import(api: FakeRouterOSApi, kwargs: dict[str, Any]):
        rows = api.path("certificate")._rows
        file_name = kwargs["file-name"]
        counters = dict(import_counters or {})
        if file_name == UPLOAD_FULLCHAIN:
            if import_creates_leaf:
                rows.append(
                    {
                        ".id": "*100",
                        "name": f"{file_name}_0",
                        "trusted": False,
                        "private-key": False,
                        "akid": LEAF_AKID,
                        "skid": "new-leaf-skid",
                        "invalid-after": "feb/14/2027 12:00:00",
                    }
                )
            if import_creates_intermediate:
                rows.append(
                    {
                        ".id": "*101",
                        "name": f"{file_name}_1",
                        "trusted": False,
                        "private-key": False,
                        "akid": ROOT_SKID,
                        "skid": INTERMEDIATE_SKID,
                    }
                )
            counters.setdefault("certificates-imported", 2)
            counters.setdefault("private-keys-imported", 0)
        else:
            # RouterOS pairs an imported private key onto the certificate it
            # belongs to rather than creating an object of its own.
            for row in rows:
                if row.get("name") == f"{UPLOAD_FULLCHAIN}_0":
                    row["private-key"] = True
            counters.setdefault("certificates-imported", 0)
            counters.setdefault("private-keys-imported", 1)
        if import_counters is not None and not import_counters:
            return []
        return [counters]

    api = FakeRouterOSApi(
        menus=menus,
        command_handlers={"/tool/fetch": _fetch, "/certificate/import": _import},
    )
    if rebind_is_a_no_op:
        # Reproduces the failure the shell script's own comment records:
        # a `set` that returns cleanly and changes nothing. If the adapter
        # trusted "no exception" as success, this router would go on serving
        # the expired certificate and every log would say the push worked.
        api.silently_ignore_updates.add(("ip", "hotspot", "profile"))
    return api


@pytest.fixture
def adapter() -> MikroTikAdapter:
    return MikroTikAdapter()


def _op_index(api: FakeRouterOSApi, predicate) -> int:
    for index, op in enumerate(api.ops):
        if predicate(op):
            return index
    raise AssertionError(f"no matching op in {api.ops}")


def _certificate_names(api: FakeRouterOSApi) -> list[str]:
    return [str(row.get("name")) for row in api.path("certificate")]


class _LateVisibilityRows(list):
    """A ``/certificate`` store where a just-created object is missing from
    the very next print and present in the one after.

    Not a hypothetical: the shell script this push is ported from carries a
    ``:delay 1s`` after its imports precisely because RouterOS does not
    promise that. Swapped in as the menu's backing list so that reads go
    through ``__iter__`` exactly as a real ``print`` would.
    """

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        super().__init__(rows)
        self._hidden: list[dict[str, Any]] = []
        self.reads_while_hidden = 0

    def hide_one_read(self, name_prefix: str) -> None:
        doomed = [
            r for r in list(self) if str(r.get("name", "")).startswith(name_prefix)
        ]
        for row in doomed:
            super().remove(row)
            self._hidden.append(row)

    def __iter__(self):
        if self._hidden:
            if self.reads_while_hidden:
                self.extend(self._hidden)
                self._hidden.clear()
            else:
                self.reads_while_hidden += 1
        return super().__iter__()


# ---------------------------------------------------------------------------
# happy path + ordering
# ---------------------------------------------------------------------------


async def test_happy_path_reports_what_the_device_says(
    adapter, mikrotik_creds, patch_connect
):
    api = _make_api()
    patch_connect(api)

    result = await adapter.push_hotspot_certificate(mikrotik_creds, push=PUSH)

    assert result.cert_name == CERT_NAME
    assert result.bound_ssl_certificate == CERT_NAME
    assert result.bound_login_by == "https,http-pap"
    assert result.leaf_has_private_key is True
    assert result.chain_issuer_present is True
    assert result.chain_cert_names == (f"{CERT_NAME}-chain-1",)
    assert result.certificates_imported == 2
    assert result.private_keys_imported == 1
    # Read off the device, not computed from the PEM we uploaded.
    assert result.leaf_invalid_after == "feb/14/2027 12:00:00"
    assert result.profile_dns_name == "wifi.wyfyguest.com"
    assert api.closed is True


async def test_router_pulls_both_pems_before_the_certificate_store_is_touched(
    adapter, mikrotik_creds, patch_connect
):
    """Step 3 removes the currently-serving intermediate. Every failure that
    can happen before that -- including "the router cannot reach the URL at
    all", which is the unproven one -- must happen before it."""
    api = _make_api()
    patch_connect(api)

    await adapter.push_hotspot_certificate(mikrotik_creds, push=PUSH)

    fetches = [kwargs for cmd, kwargs in api.command_calls if cmd == "/tool/fetch"]
    assert [f["dst-path"] for f in fetches] == [UPLOAD_FULLCHAIN, UPLOAD_PRIVKEY]
    assert [f["url"] for f in fetches] == [PUSH.fullchain_url, PUSH.privkey_url]
    assert all(f["mode"] == "http" for f in fetches)

    last_fetch = _op_index(
        api, lambda op: op[0] == "command" and op[1] == ("/tool/fetch",)
    )
    # reversed() rather than the first match: what matters is that no removal
    # precedes the LAST fetch.
    first_removal = _op_index(
        api, lambda op: op[0] == "remove" and op[1] == ("certificate",)
    )
    assert last_fetch < first_removal


async def test_https_url_is_fetched_with_certificate_checking_on(
    adapter, mikrotik_creds, patch_connect
):
    """The response body is the fleet private key. The speed test's
    ``check-certificate=no`` is fine for a throwaway blob and is not fine
    here."""
    api = _make_api()
    patch_connect(api)

    await adapter.push_hotspot_certificate(
        mikrotik_creds,
        push=HotspotCertificatePush(
            cert_name=CERT_NAME,
            hotspot_profile=PROFILE,
            fullchain_url="https://cert.internal/tok-a",
            privkey_url="https://cert.internal/tok-b",
        ),
    )

    fetches = [kwargs for cmd, kwargs in api.command_calls if cmd == "/tool/fetch"]
    assert all(f["mode"] == "https" for f in fetches)
    assert all(f["check-certificate"] == "yes" for f in fetches)


async def test_rebind_sets_ssl_certificate_and_login_by_in_one_call(
    adapter, mikrotik_creds, patch_connect
):
    """Splitting these across two ``set`` calls is what silently no-op'd
    during the 2026-08-18 incident."""
    api = _make_api()
    patch_connect(api)

    await adapter.push_hotspot_certificate(mikrotik_creds, push=PUSH)

    profile_updates = [
        fields
        for segments, fields in api.update_calls
        if segments == ("ip", "hotspot", "profile")
    ]
    # Two binds, both atomic: onto the temporary name (which is what makes
    # removing the old leaf safe), then onto the stable name after the
    # rename -- see step 7b in _push_hotspot_certificate_sync.
    assert len(profile_updates) == 2
    assert [fields["ssl-certificate"] for fields in profile_updates] == [
        f"{CERT_NAME}-new",
        CERT_NAME,
    ]
    assert all(fields["login-by"] == "https,http-pap" for fields in profile_updates)


async def test_old_leaf_is_removed_only_after_the_rebind(
    adapter, mikrotik_creds, patch_connect
):
    """The live certificate must never be deleted while still referenced."""
    api = _make_api()
    patch_connect(api)

    await adapter.push_hotspot_certificate(mikrotik_creds, push=PUSH)

    rebind = _op_index(
        api, lambda op: op[0] == "update" and op[1] == ("ip", "hotspot", "profile")
    )
    old_leaf_removed = _op_index(
        api,
        lambda op: op[0] == "remove"
        and op[1] == ("certificate",)
        and "*1" in op[2],
    )
    assert rebind < old_leaf_removed


async def test_uploaded_pems_are_deleted_from_flash(
    adapter, mikrotik_creds, patch_connect
):
    api = _make_api()
    patch_connect(api)

    await adapter.push_hotspot_certificate(mikrotik_creds, push=PUSH)

    assert [row.get("name") for row in api.path("file")] == []


# ---------------------------------------------------------------------------
# the 2026-08-18 incident
# ---------------------------------------------------------------------------


async def test_intermediate_survives_the_push(adapter, mikrotik_creds, patch_connect):
    """THE regression test. An earlier version of this push deleted the
    Let's Encrypt intermediate immediately after importing it, and the router
    then served the leaf alone -- genuinely LE-issued, verifiable offline,
    incomplete on the wire. Strict TLS clients reject that outright; desktop
    browsers paper over it, which is why it went unnoticed.

    Asserted on the state the device is actually left in, not on the command
    sequence: after the push, some certificate in the store must claim the
    leaf's ``akid`` as its own ``skid``, and it must be trusted.
    """
    api = _make_api()
    patch_connect(api)

    await adapter.push_hotspot_certificate(mikrotik_creds, push=PUSH)

    certificates = [dict(row) for row in api.path("certificate")]
    leaf = next(row for row in certificates if row["name"] == CERT_NAME)
    issuers = [
        row
        for row in certificates
        if row.get("skid") == leaf["akid"] and row["name"] != CERT_NAME
    ]
    assert issuers, f"leaf akid is orphaned; store is {_certificate_names(api)}"
    assert issuers[0]["name"] == f"{CERT_NAME}-chain-1"
    assert issuers[0]["trusted"] == "yes"


async def test_a_push_that_loses_the_intermediate_is_rejected(
    adapter, mikrotik_creds, patch_connect
):
    """The inverse: if the intermediate is not there at the end, the push
    must fail loudly rather than report success. This is the state the
    incident actually left the router in."""
    api = _make_api(import_creates_intermediate=False)
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError) as excinfo:
        await adapter.push_hotspot_certificate(mikrotik_creds, push=PUSH)

    assert "orphaned akid" in str(excinfo.value)
    assert "2026-08-18" in str(excinfo.value)


async def test_multiple_intermediates_are_all_preserved(
    adapter, mikrotik_creds, patch_connect
):
    """Do not assume Let's Encrypt's chain has exactly one intermediate --
    the shell script this is ported from says so explicitly."""
    api = _make_api()
    patch_connect(api)
    inner = api._command_handlers["/certificate/import"]  # type: ignore[attr-defined]

    def _import_three(fake: FakeRouterOSApi, kwargs: dict[str, Any]):
        reply = inner(fake, kwargs)
        if kwargs["file-name"] == UPLOAD_FULLCHAIN:
            fake.path("certificate")._rows.append(
                {
                    ".id": "*102",
                    "name": f"{UPLOAD_FULLCHAIN}_2",
                    "trusted": False,
                    "private-key": False,
                    "akid": "",
                    "skid": ROOT_SKID,
                }
            )
        return reply

    api._command_handlers["/certificate/import"] = _import_three  # type: ignore[attr-defined]

    result = await adapter.push_hotspot_certificate(mikrotik_creds, push=PUSH)

    assert result.chain_cert_names == (
        f"{CERT_NAME}-chain-1",
        f"{CERT_NAME}-chain-2",
    )
    assert f"{UPLOAD_FULLCHAIN}_1" not in _certificate_names(api)
    assert f"{UPLOAD_FULLCHAIN}_2" not in _certificate_names(api)


# ---------------------------------------------------------------------------
# fail closed
# ---------------------------------------------------------------------------


async def test_silent_import_no_op_leaves_the_router_on_its_working_cert(
    adapter, mikrotik_creds, patch_connect
):
    """Unknown #1, handled rather than assumed. If ``/certificate import``
    turns out not to be callable over the API on this firmware -- or is, and
    does nothing -- the router must still be serving the certificate it was
    serving before, because nothing destructive runs until the new leaf has
    been read back by name."""
    api = _make_api(import_creates_leaf=False, import_creates_intermediate=False)
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError) as excinfo:
        await adapter.push_hotspot_certificate(mikrotik_creds, push=PUSH)

    assert "the import did nothing" in str(excinfo.value)
    profile = next(iter(api.path("ip", "hotspot", "profile")))
    assert profile["ssl-certificate"] == CERT_NAME
    assert CERT_NAME in _certificate_names(api)
    # and the private key is not left lying on the router's flash
    assert [row.get("name") for row in api.path("file")] == []


async def test_fetch_failure_is_reported_as_the_unproven_direction(
    adapter, mikrotik_creds, patch_connect
):
    """Unknown #2, scoped rather than settled. Nothing in this repo has ever
    made a router originate a connection back to the app server; if it turns
    out it cannot, this is the message the operator gets, and the certificate
    store is untouched."""
    api = _make_api(fetch_status="failed")
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError) as excinfo:
        await adapter.push_hotspot_certificate(mikrotik_creds, push=PUSH)

    message = str(excinfo.value)
    assert "could not fetch" in message
    assert "routes over the tunnel" in message
    assert api.remove_calls == []
    assert api.update_calls == []
    assert [cmd for cmd, _ in api.command_calls] == ["/tool/fetch"]


async def test_rebind_that_silently_does_nothing_is_not_reported_as_success(
    adapter, mikrotik_creds, patch_connect
):
    """A first push onto a router that has never carried this certificate --
    which the fleet inventory says is most of them ("the founder's router had
    ZERO certificates on it", measured 2026-08-23). Here a silently-no-op'd
    rebind is visible, and must not be reported as success."""
    api = _make_api(
        existing_certificates=[],
        profile={
            ".id": "*10",
            "name": PROFILE,
            "dns-name": "wifi.wyfyguest.com",
            "ssl-certificate": "none",
            "login-by": "http-pap",
        },
        rebind_is_a_no_op=True,
    )
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError) as excinfo:
        await adapter.push_hotspot_certificate(mikrotik_creds, push=PUSH)

    assert "did not take" in str(excinfo.value)


async def test_a_no_op_rebind_never_reaches_the_removal_of_the_old_leaf(
    adapter, mikrotik_creds, patch_connect
):
    """The gap this closes in the shell script it is ported from.

    ``REMOTE_SCRIPT`` waits a second after the rebind and then removes the
    old leaf unconditionally. On a router where the rebind returns cleanly
    and changes nothing -- the 2026-08-18 shape -- that deletes the
    certificate the router is at that moment still serving, and the venue
    goes dark for a failure that had not actually broken anything yet.
    """
    api = _make_api(rebind_is_a_no_op=True)
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError) as excinfo:
        await adapter.push_hotspot_certificate(mikrotik_creds, push=PUSH)

    assert "did not take" in str(excinfo.value)
    assert "2026-08-18" in str(excinfo.value)
    # The old, still-bound leaf is untouched, and so is the binding.
    assert CERT_NAME in _certificate_names(api)
    profile = next(iter(api.path("ip", "hotspot", "profile")))
    assert profile["ssl-certificate"] == CERT_NAME
    # and the private key is not left on flash
    assert [row.get("name") for row in api.path("file")] == []


async def test_an_import_that_lands_a_beat_late_is_waited_for(
    adapter, mikrotik_creds, patch_connect
):
    """``REMOTE_SCRIPT`` carries a ``:delay 1s`` after the imports, because
    neither the import nor the profile ``set`` is guaranteed to be visible to
    the very next command. Dropping that on the port would have made the
    first hardware run fail with "the import did nothing" -- the exact wrong
    answer to the one question that run exists to settle.
    """
    api = _make_api()
    rows = _LateVisibilityRows(api._menus[("certificate",)])  # type: ignore[attr-defined]
    api._menus[("certificate",)] = rows  # type: ignore[attr-defined]
    patch_connect(api)
    inner = api._command_handlers["/certificate/import"]  # type: ignore[attr-defined]

    def _import_late(fake: FakeRouterOSApi, kwargs: dict[str, Any]):
        reply = inner(fake, kwargs)
        if kwargs["file-name"] == UPLOAD_PRIVKEY:
            # Both imports have landed on the device; the objects they
            # created are simply not in the next /certificate print yet.
            rows.hide_one_read(f"{UPLOAD_FULLCHAIN}_")
        return reply

    api._command_handlers["/certificate/import"] = _import_late  # type: ignore[attr-defined]

    result = await adapter.push_hotspot_certificate(mikrotik_creds, push=PUSH)

    # It really did have to look twice -- otherwise this test would pass
    # against an adapter with no wait at all.
    assert rows.reads_while_hidden == 1
    assert result.bound_ssl_certificate == CERT_NAME
    assert result.leaf_has_private_key is True
    assert result.chain_issuer_present is True


async def test_first_push_onto_a_router_with_no_certificates_works(
    adapter, mikrotik_creds, patch_connect
):
    """Same router, real rebind. There is no old leaf to remove and the
    profile has never been bound; neither is an error."""
    api = _make_api(
        existing_certificates=[],
        profile={
            ".id": "*10",
            "name": PROFILE,
            "dns-name": "wifi.wyfyguest.com",
            "ssl-certificate": "none",
            "login-by": "http-pap",
        },
    )
    patch_connect(api)

    result = await adapter.push_hotspot_certificate(mikrotik_creds, push=PUSH)

    assert result.bound_ssl_certificate == CERT_NAME
    assert result.bound_login_by == "https,http-pap"


async def test_login_by_is_compared_as_a_set_not_a_string(
    adapter, mikrotik_creds, patch_connect
):
    """RouterOS is free to answer the read in its own order. A string
    comparison would fail every correctly-rebound profile."""
    api = _make_api()
    patch_connect(api)
    profile_rows = api.path("ip", "hotspot", "profile")._rows

    original = FakeRouterOSApi.path

    def _reorder_on_read(self: FakeRouterOSApi, *segments: str):
        path = original(self, *segments)
        if segments == ("ip", "hotspot", "profile"):
            for row in profile_rows:
                if row.get("login-by") == "https,http-pap":
                    row["login-by"] = "http-pap,https"
        return path

    api.path = _reorder_on_read.__get__(api)  # type: ignore[method-assign]

    result = await adapter.push_hotspot_certificate(mikrotik_creds, push=PUSH)

    assert result.bound_login_by == "http-pap,https"


async def test_missing_profile_is_refused_before_anything_is_written(
    adapter, mikrotik_creds, patch_connect
):
    api = _make_api(profile={".id": "*10", "name": "some-other-profile"})
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError) as excinfo:
        await adapter.push_hotspot_certificate(mikrotik_creds, push=PUSH)

    assert "no /ip hotspot profile" in str(excinfo.value)
    assert api.command_calls == []
    assert api.ops == []


async def test_profile_dns_name_outside_the_certificate_sans_is_refused(
    adapter, mikrotik_creds, patch_connect
):
    """Pushing a certificate that does not cover the host in the guest's URL
    bar produces the exact browser warning this push exists to remove, while
    succeeding in every log."""
    api = _make_api(
        profile={
            ".id": "*10",
            "name": PROFILE,
            "dns-name": "portal.someoneelse.example",
            "ssl-certificate": CERT_NAME,
            "login-by": "https,http-pap",
        }
    )
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError) as excinfo:
        await adapter.push_hotspot_certificate(mikrotik_creds, push=PUSH)

    assert "does not cover" in str(excinfo.value)
    assert api.ops == []


async def test_encrypted_pem_is_reported_not_swallowed(
    adapter, mikrotik_creds, patch_connect
):
    api = _make_api(
        import_counters={"certificates-imported": 0, "decryption-failures": 1}
    )
    patch_connect(api)

    with pytest.raises(MikroTikDeviceError) as excinfo:
        await adapter.push_hotspot_certificate(mikrotik_creds, push=PUSH)

    assert "decryption failure" in str(excinfo.value)


async def test_import_counters_are_recorded_but_never_gated_on(
    adapter, mikrotik_creds, patch_connect
):
    """Unknown #1's other half. Whether this firmware answers
    ``/certificate import`` with counters over the API is unconfirmed, so a
    silent reply must not fail an otherwise-verified push -- it just means
    the result says ``None`` instead of a number, and the read-back is doing
    all the work."""
    api = _make_api(import_counters={})
    patch_connect(api)

    result = await adapter.push_hotspot_certificate(mikrotik_creds, push=PUSH)

    assert result.certificates_imported is None
    assert result.private_keys_imported is None
    assert result.bound_ssl_certificate == CERT_NAME
    assert result.chain_issuer_present is True


async def test_leaf_without_a_private_key_is_rejected(
    adapter, mikrotik_creds, patch_connect
):
    """A certificate imported with no key binds cleanly and then fails every
    handshake -- the portal is down and the router reports nothing wrong."""
    api = _make_api()
    patch_connect(api)
    inner = api._command_handlers["/certificate/import"]  # type: ignore[attr-defined]

    def _drop_the_key(fake: FakeRouterOSApi, kwargs: dict[str, Any]):
        if kwargs["file-name"] == UPLOAD_PRIVKEY:
            return [{"certificates-imported": 0, "private-keys-imported": 0}]
        return inner(fake, kwargs)

    api._command_handlers["/certificate/import"] = _drop_the_key  # type: ignore[attr-defined]

    with pytest.raises(MikroTikDeviceError) as excinfo:
        await adapter.push_hotspot_certificate(mikrotik_creds, push=PUSH)

    assert "has no private key" in str(excinfo.value)


# ---------------------------------------------------------------------------
# SAN coverage
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("dns_name", "expected"),
    [
        ("wifi.wyfyguest.com", True),
        ("WIFI.WyfyGuest.com", True),
        ("wifi.wyfyguest.com.", True),
        ("site42.portal.wyfyguest.com", True),
        # a wildcard covers exactly one label, never zero and never two
        ("portal.wyfyguest.com", False),
        ("a.b.portal.wyfyguest.com", False),
        ("wifi.wyfyguest.com.evil.example", False),
        ("", False),
        (None, False),
    ],
)
def test_dns_name_coverage(dns_name, expected):
    assert (
        _dns_name_covered(dns_name, ("wifi.wyfyguest.com", "*.portal.wyfyguest.com"))
        is expected
    )


def test_no_sans_means_no_coverage_claim():
    """An empty SAN list must never read as "covers everything"."""
    assert _dns_name_covered("wifi.wyfyguest.com", ()) is False
