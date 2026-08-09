"""Unit tests for ``wyfy_device_gateway.snmp_poller`` -- mocks the
``pysnmp`` command functions themselves (``get_cmd``/``bulk_walk_cmd``/
``walk_cmd``), the exact "mock at the third-party-library boundary"
convention this package's own real-device-I/O module
(``mikrotik_adapter.py``, which would mock ``librouteros.connect``) uses.
No real SNMP agent exists anywhere in this sandbox -- confirmed separately
(see ``snmp_poller.py``'s own module docstring) that a real request to an
unreachable host produces a real, honest timeout error; these tests cover
the reply-parsing/OID-walking logic that only a canned, controlled reply
can exercise deterministically.

Follows this project's plain-``assert``/native-``async def`` style;
``asyncio_mode = "auto"`` runs async tests directly.
"""

from __future__ import annotations

import pytest
from pysnmp.hlapi.v3arch.asyncio import (
    Counter64,
    EndOfMibView,
    Integer32,
    ObjectIdentifier,
    OctetString,
    TimeTicks,
)
from wyfy_device_gateway import snmp_poller as poller_module
from wyfy_device_gateway.snmp_poller import (
    HR_PROCESSOR_LOAD_OID,
    HR_STORAGE_TYPE_OID,
    IF_HC_IN_OCTETS_OID,
    IF_HC_OUT_OCTETS_OID,
    IF_OPER_STATUS_OID,
    IF_X_NAME_OID,
    SYS_UPTIME_OID,
    SnmpConnectionError,
    SnmpCredentials,
    SnmpDeviceError,
    SnmpPoller,
)

CREDS = SnmpCredentials(host="10.0.0.1", community="public")


def _var_bind(oid: str, value: object) -> tuple[object, object]:
    """A lightweight stand-in for a real, already-resolved pysnmp
    ``ObjectType`` reply row -- ``SnmpPoller`` only ever calls
    ``str(var_bind[0])``/reads ``var_bind[1]`` directly (see its own
    ``_get``/``_walk``), so a plain ``(oid_str, value)`` tuple exercises
    the exact same code path a real reply would without needing pysnmp's
    internal MIB-resolution machinery a hand-built ``ObjectType`` requires."""
    return (oid, value)


class _FakeErrorStatus:
    """Mirrors the real ``pysnmp`` ``errorStatus`` reply value's own
    ``__bool__``/``prettyPrint`` shape closely enough for this module's
    ``_raise_for_reply_error`` to exercise faithfully."""

    def __init__(self, truthy: bool, text: str = "noSuchName") -> None:
        self._truthy = truthy
        self._text = text

    def __bool__(self) -> bool:
        return self._truthy

    def prettyPrint(self) -> str:  # noqa: N802 -- matches pysnmp's own method name
        return self._text


_NO_ERROR = _FakeErrorStatus(False)


async def _fake_get_cmd_ok(oid: str, value: object):
    async def _get_cmd(engine, auth, target, context, object_type, **kwargs):  # noqa: ANN001
        return (None, _NO_ERROR, 0, (_var_bind(oid, value),))

    return _get_cmd


# ============================================================================
# get_uptime_seconds / get_system_description / get_system_name
# ============================================================================


class TestScalarGets:
    async def test_get_uptime_seconds_converts_centiseconds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_get_cmd(engine, auth, target, context, object_type, **kwargs):  # noqa: ANN001
            return (None, _NO_ERROR, 0, (_var_bind(SYS_UPTIME_OID, TimeTicks(360000)),))

        monkeypatch.setattr(poller_module, "get_cmd", fake_get_cmd)
        result = await SnmpPoller().get_uptime_seconds(CREDS)
        assert result == 3600  # 360000 centiseconds == 3600 real seconds

    async def test_get_system_name_strips_and_returns_string(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_get_cmd(engine, auth, target, context, object_type, **kwargs):  # noqa: ANN001
            return (
                None,
                _NO_ERROR,
                0,
                (_var_bind("1.3.6.1.2.1.1.5.0", OctetString("edge-router-01")),),
            )

        monkeypatch.setattr(poller_module, "get_cmd", fake_get_cmd)
        assert await SnmpPoller().get_system_name(CREDS) == "edge-router-01"

    async def test_get_uptime_seconds_none_when_no_reply(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_get_cmd(engine, auth, target, context, object_type, **kwargs):  # noqa: ANN001
            return (None, _NO_ERROR, 0, ())

        monkeypatch.setattr(poller_module, "get_cmd", fake_get_cmd)
        assert await SnmpPoller().get_uptime_seconds(CREDS) is None

    async def test_get_uptime_seconds_none_on_no_such_object(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A real, valid SNMP reply meaning "this agent doesn't implement
        this OID" -- never treated as a fabricated 0 or an error."""

        async def fake_get_cmd(engine, auth, target, context, object_type, **kwargs):  # noqa: ANN001
            return (None, _NO_ERROR, 0, (_var_bind(SYS_UPTIME_OID, EndOfMibView()),))

        monkeypatch.setattr(poller_module, "get_cmd", fake_get_cmd)
        assert await SnmpPoller().get_uptime_seconds(CREDS) is None


# ============================================================================
# Real, honest failure handling
# ============================================================================


class TestErrorHandling:
    async def test_get_raises_connection_error_on_error_indication(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_get_cmd(engine, auth, target, context, object_type, **kwargs):  # noqa: ANN001
            return ("No SNMP response received before timeout", _NO_ERROR, 0, ())

        monkeypatch.setattr(poller_module, "get_cmd", fake_get_cmd)
        with pytest.raises(SnmpConnectionError) as exc_info:
            await SnmpPoller().get_uptime_seconds(CREDS)
        assert exc_info.value.host == CREDS.host
        assert "timeout" in exc_info.value.detail.lower()

    async def test_get_raises_device_error_on_error_status(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_get_cmd(engine, auth, target, context, object_type, **kwargs):  # noqa: ANN001
            return (None, _FakeErrorStatus(True, "noSuchName"), 1, ())

        monkeypatch.setattr(poller_module, "get_cmd", fake_get_cmd)
        with pytest.raises(SnmpDeviceError):
            await SnmpPoller().get_uptime_seconds(CREDS)

    async def test_walk_raises_connection_error_on_error_indication(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_bulk_walk_cmd(
            engine, auth, target, context, non_repeaters, max_reps, obj_type, **kwargs
        ):  # noqa: ANN001
            yield ("No SNMP response received before timeout", _NO_ERROR, 0, ())

        monkeypatch.setattr(poller_module, "bulk_walk_cmd", fake_bulk_walk_cmd)
        with pytest.raises(SnmpConnectionError):
            await SnmpPoller().get_cpu_load_percent(CREDS)


# ============================================================================
# Table walks: CPU / memory / interfaces
# ============================================================================


class TestCpuLoad:
    async def test_averages_multiple_processor_cores(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_bulk_walk_cmd(
            engine, auth, target, context, non_repeaters, max_reps, obj_type, **kwargs
        ):  # noqa: ANN001
            yield (
                None,
                _NO_ERROR,
                0,
                (
                    _var_bind(f"{HR_PROCESSOR_LOAD_OID}.1", Integer32(10)),
                    _var_bind(f"{HR_PROCESSOR_LOAD_OID}.2", Integer32(30)),
                ),
            )

        monkeypatch.setattr(poller_module, "bulk_walk_cmd", fake_bulk_walk_cmd)
        assert await SnmpPoller().get_cpu_load_percent(CREDS) == 20.0

    async def test_none_when_no_host_resources_mib_support(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_bulk_walk_cmd(
            engine, auth, target, context, non_repeaters, max_reps, obj_type, **kwargs
        ):  # noqa: ANN001
            yield (
                None,
                _NO_ERROR,
                0,
                (_var_bind(HR_PROCESSOR_LOAD_OID, EndOfMibView()),),
            )

        monkeypatch.setattr(poller_module, "bulk_walk_cmd", fake_bulk_walk_cmd)
        assert await SnmpPoller().get_cpu_load_percent(CREDS) is None

    async def test_walk_stops_at_subtree_boundary(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A real GETBULK reply routinely returns rows beyond the
        requested subtree once the table ends -- must not be mistaken for
        real processor rows."""

        async def fake_bulk_walk_cmd(
            engine, auth, target, context, non_repeaters, max_reps, obj_type, **kwargs
        ):  # noqa: ANN001
            yield (
                None,
                _NO_ERROR,
                0,
                (
                    _var_bind(f"{HR_PROCESSOR_LOAD_OID}.1", Integer32(42)),
                    # Next OID in the MIB tree, outside hrProcessorLoad:
                    _var_bind("1.3.6.1.2.1.25.3.3.1.3.1", Integer32(999)),
                ),
            )

        monkeypatch.setattr(poller_module, "bulk_walk_cmd", fake_bulk_walk_cmd)
        assert await SnmpPoller().get_cpu_load_percent(CREDS) == 42.0


class TestMemoryUsage:
    # NOTE on these fakes: a hand-built ``ObjectType(ObjectIdentity(oid))``
    # (no value) genuinely cannot be indexed/introspected outside of
    # pysnmp's own internal MIB-resolution machinery (confirmed directly:
    # raises ``SmiError("... object not fully initialized")``) -- real
    # replies from real ``get_cmd``/``bulk_walk_cmd`` calls are already
    # resolved by pysnmp itself, but the *request* ``ObjectType`` the code
    # under test constructs and passes in is not. So these fakes dispatch
    # by real, fixed call order (``get_memory_usage_percent``'s own real,
    # deterministic sequence: one walk, then two GETs) rather than by
    # inspecting the incoming ``object_type`` argument -- ``SnmpPoller``
    # itself never inspects the OID string it gets back either (it only
    # reads ``var_bind[1]``, the value), so this is a faithful stand-in.
    async def test_finds_ram_row_and_computes_percentage(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ram_type_oid = poller_module.HR_STORAGE_RAM_TYPE_OID

        async def fake_bulk_walk_cmd(
            engine, auth, target, context, non_repeaters, max_reps, obj_type, **kwargs
        ):  # noqa: ANN001
            yield (
                None,
                _NO_ERROR,
                0,
                (
                    # Index 1: flash (not RAM) -- must be skipped.
                    _var_bind(
                        f"{HR_STORAGE_TYPE_OID}.1",
                        ObjectIdentifier("1.3.6.1.2.1.25.2.1.9"),
                    ),
                    # Index 2: RAM.
                    _var_bind(
                        f"{HR_STORAGE_TYPE_OID}.2", ObjectIdentifier(ram_type_oid)
                    ),
                ),
            )

        get_responses = [Integer32(1000), Integer32(250)]  # size.2, then used.2
        call_count = {"n": 0}

        async def fake_get_cmd(engine, auth, target, context, object_type, **kwargs):  # noqa: ANN001
            value = get_responses[call_count["n"]]
            call_count["n"] += 1
            return (None, _NO_ERROR, 0, (_var_bind("ignored", value),))

        monkeypatch.setattr(poller_module, "bulk_walk_cmd", fake_bulk_walk_cmd)
        monkeypatch.setattr(poller_module, "get_cmd", fake_get_cmd)
        assert await SnmpPoller().get_memory_usage_percent(CREDS) == 25.0
        assert call_count["n"] == 2

    async def test_none_when_no_ram_row_found(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_bulk_walk_cmd(
            engine, auth, target, context, non_repeaters, max_reps, obj_type, **kwargs
        ):  # noqa: ANN001
            yield (None, _NO_ERROR, 0, ())

        monkeypatch.setattr(poller_module, "bulk_walk_cmd", fake_bulk_walk_cmd)
        assert await SnmpPoller().get_memory_usage_percent(CREDS) is None

    async def test_none_when_size_is_zero_never_divides_by_zero(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ram_type_oid = poller_module.HR_STORAGE_RAM_TYPE_OID

        async def fake_bulk_walk_cmd(
            engine, auth, target, context, non_repeaters, max_reps, obj_type, **kwargs
        ):  # noqa: ANN001
            yield (
                None,
                _NO_ERROR,
                0,
                (
                    _var_bind(
                        f"{HR_STORAGE_TYPE_OID}.1", ObjectIdentifier(ram_type_oid)
                    ),
                ),
            )

        async def fake_get_cmd(engine, auth, target, context, object_type, **kwargs):  # noqa: ANN001
            return (None, _NO_ERROR, 0, (_var_bind("ignored", Integer32(0)),))

        monkeypatch.setattr(poller_module, "bulk_walk_cmd", fake_bulk_walk_cmd)
        monkeypatch.setattr(poller_module, "get_cmd", fake_get_cmd)
        assert await SnmpPoller().get_memory_usage_percent(CREDS) is None


class TestInterfaceCounters:
    # Same "dispatch by real, fixed call order, not by introspecting the
    # unresolved request ObjectType" rationale as TestMemoryUsage above.
    # get_interface_counters's own real, deterministic sequence is exactly
    # four walks: ifName, ifHCInOctets, ifHCOutOctets, ifOperStatus (see
    # its own docstring).
    async def test_joins_name_counters_and_status_by_index(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        walk_responses = [
            (_var_bind(f"{IF_X_NAME_OID}.1", OctetString("ether1")),),
            (_var_bind(f"{IF_HC_IN_OCTETS_OID}.1", Counter64(123456789)),),
            (_var_bind(f"{IF_HC_OUT_OCTETS_OID}.1", Counter64(987654321)),),
            (_var_bind(f"{IF_OPER_STATUS_OID}.1", Integer32(1)),),
        ]
        call_count = {"n": 0}

        async def fake_bulk_walk_cmd(
            engine, auth, target, context, non_repeaters, max_reps, obj_type, **kwargs
        ):  # noqa: ANN001
            rows = walk_responses[call_count["n"]]
            call_count["n"] += 1
            yield (None, _NO_ERROR, 0, rows)

        monkeypatch.setattr(poller_module, "bulk_walk_cmd", fake_bulk_walk_cmd)
        interfaces = await SnmpPoller().get_interface_counters(CREDS)
        assert len(interfaces) == 1
        iface = interfaces[0]
        assert iface.if_index == 1
        assert iface.if_name == "ether1"
        assert iface.in_octets == 123456789
        assert iface.out_octets == 987654321
        assert iface.if_oper_status_up is True

    async def test_down_interface_reports_not_up(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        walk_responses = [
            (_var_bind(f"{IF_X_NAME_OID}.2", OctetString("ether2")),),
            (),
            (),
            (_var_bind(f"{IF_OPER_STATUS_OID}.2", Integer32(2)),),
        ]
        call_count = {"n": 0}

        async def fake_bulk_walk_cmd(
            engine, auth, target, context, non_repeaters, max_reps, obj_type, **kwargs
        ):  # noqa: ANN001
            rows = walk_responses[call_count["n"]]
            call_count["n"] += 1
            yield (None, _NO_ERROR, 0, rows)

        monkeypatch.setattr(poller_module, "bulk_walk_cmd", fake_bulk_walk_cmd)
        interfaces = await SnmpPoller().get_interface_counters(CREDS)
        assert len(interfaces) == 1
        assert interfaces[0].if_oper_status_up is False
        assert interfaces[0].in_octets is None
        assert interfaces[0].out_octets is None


# ============================================================================
# SNMPv1 uses walk_cmd (GETNEXT), never bulk_walk_cmd (no GETBULK in v1)
# ============================================================================


class TestSnmpV1UsesWalkNotBulkWalk:
    async def test_v1_credentials_use_walk_cmd(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        called = {"walk_cmd": False, "bulk_walk_cmd": False}

        async def fake_walk_cmd(engine, auth, target, context, object_type, **kwargs):  # noqa: ANN001
            called["walk_cmd"] = True
            yield (
                None,
                _NO_ERROR,
                0,
                (_var_bind(f"{HR_PROCESSOR_LOAD_OID}.1", Integer32(5)),),
            )

        async def fake_bulk_walk_cmd(*args, **kwargs):  # noqa: ANN001, ANN002, ANN003
            called["bulk_walk_cmd"] = True
            yield (None, _NO_ERROR, 0, ())

        monkeypatch.setattr(poller_module, "walk_cmd", fake_walk_cmd)
        monkeypatch.setattr(poller_module, "bulk_walk_cmd", fake_bulk_walk_cmd)
        v1_creds = SnmpCredentials(host="10.0.0.1", community="public", version="1")
        result = await SnmpPoller().get_cpu_load_percent(v1_creds)
        assert result == 5.0
        assert called["walk_cmd"] is True
        assert called["bulk_walk_cmd"] is False
