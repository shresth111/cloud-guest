"""Tests for the hub's FreeRADIUS client-provisioning agent
(``ops/hub-agents/radius_agent.py``).

This file is deployed to the hub VM at ``/usr/local/sbin/radius_agent.py``
and runs outside the application container, so it is imported here by path
rather than as a package. It had no tests at all, which is why it shipped
with only ``do_POST``: the backend had been sending it ``DELETE`` requests
for months and getting ``501 Unsupported method ('DELETE')`` back every
single time.

Everything below drives the real parsing/removal functions against real
``clients.conf`` text -- including the live hub's actual pathologies
(doubled ``cg-cg-`` labels, seven identically-labelled stanzas for one
NAS, commented-out example blocks in Ubuntu's stock file). ``freeradius
-CX`` and ``systemctl`` are the only things stubbed; there is no
FreeRADIUS binary here.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from typing import Any

import pytest

_AGENT_PATH = (
    Path(__file__).resolve().parents[2] / "ops" / "hub-agents" / "radius_agent.py"
)
_spec = importlib.util.spec_from_file_location("wyfy_radius_agent", _AGENT_PATH)
assert _spec is not None and _spec.loader is not None
radius_agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(radius_agent)


# Ubuntu's stock clients.conf opens with ~290 lines of commented-out
# examples, several of which are `#client foo {` blocks. Anything that
# treats those as real would corrupt the file.
_STOCK_PREAMBLE = """\
#  client example {
#\tipaddr = 192.0.2.4
#\tsecret = testing123
#  }

client localhost {
\tipaddr = 127.0.0.1
\tproto = *
\tsecret = testing123
\trequire_message_authenticator = no
\tlimit {
\t\tmax_connections = 16
\t\tlifetime = 0
\t\tidle_timeout = 30
\t}
}
"""

_CG_STANZA = """
client cg-{ident} {{
\tipaddr = {ip}/32
\tsecret = s3cr3t-{ip}
\tshortname = {ident}
\tbackend_secret = s3cr3t-{ip}
\trequire_message_authenticator = {rma}
\tnas_type = other
}}
"""


def _stanza(ident: str, ip: str, rma: str = "no") -> str:
    return _CG_STANZA.format(ident=ident, ip=ip, rma=rma)


@pytest.fixture()
def conf(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A real clients.conf on disk, with the agent pointed at it and its
    two shell-outs stubbed to succeed."""
    path = tmp_path / "clients.conf"
    path.write_text(_STOCK_PREAMBLE)
    monkeypatch.setattr(radius_agent, "CLIENTS_CONF", str(path))
    monkeypatch.setattr(radius_agent, "BACKUP_DIR", str(tmp_path / "backups"))

    def _fake_run(cmd: list[str], **kwargs: Any) -> Any:
        if cmd[:2] == ["freeradius", "-CX"]:
            return subprocess.CompletedProcess(
                cmd, 0, stdout="Configuration appears to be OK\n", stderr=""
            )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(radius_agent.subprocess, "run", _fake_run)
    return path


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


class TestBlockParsing:
    def test_commented_out_example_blocks_are_not_clients(self) -> None:
        blocks = radius_agent._split_client_blocks(_STOCK_PREAMBLE)
        assert len(blocks) == 1

    def test_nested_braces_do_not_end_a_block_early(self) -> None:
        """``localhost`` contains a ``limit {}`` sub-block. A naive
        first-closing-brace scan would cut the stanza in half and leave
        orphaned lines behind, breaking FreeRADIUS for the whole fleet."""
        text = _STOCK_PREAMBLE
        (start, end, _shortname) = radius_agent._split_client_blocks(text)[0]
        block = "\n".join(text.split("\n")[start:end])
        assert block.count("{") == block.count("}") == 2
        assert "idle_timeout" in block

    def test_unterminated_block_refuses_to_guess(self) -> None:
        with pytest.raises(RuntimeError, match="unterminated"):
            radius_agent._split_client_blocks("client broken {\n\tipaddr = 1.2.3.4\n")

    def test_shortname_not_the_label_identifies_a_stanza(self) -> None:
        """The live hub's labels read ``cg-cg-5d3a509e`` (the agent prefixes
        ``cg-`` onto an identifier that already starts with ``cg-``) while
        the ``shortname`` inside is the real ``cg-5d3a509e`` the database
        and ``%{client:shortname}`` both use."""
        text = _STOCK_PREAMBLE + _stanza("cg-5d3a509e", "10.20.0.28")
        _, removed = radius_agent._strip_clients_with_shortname(text, "cg-cg-5d3a509e")
        assert removed == []
        _, removed = radius_agent._strip_clients_with_shortname(text, "cg-5d3a509e")
        assert len(removed) == 1


# ---------------------------------------------------------------------------
# Removal
# ---------------------------------------------------------------------------


class TestStripClients:
    def test_removes_every_stanza_for_one_identifier(self) -> None:
        """The live hub has seven stanzas labelled ``cg-cg-11462682``, one
        per tunnel IP that router has held. Leaving any behind leaves a
        valid shared secret for a NAS that was just revoked."""
        text = _STOCK_PREAMBLE + "".join(
            _stanza("cg-11462682", f"10.20.0.{i}") for i in range(55, 62)
        )
        out, removed = radius_agent._strip_clients_with_shortname(text, "cg-11462682")
        assert len(removed) == 7
        assert "cg-11462682" not in out
        assert "client localhost {" in out

    def test_leaves_other_clients_untouched(self) -> None:
        text = (
            _STOCK_PREAMBLE
            + _stanza("cg-5d3a509e", "10.20.0.28")
            + _stanza("cg-c61ae7af", "10.20.0.40")
        )
        out, removed = radius_agent._strip_clients_with_shortname(text, "cg-5d3a509e")
        assert len(removed) == 1
        assert "cg-c61ae7af" in out
        assert "10.20.0.40" in out
        assert "10.20.0.28" not in out
        #  Still parses as balanced config, not a file with a hole in it.
        assert out.count("{") == out.count("}")

    def test_unknown_identifier_changes_nothing(self) -> None:
        text = _STOCK_PREAMBLE + _stanza("cg-5d3a509e", "10.20.0.28")
        out, removed = radius_agent._strip_clients_with_shortname(text, "cg-nosuch")
        assert removed == []
        assert out == text


class TestRemoveClient:
    def test_removes_and_reports_the_count(self, conf: Path) -> None:
        conf.write_text(
            _STOCK_PREAMBLE
            + _stanza("cg-04f81868", "10.20.0.50")
            + _stanza("cg-04f81868", "10.20.0.51")
        )
        assert radius_agent.remove_client("cg-04f81868") == {
            "status": "ok",
            "removed": 2,
        }
        assert "cg-04f81868" not in conf.read_text()

    def test_no_op_does_not_restart_freeradius(
        self, conf: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A delete for a NAS that was never on this hub must not bounce
        the RADIUS service for every other router."""
        calls: list[list[str]] = []
        monkeypatch.setattr(
            radius_agent.subprocess,
            "run",
            lambda cmd, **kw: calls.append(cmd)
            or subprocess.CompletedProcess(cmd, 0, stdout="", stderr=""),
        )
        before = conf.read_text()
        assert radius_agent.remove_client("cg-nosuch") == {
            "status": "ok",
            "removed": 0,
        }
        assert calls == []
        assert conf.read_text() == before

    def test_failed_config_check_reverts_and_raises(
        self, conf: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A removal that leaves FreeRADIUS unable to parse its config must
        put the file back and fail loudly, never report success."""
        conf.write_text(_STOCK_PREAMBLE + _stanza("cg-5d3a509e", "10.20.0.28"))
        before = conf.read_text()

        def _bad_check(cmd: list[str], **kw: Any) -> Any:
            if cmd[:2] == ["freeradius", "-CX"]:
                return subprocess.CompletedProcess(
                    cmd, 1, stdout="Errors reading clients.conf\n", stderr=""
                )
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(radius_agent.subprocess, "run", _bad_check)
        with pytest.raises(RuntimeError, match="reverted"):
            radius_agent.remove_client("cg-5d3a509e")
        assert conf.read_text() == before

    def test_config_check_exit_zero_but_no_ok_banner_still_fails(
        self, conf: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``freeradius -CX`` has been seen exiting 0 while still reporting
        problems. Trusting the exit status alone is exactly the
        "operation reported success while doing nothing" pattern this
        project keeps getting burned by."""
        conf.write_text(_STOCK_PREAMBLE + _stanza("cg-5d3a509e", "10.20.0.28"))
        before = conf.read_text()
        monkeypatch.setattr(
            radius_agent.subprocess,
            "run",
            lambda cmd, **kw: subprocess.CompletedProcess(
                cmd, 0, stdout="something else entirely\n", stderr=""
            ),
        )
        with pytest.raises(RuntimeError, match="reverted"):
            radius_agent.remove_client("cg-5d3a509e")
        assert conf.read_text() == before

    def test_rejects_a_malformed_identifier(self, conf: Path) -> None:
        with pytest.raises(ValueError):
            radius_agent.remove_client("../../etc/passwd")

    def test_backs_the_file_up_before_editing(self, conf: Path) -> None:
        conf.write_text(_STOCK_PREAMBLE + _stanza("cg-5d3a509e", "10.20.0.28"))
        radius_agent.remove_client("cg-5d3a509e")
        backups = list(Path(radius_agent.BACKUP_DIR).glob("clients.conf.bak-*"))
        assert len(backups) == 1
        assert "cg-5d3a509e" in backups[0].read_text()


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestAddClient:
    def test_re_registration_replaces_rather_than_appends(self, conf: Path) -> None:
        """Appending is how the live hub ended up with five stanzas for
        ``cg-04f81868``: every secret rotation left the previous one in
        place, still valid, still bound to a tunnel IP WireGuard is free
        to hand to a different router."""
        radius_agent.add_client("10.20.0.50", "cg-04f81868", "secret-one")
        result = radius_agent.add_client("10.20.0.51", "cg-04f81868", "secret-two")
        assert result["superseded"] == 1

        text = conf.read_text()
        _, matches = radius_agent._strip_clients_with_shortname(text, "cg-04f81868")
        assert len(matches) == 1
        assert "secret-one" not in text
        assert "secret-two" in text
        assert "10.20.0.50" not in text

    def test_hardened_message_authenticator_survives_re_registration(
        self, conf: Path
    ) -> None:
        """Three live stanzas were hand-set to ``require_message_authenticator
        = yes`` during the 2026-08-18 incident. A re-registration silently
        downgrading them back to ``no`` would quietly weaken a router an
        operator deliberately hardened (BlastRADIUS, CVE-2024-3596)."""
        conf.write_text(
            _STOCK_PREAMBLE + _stanza("cg-5d3a509e", "10.20.0.28", rma="yes")
        )
        radius_agent.add_client("10.20.0.29", "cg-5d3a509e", "rotated-secret")
        assert "require_message_authenticator = yes" in conf.read_text()

    def test_a_brand_new_nas_keeps_the_established_default(self, conf: Path) -> None:
        """``no`` stays the default for a NAS with no prior stanza.
        Flipping it would hard-reject any router that does not send a
        Message-Authenticator on its Access-Request -- a fleet-wide
        behaviour change, not this change's business."""
        radius_agent.add_client("10.20.0.70", "cg-brandnew", "a-secret-value")
        assert "require_message_authenticator = no" in conf.read_text()

    def test_writes_the_fields_the_site_config_reads(self, conf: Path) -> None:
        """``sites-available/default`` resolves NAS identity through
        ``%{client:shortname}`` and ``%{client:backend_secret}``. Without
        both, every RADIUS request from this router 401s at ``CurrentNas``."""
        radius_agent.add_client("10.20.0.70", "cg-brandnew", "a-secret-value")
        text = conf.read_text()
        assert "shortname = cg-brandnew" in text
        assert "backend_secret = a-secret-value" in text
        assert "ipaddr = 10.20.0.70/32" in text

    def test_rejects_bad_input(self, conf: Path) -> None:
        with pytest.raises(ValueError):
            radius_agent.add_client("not-an-ip", "cg-x", "a-secret-value")
        with pytest.raises(ValueError):
            radius_agent.add_client("10.20.0.70", "bad ident", "a-secret-value")
        with pytest.raises(ValueError):
            radius_agent.add_client("10.20.0.70", "cg-x", "short")


class TestHandlerSurface:
    def test_delete_is_implemented(self) -> None:
        """The whole bug in one assertion: ``http.server`` answers 501 for
        any verb whose ``do_<VERB>`` is missing, and ``do_DELETE`` was."""
        assert hasattr(radius_agent.Handler, "do_DELETE")
        assert hasattr(radius_agent.Handler, "do_POST")


class TestRemovalIsVerifiedOnDisk:
    def test_a_removal_that_did_not_stick_raises_instead_of_reporting_success(
        self, conf: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The agent is not the only writer of clients.conf -- the
        ``wyfy-radius-sync`` timer regenerates it on a schedule, and a
        restore/rollback elsewhere can put the old file back under us. If
        the stanza is still on disk after the restart, this is a removal
        that did not happen, and it must not be reported as one. This is
        the same class of bug as ``/certificate sign X ca=X`` and
        ``set [find ...]`` against an empty match: the operation returned
        cleanly and changed nothing.
        """
        original = _STOCK_PREAMBLE + _stanza("cg-5d3a509e", "10.20.0.28")
        conf.write_text(original)

        def _clobbering_run(cmd: list[str], **kw: Any) -> Any:
            if cmd[:2] == ["freeradius", "-CX"]:
                return subprocess.CompletedProcess(
                    cmd, 0, stdout="Configuration appears to be OK\n", stderr=""
                )
            #  Something else rewrote the file between our write and now.
            conf.write_text(original)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        monkeypatch.setattr(radius_agent.subprocess, "run", _clobbering_run)
        with pytest.raises(RuntimeError, match="still.*present"):
            radius_agent.remove_client("cg-5d3a509e")
