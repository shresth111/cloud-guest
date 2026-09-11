"""Tests for the two halves of the catch-all RADIUS client fix:
``ops/freeradius/gen_clients_conf.py`` (never emit a wildcard stanza) and
``ops/freeradius/audit_clients_conf.py`` (find the ones already on the box).

Both files are deployed outside the application container -- the generator is
``docker cp``'d into ``deploy-api-1`` by ``sync_radius_clients.sh``, the
auditor is run by hand -- so they are imported by path rather than as a
package, the same way ``test_hub_radius_agent.py`` imports the hub agent.

The ``clients.conf`` fixture below is not invented. It reproduces the exact
pathologies of the 2026-08-22 capture of the live hub: Ubuntu's commented-out
``#client`` examples, a nested ``limit { }`` inside the stock ``localhost``
stanza, a ``0.0.0.0/0`` catch-all, doubled ``cg-cg-`` labels, and one router
holding several stanzas because its WireGuard tunnel address was reallocated
and nothing ever removed the old one.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_OPS = Path(__file__).resolve().parents[2] / "ops" / "freeradius"


def _load(name: str):
    #  `sys.modules` must hold the module BEFORE `exec_module` runs.
    #  `@dataclass` resolves its annotations through
    #  `sys.modules[cls.__module__]`, so a by-path import that skips this
    #  registration fails at class-definition time with a bare
    #  `AttributeError: 'NoneType' object has no attribute '__dict__'`.
    modname = f"wyfy_{name}"
    spec = importlib.util.spec_from_file_location(modname, _OPS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[modname] = module
    spec.loader.exec_module(module)
    return module


audit = _load("audit_clients_conf")


#  Trimmed to the shapes that matter, with the real labels and the real
#  duplicate counts kept.
CAPTURED_CLIENTS_CONF = """\
# Ubuntu's stock file opens with a few hundred commented-out examples.
#client example_from_the_docs {
#\tipaddr = 192.0.2.4
#\tsecret = testing123
#}

client localhost {
\tipaddr = 127.0.0.1
\tsecret = testing123
\trequire_message_authenticator = no
\tlimit {
\t\tmax_connections = 16
\t\tlifetime = 0
\t\tidle_timeout = 30
\t}
}

client localhost_ipv6 {
\tipv6addr = ::1
\tsecret = testing123
}

client cloudguest-dynamic-wan {
\tipaddr = 0.0.0.0/0
\tsecret = 14a06e26deadbeef
\trequire_message_authenticator = yes
\tnas_type = other
}

client cg-cg-bfc7ed1c {
\tipaddr = 10.20.0.19/32
\tsecret = s-bfc7ed1c
\tshortname = cg-bfc7ed1c
\tbackend_secret = s-bfc7ed1c
\trequire_message_authenticator = yes
\tnas_type = other
}

client cg-cg-04f81868 {
\tipaddr = 10.20.0.50/32
\tsecret = s-04f81868
\tshortname = cg-04f81868
\tbackend_secret = s-04f81868
\tnas_type = other
}

client cg-cg-04f81868 {
\tipaddr = 10.20.0.51/32
\tsecret = s-04f81868
\tshortname = cg-04f81868
\tbackend_secret = s-04f81868
\tnas_type = other
}

client cg-cg-11462682 {
\tipaddr = 10.20.0.55/32
\tsecret = s-11462682
\tshortname = cg-11462682
\tbackend_secret = s-11462682
\tnas_type = other
}
"""

#  The one NAS with a live radius_nas_clients row in production on
#  2026-09-11 (router "Office Guest", tunnel 10.20.0.19).
ACTIVE = {"cg-bfc7ed1c"}


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------


def test_commented_out_example_blocks_are_not_stanzas():
    """The stock file's ``#client example {`` must not be parsed as real.

    If it were, the removal plan would propose deleting FreeRADIUS's own
    documentation, and an operator following the plan would produce a diff
    that looks like vandalism and would reasonably refuse to apply any of it.
    """
    stanzas = audit.parse_clients_conf(CAPTURED_CLIENTS_CONF)
    assert "example_from_the_docs" not in {s.label for s in stanzas}


def test_nested_limit_block_does_not_truncate_the_stanza():
    """``localhost`` contains a nested ``limit { }``. A parser that closed on
    the first ``}`` would end the stanza inside it and treat the trailing
    lines as top-level, shifting every subsequent stanza's line span."""
    stanzas = audit.parse_clients_conf(CAPTURED_CLIENTS_CONF)
    localhost = next(s for s in stanzas if s.label == "localhost")
    body = CAPTURED_CLIENTS_CONF.splitlines()[localhost.start : localhost.end]
    assert body[-1].strip() == "}"
    assert any("max_connections" in line for line in body)
    assert sum(line.count("{") for line in body) == sum(
        line.count("}") for line in body
    )


def test_unterminated_block_is_an_error_not_a_silent_truncation():
    with pytest.raises(ValueError, match="unterminated"):
        audit.parse_clients_conf("client broken {\n\tipaddr = 10.0.0.1\n")


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------


def test_catch_all_is_flagged_even_though_it_is_inert_today():
    """``cloudguest-dynamic-wan`` has no ``backend_secret``. That makes it a
    dead end rather than a live impersonation route -- the REST call it
    produces carries an empty credential and ``CurrentNas`` refuses it -- but
    it is still a wildcard client with a static secret and it still has to
    go. The reasons must say which of the two it is, because the urgency
    differs by an order of magnitude."""
    stanzas = audit.classify(audit.parse_clients_conf(CAPTURED_CLIENTS_CONF), ACTIVE)
    catch_all = next(s for s in stanzas if s.label == "cloudguest-dynamic-wan")
    assert catch_all.classification == audit.CATCH_ALL
    assert not catch_all.has_backend_secret
    assert any("no backend_secret" in r for r in catch_all.reasons)
    assert not any(
        "authenticates to the platform API as" in r for r in catch_all.reasons
    )


def test_catch_all_carrying_backend_secret_is_reported_as_impersonation():
    """The severe variant -- what ``gen_clients_conf.py``'s old
    ``0.0.0.0/0`` fallback produced. Same wildcard address, but the stanza
    carries a real router's ``shortname`` and ``backend_secret``, so an
    unmatched source authenticates to the platform API *as that venue*."""
    text = """\
client nas_generated_fallback {
\tipaddr = 0.0.0.0/0
\tsecret = s-bfc7ed1c
\tbackend_secret = s-bfc7ed1c
\tshortname = cg-bfc7ed1c
}
"""
    stanza = audit.classify(audit.parse_clients_conf(text), ACTIVE)[0]
    assert stanza.classification == audit.CATCH_ALL
    assert stanza.has_backend_secret
    assert any("authenticates to the platform API as" in r for r in stanza.reasons)


def test_stanza_for_a_live_nas_is_active_and_never_removed():
    stanzas = audit.classify(audit.parse_clients_conf(CAPTURED_CLIENTS_CONF), ACTIVE)
    live = next(s for s in stanzas if s.shortname == "cg-bfc7ed1c")
    assert live.classification == audit.ACTIVE
    assert live.label not in {s.label for s in audit.removable(stanzas)}


def test_stanzas_for_deleted_nas_rows_are_orphans():
    """``cg-04f81868`` and ``cg-11462682`` have no ``radius_nas_clients`` row
    -- both routers were deleted while ``radius_agent.py`` still answered
    ``DELETE`` with ``501``, so the database forgot them and the RADIUS
    server did not."""
    stanzas = audit.classify(audit.parse_clients_conf(CAPTURED_CLIENTS_CONF), ACTIVE)
    orphans = {s.shortname for s in stanzas if s.classification == audit.ORPHAN}
    assert orphans == {"cg-04f81868", "cg-11462682"}


def test_duplicate_stanzas_for_one_live_nas_keep_exactly_one():
    """A router reallocated across tunnel addresses accumulates a stanza per
    address, all of which still authenticate. Only the first is kept; the
    rest are orphans. Keeping one is what makes this safe to apply -- the
    venue never loses its ability to authenticate."""
    text = CAPTURED_CLIENTS_CONF + """
client cg-cg-bfc7ed1c {
\tipaddr = 10.20.0.99/32
\tsecret = s-bfc7ed1c
\tshortname = cg-bfc7ed1c
\tbackend_secret = s-bfc7ed1c
}
"""
    stanzas = audit.classify(audit.parse_clients_conf(text), ACTIVE)
    live = [s for s in stanzas if s.shortname == "cg-bfc7ed1c"]
    assert len(live) == 2
    assert [s.classification for s in live] == [audit.ACTIVE, audit.ORPHAN]


def test_stock_localhost_stanzas_are_left_alone():
    stanzas = audit.classify(audit.parse_clients_conf(CAPTURED_CLIENTS_CONF), ACTIVE)
    stock = [s for s in stanzas if s.classification == audit.STOCK]
    assert {s.label for s in stock} == {"localhost", "localhost_ipv6"}
    assert not {s.label for s in stock} & {s.label for s in audit.removable(stanzas)}


def test_identity_prefers_shortname_over_the_doubled_label():
    """The live labels read ``cg-cg-11462682`` and are not unique. The
    backend only ever knows ``cg-11462682``, which is what
    ``%{client:shortname}`` sends."""
    stanzas = audit.parse_clients_conf(CAPTURED_CLIENTS_CONF)
    stanza = next(s for s in stanzas if s.label == "cg-cg-11462682")
    assert stanza.identity == "cg-11462682"


# ---------------------------------------------------------------------------
# the plan, and the pruned output
# ---------------------------------------------------------------------------


def test_prune_removes_exactly_the_planned_stanzas_and_nothing_else():
    stanzas = audit.classify(audit.parse_clients_conf(CAPTURED_CLIENTS_CONF), ACTIVE)
    pruned = audit.prune(CAPTURED_CLIENTS_CONF, audit.removable(stanzas))

    assert "0.0.0.0/0" not in pruned
    assert "cloudguest-dynamic-wan" not in pruned
    assert "cg-04f81868" not in pruned
    assert "cg-11462682" not in pruned
    # kept: the live NAS, both stock stanzas, and the documentation
    assert "shortname = cg-bfc7ed1c" in pruned
    assert "client localhost {" in pruned
    assert "client localhost_ipv6 {" in pruned
    assert "#client example_from_the_docs {" in pruned


def test_pruned_output_still_parses_and_is_then_clean():
    """The removal must leave a file FreeRADIUS can still read. Deleting line
    spans back-to-front is what guarantees that; deleting front-to-back
    shifts every later span and reliably cuts a stanza in half."""
    stanzas = audit.classify(audit.parse_clients_conf(CAPTURED_CLIENTS_CONF), ACTIVE)
    pruned = audit.prune(CAPTURED_CLIENTS_CONF, audit.removable(stanzas))
    again = audit.classify(audit.parse_clients_conf(pruned), ACTIVE)
    assert audit.removable(again) == []
    assert {s.classification for s in again} == {audit.ACTIVE, audit.STOCK}


def test_pruning_never_removes_a_live_venue_even_if_every_row_is_unknown():
    """The safety property stated as a test: if the caller supplies no active
    NAS identifiers at all -- a mistyped argument, a failed database read --
    every real stanza classifies as an orphan and the plan is destructive.
    The guard is that this is *visible*: the plan names each one. Nothing
    here is applied automatically, and ``--emit-pruned`` writes elsewhere."""
    stanzas = audit.classify(audit.parse_clients_conf(CAPTURED_CLIENTS_CONF), set())
    doomed = {s.shortname for s in audit.removable(stanzas) if s.shortname}
    assert "cg-bfc7ed1c" in doomed  # would be removed -- hence review, not automation
    text = audit.render_text(stanzas, set())
    assert "cg-bfc7ed1c" in text
    assert "Nothing has been changed" in text


def test_cli_exit_status_gates_on_whether_anything_would_be_removed(tmp_path):
    dirty = tmp_path / "clients.conf"
    dirty.write_text(CAPTURED_CLIENTS_CONF, encoding="utf-8")
    assert audit.main([str(dirty), "--active-nas", "cg-bfc7ed1c"]) == 1

    out = tmp_path / "clients.conf.pruned"
    audit.main(
        [str(dirty), "--active-nas", "cg-bfc7ed1c", "--emit-pruned", str(out)]
    )
    assert dirty.read_text(encoding="utf-8") == CAPTURED_CLIENTS_CONF  # untouched
    assert audit.main([str(out), "--active-nas", "cg-bfc7ed1c"]) == 0


def test_emit_pruned_refuses_to_overwrite_its_own_input(tmp_path):
    """Including via a second name for the same file -- ``clients.conf`` and
    ``./clients.conf`` are one file, and the whole point of this script is
    that it cannot be the thing that edits the live one."""
    path = tmp_path / "clients.conf"
    path.write_text(CAPTURED_CLIENTS_CONF, encoding="utf-8")
    alias = tmp_path / "." / "clients.conf"
    assert audit.main([str(path), "--emit-pruned", str(alias)]) == 2
    assert path.read_text(encoding="utf-8") == CAPTURED_CLIENTS_CONF


# ---------------------------------------------------------------------------
# the generator -- ops/freeradius/gen_clients_conf.py
# ---------------------------------------------------------------------------

gen = _load("gen_clients_conf")


def test_generator_emits_a_slash_32_stanza_scoped_to_the_tunnel_address():
    block = gen.render_client_block(
        "11111111-2222-3333-4444-555555555555",
        "cg-bfc7ed1c",
        "s-bfc7ed1c",
        "10.20.0.19",
    )
    assert block is not None
    assert "ipaddr = 10.20.0.19/32" in block
    assert 'shortname = "cg-bfc7ed1c"' in block
    #  Without backend_secret the router authenticates to the platform API
    #  with an empty credential and gets Auth-Type: Reject behind an HTTP 200.
    assert 'backend_secret = "s-bfc7ed1c"' in block


def test_generator_refuses_to_emit_a_stanza_for_a_nas_with_no_tunnel_address():
    """The defect. This used to return ``ipaddr = 0.0.0.0/0`` *with* the
    router's real shortname and backend_secret -- a catch-all that answers
    every unmatched source address and authenticates to the platform API as a
    genuine venue.

    Dropping the row breaks nothing real: RADIUS is reachable only from
    ``10.20.0.0/24`` and the VPC, so a NAS with no WireGuard peer has no path
    to FreeRADIUS at all and its stanza could only ever have matched somebody
    else."""
    assert (
        gen.render_client_block("id", "cg-bfc7ed1c", "s-bfc7ed1c", None) is None
    )
    assert gen.render_client_block("id", "cg-bfc7ed1c", "s-bfc7ed1c", "") is None


def test_no_rendered_stanza_can_contain_a_wildcard_address():
    """Belt and braces: whatever the inputs, the generator must never produce
    a wildcard. The 2026-08-18 incident was caused by exactly this string
    reaching clients.wyfy.conf."""
    for tunnel_ip in ("10.20.0.19", "10.20.0.255", "172.31.40.230"):
        block = gen.render_client_block("id", "cg-x", "s", tunnel_ip)
        assert block is not None
        for wildcard in ("0.0.0.0/0", "0.0.0.0", "::/0", "*"):
            assert f"ipaddr = {wildcard}\n" not in block


# ---------------------------------------------------------------------------
# build_client_config -- the three outcomes that decide whether a bad database
# read can deauthenticate the fleet
# ---------------------------------------------------------------------------

LIVE_ROW = ("id-1", "cg-bfc7ed1c", "s-bfc7ed1c", "10.20.0.19")
NO_TUNNEL_ROW = ("id-2", "cg-no-peer", "s-no-peer", None)


def test_normal_path_emits_one_stanza_per_renderable_row():
    body, warnings = gen.build_client_config([LIVE_ROW])
    assert body.count("client nas_") == 1
    assert "ipaddr = 10.20.0.19/32" in body
    assert "0.0.0.0/0" not in body
    assert any("generated 1 client(s)" in w for w in warnings)


def test_a_skipped_row_is_named_in_the_file_and_on_stderr():
    """An operator reading clients.wyfy.conf has to be able to see why a NAS
    they registered is missing, without going to find a log."""
    body, warnings = gen.build_client_config([LIVE_ROW, NO_TUNNEL_ROW])
    assert body.count("client nas_") == 1
    assert "# SKIPPED nas cg-no-peer" in body
    assert any("WARNING nas cg-no-peer" in w for w in warnings)


def test_all_rows_unrenderable_aborts_rather_than_emitting_comments():
    """The dangerous case. A comments-only file is NOT empty, so
    `sync_radius_clients.sh`'s `[ ! -s "$TMP" ]` guard would let it through and
    `cp` it over clients.wyfy.conf -- removing every live NAS stanza. Exiting
    non-zero makes that script's `set -e` abort with the last good file in
    place."""
    with pytest.raises(SystemExit) as excinfo:
        gen.build_client_config([NO_TUNNEL_ROW])
    assert excinfo.value.code == 1


def test_zero_active_rows_emits_literally_nothing():
    """Zero bytes, not one.

    `test -s` is "size > 0". This used to fall through to
    `print("\\n".join([]))`, which writes a single newline -- so the sync
    script's emptiness guard did not fire, and a one-byte file was copied over
    clients.wyfy.conf and FreeRADIUS reloaded with no clients. Zero rows has
    really happened here: on 2026-08-22 every NAS client was deleted through
    the master console."""
    body, warnings = gen.build_client_config([])
    assert body == ""
    assert len(body.encode()) == 0
    assert any("emitting nothing" in w for w in warnings)


def test_emptiness_guard_semantics_hold_for_each_outcome():
    """Ties the three cases to the actual shell test they have to satisfy:
    `[ ! -s "$TMP" ]` keeps the existing file only when the output is zero
    bytes."""

    def guard_keeps_existing_file(body: str) -> bool:
        return len(body.encode()) == 0

    assert guard_keeps_existing_file(gen.build_client_config([])[0])
    assert not guard_keeps_existing_file(gen.build_client_config([LIVE_ROW])[0])
    # and the all-skipped case never reaches the guard at all
    with pytest.raises(SystemExit):
        gen.build_client_config([NO_TUNNEL_ROW])
