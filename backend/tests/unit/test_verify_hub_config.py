# ruff: noqa: E501 -- the fixtures below are verbatim FreeRADIUS config lines
# captured from the hub. Reflowing them to 88 columns would change what is
# being tested: the checker parses these strings, and a wrapped `%{expr:...}`
# or a split JSON `data =` line is a different config than the one that shipped.
"""Tests for ``ops/freeradius/verify_hub_config.py``.

The point of this suite is not that the checker runs -- it is that the
checker **would have caught the defects that actually shipped**. So the
central fixture is a faithful reconstruction of the hub's FreeRADIUS tree as
captured on 2026-08-22 at 06:49, with its real pathologies:

* ``accounting{}`` is stock Debian and never calls ``rest``
* ``mods-enabled/rest`` maps running octet totals onto the backend's
  *additive* ``bytes_uploaded_delta`` field, with no Gigawords reassembly
* ``connect_uri`` names an Azure address, five days before the AWS cutover
* ``clients.conf`` carries a ``0.0.0.0/0`` catch-all
* ``sites-enabled/default`` is a real file, not a symlink

Every one of those is a FAIL below. The "fixed" tree is the same tree with
this repo's ``sites-default.snippets.conf`` and ``rest.conf`` applied, and it
must come back clean.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_OPS = Path(__file__).resolve().parents[2] / "ops" / "freeradius"


def _load(name: str):
    #  Registered in sys.modules before exec_module: @dataclass resolves its
    #  annotations through sys.modules[cls.__module__].
    modname = f"wyfy_{name}"
    spec = importlib.util.spec_from_file_location(modname, _OPS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[modname] = module
    spec.loader.exec_module(module)
    return module


verify = _load("verify_hub_config")


BROKEN_SITE = """\
authorize {
	filter_username
	preprocess
	update control {
		REST-HTTP-Header += "X-RADIUS-NAS-Identifier: cg-04f81868"
		REST-HTTP-Header += "X-RADIUS-Shared-Secret: hardcoded-secret"
	}
	rest
	chap
	mschap
	suffix
	eap {
		ok = return
	}
	files
	-sql
	expiration
	logintime
	pap
}

accounting {
	detail
	unix
	-sql
	exec
	attr_filter.accounting_response
}

post-auth {
	update {
		&reply: += &session-state:
	}
	Post-Auth-Type REJECT {
		attr_filter.access_reject
	}
}
"""

FIXED_SITE = """\
authorize {
	filter_username
	preprocess
	update control {
		REST-HTTP-Header += "X-RADIUS-NAS-Identifier: %{client:shortname}"
		REST-HTTP-Header += "X-RADIUS-Shared-Secret: %{client:backend_secret}"
	}
	rest
	update reply {
		Message-Authenticator := 0x00
	}
	chap
	mschap
	suffix
	files
	-sql
	expiration
	logintime
	pap
}

accounting {
	detail
	if (!&Acct-Input-Octets) {
		update request { Acct-Input-Octets := 0 }
	}
	if (!&Acct-Input-Gigawords) {
		update request { Acct-Input-Gigawords := 0 }
	}
	update control {
		Tmp-String-0 := "%{tolower:%{Acct-Status-Type}}"
		Tmp-Integer64-0 := "%{expr:(%{Acct-Input-Gigawords} * 4294967296) + %{Acct-Input-Octets}}"
		Tmp-Integer64-1 := "%{expr:(%{Acct-Output-Gigawords} * 4294967296) + %{Acct-Output-Octets}}"
		REST-HTTP-Header := "X-RADIUS-NAS-Identifier: %{client:shortname}"
		REST-HTTP-Header += "X-RADIUS-Shared-Secret: %{client:backend_secret}"
	}
	rest {
		invalid = 1
		reject = 1
	}
	if (!(ok || updated)) {
		ok
	}
	unix
	-sql
	exec
	attr_filter.accounting_response
}
"""

BROKEN_REST = """\
rest {
	tls {
	}
	connect_uri = "http://20.219.51.94:8000/api/v1"
	authorize {
		uri = "${..connect_uri}/radius/authorize"
		method = 'post'
		body = 'json'
		data = '{"username":"%{User-Name}"}'
	}
	accounting {
		uri = "${..connect_uri}/radius/accounting"
		method = 'post'
		body = 'json'
		data = '{"status_type":"%{tolower:%{Acct-Status-Type}}","bytes_uploaded_delta":"%{%{Acct-Input-Octets}:-0}","bytes_downloaded_delta":"%{%{Acct-Output-Octets}:-0}"}'
	}
}
"""

FIXED_REST = """\
rest {
	tls {
	}
	connect_uri = "http://172.31.38.118:8000/api/v1"
	authorize {
		uri = "${..connect_uri}/radius/authorize"
		method = 'post'
		body = 'json'
		data = "{\\"username\\": \\"%{User-Name}\\"}"
	}
	accounting {
		uri = "${..connect_uri}/radius/accounting"
		method = 'post'
		body = 'json'
		data = "{\\"status_type\\": \\"%{control:Tmp-String-0}\\", \\"bytes_uploaded_total\\": %{control:Tmp-Integer64-0}, \\"bytes_downloaded_total\\": %{control:Tmp-Integer64-1}}"
	}
}
"""

CATCH_ALL_CLIENTS = """\
client localhost {
	ipaddr = 127.0.0.1
	secret = testing123
}

client cloudguest-dynamic-wan {
	ipaddr = 0.0.0.0/0
	secret = 14a06e26deadbeef
}
"""

CLEAN_CLIENTS = """\
client localhost {
	ipaddr = 127.0.0.1
	secret = testing123
}

client nas_bfc7ed1c {
	ipaddr = 10.20.0.19/32
	secret = "s-bfc7ed1c"
	backend_secret = "s-bfc7ed1c"
	shortname = "cg-bfc7ed1c"
}
"""


def _tree(
    tmp_path: Path,
    *,
    site: str,
    rest: str,
    clients: str,
    symlink_site: bool,
    stale_enabled_site: str | None = None,
    name: str = "3.0",
) -> Path:
    """``stale_enabled_site``, when given, is written to
    ``sites-enabled/default`` *instead of* ``site`` -- reproducing the
    2026-08-18 state where the enabled copy had drifted away from the
    available one and every edit to the latter was inert."""
    root = tmp_path / name
    for sub in ("sites-available", "sites-enabled", "mods-available", "mods-enabled"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    (root / "sites-available/default").write_text(site, encoding="utf-8")
    if symlink_site:
        (root / "sites-enabled/default").symlink_to("../sites-available/default")
    else:
        (root / "sites-enabled/default").write_text(
            stale_enabled_site if stale_enabled_site is not None else site,
            encoding="utf-8",
        )
    (root / "mods-available/rest").write_text(rest, encoding="utf-8")
    (root / "mods-enabled/rest").write_text(rest, encoding="utf-8")
    (root / "clients.conf").write_text(clients, encoding="utf-8")
    return root


def _by_name(findings, fragment: str):
    return next(f for f in findings if fragment in f.check)


@pytest.fixture
def broken_tree(tmp_path):
    #  The 2026-08-18 shape exactly: somebody fixed sites-available/default
    #  and the server kept reading an independent, stale sites-enabled/default.
    #  Every check below therefore has to be made against the ENABLED copy --
    #  a checker that read sites-available would have reported this tree clean.
    return _tree(
        tmp_path,
        site=FIXED_SITE,
        stale_enabled_site=BROKEN_SITE,
        rest=BROKEN_REST,
        clients=CATCH_ALL_CLIENTS,
        symlink_site=False,
        name="broken-3.0",
    )


@pytest.fixture
def fixed_tree(tmp_path):
    return _tree(
        tmp_path,
        site=FIXED_SITE,
        rest=FIXED_REST,
        clients=CLEAN_CLIENTS,
        symlink_site=True,
        name="fixed-3.0",
    )


# ---------------------------------------------------------------------------
# the checker catches every defect that actually shipped
# ---------------------------------------------------------------------------


def test_accounting_not_calling_rest_is_caught(broken_tree):
    """The headline defect-2 claim. Stock Debian ``accounting{}`` is
    ``detail / unix / -sql / exec / attr_filter`` -- no ``rest``, so no byte
    data reaches the backend and no data cap can enforce."""
    finding = _by_name(verify.check_tree(broken_tree), "accounting{} calls rest")
    assert finding.status == verify.FAIL
    assert "never calls rest" in finding.detail


def test_delta_mapped_octet_counters_are_caught(broken_tree):
    """``Acct-Input-Octets`` is a running total; the backend's
    ``bytes_uploaded_delta`` is additive. Wiring one to the other makes a
    session's recorded usage grow with uptime rather than with traffic --
    worse than having no data, because a cap then fires against it."""
    finding = _by_name(verify.check_tree(broken_tree), "totals, not deltas")
    assert finding.status == verify.FAIL
    assert "quadratically" in finding.detail


def test_missing_gigawords_reassembly_is_caught(broken_tree):
    finding = _by_name(verify.check_tree(broken_tree), "Gigawords")
    assert finding.status == verify.FAIL
    assert "4 GiB" in finding.detail


def test_hardcoded_nas_identifier_is_caught(broken_tree):
    """2026-08-18 root cause #2 -- one router's identifier baked into the
    header block, so every other router 401'd."""
    finding = _by_name(verify.check_tree(broken_tree), "per-NAS REST headers")
    assert finding.status == verify.FAIL


def test_missing_message_authenticator_is_caught(broken_tree):
    """2026-08-18 root cause #4 -- RouterOS counts a reply with no
    Message-Authenticator as a "bad-reply", which is neither a reject nor a
    timeout and appears in no counter anyone was watching."""
    finding = _by_name(verify.check_tree(broken_tree), "Message-Authenticator")
    assert finding.status == verify.FAIL


def test_sites_enabled_not_being_a_symlink_is_caught(broken_tree):
    """2026-08-18 root cause #1 -- the single most expensive defect in this
    system's history. ``sites-enabled/default`` was an independent stale copy,
    so three weeks of edits to ``sites-available/default`` were inert."""
    finding = _by_name(verify.check_tree(broken_tree), "sites-enabled/default tracks")
    assert finding.status == verify.FAIL
    assert "DIFFERS" in finding.detail


def test_stale_azure_connect_uri_is_caught(broken_tree):
    """Production moved to AWS on 2026-08-27. A connect_uri still naming an
    Azure address is syntactically perfect and completely dead."""
    finding = _by_name(
        verify.check_tree(broken_tree, expect_api_cidr="172.31.0.0/16"),
        "connect_uri is reachable",
    )
    assert finding.status == verify.FAIL
    assert "20.219.51.94" in finding.detail


def test_catch_all_client_is_caught(broken_tree):
    finding = _by_name(verify.check_tree(broken_tree), "no catch-all client")
    assert finding.status == verify.FAIL


def test_the_broken_tree_fails_overall(broken_tree):
    findings = verify.check_tree(broken_tree, expect_api_cidr="172.31.0.0/16")
    assert sum(1 for f in findings if f.status == verify.FAIL) >= 7


# ---------------------------------------------------------------------------
# and passes the tree this repo actually describes
# ---------------------------------------------------------------------------


def test_the_fixed_tree_passes_every_check(fixed_tree):
    findings = verify.check_tree(fixed_tree, expect_api_cidr="172.31.0.0/16")
    failures = [f for f in findings if f.status == verify.FAIL]
    assert failures == [], "\n".join(f"{f.check}: {f.detail}" for f in failures)


def test_byte_identical_regular_file_passes_but_says_it_is_still_a_trap(tmp_path):
    """A regular ``sites-enabled/default`` that happens to match
    ``sites-available`` today is not a failure -- the running config is
    correct -- but it is one edit away from the 2026-08-18 outage, and the
    report has to say so rather than printing a bare PASS."""
    root = _tree(
        tmp_path,
        site=FIXED_SITE,
        rest=FIXED_REST,
        clients=CLEAN_CLIENTS,
        symlink_site=False,
    )
    finding = _by_name(verify.check_tree(root), "sites-enabled/default tracks")
    assert finding.status == verify.PASS
    assert "NOT a symlink" in finding.detail
    assert "drift" in finding.detail


# ---------------------------------------------------------------------------
# parser behaviour the checks depend on
# ---------------------------------------------------------------------------


def test_nested_blocks_do_not_truncate_a_section():
    """``accounting{}`` contains ``if (...) { }`` and ``rest { }`` with an
    rcode body. A section reader that stopped at the first ``}`` would report
    "accounting does not call rest" on a file where it plainly does -- the
    exact false negative that would make this whole tool untrustworthy."""
    section = verify._section(FIXED_SITE, "accounting")
    assert section is not None
    assert "attr_filter.accounting_response" in section
    assert section.count("{") == section.count("}")


def test_a_commented_out_rest_call_does_not_count():
    """How an invariant gets lost: someone comments the call out to debug
    something and never restores it. A checker that greps for the bare word
    reports everything is fine."""
    site = FIXED_SITE.replace("\trest {\n", "\t#rest {\n").replace(
        "\t\tinvalid = 1\n\t\treject = 1\n\t}\n", "\t#\tinvalid = 1\n"
    )
    stripped = verify._strip_comments(site)
    accounting = verify._section(stripped, "accounting")
    assert accounting is not None
    assert "#rest" not in accounting


def test_hostname_connect_uri_is_skipped_not_failed(tmp_path):
    """A DNS name is not checkable here and is not wrong. Reporting SKIP is
    honest; reporting FAIL would train people to ignore the output."""
    root = _tree(
        tmp_path,
        site=FIXED_SITE,
        rest=FIXED_REST.replace("172.31.38.118", "api.internal.wyfyguest.com"),
        clients=CLEAN_CLIENTS,
        symlink_site=True,
    )
    finding = _by_name(
        verify.check_tree(root, expect_api_cidr="172.31.0.0/16"),
        "connect_uri is reachable",
    )
    assert finding.status == verify.SKIP


def test_cli_exit_status(broken_tree, fixed_tree, capsys):
    assert verify.main([str(broken_tree), "--expect-api-cidr", "172.31.0.0/16"]) == 1
    assert verify.main([str(fixed_tree), "--expect-api-cidr", "172.31.0.0/16"]) == 0


# ---------------------------------------------------------------------------
# check 10 -- a generated clients file that nothing loads
#
# This is the one that was missed. The generator's own catch-all defect was
# found, fixed and merged before anyone checked whether the generator is read
# at all. On the hub it is not: `clients.wyfy.conf` does not exist, nothing
# `$INCLUDE`s it, and `radiusd.conf` loads only `clients.conf` -- so every fix
# to `gen_clients_conf.py`, including a security fix, was inert there.
# ---------------------------------------------------------------------------

RADIUSD_CONF = """\
prefix = /usr
$INCLUDE proxy.conf
$INCLUDE clients.conf
modules {
	$INCLUDE mods-enabled/
}
$INCLUDE sites-enabled/
"""

GENERATED_STANZA = """\
client nas_bfc7ed1c {
	ipaddr = 10.20.0.19/32
	secret = "s-bfc7ed1c"
	backend_secret = "s-bfc7ed1c"
	shortname = "cg-bfc7ed1c"
}
"""


def _clients_tree(
    tmp_path: Path,
    *,
    radiusd: str = RADIUSD_CONF,
    clients: str = CLEAN_CLIENTS,
    generated: str | None = None,
    name: str = "clients-3.0",
) -> Path:
    root = _tree(
        tmp_path,
        site=FIXED_SITE,
        rest=FIXED_REST,
        clients=clients,
        symlink_site=True,
        name=name,
    )
    (root / "radiusd.conf").write_text(radiusd, encoding="utf-8")
    if generated is not None:
        (root / "clients.wyfy.conf").write_text(generated, encoding="utf-8")
    return root


def test_generated_file_present_and_included_passes(tmp_path):
    root = _clients_tree(
        tmp_path,
        radiusd=RADIUSD_CONF + "$INCLUDE clients.wyfy.conf\n",
        generated=GENERATED_STANZA,
    )
    finding = _by_name(verify.check_tree(root), "generated clients file")
    assert finding.status == verify.PASS


def test_generated_file_present_but_not_included_is_a_failure(tmp_path):
    """The dangerous asymmetry, and the reason this check exists.

    `sync_radius_clients.sh` writes the file, diffs it, reloads FreeRADIUS and
    logs success — and the server reads none of it. Every NAS the file defines
    is silently absent, which looks from the outside exactly like the router
    being misconfigured."""
    root = _clients_tree(tmp_path, generated=GENERATED_STANZA)
    finding = _by_name(verify.check_tree(root), "generated clients file")
    assert finding.status == verify.FAIL
    assert "EXISTS but nothing $INCLUDEs it" in finding.detail


def test_generated_file_included_but_missing_is_a_failure(tmp_path):
    """FreeRADIUS refuses to start on a missing `$INCLUDE`, so this one is not
    a silent failure — it is an outage waiting for the next restart, which may
    be days after the change that caused it."""
    root = _clients_tree(
        tmp_path, radiusd=RADIUSD_CONF + "$INCLUDE clients.wyfy.conf\n"
    )
    finding = _by_name(verify.check_tree(root), "generated clients file")
    assert finding.status == verify.FAIL
    assert "MISSING" in finding.detail


def test_neither_present_nor_included_is_reported_as_not_wired_up(tmp_path):
    """The hub's actual state on 2026-08-22, and it is deliberately SKIP, not
    FAIL: it is a coherent configuration — `radius_agent.py` writes
    `clients.conf` directly and is then the only writer. What it is not is
    obvious, so the check says it out loud instead of staying silent."""
    root = _clients_tree(tmp_path)
    finding = _by_name(verify.check_tree(root), "generated clients file")
    assert finding.status == verify.SKIP
    assert "not wired up" in finding.detail
    assert "no effect here" in finding.detail


def test_a_commented_out_include_does_not_count_as_wiring(tmp_path):
    """How the wiring gets lost in the first place: someone comments the line
    out to debug something and never restores it. A check that greps for the
    filename anywhere in the file would call this wired."""
    root = _clients_tree(
        tmp_path,
        radiusd=RADIUSD_CONF + "#$INCLUDE clients.wyfy.conf\n",
        generated=GENERATED_STANZA,
    )
    finding = _by_name(verify.check_tree(root), "generated clients file")
    assert finding.status == verify.FAIL


def test_include_is_matched_by_basename_not_by_exact_path(tmp_path):
    """`$INCLUDE` paths are relative to the config dir and are written several
    ways in the wild (`clients.wyfy.conf`, `./clients.wyfy.conf`,
    `${confdir}/clients.wyfy.conf`). Matching the literal string would report a
    correctly-wired hub as broken, which is the fastest way to get a checker
    ignored."""
    root = _clients_tree(
        tmp_path,
        radiusd=RADIUSD_CONF + "$INCLUDE ${confdir}/clients.wyfy.conf\n",
        generated=GENERATED_STANZA,
    )
    finding = _by_name(verify.check_tree(root), "generated clients file")
    assert finding.status == verify.PASS


def test_the_real_hub_capture_shape_is_reported_correctly(tmp_path):
    """End to end on the shape actually captured from the hub: radiusd.conf
    loads only clients.conf, clients.conf has no $INCLUDE, and
    clients.wyfy.conf is absent."""
    root = _clients_tree(tmp_path, clients=CATCH_ALL_CLIENTS)
    findings = verify.check_tree(root, expect_api_cidr="172.31.0.0/16")
    wiring = _by_name(findings, "generated clients file")
    catch_all = _by_name(findings, "no catch-all client")
    assert wiring.status == verify.SKIP
    assert catch_all.status == verify.FAIL
