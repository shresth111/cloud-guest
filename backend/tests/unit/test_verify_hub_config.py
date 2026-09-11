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
