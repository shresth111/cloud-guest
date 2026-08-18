"""Regression test for the 2026-08-18 ``clients.wyfy.conf`` "Failed to add
duplicate client" production incident.

**What actually happened** (confirmed live against cloudguest-vm's real DB
and ``journalctl -u freeradius``, not just theorized): every client block
``ops/freeradius/gen_clients_conf.py`` generated was scoped to a blanket
``ipaddr = 0.0.0.0/0``, a gap the script's own docstring already called out
on 2026-08-10 as "correct with today's single real NAS, wrong once there
are several." Once the fleet grew past one NAS (2026-08-15), FreeRADIUS's
IP-keyed client trie could only ever hold **one** ``0.0.0.0/0`` entry --
every NAS after the first-parsed one in a given ``clients.wyfy.conf`` was
rejected outright as ``Failed to add duplicate client``, regardless of that
NAS's own shortname (``cg-5d3a509e``, ``cg-549153bd``, ``cg-c61ae7af``,
``cg-856aa5ca`` all seen rotating through the "duplicate" role across
different sync-timer runs, because the un-ordered generator ``SELECT`` has
no stable row order -- not because any of them ever had a real duplicate
``radius_nas_clients`` row; verified there was never more than one
non-deleted row per ``router_id``, see ``TestNasLifecycle
.test_reregistering_same_router_raises_not_a_new_row`` in
``test_guest.py``).

This test pins the fix: :func:`render_client_block` must scope ``ipaddr``
to that NAS's own WireGuard tunnel IP (a ``/32``) whenever one is known, so
two distinct, simultaneously-active NAS clients never again share one
IP/CIDR key in FreeRADIUS's client table.
"""

from __future__ import annotations

import importlib.util
import sys
import uuid
from pathlib import Path

import pytest

_MODULE_PATH = (
    Path(__file__).resolve().parents[2] / "ops" / "freeradius" / "gen_clients_conf.py"
)


def _load_gen_clients_conf():
    """Imports ``ops/freeradius/gen_clients_conf.py`` directly by file path
    -- it lives outside the ``app`` package (a standalone ops script run
    inside the ``deploy-api-1`` container, see its own module docstring)
    and its ``sys.path.insert(0, "/app")`` line is a no-op in this test
    environment, so this loads it without needing that path or a real DB
    connection: only :func:`render_client_block`/``QUERY`` (pure, no I/O)
    are exercised here, never ``main()``."""
    spec = importlib.util.spec_from_file_location(
        "gen_clients_conf_under_test", _MODULE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gen_clients_conf():
    return _load_gen_clients_conf()


class TestGenClientsConfIpaddrScoping:
    def test_client_with_known_tunnel_ip_gets_scoped_not_blanket(
        self, gen_clients_conf
    ) -> None:
        nas_id = uuid.uuid4()
        block = gen_clients_conf.render_client_block(
            nas_id, "cg-5d3a509e", "s3cr3t", "10.20.0.28"
        )
        assert "ipaddr = 10.20.0.28/32" in block
        assert "0.0.0.0/0" not in block
        assert 'shortname = "cg-5d3a509e"' in block
        assert f"client nas_{str(nas_id).replace('-', '_')} {{" in block

    def test_client_with_no_tunnel_ip_falls_back_explicitly(
        self, gen_clients_conf
    ) -> None:
        block = gen_clients_conf.render_client_block(
            uuid.uuid4(), "cg-no-peer-yet", "s3cr3t", None
        )
        assert "ipaddr = 0.0.0.0/0" in block

    def test_two_active_nas_clients_never_collide_on_ipaddr(
        self, gen_clients_conf
    ) -> None:
        """The actual incident, reproduced directly: two distinct, active
        NAS clients, each with its own real tunnel IP, must render two
        blocks with two *different* ``ipaddr`` values -- the exact
        property that was false before this fix (both were
        ``0.0.0.0/0``), which is what made FreeRADIUS reject the second
        block as a literal duplicate of the first."""
        block_a = gen_clients_conf.render_client_block(
            uuid.uuid4(), "cg-5d3a509e", "secret-a", "10.20.0.28"
        )
        block_b = gen_clients_conf.render_client_block(
            uuid.uuid4(), "cg-c61ae7af", "secret-b", "10.20.0.40"
        )

        def _ipaddr_line(block: str) -> str:
            return next(
                line.strip() for line in block.splitlines() if "ipaddr" in line
            )

        assert _ipaddr_line(block_a) != _ipaddr_line(block_b)

    def test_query_left_joins_wireguard_peers_by_router_id(
        self, gen_clients_conf
    ) -> None:
        """Pins the query shape itself, not just the rendering function --
        a regression that dropped the ``LEFT JOIN`` (or swapped it for an
        ``INNER JOIN``, silently hiding any NAS with no tunnel peer row
        instead of falling back to ``0.0.0.0/0``) would pass every
        ``render_client_block`` test above while still breaking production."""
        sql = str(gen_clients_conf.QUERY)
        assert "radius_nas_clients" in sql
        assert "LEFT JOIN wireguard_peers" in sql
        assert "w.router_id = n.router_id" in sql
        assert "is_deleted = false" in sql
        assert "status = 'active'" in sql
