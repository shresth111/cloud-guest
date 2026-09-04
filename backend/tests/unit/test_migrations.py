"""Alembic must be able to see every table this application defines.

`alembic/env.py` sets `target_metadata = Base.metadata`, and a model class
only lands in that metadata when its module has been imported. So the list
of imports at the top of `env.py` is not a formality -- it is the entire
definition of what Alembic believes the schema is.

On 2026-09-04 that list was missing **nineteen** domains, hiding **thirty**
tables: `vlans`, `dhcp_pools`, `qos_traffic_rules`, `port_forwarding_rules`,
`content_filter_rules`, `hotspot_profiles`, `isp_links`, `campaigns`,
`channel_partners`, `support_tickets`, `quotations`, `connected_devices`
and more.

Nothing had gone wrong only because every migration in this repository is
hand-written. Autogenerate reads "present in the database, absent from the
metadata" as "this table was deleted" -- so the first person to run
`alembic revision --autogenerate` would have been handed a migration that
drops all thirty, and it would have looked like a perfectly ordinary
migration in review.

That is a one-command distance from losing most of the platform's data,
and it is invisible until someone runs the command. Hence a test rather
than a comment.

Deliberately structural: it discovers domains from the filesystem rather
than pinning a list, because a hard-coded list has exactly the failure
mode it is meant to prevent -- the next domain to define models would be
missing from both places at once.
"""

from __future__ import annotations

import ast
import pathlib

BACKEND_ROOT = pathlib.Path(__file__).resolve().parents[2]
DOMAINS_DIR = BACKEND_ROOT / "app" / "domains"
ENV_PY = BACKEND_ROOT / "alembic" / "env.py"


def _domains_defining_models() -> set[str]:
    """Every `app/domains/<name>/models.py` on disk."""
    return {path.parent.name for path in DOMAINS_DIR.glob("*/models.py")}


def _domains_imported_by_env() -> set[str]:
    """Every `app.domains.<name>` that `env.py` imports.

    Parsed from the AST rather than matched with a regex: the file uses
    both `from app.domains.x import models as y` and the parenthesised
    multi-line form for long names, and a regex that understood only one
    of them would report a domain as missing when it is not -- or worse,
    as present when it is not.
    """
    tree = ast.parse(ENV_PY.read_text())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            parts = node.module.split(".")
            if len(parts) >= 3 and parts[0] == "app" and parts[1] == "domains":
                imported.add(parts[2])
    return imported


def test_alembic_imports_every_domain_that_defines_models() -> None:
    on_disk = _domains_defining_models()
    imported = _domains_imported_by_env()
    missing = sorted(on_disk - imported)

    assert not missing, (
        "alembic/env.py does not import these domains, so their tables are "
        "absent from `Base.metadata` and `alembic revision --autogenerate` "
        "would emit `op.drop_table` for every one of them: "
        f"{', '.join(missing)}"
    )


def test_the_discovery_actually_finds_domains() -> None:
    """A guard on the guard.

    If `DOMAINS_DIR` ever stops resolving -- a moved file, a renamed
    directory -- `_domains_defining_models()` returns an empty set, the
    assertion above compares nothing to nothing, and this test passes
    forever while checking absolutely nothing. That is the failure mode
    worth pinning: a green test that has quietly stopped looking.
    """
    on_disk = _domains_defining_models()

    assert len(on_disk) > 30, (
        f"only found {len(on_disk)} domains with models.py -- the discovery "
        "is looking in the wrong place, so the check above is vacuous"
    )
    # Spot-check a few that must always be there, so a partial glob failure
    # is caught too.
    for domain in ("router", "vlan", "guest", "billing"):
        assert domain in on_disk, f"{domain}/models.py not discovered"
