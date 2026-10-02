"""The ``python -m app.domains.rbac.seed`` entrypoint must work standalone.

Regression test for a real production incident on 2026-09-22: the documented
CLI entrypoint could not run at all. ``rbac.seed`` registers only the RBAC
models, so ``Role.organization_id``'s ForeignKey to ``organizations.id`` had no
target and the first write -- ``remove_role_permission``, partway through the
reconcile -- died with::

    Foreign key associated with column 'roles.organization_id' could not find
    table 'organizations' with which to generate a foreign key to target
    column 'id'

The failure surfaced late and looked like a data problem rather than a missing
import, and it blocked seeding a newly shipped permission, so the feature that
depended on it silently 403'd for everyone.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

REQUIRED_MODEL_MODULES = {
    "app.domains.auth.models",
    "app.domains.location.models",
    "app.domains.organization.models",
    "app.domains.router.models",
}


def _main_function_imports() -> set[str]:
    """Module paths imported inside ``rbac.seed._main``."""
    from app.domains.rbac import seed

    tree = ast.parse(inspect.getsource(seed._main))
    return {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }


def test_main_imports_the_models_its_foreign_keys_need() -> None:
    """Deleting any of these imports must fail here, not in production."""
    missing = REQUIRED_MODEL_MODULES - _main_function_imports()
    assert not missing, (
        f"app.domains.rbac.seed._main no longer imports {sorted(missing)}. "
        "Those imports look unused but register the SQLAlchemy mappers that "
        "roles.organization_id's ForeignKey resolves against; without them "
        "`python -m app.domains.rbac.seed` dies mid-reconcile."
    )


# NOTE: there is no dynamic test that reproduces the failure, and that is not an
# oversight. The ForeignKey target is resolved lazily, when SQLAlchemy builds the
# constraint during a flush -- not by ``configure_mappers()``, which returns
# cleanly with ``organizations`` absent from the metadata (verified: 11 tables
# registered, no error). Reproducing it therefore needs a real database and a
# write, which is precisely the production path this guards. A static assertion
# that the imports are still present is the honest tool for the job: the fix was
# verified against the production database on 2026-09-22, where it seeded
# ``quotations.delete`` successfully after failing without these imports.


def test_scripts_seed_still_imports_them_too() -> None:
    """``scripts/seed.py`` relies on the same trick; keep them in step."""
    source = (Path(__file__).resolve().parents[2] / "scripts" / "seed.py").read_text(
        encoding="utf-8"
    )
    for module in REQUIRED_MODEL_MODULES - {"app.domains.auth.models"}:
        assert module in source, (
            f"scripts/seed.py no longer imports {module}; it needs the same "
            "mapper registration as rbac.seed._main."
        )
