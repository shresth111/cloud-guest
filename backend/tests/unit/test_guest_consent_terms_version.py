"""Migration 0116's frozen copy of ``compute_terms_version``, checked
against the runtime original.

The backfill and the write path must produce the same string for the same
text, or a row backfilled today carries a different version from a row
written tomorrow for words that never changed -- which is the exact
failure the column exists to prevent.

The write path's own tests live with the post-connect asks change that
introduced it (``test_portal_profile_and_reviews.py``). This file is only
about the migration.
"""

from __future__ import annotations

import importlib.util
import pathlib

import pytest

from app.domains.captive_portal.validators import compute_terms_version


class TestBackfillMigrationMatchesTheRuntime:
    """Migration 0116 carries a frozen copy of ``compute_terms_version``
    -- migrations must not import application code that moves underneath
    them. The two still have to agree, or a row backfilled today carries a
    different version from a row written tomorrow for the same unchanged
    text, which is the exact failure the column exists to prevent.

    If this fails, the migration's copy is the stale one; do not "fix" it
    by changing the runtime function, because rows already carry its
    output.
    """

    @staticmethod
    def _migration_module():
        path = (
            pathlib.Path(__file__).resolve().parents[2]
            / "alembic"
            / "versions"
            / "0116_backfill_guest_consent_terms_version.py"
        )
        spec = importlib.util.spec_from_file_location("_migration_0116", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    @pytest.mark.parametrize(
        "args",
        [
            (None, None, None, None),
            ("Terms", None, None, None),
            ("Terms", "https://example.com/t", "Privacy", "https://example.com/p"),
            ("ab", "c", None, None),
            ("शर्तें", None, None, None),
        ],
    )
    def test_the_frozen_copy_agrees(self, args: tuple) -> None:
        module = self._migration_module()
        assert module._compute_terms_version(*args) == compute_terms_version(
            terms_and_conditions_text=args[0],
            terms_and_conditions_url=args[1],
            privacy_policy_text=args[2],
            privacy_policy_url=args[3],
        )


