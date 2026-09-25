"""Guest access rules and MAC authorization entries: an unfiltered listing is
confined to the caller's granted sites.

Sibling of ``test_guest_list_location_confinement.py``. It is the same
defect: a listing with no ``location_id`` was filtered on organization only,
so a caller whose grants cover one site listed every site's rows. These rows
carry guest phone numbers, emails and device MACs.

One difference: on these tables ``location_id IS NULL`` means the row is
organization-wide and applies at every site, including the caller's. A confined
caller must keep seeing those rows (``AnyOfOrNull``), because hiding them would
hide the rules that actually govern their own venue.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from sqlalchemy.dialects import postgresql

from app.database.utils.filters import AnyOfOrNull, apply_filters
from app.domains.guest_access.exceptions import CrossLocationAccessRuleError
from app.domains.guest_access.models import GuestAccessRule
from app.domains.guest_access.service import GuestAccessService
from app.domains.mac_authorization.exceptions import (
    CrossLocationMacAuthorizationAccessError,
)
from app.domains.mac_authorization.service import MacAuthorizationService


def _matches(row: object, filters: dict[str, object] | None) -> bool:
    """``apply_filters`` semantics, including ``AnyOfOrNull``."""
    for key, value in (filters or {}).items():
        if value is None:
            continue
        actual = getattr(row, key)
        if isinstance(value, AnyOfOrNull):
            if actual is not None and actual not in value.values:
                return False
        elif isinstance(value, list | tuple | set):
            if actual not in value:
                return False
        elif actual != value:
            return False
    return True


def _meta(total: int) -> SimpleNamespace:
    return SimpleNamespace(total_items=total)


class _World:
    """One organization, sites A/B/C, one row per site plus one org-wide row."""

    def __init__(self) -> None:
        self.org = uuid.uuid4()
        self.site_a = uuid.uuid4()
        self.site_b = uuid.uuid4()
        self.site_c = uuid.uuid4()
        self.rows = [
            SimpleNamespace(id=uuid.uuid4(), organization_id=self.org, location_id=s)
            for s in (self.site_a, self.site_b, self.site_c, None)
        ]
        self.all_locations = {self.site_a, self.site_b, self.site_c, None}

    def _list(self, filters):
        items = [r for r in self.rows if _matches(r, filters)]
        return items, _meta(len(items))

    def access_service(self, scope) -> GuestAccessService:
        world = self

        class _Repo:
            async def list_guest_rules(self, *, page, page_size, filters=None, **_):
                return world._list(filters)

            async def list_device_rules(self, *, page, page_size, filters=None, **_):
                return world._list(filters)

        return GuestAccessService(
            _Repo(),
            block_enforcer=None,
            location_lookup=None,
            caller_location_scope=scope,
        )

    def mac_service(self, scope) -> MacAuthorizationService:
        world = self

        class _Repo:
            async def list_entries(
                self, *, requesting_organization_id, location_id=None, page, page_size
            ):
                filters = {
                    "organization_id": requesting_organization_id,
                    "location_id": location_id,
                }
                return world._list(filters)

        return MacAuthorizationService(_Repo(), caller_location_scope=scope)


async def _list(world: _World, which: str, scope, **kwargs) -> set:
    """Run one listing and return the ``location_id``s it returned."""
    if which == "mac":
        rows, _ = await world.mac_service(scope).list_entries(
            requesting_organization_id=world.org, **kwargs
        )
    else:
        method = getattr(world.access_service(scope), which)
        result = await method(requesting_organization_id=world.org, **kwargs)
        rows = result.items
    return {r.location_id for r in rows}


_LISTINGS = [
    ("list_guest_rules", CrossLocationAccessRuleError),
    ("list_device_rules", CrossLocationAccessRuleError),
    ("mac", CrossLocationMacAuthorizationAccessError),
]


@pytest.mark.parametrize(("which", "error"), _LISTINGS)
class TestListingConfinement:
    async def test_single_site_caller_sees_own_site_and_org_wide(
        self, which, error
    ) -> None:
        world = _World()

        seen = await _list(world, which, frozenset({world.site_a}))

        assert seen == {world.site_a, None}

    async def test_multi_site_caller_sees_exactly_their_sites(
        self, which, error
    ) -> None:
        world = _World()

        seen = await _list(world, which, frozenset({world.site_a, world.site_c}))

        assert seen == {world.site_a, world.site_c, None}

    async def test_foreign_location_filter_is_refused(self, which, error) -> None:
        world = _World()

        with pytest.raises(error) as exc_info:
            await _list(
                world, which, frozenset({world.site_a}), location_id=world.site_b
            )
        assert exc_info.value.status_code == 403

    async def test_own_location_filter_is_allowed(self, which, error) -> None:
        world = _World()

        seen = await _list(
            world, which, frozenset({world.site_a}), location_id=world.site_a
        )

        assert seen == {world.site_a}

    async def test_organization_caller_is_unchanged(self, which, error) -> None:
        """``None`` is what ``CallerLocationScope`` returns for an ORGANIZATION
        or GLOBAL role holder."""
        world = _World()

        assert await _list(world, which, None) == world.all_locations
        assert await _list(world, which, None, location_id=world.site_b) == {
            world.site_b
        }

    async def test_caller_with_no_sites_sees_only_org_wide(self, which, error) -> None:
        world = _World()

        assert await _list(world, which, frozenset()) == {None}


class TestAnyOfOrNullReachesSql:
    """The fakes above mirror ``apply_filters``; this checks the real SQL."""

    def test_compiles_to_in_or_is_null(self) -> None:
        a, b = uuid.uuid4(), uuid.uuid4()
        statement = apply_filters(
            select(GuestAccessRule),
            GuestAccessRule,
            {"location_id": AnyOfOrNull((a, b))},
        )
        sql = str(
            statement.compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )
        where = sql.split("WHERE", 1)[1]
        assert "location_id IN" in where
        assert "location_id IS NULL" in where
        assert " OR " in where
        assert str(a) in where and str(b) in where

    def test_empty_values_matches_only_null(self) -> None:
        statement = apply_filters(
            select(GuestAccessRule),
            GuestAccessRule,
            {"location_id": AnyOfOrNull(())},
        )
        where = str(statement.compile(dialect=postgresql.dialect())).split("WHERE", 1)[
            1
        ]
        assert "location_id IS NULL" in where
