"""Guest access rules and MAC authorization entries: an unfiltered listing (and
the MAC CSV export) is confined to the caller's granted sites.

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

import csv
import io
import uuid
from datetime import UTC, datetime
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


# ---------------------------------------------------------------------------
# GET /mac-authorization/entries/export -- the same rows, as a CSV download
# ---------------------------------------------------------------------------


def _export_world() -> _World:
    world = _World()
    for row in world.rows:
        row.mac_address = "AA:BB:CC:DD:EE:FF"
        row.authorization_type = "permanent"
        row.expires_at = None
        row.comment = None
        row.is_enabled = True
        row.created_at = datetime(2026, 9, 25, tzinfo=UTC)
    return world


async def _export(world: _World, scope, **kwargs) -> set:
    rows = world.rows

    class _Repo:
        async def list_all_for_organization(self, organization_id):
            return [r for r in rows if r.organization_id == organization_id]

    service = MacAuthorizationService(_Repo(), caller_location_scope=scope)
    text = await service.export_entries_csv(
        requesting_organization_id=world.org, **kwargs
    )
    return {
        uuid.UUID(r["location_id"]) if r["location_id"] else None
        for r in csv.DictReader(io.StringIO(text))
    }


class TestMacExportConfinement:
    async def test_single_site_caller_exports_own_site_and_org_wide(self) -> None:
        world = _export_world()

        assert await _export(world, frozenset({world.site_a})) == {world.site_a, None}

    async def test_multi_site_caller_exports_exactly_their_sites(self) -> None:
        world = _export_world()

        seen = await _export(world, frozenset({world.site_a, world.site_c}))

        assert seen == {world.site_a, world.site_c, None}

    async def test_foreign_location_is_refused(self) -> None:
        world = _export_world()

        with pytest.raises(CrossLocationMacAuthorizationAccessError) as exc_info:
            await _export(world, frozenset({world.site_a}), location_id=world.site_b)
        assert exc_info.value.status_code == 403

    async def test_own_location_filter_is_allowed(self) -> None:
        world = _export_world()

        seen = await _export(world, frozenset({world.site_a}), location_id=world.site_a)

        assert seen == {world.site_a}

    async def test_organization_caller_is_unchanged(self) -> None:
        world = _export_world()

        assert await _export(world, None) == world.all_locations

    async def test_caller_with_no_sites_exports_only_org_wide(self) -> None:
        world = _export_world()

        assert await _export(world, frozenset()) == {None}

    def test_route_accepts_a_location_filter(self) -> None:
        """The route must pass ``location_id`` through, or the 403 above is
        unreachable over HTTP and a venue user can only ever get the
        confined whole-organization file."""
        import inspect

        from app.domains.mac_authorization.router import (
            export_mac_authorization_entries,
        )

        assert (
            "location_id"
            in inspect.signature(export_mac_authorization_entries).parameters
        )
