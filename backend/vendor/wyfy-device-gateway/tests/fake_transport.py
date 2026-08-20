"""In-memory stand-in for ``librouteros.connect`` used by
``ReadOnlyDeviceReader`` unit tests.

Mirrors the tiny subset of the real ``librouteros`` connection object that
the reader actually uses: ``api.path(*segments)`` is iterable (each
iteration is a ``/.../print`` on a real device) and ``api.close()`` is a
no-op. Mutating Path methods (``.add`` / ``.update`` / ``.remove``) are
deliberately absent -- if a future change to the reader starts calling
them, these tests fail loudly with ``AttributeError`` rather than
silently pretending a write succeeded.

No real MikroTik device exists in this sandbox (see
``mikrotik_adapter.py``'s own module docstring). Every canned reply below
is hand-authored to exercise sanitization and allowlist logic.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
from typing import Any

from librouteros.exceptions import LibRouterosError


class FakePath:
    """Iterable stand-in for a ``librouteros`` Path. Intentionally has no
    ``add`` / ``update`` / ``remove`` -- those are write verbs the
    read-only reader must never call."""

    def __init__(self, rows: Sequence[Mapping[str, Any]], *, fail: bool = False) -> None:
        self._rows = [dict(row) for row in rows]
        self._fail = fail

    def __iter__(self) -> Iterator[dict[str, Any]]:
        if self._fail:
            raise LibRouterosError("no such command prefix")
        return iter(self._rows)


class FakeApi:
    def __init__(
        self,
        sections: Mapping[tuple[str, ...], Sequence[Mapping[str, Any]]],
        *,
        failing: Iterable[tuple[str, ...]] = (),
    ) -> None:
        self._sections = {path: list(rows) for path, rows in sections.items()}
        self._failing = set(failing)
        self.closed = False
        self.path_calls: list[tuple[str, ...]] = []

    def path(self, *segments: str) -> FakePath:
        key = tuple(segments)
        self.path_calls.append(key)
        if key in self._failing:
            return FakePath([], fail=True)
        return FakePath(self._sections.get(key, []))

    def close(self) -> None:
        self.closed = True


def make_connect_fn(
    sections: Mapping[tuple[str, ...], Sequence[Mapping[str, Any]]],
    *,
    failing: Iterable[tuple[str, ...]] = (),
    connect_error: BaseException | None = None,
) -> tuple[Any, list[FakeApi]]:
    """Returns ``(connect_fn, apis_opened)``. ``connect_fn`` matches the
    ``librouteros.connect(**kwargs)`` signature the reader injects."""

    opened: list[FakeApi] = []

    def connect_fn(**_kwargs: Any) -> FakeApi:
        if connect_error is not None:
            raise connect_error
        api = FakeApi(sections, failing=failing)
        opened.append(api)
        return api

    return connect_fn, opened


__all__ = ["FakeApi", "FakePath", "make_connect_fn"]
