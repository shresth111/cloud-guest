"""A WRITE-capable fake RouterOS transport.

Kept separate from ``fake_transport.py`` on purpose. That module's own
docstring states that mutating Path methods are "deliberately absent -- if
a future change to the reader starts calling them, these tests fail loudly
with AttributeError". That is a real guarantee for the read-only reader and
must not be weakened, so write-op tests get their own fake rather than
teaching the read-only one to mutate.

A fake/mocked RouterOS transport standing in for a real
``librouteros.connect(...)`` connection -- mirrors the "real client code,
never exercised against a live device in this sandbox" honesty posture the
ported source adapters already state in their own docstrings (PRD section
7, Step 1). No test in this suite ever opens a real socket.

Mimics just enough of the real ``librouteros`` API surface (confirmed
against the ported adapters' own usage, not guessed): ``connect(...)``
returns an object that is

* iterable-menu-capable via ``.path(*segments)`` -> a ``FakePath`` that
  itself supports ``__iter__`` (yields dict-like rows), ``.add(**fields)``
  (returns a new fake ``.id``), ``.update(**fields)``, ``.remove(*ids)``;
* directly callable for one-shot commands: ``api("/tool/ping", **kwargs)``
  -> an iterable of dict-like reply rows;
* closeable via ``.close()``.
"""

from __future__ import annotations

from typing import Any


class FakePath:
    def __init__(self, rows: list[dict[str, Any]], recorder: "FakeRouterOSApi", segments: tuple[str, ...]):
        self._rows = rows
        self._recorder = recorder
        self._segments = segments

    def __iter__(self):
        return iter(self._rows)

    def __call__(self, **kwargs: Any):
        """RouterOS menu paths are themselves callable to invoke the bare
        command they represent (e.g. ``api.path("system", "reboot")()``),
        distinct from ``.add``/``.update``/``.remove`` -- confirmed by the
        real ``_reboot_sync`` usage this fake mirrors."""
        return iter(self._rows)

    def add(self, **fields: Any) -> str:
        new_id = f"*{len(self._rows) + 1}"
        # RouterOS *consumes* place-before: it decides where the row lands
        # and is not itself stored on the row. Verified on 7.23.3 (hEX
        # lite) as device test T1 -- adding a, b, then c with
        # place-before=<b .id> prints in the order a, c, b -- so it takes a
        # .id, never an ordinal. A fake that appended regardless would let
        # an ordering bug pass every test in this suite.
        anchor_id = fields.pop("place-before", None)
        row = {".id": new_id, **fields}
        index = None
        if anchor_id is not None:
            index = next(
                (i for i, r in enumerate(self._rows) if r.get(".id") == anchor_id),
                None,
            )
        if index is None:
            self._rows.append(row)
        else:
            self._rows.insert(index, row)
        recorded = (
            dict(fields) if anchor_id is None
            else {**fields, "place-before": anchor_id}
        )
        self._recorder.add_calls.append((self._segments, recorded))
        self._recorder.ops.append(("add", self._segments, recorded))
        return new_id

    def update(self, **fields: Any) -> None:
        self._recorder.update_calls.append((self._segments, fields))
        self._recorder.ops.append(("update", self._segments, fields))
        target_id = fields.get(".id")
        for row in self._rows:
            if target_id is None or row.get(".id") == target_id:
                row.update(fields)
                if target_id is not None:
                    break

    def remove(self, *ids: Any) -> None:
        self._recorder.remove_calls.append((self._segments, ids))
        self._recorder.ops.append(("remove", self._segments, ids))
        self._rows[:] = [row for row in self._rows if row.get(".id") not in ids]


class FakeRouterOSApi:
    """Configure ``menus`` up front with ``{("ip", "address"): [...]}``-style
    keys, and/or ``command_replies`` with ``{"/tool/ping": [...]}``-style
    keys for raw one-shot commands. Missing menus behave like an empty
    RouterOS reply (empty list), *unless* listed in ``missing_menus`` (a set
    of path tuples), in which case iterating raises
    ``librouteros.exceptions.LibRouterosError`` -- mirrors a real router
    without a given package/menu installed (e.g. no wireless package)."""

    def __init__(
        self,
        menus: dict[tuple[str, ...], list[dict[str, Any]]] | None = None,
        command_replies: dict[str, list[dict[str, Any]]] | None = None,
        missing_menus: set[tuple[str, ...]] | None = None,
        raise_on_command: dict[str, Exception] | None = None,
    ) -> None:
        self._menus = {k: list(v) for k, v in (menus or {}).items()}
        self._command_replies = command_replies or {}
        self._missing_menus = missing_menus or set()
        self._raise_on_command = raise_on_command or {}
        self.closed = False
        self.add_calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []
        self.update_calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []
        self.remove_calls: list[tuple[tuple[str, ...], tuple[Any, ...]]] = []
        # One interleaved log of every write, in the order it was issued.
        # The three lists above cannot answer "did the add happen before the
        # remove", and for a security control that must fail closed --
        # never leaving the chain without its DROP -- that ordering is the
        # thing worth asserting.
        self.ops: list[tuple[str, tuple[str, ...], Any]] = []

    def path(self, *segments: str) -> FakePath:
        from librouteros.exceptions import LibRouterosError

        if segments in self._missing_menus:
            raise LibRouterosError(f"no such menu: {'/'.join(segments)}")
        rows = self._menus.setdefault(segments, [])
        return FakePath(rows, self, segments)

    def __call__(self, cmd: str, **kwargs: Any):
        if cmd in self._raise_on_command:
            raise self._raise_on_command[cmd]
        return iter(self._command_replies.get(cmd, []))

    def close(self) -> None:
        self.closed = True
