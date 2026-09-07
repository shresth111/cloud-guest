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

# Fields whose values RouterOS validates against the names of things that
# actually exist (DHCP option names, option-set names). Writing a name that
# does not exist is rejected, not stored.
_NAME_VALIDATED_FIELDS = frozenset({"dhcp-option", "dhcp-option-set"})


class FakePath:
    def __init__(self, rows: list[dict[str, Any]], recorder: "FakeRouterOSApi", segments: tuple[str, ...]):
        self._rows = rows
        self._recorder = recorder
        self._segments = segments

    def __iter__(self):
        return iter(self._rows)

    def __call__(self, cmd: str | None = None, **kwargs: Any):
        """RouterOS menu paths are themselves callable to invoke the bare
        command they represent (e.g. ``api.path("system", "reboot")()``),
        distinct from ``.add``/``.update``/``.remove`` -- confirmed by the
        real ``_reboot_sync`` usage this fake mirrors.

        ``cmd`` is modelled because ``unset`` has no ``librouteros`` helper
        and is issued this way -- ``path("unset", **{".id": ..,
        "value-name": ..})``. It is the *only* way to clear a RouterOS
        field: ``set field=""`` fails with "ambiguous value ... more than
        one possible value matches input" on real hardware. If this fake
        did not model ``unset``, a removal that silently left
        ``dhcp-option-set`` attached would pass every test in this suite.

        The real ``librouteros`` ``Path.__call__`` is a generator, so a
        caller that never consumes it sends nothing. Returning an iterator
        here preserves that: a bare, unconsumed call mutates nothing in
        this fake either, exactly as on a device.
        """
        if cmd != "unset":
            return iter(self._rows)

        def _apply():
            from librouteros.exceptions import LibRouterosError

            target_id = kwargs.get(".id")
            value_name = kwargs.get("value-name")
            self._recorder.unset_calls.append(
                (self._segments, target_id, value_name)
            )
            # `unset` is undocumented and per-menu optional -- it is not in the
            # Console page's list of general commands. Its `value-name` is an
            # enum, and a name-reference property that always has a value
            # (default `none`) is not a member of it. RouterOS 7.23.3 answers
            # "input does not match any value of value-name" for
            # dhcp-option-set on /ip/dhcp-server/network. Observed on the venue
            # router; this is the failure the removal path shipped with.
            if value_name in self._name_reference_fields():
                raise LibRouterosError(
                    "input does not match any value of value-name"
                )
            self._recorder.ops.append(
                ("unset", self._segments, (target_id, value_name))
            )
            for row in self._rows:
                if row.get(".id") == target_id:
                    row.pop(value_name, None)
                    break
            return
            yield  # pragma: no cover - generator marker

        return _apply()

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

    def _name_reference_fields(self) -> set[str]:
        return self._recorder.name_reference_fields.get(self._segments, set())

    def update(self, **fields: Any) -> None:
        from librouteros.exceptions import LibRouterosError

        self._recorder.update_calls.append((self._segments, fields))
        self._recorder.ops.append(("update", self._segments, fields))
        references = self._name_reference_fields()
        # RouterOS resolves a name-typed value by PREFIX against the candidate
        # names, so "" is a prefix of every one of them. With `none` plus at
        # least one defined set in play that is >1 match, and the router
        # answers "ambiguous value of X, more than one possible value matches
        # input" -- observed on 7.23.3 (hEX lite) and reproduced verbatim on
        # /ip firewall nat in-interface by other people. Modelled here so that
        # any future "simplification" back to `set field=""` fails loudly in
        # this suite instead of on a venue's router.
        for field, value in fields.items():
            if field in references and value == "":
                raise LibRouterosError(
                    f"ambiguous value of {field}, "
                    "more than one possible value matches input"
                )
            # `dhcp-option` and `dhcp-option-set` hold RouterOS *names*, which
            # the device validates. On a field that is not a `name | none`
            # reference there is no option called "none", so RouterOS rejects
            # the literal rather than storing it -- which is what makes it safe
            # for the clear ladder to try `field=none` on any field.
            if (
                field in _NAME_VALIDATED_FIELDS
                and field not in references
                and value == "none"
            ):
                raise LibRouterosError(
                    f"input does not match any value of {field}"
                )
        if self._segments in self._recorder.silently_ignore_updates:
            # A `set` that returns cleanly and changes nothing. Not
            # hypothetical: this is the exact shape of the 2026-08-18
            # hotspot-profile rebind failure, and any code that treats "no
            # exception" as success passes every other test in this suite
            # while leaving the device untouched.
            return
        target_id = fields.get(".id")
        for row in self._rows:
            if target_id is None or row.get(".id") == target_id:
                for field, value in fields.items():
                    # RouterOS's DOCUMENTED clear: "The parameter can be unset
                    # by specifying '!' before the parameter" (Scripting docs,
                    # `set`). On the wire that is the attribute word
                    # `=!dhcp-option-set=`, which is what librouteros emits for
                    # a "!"-prefixed key.
                    #
                    # ...and on a name-reference field it is a SILENT NO-OP on
                    # RouterOS 7.23.3. Observed on the venue router
                    # (2026-09-07): the sentence was accepted with no trap and
                    # no error, and the field was still set afterwards. It is
                    # modelled as a no-op here rather than as a clear, because
                    # a fake that clears where the device does not is the exact
                    # lie that would let a "just send the documented command"
                    # simplification pass this suite and fail on hardware.
                    if field.startswith("!"):
                        if field[1:] in references:
                            continue
                        row.pop(field[1:], None)
                    elif field in references and value == "none":
                        # `name | none` typed property: `none` is the literal
                        # that means "no set", and it matches exactly one
                        # candidate, so unlike "" it is never ambiguous. This
                        # is the shape that actually cleared dhcp-option-set on
                        # the venue router.
                        row[field] = ""
                    else:
                        row[field] = value
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
        command_handlers: dict[str, Any] | None = None,
        name_reference_fields: dict[tuple[str, ...], set[str]] | None = None,
    ) -> None:
        self._menus = {k: list(v) for k, v in (menus or {}).items()}
        self._command_replies = command_replies or {}
        self._missing_menus = missing_menus or set()
        self._raise_on_command = raise_on_command or {}
        # A one-shot command that *changes the device* -- /certificate
        # import is the real example: it creates certificate objects, and a
        # fake that only replayed a canned reply would let a push whose
        # whole point is those objects pass without ever creating them.
        # A handler is called as handler(api, kwargs) and returns the reply
        # rows, having mutated ``api`` however the real command would.
        self._command_handlers = command_handlers or {}
        # Per-menu sets of RouterOS *name-reference* properties (`name | none`,
        # default `none`) -- e.g.
        # {("ip","dhcp-server","network"): {"dhcp-option-set"}}. A field listed
        # here behaves the way the live venue router behaves: `set field=""`
        # is ambiguous, `unset value-name=field` is not in the enum, and only
        # `set !field` (or `set field=none`) actually clears it. Opt-in,
        # because most fields are ordinary strings for which `set field=""` is
        # fine, and modelling every field this way would be a lie in the other
        # direction.
        self.name_reference_fields: dict[tuple[str, ...], set[str]] = dict(
            name_reference_fields or {}
        )
        self.closed = False
        self.add_calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []
        self.update_calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []
        self.remove_calls: list[tuple[tuple[str, ...], tuple[Any, ...]]] = []
        # RouterOS ``unset`` -- (path, .id, value-name). Its own list
        # because it is neither an update nor a remove, and the removal
        # path's correctness is exactly "did it unset, or did it try to
        # set an empty string".
        self.unset_calls: list[tuple[tuple[str, ...], Any, Any]] = []
        # One interleaved log of every write, in the order it was issued.
        # The three lists above cannot answer "did the add happen before the
        # remove", and for a security control that must fail closed --
        # never leaving the chain without its DROP -- that ordering is the
        # thing worth asserting.
        self.ops: list[tuple[str, tuple[str, ...], Any]] = []
        # One-shot commands (``api("/tool/fetch", ...)``) land in ``ops``
        # too, as ``("command", (cmd,), kwargs)``. A certificate push is
        # only correct if the fetches happen before the certificate store
        # is swept and the rebind happens before the old leaf is removed,
        # and neither of those orderings is assertable if the commands and
        # the menu writes are recorded in two separate lists.
        self.command_calls: list[tuple[str, dict[str, Any]]] = []
        # Menus (as path tuples) whose ``update`` records the call and then
        # does nothing -- see FakePath.update.
        self.silently_ignore_updates: set[tuple[str, ...]] = set()

    def path(self, *segments: str) -> FakePath:
        from librouteros.exceptions import LibRouterosError

        if segments in self._missing_menus:
            raise LibRouterosError(f"no such menu: {'/'.join(segments)}")
        rows = self._menus.setdefault(segments, [])
        return FakePath(rows, self, segments)

    def __call__(self, cmd: str, **kwargs: Any):
        self.command_calls.append((cmd, dict(kwargs)))
        self.ops.append(("command", (cmd,), dict(kwargs)))
        if cmd in self._raise_on_command:
            raise self._raise_on_command[cmd]
        handler = self._command_handlers.get(cmd)
        if handler is not None:
            return iter(handler(self, dict(kwargs)))
        return iter(self._command_replies.get(cmd, []))

    def close(self) -> None:
        self.closed = True
