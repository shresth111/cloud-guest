"""Every name a vendored-gateway module advertises actually exists.

## Why this is a test rather than a code review note

On 2026-09-11 the conflict resolution for #206 deleted an orphaned
``deauthorize_client`` from ``wyfy_device_gateway.omada.portal`` -- correctly:
it was a second function of that name, built on TP-Link's Open API
``cancelAuthClient``, that nothing called, and #214 had already landed the
legacy-hotspot revocation that was actually run against a controller. What the
deletion missed was the module's own ``__all__``, which kept listing the name.

That is not a cosmetic leftover. ``__all__`` is what ``from ... import *``
resolves against, so the module could no longer be star-imported at all --
``AttributeError: module 'wyfy_device_gateway.omada.portal' has no attribute
'deauthorize_client'`` -- and the failure is invisible to everything that was
watching that day:

* ``ruff check .`` passes, because ``[tool.ruff] exclude`` lists ``vendor``.
  (``--select F`` over the package finds it instantly, and CI now does that.)
* The 5,286-test backend suite passes, because ``testpaths = ["tests"]`` and
  nothing under ``tests/`` star-imports a gateway module.
* The gateway's own 544 tests pass, and were run by nothing at all.

So the gate belongs in the one suite that always runs. This checks the whole
``omada`` package rather than the one module, because the next incomplete
deletion will be in a different file.
"""

from __future__ import annotations

import importlib
import pkgutil

import wyfy_device_gateway.omada as omada_package


def _modules() -> list[str]:
    names = [omada_package.__name__]
    names.extend(
        info.name
        for info in pkgutil.walk_packages(
            omada_package.__path__, prefix=f"{omada_package.__name__}."
        )
    )
    return sorted(names)


def test_the_omada_package_has_modules_to_check() -> None:
    """A guard on the guard: an empty walk would make this file vacuous."""
    assert len(_modules()) > 5


def test_every_name_in_dunder_all_is_actually_defined() -> None:
    missing: dict[str, list[str]] = {}
    for name in _modules():
        module = importlib.import_module(name)
        exported = getattr(module, "__all__", None)
        if not exported:
            continue
        absent = [n for n in exported if not hasattr(module, n)]
        if absent:
            missing[name] = absent
    assert missing == {}, (
        "these modules advertise names they do not define, so `from <module> "
        f"import *` raises AttributeError: {missing}"
    )
