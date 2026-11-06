"""Every service a Celery task builds by hand must match that service's
real ``__init__``.

Request handlers get their services from FastAPI dependencies, which are
exercised on every request. Tasks cannot: each ``*tasks.py`` module wires
its own graph inside the task body, behind a database session, so a
constructor that gains a required argument breaks nothing until the task
next runs on a worker -- and then it fails every run.

Two real instances this file pins:

* ``LocationService`` gained the required keyword-only
  ``location_code_counter``; ``run_scheduled_reports`` was not updated and
  raised ``TypeError`` on every Beat tick.
* ``RouterService`` takes ``(repository, location_lookup,
  organization_lookup)``; two builders passed the organization service and
  the location service the other way round. That binds, so only a check on
  what is passed where can see it.

The check reads the call sites from source and binds them against the live
signatures, rather than mocking the constructors -- a mocked constructor
accepts anything, which is how both of these survived their own tests.
"""

from __future__ import annotations

import ast
import importlib
import importlib.util
import inspect
import sys
from pathlib import Path

import pytest

APP_ROOT = Path(__file__).resolve().parents[2] / "app"
TASK_MODULES = sorted(
    p for p in APP_ROOT.rglob("*tasks*.py") if "__pycache__" not in p.parts
)

_ROLE_SUFFIXES = (
    "_service",
    "_repository",
    "_repo",
    "_lookup",
    "_writer",
    "_resolver",
)


def _stem(name: str) -> str | None:
    """``organization_service`` -> ``organization``; ``None`` when the name
    does not follow the ``<subject>_<role>`` convention."""
    for suffix in _ROLE_SUFFIXES:
        if name.endswith(suffix) and len(name) > len(suffix):
            return name[: -len(suffix)]
    return None


def _module_name(path: Path) -> str:
    return ".".join(path.relative_to(APP_ROOT.parent).with_suffix("").parts)


def _imported_names(tree: ast.AST) -> dict[str, tuple[str, str]]:
    """Every ``from x import Y [as Z]`` in the file, function-local ones
    included -- most task builders import their services inside the task
    body, so module attributes alone miss the majority of call sites."""
    names: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                names[alias.asname or alias.name] = (node.module, alias.name)
    return names


def _app_class(
    module: object, imported: dict[str, tuple[str, str]], func: ast.expr
) -> type | None:
    if not isinstance(func, ast.Name):
        return None
    target = getattr(module, func.id, None)
    if target is None and func.id in imported:
        source_module, attribute = imported[func.id]
        target = getattr(importlib.import_module(source_module), attribute, None)
    if not inspect.isclass(target):
        return None
    if not (target.__module__ or "").startswith("app."):
        return None
    return target


def _wiring_problems(path: Path) -> list[str]:
    return _check_tree(importlib.import_module(_module_name(path)), path)


def _check_tree(module: object, path: Path) -> list[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    imported = _imported_names(tree)
    problems: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        cls = _app_class(module, imported, node.func)
        if cls is None or "__init__" not in vars(cls):
            continue
        if any(isinstance(a, ast.Starred) for a in node.args) or any(
            k.arg is None for k in node.keywords
        ):
            continue
        where = f"{path.name}:{node.lineno} {cls.__name__}(...)"
        signature = inspect.signature(cls)
        try:
            bound = signature.bind(
                *node.args, **{k.arg: k.value for k in node.keywords if k.arg}
            )
        except TypeError as exc:
            problems.append(f"{where}: {exc}")
            continue
        stems = {name: _stem(name) for name in signature.parameters if _stem(name)}
        for param, value in bound.arguments.items():
            if not isinstance(value, ast.Name):
                continue
            passed, expected = _stem(value.id), stems.get(param)
            if passed is None or expected is None or passed == expected:
                continue
            if passed in stems.values():
                problems.append(
                    f"{where}: `{value.id}` is passed as `{param}`, but the "
                    f"constructor has a separate `{passed}_*` parameter"
                )
    return problems


@pytest.mark.parametrize(
    "path", TASK_MODULES, ids=[_module_name(p) for p in TASK_MODULES]
)
def test_task_module_builds_services_with_their_real_signatures(path: Path) -> None:
    problems = _wiring_problems(path)
    assert not problems, "\n".join(problems)


def test_the_sweep_actually_covers_the_task_modules() -> None:
    """A sweep that silently matches nothing passes forever."""
    names = {_module_name(p) for p in TASK_MODULES}
    assert "app.domains.analytics.report_tasks" in names
    assert "app.domains.guest.tasks" in names
    assert len(names) >= 15


def test_the_check_rejects_a_missing_required_keyword(tmp_path: Path) -> None:
    """The exact shape that broke ``run_scheduled_reports``."""
    source = (
        "from app.domains.location.service import LocationService\n"
        "def build(repo, organization_service):\n"
        "    return LocationService(repo, organization_service)\n"
    )
    problems = _problems_for_source(tmp_path, source)
    assert len(problems) == 1
    assert "location_code_counter" in problems[0]


def test_the_check_rejects_swapped_lookups(tmp_path: Path) -> None:
    """The exact shape found in two ``guest.tasks`` builders."""
    source = (
        "from app.domains.router.service import RouterService\n"
        "def build(repo, organization_service, location_service):\n"
        "    return RouterService(repo, organization_service, location_service)\n"
    )
    problems = _problems_for_source(tmp_path, source)
    assert len(problems) == 2
    assert "`organization_service` is passed as `location_lookup`" in problems[0]


def test_the_check_accepts_the_correct_order(tmp_path: Path) -> None:
    source = (
        "from app.domains.router.service import RouterService\n"
        "def build(repo, organization_service, location_service):\n"
        "    return RouterService(repo, location_service, organization_service)\n"
    )
    assert _problems_for_source(tmp_path, source) == []


def _problems_for_source(tmp_path: Path, source: str) -> list[str]:
    """Run the same check over an injected module, so the self-checks above
    exercise ``_wiring_problems`` itself and not a private copy of it."""
    package = tmp_path / "app_wiring_probe"
    package.mkdir()
    probe = package / "probe_tasks.py"
    probe.write_text(source)
    module_name = "app_wiring_probe_module"
    spec = importlib.util.spec_from_file_location(module_name, probe)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        return _check_tree(module, probe)
    finally:
        sys.modules.pop(module_name, None)
