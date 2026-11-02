"""Inventory of every machine error code the ISP partner API can return.

ERROR-COPY lane. Walks ``app/domains/isp_partner`` and ``app/domains/tr069``
with ``ast`` (no imports, no app start) and finds the codes in every form the
domain uses:

* a class with ``code = "X"`` (an ``IspError`` subclass), status from
  ``status_code_default`` on the class or a base, message from
  ``default_message``;
* a factory call such as ``_err("Name", "X", 409, "message")``: any call whose
  positional args hold a code-shaped string followed by an int 400-599;
* a ``{"code": "X"}`` dict inside a call that also names ``status_code``;
* a ``code="X"`` / ``reason="X"`` keyword on a raise of a known error class.

The partner console needs friendly copy for every one of them; the FE test
``scripts/test-isp-partner-error-copy.mjs`` reads the JSON this writes.

    python -m scripts.isp_error_inventory            # print JSON
    python -m scripts.isp_error_inventory --write    # refresh the snapshot
    python -m scripts.isp_error_inventory --check    # exit 1 when stale
"""

from __future__ import annotations

import ast
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
ROOTS = (
    BACKEND / "app" / "domains" / "isp_partner",
    BACKEND / "app" / "domains" / "tr069",
)
SNAPSHOT = BACKEND / "scripts" / "isp_error_codes.json"

CODE_RE = re.compile(r"^(?:ISP|TR069|PLAN|USER|RATE)_[A-Z0-9_]{2,}$")
# Names that look like codes but are settings / env names, not error codes.
NOT_CODES = re.compile(r"(?<!_NOT)_(ENABLED|SECRET|URL|DIR|PATH|KEY|TOKEN|PREFIX)$")
# Base classes that are not ISP errors but still carry a status.
EXTERNAL_BASES = {"CloudGuestError": 500, "Exception": 500}


@dataclass
class Entry:
    code: str
    status: int | None
    message: str
    sources: list[str] = field(default_factory=list)
    kind: str = "code"
    parents: set[str] = field(default_factory=set)


def _status_of(node: ast.AST | None) -> int | None:
    """An int literal, or ``status.HTTP_409_CONFLICT`` style attribute."""
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.Attribute):
        m = re.match(r"HTTP_(\d{3})_", node.attr)
        if m:
            return int(m.group(1))
    return None


def _str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = [v.value if isinstance(v, ast.Constant) else "{…}" for v in node.values]
        return "".join(str(p) for p in parts)
    return None


def _is_code(s: str | None) -> bool:
    return bool(s and CODE_RE.match(s) and not NOT_CODES.search(s))


@dataclass
class ClassInfo:
    name: str
    bases: list[str]
    code: str | None
    status: int | None
    message: str | None
    where: str


def _iter_files() -> list[Path]:
    out: list[Path] = []
    for root in ROOTS:
        out.extend(sorted(p for p in root.rglob("*.py") if p.is_file()))
    return out


def _rel(path: Path) -> str:
    return str(path.relative_to(BACKEND))


def collect() -> dict[str, Entry]:
    trees = {p: ast.parse(p.read_text(), filename=str(p)) for p in _iter_files()}

    # Pass 1: classes and factory-made classes.
    classes: dict[str, ClassInfo] = {
        "IspError": ClassInfo("IspError", [], None, 400, None, "exceptions.py"),
    }
    entries: dict[str, Entry] = {}
    coded: list[ClassInfo] = []

    def add(
        code: str,
        status: int | None,
        message: str | None,
        where: str,
        parent: str | None = None,
    ) -> None:
        where = where.split(":")[0]  # files only: line numbers churn
        e = entries.get(code)
        if e is None:
            e = entries[code] = Entry(code, status, message or "", [where])
            if parent:
                e.kind = "reason"
        if parent:
            e.parents.add(parent)
        if where not in e.sources:
            e.sources.append(where)
        if e.status is None:
            e.status = status
        if not e.message and message:
            e.message = message

    for path, tree in trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                info = ClassInfo(
                    node.name,
                    [
                        (
                            b.id if isinstance(b, ast.Name) else getattr(b, "attr", "")
                        ).lstrip("_")
                        for b in node.bases
                    ],
                    None,
                    None,
                    None,
                    f"{_rel(path)}:{node.lineno}",
                )
                for stmt in node.body:
                    if isinstance(stmt, ast.Assign | ast.AnnAssign):
                        targets = (
                            stmt.targets
                            if isinstance(stmt, ast.Assign)
                            else [stmt.target]
                        )
                        for t in targets:
                            if not isinstance(t, ast.Name):
                                continue
                            if t.id == "code" and _is_code(_str(stmt.value)):
                                info.code = _str(stmt.value)
                            elif t.id in ("status_code_default", "status_code"):
                                info.status = _status_of(stmt.value)
                            elif t.id in ("default_message", "message"):
                                info.message = _str(stmt.value)
                classes.setdefault(node.name.lstrip("_"), info)
                coded.append(info)
            # [Name =] _err("Name", "CODE", 404, "msg") (any factory shape).
            if isinstance(node, ast.Call):
                args = node.args
                for i, a in enumerate(args[:-1]):
                    code = _str(a)
                    status = _status_of(args[i + 1])
                    if _is_code(code) and status and 400 <= status <= 599:
                        msg = _str(args[i + 2]) if len(args) > i + 2 else None
                        name = _str(args[0]) if i > 0 else None
                        made = ClassInfo(
                            name or code,
                            ["IspError"],
                            code,
                            status,
                            msg,
                            f"{_rel(path)}:{node.lineno}",
                        )
                        coded.append(made)
                        if name:
                            classes.setdefault(name, made)
                        break
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                made_name = None
                for c in coded[-1:]:
                    if c.where == f"{_rel(path)}:{node.value.lineno}":
                        made_name = c
                for t in node.targets:
                    if made_name and isinstance(t, ast.Name):
                        classes.setdefault(t.id, made_name)

    def resolve(name: str, attr: str, seen: frozenset[str] = frozenset()) -> object:
        info = classes.get(name)
        if info is None or name in seen:
            return EXTERNAL_BASES.get(name) if attr == "status" else None
        val = getattr(info, attr)
        if val is not None:
            return val
        for b in info.bases:
            got = resolve(b, attr, seen | {name})
            if got is not None:
                return got
        return None

    def is_error_class(name: str, seen: frozenset[str] = frozenset()) -> bool:
        if name in ("IspError", "CloudGuestError"):
            return True
        info = classes.get(name)
        if info is None or name in seen:
            return False
        return any(is_error_class(b, seen | {name}) for b in info.bases)

    def resolve_info(info: ClassInfo, attr: str) -> object:
        val = getattr(info, attr)
        if val is not None:
            return val
        for b in info.bases:
            got = resolve(b, attr)
            if got is not None:
                return got
        return None

    for info in coded:
        if info.code and any(is_error_class(b) for b in info.bases):
            add(
                info.code,
                resolve_info(info, "status"),  # type: ignore[arg-type]
                resolve_info(info, "message"),  # type: ignore[arg-type]
                info.where,
            )

    # Pass 2: dict codes and keyword codes at call sites.
    for path, tree in trees.items():
        parents: dict[ast.AST, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                pairs = {
                    _str(k): _str(v)
                    for k, v in zip(node.keys, node.values, strict=False)
                }
                code = pairs.get("code")
                if _is_code(code):
                    status, message = _enclosing_status(node, parents)
                    add(code, status, message, _rel(path))  # type: ignore[arg-type]
                    if _is_code(pairs.get("reason")):
                        add(pairs["reason"], status, message, _rel(path), parent=code)  # type: ignore[arg-type]
            if isinstance(node, ast.Call):
                fname = (
                    node.func.id
                    if isinstance(node.func, ast.Name)
                    else getattr(node.func, "attr", "")
                )
                for kw in node.keywords:
                    val = _str(kw.value)
                    if kw.arg == "code" and _is_code(val) and is_error_class(fname):
                        msg = _str(node.args[0]) if node.args else None
                        add(
                            val,
                            resolve(fname, "status"),
                            msg,
                            f"{_rel(path)}:{node.lineno}",
                        )  # type: ignore[arg-type]
                    if kw.arg == "reason" and _is_code(val) and is_error_class(fname):
                        base = resolve(fname, "code")
                        msg = _str(node.args[0]) if node.args else None
                        add(
                            val,  # type: ignore[arg-type]
                            resolve(fname, "status"),  # type: ignore[arg-type]
                            msg,
                            _rel(path),
                            parent=str(base),
                        )
    return entries


def _enclosing_status(
    node: ast.AST, parents: dict[ast.AST, ast.AST]
) -> tuple[int | None, str | None]:
    cur: ast.AST | None = node
    while cur is not None:
        cur = parents.get(cur)
        if isinstance(cur, ast.Call):
            status = None
            message = None
            for kw in cur.keywords:
                if kw.arg == "status_code":
                    status = _status_of(kw.value)
                if kw.arg == "message":
                    message = _str(kw.value)
            # _reply(request, 404, "msg", data={...}) style helpers
            for i, a in enumerate(cur.args):
                st = _status_of(a)
                if status is None and st and 400 <= st <= 599:
                    status = st
                    if len(cur.args) > i + 1 and message is None:
                        message = _str(cur.args[i + 1])
            if status is not None:
                return status, message
        if isinstance(cur, ast.FunctionDef | ast.AsyncFunctionDef | ast.Module):
            break
    return None, None


def inventory() -> list[dict[str, object]]:
    rows = []
    for code, e in sorted(collect().items()):
        row: dict[str, object] = {
            "code": code,
            "kind": e.kind,
            "status": e.status,
            "message": e.message,
            "sources": sorted(set(e.sources)),
        }
        if e.parents:
            row["parents"] = sorted(e.parents)
        rows.append(row)
    return rows


def render() -> str:
    return (
        json.dumps(
            {
                "_generated_by": "backend/scripts/isp_error_inventory.py",
                "codes": inventory(),
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )


def _key(rows: list[dict[str, object]]) -> dict[str, object]:
    return {str(r["code"]): (r["kind"], r["status"]) for r in rows}


def stale_codes() -> list[str]:
    """What differs between the source and the snapshot, by code, kind and
    status only (messages and file lists may drift without failing)."""
    current = json.loads(SNAPSHOT.read_text())["codes"] if SNAPSHOT.exists() else []
    have, want = _key(current), _key(inventory())
    out = [f"missing {c}" for c in sorted(set(want) - set(have))]
    out += [f"gone {c}" for c in sorted(set(have) - set(want))]
    out += [
        f"changed {c} {have[c]} -> {want[c]}"
        for c in sorted(set(want) & set(have))
        if have[c] != want[c]
    ]
    return out


def main(argv: list[str]) -> int:
    text = render()
    if "--write" in argv:
        SNAPSHOT.write_text(text)
        print(f"wrote {SNAPSHOT} ({len(json.loads(text)['codes'])} codes)")
        return 0
    if "--check" in argv:
        stale = stale_codes()
        if stale:
            print("isp_error_codes.json is stale: " + "; ".join(stale))
            print("run: python -m scripts.isp_error_inventory --write")
            return 1
        return 0
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
