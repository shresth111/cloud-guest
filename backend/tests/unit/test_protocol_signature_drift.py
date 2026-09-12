"""A narrow Protocol and the class that satisfies it must not drift apart.

## The bug this exists to prevent

`POST /api/v1/locations/provision` returned 500 in production with:

    TypeError: OrganizationService.invite_member() missing 1 required
    keyword-only argument: 'requesting_organization_id'

`invite_member` gained that keyword-only argument, deliberately with **no
default**, to close a cross-tenant membership write: the method took its
target organization from the path while `RequirePermission` scoped off the
`X-Organization-Id` header, so a caller holding the permission on its own
organization could plant a member inside any other tenant. Refusing a
default was the right call -- a caller that forgets gets a `TypeError`
rather than a silent cross-tenant write.

What was missed is that `UserService` does not depend on
`OrganizationService`. It depends on `OrganizationLookupProtocol`, a
structural Protocol declared in its own module. The concrete method gained
the argument; the Protocol did not. So:

* every type checker was satisfied -- the call matched the Protocol it was
  written against;
* every unit test passed -- they inject fakes that also match the Protocol;
* and the only thing that knew the two had diverged was the running
  interpreter, at the moment a real operator provisioned a real customer.

This codebase uses narrow Protocols heavily and on purpose (they keep
`service.py` from importing other domains' concretes). That is a good
design, and this is its one sharp edge: a Protocol is a promise checked
against fakes, so when it drifts from the real implementation the fakes
keep the tests green and production is the first thing to notice.

## What this asserts

For each (Protocol, concrete) pair below, every method the Protocol
declares must be callable on the concrete class with exactly the keyword
arguments the Protocol promises -- and, more importantly, the concrete must
not *require* a parameter the Protocol does not mention. That second
direction is the one that was violated here, and it is the one that fails
at runtime rather than at type-check time.

Parameters the concrete adds with a default are allowed: they are optional,
so a caller written against the Protocol still works. Parameters the
concrete adds *without* a default are not.
"""

from __future__ import annotations

import inspect
from typing import Protocol, get_type_hints

import pytest

from app.domains.organization.service import OrganizationService
from app.domains.user.service import OrganizationLookupProtocol

# (Protocol, concrete class that is passed in its place at runtime)
PROTOCOL_PAIRS = [
    (OrganizationLookupProtocol, OrganizationService),
]


def _protocol_methods(proto: type) -> list[str]:
    return [
        name
        for name, value in vars(proto).items()
        if callable(value) and not name.startswith("_")
    ]


def _params(func) -> dict[str, inspect.Parameter]:
    return dict(inspect.signature(func).parameters)


@pytest.mark.parametrize(
    ("proto", "concrete"),
    PROTOCOL_PAIRS,
    ids=lambda v: getattr(v, "__name__", str(v)),
)
def test_concrete_satisfies_protocol_signatures(proto: type, concrete: type) -> None:
    assert issubclass(proto, Protocol), f"{proto.__name__} is not a Protocol"

    for method_name in _protocol_methods(proto):
        proto_method = getattr(proto, method_name)
        concrete_method = getattr(concrete, method_name, None)

        assert concrete_method is not None, (
            f"{concrete.__name__} does not implement {method_name}, which "
            f"{proto.__name__} declares."
        )

        proto_params = _params(proto_method)
        concrete_params = _params(concrete_method)

        # 1. Everything the Protocol promises must be accepted.
        missing = [
            name
            for name in proto_params
            if name not in ("self",) and name not in concrete_params
        ]
        assert not missing, (
            f"{concrete.__name__}.{method_name} does not accept "
            f"{missing}, which {proto.__name__} promises callers may pass."
        )

        # 2. THE ONE THAT BIT US: the concrete must not require anything the
        #    Protocol never mentions. A caller written against the Protocol
        #    cannot know to pass it, so this is a guaranteed TypeError the
        #    moment that path is exercised -- and only at runtime, because
        #    the type checker and every fake are satisfied by the Protocol.
        required_but_unpromised = [
            name
            for name, param in concrete_params.items()
            if name not in ("self",)
            and param.default is inspect.Parameter.empty
            and param.kind
            not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
            and name not in proto_params
        ]
        assert not required_but_unpromised, (
            f"{concrete.__name__}.{method_name} requires "
            f"{required_but_unpromised}, which {proto.__name__} does not "
            f"declare. Any caller written against the Protocol will raise "
            f"TypeError at runtime while type-checking cleanly. Add it to "
            f"the Protocol (and to every call site), or give it a default "
            f"-- but a default on a tenant-scoping argument is exactly the "
            f"silent cross-tenant write the argument exists to prevent."
        )


def test_invite_member_requires_the_tenant_scope_argument() -> None:
    """The specific regression, pinned by name.

    Kept separate from the generic check because this argument's absence is
    a security defect rather than a signature mismatch: without it,
    `invite_member` writes a membership into whatever organization the path
    names, unscoped.
    """
    params = _params(OrganizationService.invite_member)
    assert "requesting_organization_id" in params

    param = params["requesting_organization_id"]
    assert param.default is inspect.Parameter.empty, (
        "requesting_organization_id must have no default. A default means a "
        "forgotten call site silently performs an unscoped cross-tenant "
        "write instead of failing loudly."
    )
    assert "requesting_organization_id" in _params(
        OrganizationLookupProtocol.invite_member
    ), (
        "The Protocol must declare it too, or callers written against the "
        "Protocol cannot pass it -- which is exactly how "
        "/locations/provision started returning 500."
    )


def test_protocol_type_hints_resolve() -> None:
    """A Protocol whose annotations cannot be resolved is a Protocol nobody
    is really checking. Cheap, and it fails loudly if an import moves."""
    for proto, _ in PROTOCOL_PAIRS:
        for method_name in _protocol_methods(proto):
            get_type_hints(getattr(proto, method_name))
