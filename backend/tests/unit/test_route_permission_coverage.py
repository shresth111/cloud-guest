"""Enterprise SaaS Phase G (hardening): a repo-wide guard that every
mounted route either carries an RBAC authorization dependency
(``RequirePermission``/``RequireRole``/``RequireFeature``/
``RequireActiveLicense``) or is explicitly, individually allowlisted here
with a documented reason.

Every domain's own router test file already has its own
``TestEveryRouteRequiresPermission`` class checking that *domain's*
routes in isolation (see e.g. ``tests/unit/test_dns.py``,
``tests/unit/test_firewall.py``, ``tests/unit/test_policy.py``) -- this
is the single, cross-cutting backstop the gap-analysis research for this
initiative called for: a *new* router that forgets to add its own
authorization dependency (and forgets to write its own per-domain test
for it) would otherwise compile, run, and ship completely unnoticed.
This test boots the real, fully-wired app (``app.main.create_app``) and
inspects every route FastAPI actually registered, not a hand-maintained
list of routers -- so it can never silently miss a newly-added domain.

## The allowlist is the actual security review

``_ALLOWED_UNAUTHENTICATED_PATHS`` is not a suppression list -- every
entry documents, in one line, *why* that specific route has no
platform-identity check (pre-identity auth flows, genuinely guest-facing
endpoints with no platform user at all, health checks, webhook
receivers verified by their own signature/secret instead of RBAC). A new
route that should be open must be added here explicitly, with a real
reason -- it can never pass this test by accident.
"""

from __future__ import annotations

from app.main import create_app

_REQUIRE_QUALNAME_MARKERS = (
    "RequirePermission",
    "RequireRole",
    "RequireFeature",
    "RequireActiveLicense",
    # app.domains.billing.router's own custom gate for the license
    # self-service upgrade/downgrade endpoints -- calls AccessValidator
    # directly rather than going through the RequirePermission(...)
    # factory, since it also has to work around a documented RBAC seed-
    # data gap (see that function's own docstring). A real, equivalent
    # authorization check, just not named RequirePermission.
    "_require_subscription_self_service_permission",
)

# Every (method, path) pair below is deliberately reachable with no RBAC
# *permission* dependency -- see the reason on each line. ``path`` is the
# exact FastAPI route template (including ``{param}`` placeholders), not
# a prefix. Many of these still require *authentication* (CurrentUser) or
# a different, non-RBAC identity mechanism (device credential, NAS
# shared secret, provisioning token, webhook signature) -- "no RBAC
# permission check" is not the same claim as "anyone can call this".
_ALLOWED_UNAUTHENTICATED_ROUTES: dict[tuple[str, str], str] = {
    # -- Health/readiness: no identity of any kind exists yet -----------
    ("GET", "/api/v1/health/live"): "Liveness probe -- no identity exists yet.",
    ("GET", "/api/v1/health/ready"): "Readiness probe -- no identity exists yet.",
    # -- Auth: pre-identity flows by definition --------------------------
    ("POST", "/api/v1/auth/register"): "Self-registration -- no account exists yet.",
    ("POST", "/api/v1/auth/login"): "Login -- no session exists yet.",
    ("POST", "/api/v1/auth/refresh"): "Token refresh -- validated by refresh token.",
    ("POST", "/api/v1/auth/logout"): "Ends the caller's own session/JWT.",
    ("POST", "/api/v1/auth/forgot-password"): (
        "Initiates a reset -- must work for a locked-out user."
    ),
    ("POST", "/api/v1/auth/reset-password"): "Completed via a single-use reset token.",
    ("POST", "/api/v1/auth/verify-email"): (
        "Completed via a single-use verification token."
    ),
    ("POST", "/api/v1/auth/resend-verification"): (
        "Must work before the account is verified."
    ),
    # -- Self-service "act on my own account/session" -- CurrentUser
    # establishes identity; the authorization model is "must be
    # authenticated as yourself", not an RBAC permission. -------------
    ("GET", "/api/v1/auth/me"): "Self-service -- CurrentUser only, own record.",
    ("GET", "/api/v1/auth/sessions"): "Self-service -- own sessions only.",
    ("DELETE", "/api/v1/auth/sessions/{session_id}"): "Self-service -- own session.",
    ("DELETE", "/api/v1/auth/logout-all"): "Self-service -- own sessions only.",
    ("POST", "/api/v1/auth/change-password"): "Self-service -- own password.",
    ("POST", "/api/v1/auth/mfa/enroll"): "Self-service -- own MFA enrollment.",
    ("POST", "/api/v1/auth/mfa/verify"): "Self-service -- own MFA enrollment.",
    ("POST", "/api/v1/auth/mfa/disable"): "Self-service -- own MFA.",
    ("POST", "/api/v1/auth/mfa/recovery-codes/regenerate"): (
        "Self-service -- own MFA recovery codes."
    ),
    ("GET", "/api/v1/me"): "Self-service -- CurrentUser only, own record.",
    ("PUT", "/api/v1/me"): "Self-service -- own profile.",
    ("GET", "/api/v1/me/organizations"): "Self-service -- own memberships.",
    ("GET", "/api/v1/me/permissions"): "Self-service -- own effective permissions.",
    (
        "POST",
        "/api/v1/organizations/{organization_id}/members/{member_id}/accept",
    ): (
        "Self-service -- an invited-but-not-yet-active member holds no "
        "roles/permissions yet; the only real check is 'is this the "
        "invited user', enforced inside OrganizationService.accept_invite."
    ),
    # -- Guest-facing: no platform user identity exists at all ---------
    ("POST", "/api/v1/guest-teams/join"): (
        "Unauthenticated guest presenting a team join code."
    ),
    # -- Device/NAS/webhook: a different, non-RBAC identity mechanism --
    ("GET", "/api/v1/agent/actions"): "Router agent -- CurrentAgent device credential.",
    ("GET", "/api/v1/agent/config"): "Router agent -- CurrentAgent device credential.",
    ("GET", "/api/v1/agent/wireguard-config"): (
        "Router agent -- CurrentAgent device credential."
    ),
    ("POST", "/api/v1/agent/actions/{job_id}/complete"): (
        "Router agent -- CurrentAgent device credential."
    ),
    ("POST", "/api/v1/agent/heartbeat"): (
        "Router agent -- CurrentAgent device credential."
    ),
    ("POST", "/api/v1/agent/status"): (
        "Router agent -- CurrentAgent device credential."
    ),
    ("POST", "/api/v1/agent/wireguard-config/handshake"): (
        "Router agent -- CurrentAgent device credential."
    ),
    ("POST", "/api/v1/radius/authorize"): "FreeRADIUS -- CurrentNas shared secret.",
    ("POST", "/api/v1/radius/accounting"): "FreeRADIUS -- CurrentNas shared secret.",
    ("POST", "/api/v1/router-enrollment"): (
        "First-contact device enrollment -- no credential exists yet; "
        "nothing happens to real state until an RBAC-gated admin "
        "approval, itself already RequirePermission-gated."
    ),
    ("POST", "/api/v1/routers/provisioning/check-in"): (
        "Gated by a one-time provisioning token in the request body "
        "(hash-compared/expiry/single-use checked in RouterService"
        ".check_in), not RBAC."
    ),
    ("POST", "/api/v1/webhooks/stripe"): (
        "Payment gateway webhook -- verified by Stripe request signature."
    ),
    ("POST", "/api/v1/webhooks/razorpay"): (
        "Payment gateway webhook -- verified by Razorpay request signature."
    ),
}

# Path *prefixes* that are entirely guest-facing (no platform identity at
# all) -- documented per-domain in each router's own module docstring
# (e.g. app.domains.voucher.router, app.domains.campaigns.router,
# app.domains.guest.router).
_ALLOWED_UNAUTHENTICATED_PREFIXES: tuple[tuple[str, str], ...] = (
    ("/api/v1/guest/", "Guest self-service -- no platform user identity."),
    ("/api/v1/portal/", "Guest-facing campaign portal -- no platform identity."),
    (
        "/api/v1/captive-portal/resolve",
        "Guest's initial captive-portal config lookup, pre-authentication.",
    ),
    ("/api/v1/vouchers/validate", "Guest voucher validation, pre-authentication."),
    ("/api/v1/vouchers/redeem", "Guest voucher redemption, pre-authentication."),
    ("/api/v1/otp/request", "Guest OTP request, pre-authentication."),
    ("/api/v1/otp/verify", "Guest OTP verification, pre-authentication."),
)


def _is_allowlisted(method: str, path: str) -> bool:
    if (method, path) in _ALLOWED_UNAUTHENTICATED_ROUTES:
        return True
    return any(
        path.startswith(prefix) for prefix, _reason in _ALLOWED_UNAUTHENTICATED_PREFIXES
    )


def _has_authorization_dependency(route) -> bool:
    for dependency in getattr(route, "dependencies", []):
        callable_ = getattr(dependency, "dependency", None)
        qualname = getattr(callable_, "__qualname__", "") if callable_ else ""
        if any(marker in qualname for marker in _REQUIRE_QUALNAME_MARKERS):
            return True
    return False


def test_every_mounted_route_is_authorized_or_explicitly_allowlisted() -> None:
    app = create_app()
    unexplained: list[str] = []
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if path is None or not methods:
            continue
        if not path.startswith("/api/v1/"):
            continue
        for method in methods:
            if method == "HEAD":
                continue
            if _has_authorization_dependency(route):
                continue
            if _is_allowlisted(method, path):
                continue
            unexplained.append(f"{method} {path}")

    assert not unexplained, (
        "Route(s) with no RequirePermission/RequireRole/RequireFeature/"
        "RequireActiveLicense dependency and no allowlist entry -- add "
        "one or the other with a real justification:\n"
        + "\n".join(sorted(set(unexplained)))
    )


# ============================================================================
# "Test the test": prove the detection logic itself catches a real gap and
# doesn't false-positive on a real, properly-gated route.
# ============================================================================


def _fake_dependency(marker: str):
    async def _dependency() -> None:
        return None

    _dependency.__qualname__ = f"{marker}.<locals>._dependency"
    return _dependency


class _FakeDependencyWrapper:
    """Minimal stand-in for fastapi.params.Depends -- only the
    ``.dependency`` attribute _has_authorization_dependency reads."""

    def __init__(self, dependency) -> None:
        self.dependency = dependency


class _FakeRoute:
    def __init__(self, *, path: str, methods: set[str], dependencies: list) -> None:
        self.path = path
        self.methods = methods
        self.dependencies = dependencies


def test_detection_recognizes_a_real_permission_dependency() -> None:
    route = _FakeRoute(
        path="/api/v1/widgets",
        methods={"GET"},
        dependencies=[_FakeDependencyWrapper(_fake_dependency("RequirePermission"))],
    )
    assert _has_authorization_dependency(route) is True


def test_detection_flags_a_route_with_no_dependency_and_no_allowlist_entry() -> None:
    route = _FakeRoute(path="/api/v1/widgets", methods={"GET"}, dependencies=[])
    assert _has_authorization_dependency(route) is False
    assert _is_allowlisted("GET", "/api/v1/widgets") is False


def test_allowlisted_prefix_is_recognized() -> None:
    assert _is_allowlisted("GET", "/api/v1/guest/sessions") is True
