import contextvars
import time
import uuid
from dataclasses import dataclass, field

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.logging import (
    get_logger,
    organization_id_context,
    request_id_context,
    user_id_context,
)
from app.domains.rbac.enums import AuditAction

logger = get_logger(__name__)


@dataclass(slots=True)
class MaskingContext:
    """Per-request PII-masking state -- see ``app.common.masking``'s own
    module docstring for the full design write-up.

    ``masking_enabled`` mirrors ``app.domains.auth.models.User
    .data_masking_enabled`` exactly: ``True`` means PII *is* masked for
    this caller (the safe, fail-closed default until ``CurrentUser``
    resolves a real user), ``False`` means this caller sees raw values.

    ``accessed_kinds`` is mutated in place by ``app.common.masking``'s
    own ``Masked*`` serializers -- appended to only when
    ``masking_enabled`` is ``False`` and a field actually serialized
    unmasked. ``RequestContextMiddleware`` reads it once the response
    body has been fully built (after ``call_next`` returns) to decide
    whether this request needs an audit row at all."""

    masking_enabled: bool = True
    user_id: str | None = None
    organization_id: str | None = None
    accessed_kinds: list[str] = field(default_factory=list)


# A brand-new ``MaskingContext()`` is ``.set()`` fresh by the middleware on
# *every* request (see ``RequestContextMiddleware.dispatch`` below) before
# any dependency/serializer code can run. The ``ContextVar`` default is
# deliberately ``None``, never a literal ``MaskingContext()`` instance --
# a mutable object as a ``ContextVar`` default would be the same single
# shared instance returned by every ``.get()`` call made before any
# ``.set()`` in that context, which ``get_masking_context()`` below exists
# specifically to avoid (it hands back a fresh, throwaway instance in that
# case instead).
masking_context: contextvars.ContextVar[MaskingContext | None] = contextvars.ContextVar(
    "masking_context", default=None
)


def get_masking_context() -> MaskingContext:
    """Safe accessor for ``app.common.masking``'s own serializers and any
    other reader -- never returns ``None``, and never risks the shared-
    mutable-default hazard a literal ``ContextVar(default=MaskingContext())``
    would have. Outside of a request (there is no such call site in this
    codebase today), returns a fresh, fail-closed (``masking_enabled=True``)
    instance that is never stored back into the contextvar."""
    return masking_context.get() or MaskingContext()


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        user_id = request.headers.get("X-User-ID")
        organization_id = request.headers.get("X-Organization-ID")
        started_at = time.perf_counter()

        request.state.request_id = request_id
        request_token = request_id_context.set(request_id)
        user_token = user_id_context.set(user_id)
        organization_token = organization_id_context.set(organization_id)
        masking_token = masking_context.set(MaskingContext())

        try:
            response = await call_next(request)
        finally:
            elapsed_ms = round((time.perf_counter() - started_at) * 1000, 3)
            logger.info(
                "http_request_completed",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "execution_time_ms": elapsed_ms,
                    "user_id": user_id,
                    "organization_id": organization_id,
                },
            )
            await _flush_pii_access_audit(request, get_masking_context())
            request_id_context.reset(request_token)
            user_id_context.reset(user_token)
            organization_id_context.reset(organization_token)
            masking_context.reset(masking_token)

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Execution-Time-MS"] = str(elapsed_ms)
        return response


def _build_pii_audit_fields(
    request: Request, context: MaskingContext
) -> dict[str, object]:
    """Pure -- builds the ``create_audit_log_entry(**fields)`` payload for
    one request's worth of PII-unmasking access. Split out from
    ``_flush_pii_access_audit`` specifically so this shape can be unit
    tested without a real database session (see
    ``tests/unit/test_masking.py``)."""
    kinds = sorted(set(context.accessed_kinds))
    return {
        "actor_user_id": _parse_uuid(context.user_id),
        "action": AuditAction.PII_VIEWED_UNMASKED.value,
        "entity_type": "pii_access",
        "entity_id": None,
        "description": (
            f"Viewed unmasked PII ({', '.join(kinds)}) on {request.method} "
            f"{request.url.path}"
        ),
        "event_metadata": {
            "kinds": kinds,
            "count": len(context.accessed_kinds),
            "path": request.url.path,
        },
        "organization_id": _parse_uuid(context.organization_id),
    }


async def _flush_pii_access_audit(request: Request, context: MaskingContext) -> None:
    """Writes exactly one ``audit_log_entries`` row for this request if --
    and only if -- a masking-disabled caller actually caused at least one
    ``Masked*`` field to serialize unmasked (``context.accessed_kinds``
    non-empty; see ``MaskingContext``'s own docstring for why the
    serializers only ever append there in that exact case). A fresh,
    short-lived session is opened here directly (mirroring how Celery
    tasks already open ad-hoc sessions -- e.g.
    ``app.domains.provisioning_engine.tasks``) since ``BaseHTTPMiddleware
    .dispatch`` runs outside FastAPI's own per-route dependency injection
    and therefore has no request-scoped session to reuse."""
    if not context.accessed_kinds:
        return

    # Imported lazily, inside the function, to avoid a module-level import
    # cycle: app.domains.rbac.repository -> ... -> app.database.session,
    # and this middleware module is imported very early (app.main, before
    # the domain layer is guaranteed to be fully initialized).
    from app.database.session import SessionLocal
    from app.domains.rbac.repository import RBACRepository

    fields = _build_pii_audit_fields(request, context)
    async with SessionLocal() as session:
        repository = RBACRepository(session)
        await repository.create_audit_log_entry(**fields)
        await session.commit()


def _parse_uuid(value: str | None) -> uuid.UUID | None:
    if value is None:
        return None
    try:
        return uuid.UUID(value)
    except ValueError:
        return None
