from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        # The one deliberate exception: app.domains.router.router's WebFig
        # reverse-proxy endpoint is meant to be embedded in an <iframe> by
        # this same app's own Master Console (RouterDetailTabs.tsx's
        # "Open web console" panel) -- a blanket DENY here silently blocked
        # the browser from ever rendering that iframe's content at all
        # (no visible error beyond a console warning). SAMEORIGIN keeps
        # every other route's real clickjacking protection, and still
        # refuses this route to any OTHER site trying to frame it -- only
        # this app's own origin may.
        if "/webfig/" in request.url.path:
            response.headers["X-Frame-Options"] = "SAMEORIGIN"
        else:
            response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        return response

