"""
Security headers middleware stub.

Adds a baseline set of security-related HTTP headers to responses. This is a
lightweight implementation intended to be extended with more advanced
hardening as requirements evolve.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware that appends basic security headers to all responses.

    Note: This is a conservative stub and does not attempt to be exhaustive.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "no-referrer-when-downgrade",
        }
        for key, value in headers.items():
            if key not in response.headers:
                response.headers[key] = value
        return response

