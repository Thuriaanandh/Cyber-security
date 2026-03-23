"""
Request/response logging middleware specific to the API layer.
"""

from __future__ import annotations

import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request

from ...core.logger import get_logger


logger = get_logger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware that logs basic request and response information.

    This complements the core logging setup by adding HTTP-specific context.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        start_time = time.perf_counter()
        logger.info("Incoming request %s %s", request.method, request.url.path)
        response = await call_next(request)
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        logger.info(
            "Completed request %s %s status=%s duration_ms=%.2f",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
        )
        return response

