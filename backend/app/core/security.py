"""
Security primitives for the backend service.

Includes:
- API key based authentication dependency
- Asynchronous rate limiting helper built on top of Redis
- Global exception-handling middleware for consistent error responses
"""

from __future__ import annotations

from typing import Optional

from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader
from redis.asyncio import Redis
from starlette import status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse

from .config import Settings, get_settings
from .logger import get_logger


logger = get_logger(__name__)


# -----------------------------------------------------------------------------
# API key authentication
# -----------------------------------------------------------------------------

_settings = get_settings()
_api_key_header = APIKeyHeader(name=_settings.API_KEY_HEADER_NAME, auto_error=False)


async def get_api_key(
    api_key: Optional[str] = Security(_api_key_header),
    settings: Settings = Depends(get_settings),
) -> str:
    """
    FastAPI dependency that enforces API key authentication.

    The configured API key header must contain a value present in `settings.API_KEYS`.
    """

    if api_key is None or api_key not in settings.API_KEYS:
        logger.warning("Unauthorized access attempt with invalid or missing API key.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key.",
        )

    return api_key


# -----------------------------------------------------------------------------
# Rate limiting
# -----------------------------------------------------------------------------

class RateLimiter:
    """
    Simple sliding-window rate limiter backed by Redis.

    This component is intentionally infrastructure-only and should be used via
    thin dependencies in the API layer to keep business logic separate.
    """

    def __init__(self, redis_client: Redis, max_requests: int, window_seconds: int) -> None:
        self._redis = redis_client
        self._max_requests = max_requests
        self._window_seconds = window_seconds

    async def is_allowed(self, identity: str) -> bool:
        """
        Return True if the identity is allowed to perform an action, otherwise False.

        The identity is typically derived from a combination of API key and
        client IP address.
        """

        key = f"rate-limit:{identity}"
        current = await self._redis.incr(key)

        if current == 1:
            await self._redis.expire(key, self._window_seconds)

        if current > self._max_requests:
            logger.info("Rate limit exceeded for identity=%s count=%s", identity, current)
            return False

        return True


# -----------------------------------------------------------------------------
# Global error-handling middleware
# -----------------------------------------------------------------------------

class ExceptionHandlingMiddleware(BaseHTTPMiddleware):
    """
    Application-wide middleware for consistent error handling and logging.

    This middleware ensures that:
    - `HTTPException` instances are rendered as JSON with their status codes.
    - Unexpected exceptions are logged and return a generic 500 error response.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        try:
            response = await call_next(request)
            return response
        except HTTPException as exc:
            logger.warning(
                "Handled HTTPException path=%s status=%s detail=%s",
                request.url.path,
                exc.status_code,
                exc.detail,
            )
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Unhandled server error path=%s", request.url.path)
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Internal server error"},
            )

