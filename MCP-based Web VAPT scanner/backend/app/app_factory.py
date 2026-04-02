"""
FastAPI application factory and integration layer.

This module is responsible for:
- Creating and configuring the FastAPI application instance.
- Wiring routers, middleware, and exception handlers.
- Initializing shared infrastructure (logging, registries).
"""

from __future__ import annotations

import logging
from typing import List

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .app_config import AppConfig, get_app_config
from .api.exception_handlers import (
    generic_exception_handler,
    http_exception_handler,
    validation_exception_handler,
)
from .api.middleware.logging_middleware import LoggingMiddleware
from .api.middleware.security_headers_middleware import SecurityHeadersMiddleware
from .api.middleware.timing_middleware import TimingMiddleware
from .api.routes.scan import router as scan_router
from .core import ExceptionHandlingMiddleware, Settings, get_logger, get_settings, setup_logging
from .core.config import Settings
from .core.logger import get_logger
from .mcp import MCPContextManager
from .api.dependencies import get_tool_registry


logger = get_logger(__name__)


def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application instance.

    This function is the single entry point for application bootstrap.
    """

    # Initialize logging using the core configuration.
    setup_logging()
    settings: Settings = get_settings()
    app_config: AppConfig = get_app_config()

    # Optionally override root log level from AppConfig.
    logging.getLogger().setLevel(app_config.LOG_LEVEL)

    app = FastAPI(
        title=settings.APP_NAME,
        debug=settings.DEBUG,
    )

    # ----------------------------------------------------------------- middleware
    # Core exception-handling middleware
    app.add_middleware(ExceptionHandlingMiddleware)

    # API-specific middleware
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(TimingMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    # CORS configuration (relaxed by default; can be tightened via env).
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Trusted hosts middleware (stub configuration).
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"],
    )

    # ----------------------------------------------------------------- routers
    app.include_router(scan_router, prefix=settings.API_V1_PREFIX)

    # ---------------------------------------------------------- exception handlers
    from fastapi import HTTPException

    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, generic_exception_handler)

    # ------------------------------------------------------------- lifecycle hooks
    @app.on_event("startup")
    async def on_startup() -> None:
        # Initialize core registries and adapters.
        registry = get_tool_registry()
        logger.info(
            "Starting MCP Web VAPT backend | env=%s log_level=%s tools=%s",
            app_config.ENVIRONMENT,
            app_config.LOG_LEVEL,
            list(registry.list_metadata().keys()),
        )

        # If a single API key is provided via `API_KEY`, append it to the core
        # settings' API key list at runtime.
        if app_config.API_KEY:
            core_settings = get_settings()
            if app_config.API_KEY not in core_settings.API_KEYS:
                core_settings.API_KEYS.append(app_config.API_KEY)

    @app.on_event("shutdown")
    async def on_shutdown() -> None:
        logger.info("Shutting down MCP Web VAPT backend.")

    return app

