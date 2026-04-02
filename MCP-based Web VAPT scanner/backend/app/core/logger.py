"""
Centralized logging configuration for the backend service.

Logging is configured once at application startup and reused across all
modules. This keeps log formatting and log levels consistent.
"""

from __future__ import annotations

import logging
from logging.config import dictConfig
from typing import Any, Dict

from .config import get_settings


class _ContextFilter(logging.Filter):
    """
    Logging filter that guarantees presence of correlation fields.

    This prevents KeyError when log format references `trace_id` or `span_id`
    but they are not explicitly set on the logging record.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "trace_id"):
            record.trace_id = "n/a"
        if not hasattr(record, "span_id"):
            record.span_id = "n/a"
        return True


def _build_logging_config() -> Dict[str, Any]:
    """Build the logging configuration dict for `logging.config.dictConfig`."""

    settings = get_settings()
    log_format = (
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s | "
        "trace_id=%(trace_id)s span_id=%(span_id)s"
    )

    return {
        "version": 1,
        "disable_existing_loggers": False,
        "filters": {
            "context_filter": {
                "()": _ContextFilter,
            },
        },
        "formatters": {
            "default": {
                "format": log_format,
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "default",
                "filters": ["context_filter"],
            },
        },
        "root": {
            "level": settings.LOG_LEVEL,
            "handlers": ["console"],
        },
    }


def setup_logging() -> None:
    """Configure the root logger. Should be called once at application startup."""

    dictConfig(_build_logging_config())


def get_logger(name: str) -> logging.Logger:
    """Return a module-specific logger instance."""

    return logging.getLogger(name)

