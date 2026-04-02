"""
Application-level configuration for bootstrap and integration.

This module focuses on settings that are relevant to the HTTP boundary and
orchestration behavior rather than low-level infrastructure details.
"""

from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppConfig(BaseSettings):
    """
    High-level application configuration.

    This complements (but does not replace) the core `Settings` object, and is
    primarily used by the application factory.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    API_KEY: str | None = Field(
        default=None,
        description="Optional single API key to append to the allowed key list.",
    )
    LOG_LEVEL: str = Field(
        default="INFO",
        description="Override root logging level, e.g. INFO, DEBUG, WARNING.",
    )
    MAX_PARALLEL_SCANS: int = Field(
        default=3,
        description="Maximum number of tools that can run in parallel per scan.",
    )
    ENVIRONMENT: str = Field(
        default="development",
        description="High-level environment name, e.g. development/staging/production.",
    )


@lru_cache
def get_app_config() -> AppConfig:
    """Return a cached `AppConfig` instance."""

    return AppConfig()

