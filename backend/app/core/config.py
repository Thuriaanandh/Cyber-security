"""
Application configuration module.

Provides a strongly-typed, environment-driven configuration object that can be
injected throughout the application. All settings are centralized here to keep
infrastructure concerns decoupled from business logic.
"""

from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Strongly-typed application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -------------------------------------------------------------------------
    # Application
    # -------------------------------------------------------------------------
    APP_NAME: str = "MCP Web VAPT Backend"
    ENVIRONMENT: str = Field(default="development", description="Environment name, e.g. development/staging/production.")
    DEBUG: bool = Field(default=True, description="Enable or disable debug mode.")
    API_V1_PREFIX: str = "/api/v1"

    # -------------------------------------------------------------------------
    # Database (PostgreSQL)
    # -------------------------------------------------------------------------
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "vapt"
    POSTGRES_USER: str = "vapt_user"
    POSTGRES_PASSWORD: str = "change_me"

    # -------------------------------------------------------------------------
    # Cache (Redis)
    # -------------------------------------------------------------------------
    REDIS_URL: str = "redis://localhost:6379/0"

    # -------------------------------------------------------------------------
    # Task Queue / Broker (RabbitMQ via Celery)
    # -------------------------------------------------------------------------
    RABBITMQ_URL: str = "amqp://guest:guest@localhost:5672//"

    # -------------------------------------------------------------------------
    # Security / Auth
    # -------------------------------------------------------------------------
    API_KEY_HEADER_NAME: str = "X-API-Key"
    API_KEYS: List[str] = Field(
        default_factory=lambda: ["dev-api-key-change-me"],
        description="List of allowed API keys for backend access.",
    )

    # -------------------------------------------------------------------------
    # Rate limiting
    # -------------------------------------------------------------------------
    RATE_LIMIT_REQUESTS: int = Field(
        default=60,
        description="Maximum number of requests per window for a given identity.",
    )
    RATE_LIMIT_WINDOW_SECONDS: int = Field(
        default=60,
        description="Duration of the rate limiting window in seconds.",
    )

    # -------------------------------------------------------------------------
    # Logging
    # -------------------------------------------------------------------------
    LOG_LEVEL: str = Field(default="INFO", description="Root logging level.")

    @property
    def database_url(self) -> str:
        """Async SQLAlchemy connection URL for PostgreSQL."""
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )


@lru_cache
def get_settings() -> Settings:
    """
    Return a cached `Settings` instance.

    Using an LRU cache ensures we only evaluate environment variables once and
    reuse the same settings object across the application.
    """

    return Settings()

