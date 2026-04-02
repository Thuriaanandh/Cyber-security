"""
Database configuration and session management for the storage layer.

Uses SQLAlchemy's async engine with PostgreSQL.
"""

from __future__ import annotations

from functools import lru_cache
from typing import AsyncGenerator

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine


class DatabaseSettings(BaseSettings):
    """
    Storage-focused database configuration.

    These settings are intentionally independent of the core config to avoid
    modifying existing modules. They can be wired using environment variables.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://vapt_user:change_me@localhost:5432/vapt",
        description="SQLAlchemy async database URL for PostgreSQL.",
    )
    DB_POOL_SIZE: int = Field(
        default=5,
        description="Size of the SQLAlchemy connection pool.",
    )
    DB_MAX_OVERFLOW: int = Field(
        default=10,
        description="Maximum overflow size of the SQLAlchemy connection pool.",
    )


@lru_cache
def get_db_settings() -> DatabaseSettings:
    """Return cached database settings instance."""

    return DatabaseSettings()


@lru_cache
def get_engine() -> AsyncEngine:
    """Create and cache the async SQLAlchemy engine."""

    settings = get_db_settings()
    return create_async_engine(
        settings.DATABASE_URL,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        future=True,
    )


@lru_cache
def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return a cached async session factory."""

    engine = get_engine()
    return async_sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Async session dependency helper.

    This function is designed to be used with FastAPI's dependency injection,
    but it can also be used manually in application or test code.
    """

    session_factory = get_session_factory()
    async with session_factory() as session:
        yield session

