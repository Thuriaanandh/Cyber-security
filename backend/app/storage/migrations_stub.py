"""
Migrations stub for the storage layer.

This module documents a placeholder for schema migrations (e.g. via Alembic).
It does not perform any actions by itself.
"""

from __future__ import annotations


def get_migrations_instructions() -> str:
    """
    Return human-readable guidance on how migrations could be implemented.

    This function is intentionally simple and is not invoked by the
    application; it serves as a documentation anchor.
    """

    return (
        "Use Alembic or a similar tool to manage database migrations for the "
        "ORM models defined in `storage.models`. Configure the migration tool "
        "to use the same DATABASE_URL as `storage.db.DatabaseSettings`."
    )

