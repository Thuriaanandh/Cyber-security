"""
ASGI entrypoint for the MCP Web VAPT backend.

This module exposes the FastAPI `app` created by the application factory,
which is used by servers such as Uvicorn or Gunicorn.
"""

from __future__ import annotations

from fastapi import FastAPI

from .app_factory import create_app


app: FastAPI = create_app()

