# app/core/config.py — re-exports from app.config
# The API routers import from app.core.config; this shim keeps them working.
from app.config import settings  # noqa: F401
