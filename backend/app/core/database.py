# app/core/database.py — re-exports from app.database
# The API routers import from app.core.database; this shim keeps them working.
from app.database import (  # noqa: F401
    Base,
    AsyncSessionLocal,
    engine,
    get_db,
    init_db,
    close_db,
    init_redis,
    close_redis,
    get_redis_client,
)
