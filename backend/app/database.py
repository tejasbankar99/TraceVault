"""
TraceVault – Database Layer
Provides async SQLAlchemy engine, session factory, Base declarative,
dependency-injection helper, and Redis client.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Optional

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import declarative_base

from app.config import settings

# ── SQLAlchemy ────────────────────────────────────────────────────────────────

engine: AsyncEngine = create_async_engine(
    settings.database_url,
    echo=settings.is_development,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    pool_timeout=30,
    pool_recycle=1800,
)

AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)
async_session_maker = AsyncSessionLocal

Base = declarative_base()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields a database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Create all tables defined in the ORM models."""
    # Import all models so their metadata is registered with Base
    from app.models import (  # noqa: F401  # pylint: disable=import-outside-toplevel
        blockchain,
        campaign,
        case,
        email_data,
        geo,
        ioc,
        user,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all, checkfirst=True)


async def close_db() -> None:
    """Dispose the async engine connection pool."""
    await engine.dispose()


# ── Redis ─────────────────────────────────────────────────────────────────────

_redis_client: Optional[aioredis.Redis] = None  # type: ignore[type-arg]


def get_redis_client() -> aioredis.Redis:  # type: ignore[type-arg]
    """Return the shared Redis client (must call init_redis first)."""
    if _redis_client is None:
        raise RuntimeError("Redis client not initialised. Call init_redis() first.")
    return _redis_client


async def init_redis() -> None:
    """Initialise the async Redis connection pool."""
    global _redis_client  # pylint: disable=global-statement
    _redis_client = aioredis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=5,
        retry_on_timeout=True,
        health_check_interval=30,
    )
    # Verify connection
    await _redis_client.ping()


async def close_redis() -> None:
    """Close the Redis connection pool."""
    global _redis_client  # pylint: disable=global-statement
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None
