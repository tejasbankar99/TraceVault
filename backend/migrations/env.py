"""
Alembic Environment – Async-compatible migration runner using asyncpg.
"""
from __future__ import annotations

import asyncio
import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# ── Alembic Config ─────────────────────────────────────────────────────────────
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ── Import All Models So Metadata Is Populated ────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.database import Base  # noqa: E402
from app.models import (  # noqa: F401, E402
    blockchain, campaign, case, email_data, geo, ioc, user,
)

target_metadata = Base.metadata


def get_url() -> str:
    """
    Always use asyncpg driver.
    Reads DATABASE_URL from environment (set in .env / docker-compose),
    then ensures the scheme is postgresql+asyncpg://.
    """
    url = os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://tracevault:tracevault_secret@postgres:5432/tracevault",
    )
    # Normalise: replace plain postgresql:// or postgres:// with asyncpg variant
    url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    # Also handle psycopg2 if someone set it explicitly
    url = url.replace("postgresql+psycopg2://", "postgresql+asyncpg://", 1)
    return url


# ── Offline Mode ──────────────────────────────────────────────────────────────
def run_migrations_offline() -> None:
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# ── Online Mode ───────────────────────────────────────────────────────────────
def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    configuration = {
        "sqlalchemy.url": get_url(),
    }
    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


# ── Dispatch ──────────────────────────────────────────────────────────────────
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
