"""
TraceVault – FastAPI Application Entry Point
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.database import close_db, close_redis, init_db, init_redis

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=logging.DEBUG if settings.is_development else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:  # noqa: ARG001
    """Startup and shutdown lifecycle manager."""
    logger.info("TraceVault backend starting up…")

    # Initialise database tables (non-fatal — Alembic owns schema creation)
    try:
        await init_db()
        logger.info("Database initialised successfully.")
    except Exception as exc:
        # Tables already exist (e.g. on container restart after Alembic ran)
        logger.warning("Database init skipped (tables may already exist): %s", exc)

    # Initialise Redis connection
    try:
        await init_redis()
        logger.info("Redis connection established.")
    except Exception as exc:
        logger.warning("Redis unavailable (non-fatal in dev): %s", exc)

    yield  # Application is running

    logger.info("TraceVault backend shutting down…")
    await close_redis()
    await close_db()
    logger.info("Shutdown complete.")


# ── Application ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="TraceVault",
    description=(
        "AI-powered Email Threat Detection and Forensic Intelligence Platform. "
        "Provides email header analysis, IOC enrichment, geo-intelligence, "
        "blockchain-anchored audit trails, and AI-generated forensic reports."
    ),
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Case-ID", "X-Request-ID", "Content-Disposition"],
)

# ── API Routers ───────────────────────────────────────────────────────────────
# Routers are imported lazily to avoid circular imports at module load time.

def _register_routers() -> None:
    try:
        from app.api.v1 import auth  # noqa: F401
        app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
    except ImportError as e:
        logger.warning("auth router not available: %s", e)

    try:
        from app.api.v1 import cases  # noqa: F401
        app.include_router(cases.router, prefix="/api/v1/cases", tags=["Cases"])
    except ImportError as e:
        logger.warning("cases router not available: %s", e)

    try:
        from app.api.v1 import analysis  # noqa: F401
        app.include_router(analysis.router, prefix="/api/v1/analysis", tags=["Analysis"])
    except ImportError as e:
        logger.warning("analysis router not available: %s", e)

    try:
        from app.api.v1 import iocs  # noqa: F401
        app.include_router(iocs.router, prefix="/api/v1/iocs", tags=["IOCs"])
    except ImportError as e:
        logger.warning("iocs router not available: %s", e)

    try:
        from app.api.v1 import blockchain  # noqa: F401
        app.include_router(blockchain.router, prefix="/api/v1/blockchain", tags=["Blockchain"])
    except ImportError as e:
        logger.warning("blockchain router not available: %s", e)

    try:
        from app.api.v1 import reports  # noqa: F401
        app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
    except ImportError as e:
        logger.warning("reports router not available: %s", e)

    try:
        from app.api.v1 import graph  # noqa: F401
        app.include_router(graph.router, prefix="/api/v1/graph", tags=["Graph"])
    except ImportError as e:
        logger.warning("graph router not available: %s", e)

    try:
        from app.api.v1 import campaigns  # noqa: F401
        app.include_router(campaigns.router, prefix="/api/v1/campaigns", tags=["Campaigns"])
    except ImportError as e:
        logger.warning("campaigns router not available: %s", e)

    try:
        from app.api.v1 import stats  # noqa: F401
        app.include_router(stats.router, prefix="/api/v1/stats", tags=["Statistics"])
    except ImportError as e:
        logger.warning("stats router not available: %s", e)


_register_routers()

# ── Static Files ──────────────────────────────────────────────────────────────

# Note: evidence_store is NOT publicly accessible — served via authenticated endpoints only.

# ── Global Exception Handlers ─────────────────────────────────────────────────

@app.exception_handler(404)
async def not_found_handler(request: Request, exc: Exception) -> JSONResponse:  # noqa: ARG001
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": "The requested resource was not found.", "path": str(request.url.path)},
    )


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception for %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred. Please contact support."},
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception for %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected error occurred."},
    )


# ── Health & Root Endpoints ───────────────────────────────────────────────────

@app.get("/health", tags=["Health"], summary="Service health check")
async def health_check() -> dict:
    """Returns service health status. Used by Docker and load balancers."""
    from app.database import engine, get_redis_client  # noqa: PLC0415

    health: dict = {
        "status": "healthy",
        "service": "tracevault-backend",
        "version": "1.0.0",
        "environment": settings.environment,
        "components": {},
    }

    # Check database
    try:
        async with engine.connect() as conn:
            await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
        health["components"]["database"] = "healthy"
    except Exception as exc:
        health["components"]["database"] = f"unhealthy: {exc}"
        health["status"] = "degraded"

    # Check Redis
    try:
        redis = get_redis_client()
        await redis.ping()
        health["components"]["redis"] = "healthy"
    except Exception as exc:
        health["components"]["redis"] = f"unhealthy: {exc}"
        # Redis degradation is non-fatal

    return health


@app.get("/", tags=["Root"], summary="API root")
async def root() -> dict:
    """API root — returns platform identity."""
    return {
        "name": "TraceVault",
        "version": "1.0.0",
        "status": "operational",
        "description": "AI-powered Email Threat Detection and Forensic Intelligence Platform",
        "docs": "/api/docs",
    }
