"""
TraceVault – Application Configuration
All settings are loaded from environment variables (or .env file).
"""

from __future__ import annotations

import json
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central settings object. All values can be overridden via environment."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Database ───────────────────────────────────────────────────────────────
    database_url: str = (
        "postgresql+asyncpg://tracevault:tracevault_secure_2024@localhost:5432/tracevault"
    )
    sync_database_url: str = (
        "postgresql://tracevault:tracevault_secure_2024@localhost:5432/tracevault"
    )

    # ── Redis ──────────────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── JWT Authentication ─────────────────────────────────────────────────────
    secret_key: str = "change-me-in-production-use-secrets-token-hex-32"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 480

    # ── AI / Gemini ────────────────────────────────────────────────────────────
    google_api_key: str = ""

    # ── IP Intelligence ────────────────────────────────────────────────────────
    ipinfo_token: str = ""

    # ── Blockchain – Polygon Amoy Testnet ─────────────────────────────────────
    polygon_rpc_url: str = "https://rpc-amoy.polygon.technology/"
    polygon_private_key: str = ""
    polygon_account_address: str = ""
    enable_blockchain_anchoring: bool = False

    # ── Evidence Storage ───────────────────────────────────────────────────────
    evidence_store_path: str = "/app/evidence_store"
    max_email_size_mb: int = 25

    # ── Application ────────────────────────────────────────────────────────────
    environment: str = "development"
    cors_origins: List[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: object) -> List[str]:
        """Accept either a JSON array string or a real list."""
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                if isinstance(parsed, list):
                    return parsed
            except json.JSONDecodeError:
                # Treat as a comma-separated string
                return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v  # type: ignore[return-value]

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @property
    def is_development(self) -> bool:
        return self.environment.lower() == "development"

    @property
    def max_email_size_bytes(self) -> int:
        return self.max_email_size_mb * 1024 * 1024


# ── Singleton ─────────────────────────────────────────────────────────────────
settings = Settings()
