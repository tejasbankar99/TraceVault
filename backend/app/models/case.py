"""
TraceVault – Case and AnalysisResult Models
"""

from __future__ import annotations

import enum as _enum
import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class CaseStatus(str, _enum.Enum):
    """Enum for case lifecycle status — importable by API routers."""
    PENDING = "PENDING"
    ANALYZING = "ANALYZING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    DELETED = "DELETED"


class Case(Base):
    """A forensic investigation case for a single submitted email."""

    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False
    )
    case_id: Mapped[str] = mapped_column(
        String(30), unique=True, nullable=False, index=True,
        comment="Human-readable ID, e.g. TV-20240915-A3F7C2D1"
    )
    status: Mapped[str] = mapped_column(
        Enum("PENDING", "ANALYZING", "COMPLETED", "FAILED", name="case_status_enum"),
        nullable=False,
        default="PENDING",
        server_default="PENDING",
    )
    evidence_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, comment="SHA-256 of the raw .eml file"
    )
    evidence_hash3: Mapped[str] = mapped_column(
        String(64), nullable=False, comment="SHA-3-256 of the raw .eml file"
    )
    raw_email_path: Mapped[str] = mapped_column(
        String(512), nullable=False, comment="Absolute path to stored .eml"
    )
    file_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    threat_score: Mapped[int | None] = mapped_column(
        Integer, nullable=True, comment="0–100 overall threat score"
    )
    severity: Mapped[str | None] = mapped_column(
        Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", "BENIGN", name="case_severity_enum"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    # ── Relationships ──────────────────────────────────────────────────────────
    creator: Mapped["User"] = relationship(  # type: ignore[name-defined]  # noqa: F821
        "User", back_populates="cases", lazy="select"
    )
    email_headers: Mapped[list["EmailHeader"]] = relationship(  # noqa: F821
        "EmailHeader", back_populates="case", cascade="all, delete-orphan", lazy="select"
    )
    relay_hops: Mapped[list["RelayHop"]] = relationship(  # noqa: F821
        "RelayHop", back_populates="case", cascade="all, delete-orphan", lazy="select",
        order_by="RelayHop.hop_index",
    )
    auth_results: Mapped[list["AuthResult"]] = relationship(  # noqa: F821
        "AuthResult", back_populates="case", cascade="all, delete-orphan", lazy="select"
    )
    analysis_results: Mapped[list["AnalysisResult"]] = relationship(
        "AnalysisResult", back_populates="case", cascade="all, delete-orphan", lazy="select"
    )
    iocs: Mapped[list["IOC"]] = relationship(  # noqa: F821
        "IOC", back_populates="case", cascade="all, delete-orphan", lazy="select"
    )
    geo_intelligence: Mapped[list["GeoIntelligence"]] = relationship(  # noqa: F821
        "GeoIntelligence", back_populates="case", cascade="all, delete-orphan", lazy="select"
    )
    blockchain_ledger: Mapped[list["BlockchainEntry"]] = relationship(  # noqa: F821
        "BlockchainEntry", back_populates="case", lazy="select"
    )
    case_campaigns: Mapped[list["CaseCampaign"]] = relationship(  # noqa: F821
        "CaseCampaign", back_populates="case", cascade="all, delete-orphan", lazy="select"
    )

    __table_args__ = (
        Index("ix_cases_status", "status"),
        Index("ix_cases_severity", "severity"),
        Index("ix_cases_created_at", "created_at"),
        Index("ix_cases_threat_score", "threat_score"),
    )

    def __repr__(self) -> str:
        return f"<Case case_id={self.case_id!r} status={self.status!r} score={self.threat_score}>"


class AnalysisResult(Base):
    """Aggregated AI + rule-based + ML analysis result for a case."""

    __tablename__ = "analysis_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False, index=True
    )
    threat_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    threat_categories: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    rule_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ml_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    gemini_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ai_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    urgency_phrases: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    impersonation_details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    social_engineering_patterns: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    shap_features: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    recommended_actions: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    analyzed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    analysis_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    case: Mapped["Case"] = relationship("Case", back_populates="analysis_results")

    def __repr__(self) -> str:
        return f"<AnalysisResult case_id={self.case_id!r} score={self.threat_score}>"
