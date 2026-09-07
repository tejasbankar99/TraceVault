"""
TraceVault – Campaign and CaseCampaign Models
Threat actor campaigns aggregate related cases sharing common IOCs.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Campaign(Base):
    """
    A threat actor campaign — a cluster of related cases sharing indicators.
    Built by the correlation engine when similarity thresholds are exceeded.
    """

    __tablename__ = "campaigns"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    campaign_id: Mapped[str] = mapped_column(
        String(30), unique=True, nullable=False, index=True,
        comment="e.g. CAMP-20240915-B8D2"
    )
    name: Mapped[str | None] = mapped_column(Text, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    case_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    shared_indicators: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True, comment="Dict of shared IOC types and values"
    )
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    threat_actor_hypothesis: Mapped[str | None] = mapped_column(Text, nullable=True)

    case_campaigns: Mapped[list["CaseCampaign"]] = relationship(
        "CaseCampaign", back_populates="campaign", cascade="all, delete-orphan", lazy="select"
    )

    __table_args__ = (
        Index("ix_campaigns_first_seen", "first_seen"),
        Index("ix_campaigns_last_seen", "last_seen"),
    )

    def __repr__(self) -> str:
        return f"<Campaign {self.campaign_id!r} cases={self.case_count}>"


class CaseCampaign(Base):
    """Association table linking cases to campaigns with similarity metadata."""

    __tablename__ = "case_campaigns"

    case_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("cases.case_id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )
    campaign_id: Mapped[str] = mapped_column(
        String(30),
        ForeignKey("campaigns.campaign_id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )
    similarity_score: Mapped[float | None] = mapped_column(
        Float, nullable=True, comment="0.0–1.0 cosine or Jaccard similarity"
    )
    shared_ioc_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    case: Mapped["Case"] = relationship(  # type: ignore[name-defined]  # noqa: F821
        "Case", back_populates="case_campaigns"
    )
    campaign: Mapped["Campaign"] = relationship("Campaign", back_populates="case_campaigns")

    __table_args__ = (
        Index("ix_case_campaigns_case_id", "case_id"),
        Index("ix_case_campaigns_campaign_id", "campaign_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<CaseCampaign case={self.case_id!r} campaign={self.campaign_id!r} "
            f"score={self.similarity_score}>"
        )
