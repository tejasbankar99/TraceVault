"""
TraceVault – Blockchain Audit Ledger Model
Implements an application-level linked-list blockchain for immutable audit trails.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class BlockchainEntry(Base):
    """
    A single block in the TraceVault audit chain.
    Each block links to the previous via prev_hash, forming a tamper-evident log.
    Block 0 is the GENESIS block with no case association.
    """

    __tablename__ = "blockchain_ledger"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    block_index: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    case_id: Mapped[str | None] = mapped_column(
        String(30),
        ForeignKey("cases.case_id", ondelete="SET NULL"),
        nullable=True,
        comment="NULL for genesis block",
    )
    action: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment=(
            "GENESIS|EVIDENCE_SUBMITTED|ANALYSIS_STARTED|ANALYSIS_COMPLETED|"
            "REPORT_GENERATED|INTEGRITY_VERIFIED|ANALYST_ACCESSED|CASE_DELETED"
        ),
    )
    actor: Mapped[str] = mapped_column(Text, nullable=False, default="system", server_default="system")
    data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    data_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    block_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    # Polygon blockchain anchoring (optional)
    polygon_tx_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_anchored: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    case: Mapped["Case | None"] = relationship(  # type: ignore[name-defined]  # noqa: F821
        "Case", back_populates="blockchain_ledger"
    )

    __table_args__ = (
        Index("ix_blockchain_case_id", "case_id"),
        Index("ix_blockchain_action", "action"),
        Index("ix_blockchain_block_index", "block_index"),
    )

    def __repr__(self) -> str:
        return (
            f"<BlockchainEntry #{self.block_index} action={self.action!r} "
            f"case_id={self.case_id!r} anchored={self.is_anchored}>"
        )


# Alias — routers and services import BlockchainLedger, model class is BlockchainEntry
BlockchainLedger = BlockchainEntry
