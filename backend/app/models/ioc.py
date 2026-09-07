"""
TraceVault – IOC (Indicator of Compromise) Model
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class IOC(Base):
    """An extracted and enriched Indicator of Compromise linked to a case."""

    __tablename__ = "iocs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False
    )
    ioc_type: Mapped[str] = mapped_column(
        String(30), nullable=False,
        comment="IP|DOMAIN|URL|EMAIL|FILE_HASH|ATTACHMENT"
    )
    ioc_value: Mapped[str] = mapped_column(Text, nullable=False)
    defanged_value: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="e.g. hxxp://evil[.]com"
    )
    severity: Mapped[str | None] = mapped_column(
        String(20), nullable=True, comment="CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN"
    )
    context: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Where in the email this IOC was found"
    )
    is_lookalike: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    lookalike_target: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Brand being impersonated, e.g. 'paypal.com'"
    )
    is_shortened_url: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    redirect_target: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Resolved destination of shortened URL"
    )
    metadata_: Mapped[dict | None] = mapped_column(
        "metadata", JSONB, nullable=True, comment="Additional enrichment data"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    case: Mapped["Case"] = relationship(  # type: ignore[name-defined]  # noqa: F821
        "Case", back_populates="iocs"
    )

    __table_args__ = (
        Index("ix_iocs_case_id", "case_id"),
        Index("ix_iocs_type", "ioc_type"),
        Index("ix_iocs_severity", "severity"),
        Index("ix_iocs_value", "ioc_value"),
    )

    def __repr__(self) -> str:
        return f"<IOC type={self.ioc_type!r} value={self.ioc_value!r} sev={self.severity!r}>"
