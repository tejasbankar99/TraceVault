"""
TraceVault – Email Data Models: EmailHeader, RelayHop, AuthResult
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
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


class EmailHeader(Base):
    """Parsed email header fields extracted from the raw .eml file."""

    __tablename__ = "email_headers"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False
    )

    # Sender fields
    from_addr: Mapped[str | None] = mapped_column(Text, nullable=True)
    from_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    from_domain: Mapped[str | None] = mapped_column(Text, nullable=True)
    reply_to: Mapped[str | None] = mapped_column(Text, nullable=True)
    reply_to_domain: Mapped[str | None] = mapped_column(Text, nullable=True)
    return_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    return_path_domain: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Message metadata
    message_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    date_sent: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Technical headers
    x_originating_ip: Mapped[str | None] = mapped_column(Text, nullable=True)
    x_mailer: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_type: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Structured header dump
    raw_headers: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True, comment="Complete dict of all header name→value pairs"
    )
    rfc_violations: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True, comment="List of detected RFC 5322 violations"
    )
    spoofing_indicators: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True, comment="List of detected spoofing clues"
    )

    # ── Relationship ───────────────────────────────────────────────────────────
    case: Mapped["Case"] = relationship(  # type: ignore[name-defined]  # noqa: F821
        "Case", back_populates="email_headers"
    )

    __table_args__ = (Index("ix_email_headers_case_id", "case_id"),)

    def __repr__(self) -> str:
        return f"<EmailHeader case_id={self.case_id!r} from={self.from_addr!r}>"


class RelayHop(Base):
    """A single Received: header hop in the email relay chain."""

    __tablename__ = "relay_hops"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False
    )
    hop_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    by_server: Mapped[str | None] = mapped_column(Text, nullable=True)
    from_server: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(
        Text, nullable=True, comment="Stored as TEXT for cross-DB compatibility"
    )
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_public_ip: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_suspicious: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    raw_header: Mapped[str | None] = mapped_column(Text, nullable=True)

    case: Mapped["Case"] = relationship("Case", back_populates="relay_hops")  # noqa: F821

    __table_args__ = (
        Index("ix_relay_hops_case_id", "case_id"),
        Index("ix_relay_hops_case_hop", "case_id", "hop_index"),
    )

    def __repr__(self) -> str:
        return (
            f"<RelayHop case_id={self.case_id!r} hop={self.hop_index} ip={self.ip_address!r}>"
        )


class AuthResult(Base):
    """SPF, DKIM, and DMARC authentication results for a case."""

    __tablename__ = "auth_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False
    )

    # SPF
    spf_result: Mapped[str | None] = mapped_column(
        String(20), nullable=True,
        comment="pass|fail|softfail|neutral|none|permerror|temperror"
    )
    spf_domain: Mapped[str | None] = mapped_column(Text, nullable=True)
    spf_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)

    # DKIM
    dkim_result: Mapped[str | None] = mapped_column(String(20), nullable=True, comment="pass|fail|none")
    dkim_domain: Mapped[str | None] = mapped_column(Text, nullable=True)
    dkim_selector: Mapped[str | None] = mapped_column(Text, nullable=True)

    # DMARC
    dmarc_result: Mapped[str | None] = mapped_column(String(20), nullable=True, comment="pass|fail|none")
    dmarc_policy: Mapped[str | None] = mapped_column(String(20), nullable=True, comment="none|quarantine|reject")
    dmarc_subdomain_policy: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Verdict
    overall_verdict: Mapped[str | None] = mapped_column(String(20), nullable=True, comment="PASS|WARN|FAIL|CRITICAL")
    spoofing_risk: Mapped[str | None] = mapped_column(String(20), nullable=True)
    raw_auth_header: Mapped[str | None] = mapped_column(Text, nullable=True)

    case: Mapped["Case"] = relationship("Case", back_populates="auth_results")  # noqa: F821

    __table_args__ = (Index("ix_auth_results_case_id", "case_id"),)

    def __repr__(self) -> str:
        return (
            f"<AuthResult case_id={self.case_id!r} verdict={self.overall_verdict!r}>"
        )
