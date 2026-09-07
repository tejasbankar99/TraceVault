"""
TraceVault – Geo Intelligence Model
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, Float, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class GeoIntelligence(Base):
    """Geo-IP enrichment record for a public IP address found in a case."""

    __tablename__ = "geo_intelligence"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False
    )
    ip_address: Mapped[str] = mapped_column(Text, nullable=False)

    # Location
    country: Mapped[str | None] = mapped_column(Text, nullable=True)
    country_code: Mapped[str | None] = mapped_column(String(2), nullable=True)
    city: Mapped[str | None] = mapped_column(Text, nullable=True)
    region: Mapped[str | None] = mapped_column(Text, nullable=True)
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Network identity
    isp: Mapped[str | None] = mapped_column(Text, nullable=True)
    org: Mapped[str | None] = mapped_column(Text, nullable=True)
    asn: Mapped[str | None] = mapped_column(Text, nullable=True)
    hostname: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Threat flags
    is_vpn: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_tor: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_hosting: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_proxy: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # DNS / WHOIS
    ptr_record: Mapped[str | None] = mapped_column(Text, nullable=True)
    whois_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    dns_records: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    enrichment_source: Mapped[str | None] = mapped_column(Text, nullable=True)

    case: Mapped["Case"] = relationship(  # type: ignore[name-defined]  # noqa: F821
        "Case", back_populates="geo_intelligence"
    )

    __table_args__ = (
        Index("ix_geo_case_id", "case_id"),
        Index("ix_geo_ip_address", "ip_address"),
        Index("ix_geo_country_code", "country_code"),
    )

    def __repr__(self) -> str:
        return (
            f"<GeoIntelligence ip={self.ip_address!r} country={self.country_code!r}>"
        )
