"""
analysis.py - SQLAlchemy ORM models for analysis results, relay hops, auth results,
              email headers, and geo intelligence records.
"""
from sqlalchemy import Column, String, Integer, Float, Text, DateTime, JSON, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base
import uuid
from datetime import datetime, timezone

Base = declarative_base()


class AnalysisResult(Base):
    """Stores the final AI threat analysis result for a case."""
    __tablename__ = "analysis_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(String(50), nullable=False, unique=True, index=True)
    threat_score = Column(Integer, nullable=False)
    severity = Column(String(20), nullable=False)
    rule_score = Column(Integer, default=0)
    ml_score = Column(Integer, default=0)
    gemini_score = Column(Integer, default=0)
    threat_categories = Column(JSON, default=list)
    triggered_rules = Column(JSON, default=list)
    ai_explanation = Column(Text, nullable=True)
    urgency_indicators = Column(JSON, default=list)
    impersonation_analysis = Column(JSON, default=dict)
    social_engineering_patterns = Column(JSON, default=list)
    bec_indicators = Column(JSON, default=list)
    shap_features = Column(JSON, default=dict)
    recommended_actions = Column(JSON, default=list)
    confidence = Column(String(10), default="medium")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class RelayHop(Base):
    """Represents a single hop in the email relay chain."""
    __tablename__ = "relay_hops"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(String(50), nullable=False, index=True)
    hop_index = Column(Integer, nullable=False)
    ip_address = Column(String(45), nullable=True)
    hostname = Column(String(500), nullable=True)
    timestamp = Column(DateTime(timezone=True), nullable=True)
    protocol = Column(String(50), nullable=True)
    delay_seconds = Column(Integer, nullable=True)
    is_public = Column(Boolean, default=True)
    raw_header = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class EmailHeader(Base):
    """Stores parsed email header data and detected anomalies."""
    __tablename__ = "email_headers"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(String(50), nullable=False, unique=True, index=True)
    message_id = Column(String(500), nullable=True)
    subject = Column(Text, nullable=True)
    from_addr = Column(String(500), nullable=True)
    to_addr = Column(Text, nullable=True)
    reply_to = Column(String(500), nullable=True)
    return_path = Column(String(500), nullable=True)
    date_header = Column(DateTime(timezone=True), nullable=True)
    x_mailer = Column(String(255), nullable=True)
    x_originating_ip = Column(String(45), nullable=True)
    anomalies = Column(JSON, default=list)
    all_headers = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AuthResult(Base):
    """SPF/DKIM/DMARC authentication results for a case."""
    __tablename__ = "auth_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(String(50), nullable=False, unique=True, index=True)
    spf_result = Column(String(30), nullable=True)
    spf_domain = Column(String(255), nullable=True)
    spf_details = Column(JSON, default=dict)
    dkim_result = Column(String(30), nullable=True)
    dkim_domain = Column(String(255), nullable=True)
    dkim_selector = Column(String(100), nullable=True)
    dkim_details = Column(JSON, default=dict)
    dmarc_result = Column(String(30), nullable=True)
    dmarc_domain = Column(String(255), nullable=True)
    dmarc_policy = Column(String(50), nullable=True)
    dmarc_details = Column(JSON, default=dict)
    arc_result = Column(String(30), nullable=True)
    authentication_results_header = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class GeoIntelligence(Base):
    """IP geolocation and infrastructure intelligence for an IP address in a case."""
    __tablename__ = "geo_intelligence"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(String(50), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False)
    is_private = Column(Boolean, default=False)
    country = Column(String(100), nullable=True)
    country_code = Column(String(10), nullable=True)
    city = Column(String(100), nullable=True)
    region = Column(String(100), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    isp = Column(String(255), nullable=True)
    org = Column(String(255), nullable=True)
    asn = Column(String(50), nullable=True)
    hostname = Column(String(500), nullable=True)
    ptr_record = Column(String(500), nullable=True)
    is_vpn = Column(Boolean, default=False)
    is_tor = Column(Boolean, default=False)
    is_hosting = Column(Boolean, default=False)
    is_proxy = Column(Boolean, default=False)
    whois_data = Column(JSON, default=dict)
    enrichment_source = Column(String(50), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
