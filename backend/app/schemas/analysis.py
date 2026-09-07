"""
TraceVault – Analysis Pydantic Schemas
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, ConfigDict


# ── Enums ─────────────────────────────────────────────────────────────────────

class ThreatCategory(str, Enum):
    """Canonical threat categories detected by the analysis engine."""

    PHISHING = "PHISHING"
    SPEAR_PHISHING = "SPEAR_PHISHING"
    MALWARE_DELIVERY = "MALWARE_DELIVERY"
    BUSINESS_EMAIL_COMPROMISE = "BUSINESS_EMAIL_COMPROMISE"
    CREDENTIAL_HARVESTING = "CREDENTIAL_HARVESTING"
    SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"
    BRAND_IMPERSONATION = "BRAND_IMPERSONATION"
    DOMAIN_SPOOFING = "DOMAIN_SPOOFING"
    HEADER_MANIPULATION = "HEADER_MANIPULATION"
    SPAM = "SPAM"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"


# ── Response Schemas ───────────────────────────────────────────────────────────

class HeaderAnalysisResponse(BaseModel):
    """Parsed email header data for a case."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: str
    from_addr: Optional[str]
    from_name: Optional[str]
    from_domain: Optional[str]
    reply_to: Optional[str]
    reply_to_domain: Optional[str]
    return_path: Optional[str]
    return_path_domain: Optional[str]
    message_id: Optional[str]
    subject: Optional[str]
    date_sent: Optional[datetime]
    x_originating_ip: Optional[str]
    x_mailer: Optional[str]
    content_type: Optional[str]
    raw_headers: Optional[Dict[str, Any]] = None
    rfc_violations: Optional[List[Any]] = []
    spoofing_indicators: Optional[List[Any]] = []


class RelayHopResponse(BaseModel):
    """A single relay hop parsed from a Received: header."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: str
    hop_index: int
    by_server: Optional[str]
    from_server: Optional[str]
    ip_address: Optional[str]
    protocol: Optional[str]
    timestamp: Optional[datetime]
    is_public_ip: bool
    is_suspicious: bool
    raw_header: Optional[str]


class AuthResultResponse(BaseModel):
    """SPF, DKIM, and DMARC authentication results."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: str
    spf_result: Optional[str]
    spf_domain: Optional[str]
    spf_explanation: Optional[str]
    dkim_result: Optional[str]
    dkim_domain: Optional[str]
    dkim_selector: Optional[str]
    dmarc_result: Optional[str]
    dmarc_policy: Optional[str]
    dmarc_subdomain_policy: Optional[str]
    overall_verdict: Optional[str]
    spoofing_risk: Optional[str]
    raw_auth_header: Optional[str]


class AnalysisResultResponse(BaseModel):
    """Aggregated AI + rule-based + ML threat analysis result."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: str
    threat_score: int = Field(..., ge=0, le=100)
    severity: Optional[str]
    threat_categories: Optional[List[str]]
    rule_score: Optional[int]
    ml_score: Optional[float]
    gemini_score: Optional[int]
    ai_explanation: Optional[str]
    urgency_phrases: Optional[List[str]]
    impersonation_details: Optional[Dict[str, Any]]
    social_engineering_patterns: Optional[List[str]]
    shap_features: Optional[Dict[str, Any]]
    recommended_actions: Optional[List[str]]
    analyzed_at: Optional[datetime]
    analysis_duration_ms: Optional[int]


class AnalysisSummary(BaseModel):
    """High-level summary of a completed analysis (for dashboard cards)."""

    case_id: str
    threat_score: int
    severity: str
    primary_category: str
    top_ioc_count: int
    auth_verdict: Optional[str]
    analyzed_at: Optional[datetime]
    duration_ms: Optional[int]
