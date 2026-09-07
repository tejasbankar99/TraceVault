"""
TraceVault – Report Pydantic Schemas
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, ConfigDict


# ── Enums ─────────────────────────────────────────────────────────────────────

class ReportSection(str, Enum):
    """Available sections that can be included in a generated report."""

    EXECUTIVE_SUMMARY = "executive_summary"
    HEADER_ANALYSIS = "header_analysis"
    AUTHENTICATION_ANALYSIS = "authentication_analysis"
    RELAY_PATH = "relay_path"
    THREAT_SCORING = "threat_scoring"
    IOC_TABLE = "ioc_table"
    GEO_INTELLIGENCE = "geo_intelligence"
    AI_EXPLANATION = "ai_explanation"
    SHAP_FEATURES = "shap_features"
    BLOCKCHAIN_AUDIT = "blockchain_audit"
    RECOMMENDED_ACTIONS = "recommended_actions"
    TECHNICAL_APPENDIX = "technical_appendix"


class ReportFormat(str, Enum):
    """Supported report output formats."""

    PDF = "pdf"
    JSON = "json"
    HTML = "html"


# ── Request Schemas ────────────────────────────────────────────────────────────

class ReportGenerateRequest(BaseModel):
    """Request body for generating a forensic report for a case."""

    model_config = ConfigDict(str_strip_whitespace=True)

    case_id: str = Field(..., description="TraceVault case ID, e.g. TV-20240915-A3F7C2D1")
    format: ReportFormat = Field(ReportFormat.PDF, description="Output format")
    include_sections: List[ReportSection] = Field(
        default_factory=lambda: list(ReportSection),
        description="Which sections to include. Defaults to all sections.",
    )
    include_raw_headers: bool = Field(
        False, description="Whether to include the full raw headers dump in the appendix"
    )
    analyst_notes: Optional[str] = Field(
        None, max_length=4096, description="Optional analyst commentary to include in the report"
    )
    watermark: Optional[str] = Field(
        None, max_length=64, description="Optional watermark text (e.g. 'CONFIDENTIAL')"
    )


# ── Response Schemas ───────────────────────────────────────────────────────────

class ReportMetadata(BaseModel):
    """Metadata about a generated report artifact."""

    report_id: uuid.UUID
    case_id: str
    format: str
    file_path: str
    file_size_bytes: int
    sections_included: List[str]
    generated_at: datetime
    generated_by: Optional[uuid.UUID]
    download_url: str


class ReportListResponse(BaseModel):
    """List of reports generated for a case."""

    case_id: str
    reports: List[ReportMetadata]
    total: int
