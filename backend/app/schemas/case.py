"""
TraceVault – Case Pydantic Schemas
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, ConfigDict

from app.schemas.analysis import AnalysisResultResponse, AuthResultResponse, HeaderAnalysisResponse, RelayHopResponse
from app.schemas.ioc import IOCResponse


# ── Internal / Create ──────────────────────────────────────────────────────────

class CaseCreate(BaseModel):
    """Internal schema used when persisting a new case after file upload."""

    model_config = ConfigDict(str_strip_whitespace=True)

    case_id: str = Field(..., pattern=r"^TV-\d{8}-[A-F0-9]{8}$")
    evidence_hash: str = Field(..., min_length=64, max_length=64)
    evidence_hash3: str = Field(..., min_length=64, max_length=64)
    raw_email_path: str
    file_size_bytes: Optional[int] = None
    created_by: Optional[uuid.UUID] = None


# ── Response Schemas ───────────────────────────────────────────────────────────

class CaseResponse(BaseModel):
    """Summary case representation for list views."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: str
    status: Literal["PENDING", "ANALYZING", "COMPLETED", "FAILED"]
    evidence_hash: str
    evidence_hash3: str
    file_size_bytes: Optional[int]
    threat_score: Optional[int]
    severity: Optional[Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "BENIGN"]]
    created_at: datetime
    updated_at: datetime
    created_by: Optional[uuid.UUID]


class CasePagination(BaseModel):
    """Pagination metadata."""

    total: int
    page: int
    page_size: int
    total_pages: int
    has_next: bool
    has_prev: bool


class CaseListResponse(BaseModel):
    """Paginated list of cases."""

    items: List[CaseResponse]
    pagination: CasePagination


class CaseDetailResponse(BaseModel):
    """Full case detail including all sub-object relationships."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: str
    status: str
    evidence_hash: str
    evidence_hash3: str
    raw_email_path: str
    file_size_bytes: Optional[int]
    threat_score: Optional[int]
    severity: Optional[str]
    created_at: datetime
    updated_at: datetime
    created_by: Optional[uuid.UUID]

    # Related objects
    email_headers: List[HeaderAnalysisResponse] = []
    relay_hops: List[RelayHopResponse] = []
    auth_results: List[AuthResultResponse] = []
    analysis_results: List[AnalysisResultResponse] = []
    iocs: List[IOCResponse] = []


class CaseStatusUpdate(BaseModel):
    """Request body for manually updating a case status."""

    status: Literal["PENDING", "ANALYZING", "COMPLETED", "FAILED"]
    reason: Optional[str] = None
