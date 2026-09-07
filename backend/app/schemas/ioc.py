"""
TraceVault – IOC Pydantic Schemas
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, ConfigDict


# ── Response Schemas ───────────────────────────────────────────────────────────

class IOCResponse(BaseModel):
    """Full IOC enrichment record."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: str
    ioc_type: Literal["IP", "DOMAIN", "URL", "EMAIL", "FILE_HASH", "ATTACHMENT"]
    ioc_value: str
    defanged_value: Optional[str]
    severity: Optional[Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]]
    context: Optional[str]
    is_lookalike: bool
    lookalike_target: Optional[str]
    is_shortened_url: bool
    redirect_target: Optional[str]
    metadata: Optional[Any] = Field(None, validation_alias="metadata_")
    created_at: datetime

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


# ── Search / Filter Schemas ────────────────────────────────────────────────────

class IOCSearchParams(BaseModel):
    """Query parameters for IOC search and filtering."""

    ioc_type: Optional[str] = None
    severity: Optional[str] = None
    is_lookalike: Optional[bool] = None
    is_shortened_url: Optional[bool] = None
    search: Optional[str] = Field(None, description="Full-text search in ioc_value")
    page: int = Field(1, ge=1)
    page_size: int = Field(20, ge=1, le=100)


# ── Export Schemas ─────────────────────────────────────────────────────────────

class IOCExportRecord(BaseModel):
    """A single IOC record formatted for STIX/CSV export."""

    ioc_type: str
    ioc_value: str
    defanged_value: Optional[str]
    severity: Optional[str]
    case_id: str
    created_at: datetime


class IOCExportResponse(BaseModel):
    """Batch IOC export response."""

    format: Literal["csv", "json", "stix"]
    total_records: int
    records: List[IOCExportRecord]
    exported_at: datetime


class IOCStatsSummary(BaseModel):
    """Aggregated IOC statistics for dashboard display."""

    total: int
    by_type: Dict[str, int]
    by_severity: Dict[str, int]
    lookalike_count: int
    shortened_url_count: int


class IOCListResponse(BaseModel):
    items: list[IOCResponse] = []
    total: int = 0
    page: int = 1
    page_size: int = 20
    total_pages: int = 1
