"""
app/schemas/stats.py — Dashboard Statistics Pydantic schemas
"""
from __future__ import annotations

from typing import Dict, List, Optional
from pydantic import BaseModel, ConfigDict


class ThreatTrendPoint(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    date: str
    count: int


class RecentCaseSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    case_id: str
    subject: Optional[str] = None
    severity: Optional[str] = None
    status: str
    created_at: Optional[str] = None


class DashboardStats(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    total_cases: int = 0
    cases_by_severity: Dict[str, int] = {}
    cases_by_status: Dict[str, int] = {}
    total_iocs: int = 0
    iocs_by_type: Dict[str, int] = {}
    total_campaigns: int = 0
    blockchain_blocks: int = 0
    chain_integrity: bool = True
    recent_cases: List[RecentCaseSummary] = []
    threat_trend: List[ThreatTrendPoint] = []
