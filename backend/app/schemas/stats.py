"""
app/schemas/stats.py — Dashboard Statistics Pydantic schemas
"""
from __future__ import annotations

from datetime import date
from typing import Dict, List

from pydantic import BaseModel
from typing import Optional


class ThreatTrendPoint(BaseModel):
    date: date
    count: int


class RecentCaseSummary(BaseModel):
    case_id: str
    subject: Optional[str] = None
    severity: Optional[str] = None
    status: str = "PENDING"
    created_at: Optional[str] = None


class DashboardStats(BaseModel):
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
    avg_threat_score: float = 0.0
