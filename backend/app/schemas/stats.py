"""
app/schemas/stats.py — Dashboard Statistics Pydantic schemas
"""
from __future__ import annotations

from datetime import date
from typing import Dict, List

from pydantic import BaseModel


class ThreatTrendPoint(BaseModel):
    date: date
    count: int


class DashboardStats(BaseModel):
    total_cases: int = 0
    cases_by_severity: Dict[str, int] = {}
    cases_by_status: Dict[str, int] = {}
    total_iocs: int = 0
    iocs_by_type: Dict[str, int] = {}
    total_campaigns: int = 0
    blockchain_blocks: int = 0
    chain_integrity: bool = True
    threat_trend: List[ThreatTrendPoint] = []
