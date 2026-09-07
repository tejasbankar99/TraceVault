"""
app/schemas/campaign.py — Campaign Pydantic schemas
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict


class SharedIndicator(BaseModel):
    type: str
    value: str
    weight: float


class CampaignResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    campaign_id: str
    name: Optional[str] = None
    description: Optional[str] = None
    case_count: int = 0
    shared_indicators: Optional[Any] = []
    first_seen: datetime
    last_seen: datetime
    threat_actor_hypothesis: Optional[str] = None


class CampaignDetailResponse(BaseModel):
    """Extended response including linked cases."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    campaign_id: str
    name: Optional[str] = None
    description: Optional[str] = None
    case_count: int = 0
    shared_indicators: Optional[Any] = []
    first_seen: datetime
    last_seen: datetime
    threat_actor_hypothesis: Optional[str] = None
    # cases listed as dicts to avoid circular import
    cases: List[Dict[str, Any]] = []
