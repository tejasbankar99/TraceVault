"""
TraceVault — Campaign Intelligence Routes
Detected phishing / malware campaign listing and detail retrieval.
"""
from __future__ import annotations

import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.auth import get_current_user
from app.core.database import get_db
from app.models.campaign import Campaign
from app.schemas.campaign import CampaignDetailResponse, CampaignResponse

logger = logging.getLogger(__name__)

router = APIRouter()


# ──────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────


@router.get(
    "",
    response_model=list[CampaignResponse],
    summary="List all detected campaigns",
)
async def list_campaigns(
    current_user: Annotated[object, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> list[CampaignResponse]:
    """Return every detected campaign with an associated case count and summary statistics."""
    result = await db.execute(
        select(Campaign)
        .options(selectinload(Campaign.case_campaigns))
        .order_by(Campaign.first_seen.desc())
    )
    campaigns: list[Campaign] = list(result.scalars().all())
    return [CampaignResponse.model_validate(c) for c in campaigns]


@router.get(
    "/{campaign_id}",
    response_model=CampaignDetailResponse,
    summary="Retrieve full campaign details",
)
async def get_campaign(
    campaign_id: str,
    current_user: Annotated[object, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> CampaignDetailResponse:
    """Return detailed information about a specific campaign."""
    result = await db.execute(
        select(Campaign)
        .where(Campaign.campaign_id == campaign_id)
        .options(
            selectinload(Campaign.case_campaigns),
        )
    )
    campaign: Campaign | None = result.scalar_one_or_none()
    if campaign is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Campaign {campaign_id} not found",
        )
    return CampaignDetailResponse.model_validate(campaign)
