"""
TraceVault – Blockchain Pydantic Schemas
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, ConfigDict


class BlockchainEntryResponse(BaseModel):
    """A single blockchain audit log entry."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    block_index: int
    prev_hash: str
    timestamp: datetime
    case_id: Optional[str]
    action: str
    actor: str
    data: Optional[Dict[str, Any]]
    data_hash: str
    block_hash: str
    polygon_tx_hash: Optional[str]
    is_anchored: bool


class BlockchainVerifyResponse(BaseModel):
    """Result of verifying the integrity of the blockchain audit chain."""

    is_valid: bool
    chain_length: int
    verified_blocks: int
    tamper_detected_at: Optional[int] = Field(
        None, description="Block index where tampering was detected, if any"
    )
    broken_links: List[int] = Field(
        default_factory=list,
        description="List of block indices with broken prev_hash links",
    )
    verification_timestamp: datetime
    summary: str


class BlockchainAnchorRequest(BaseModel):
    """Request to anchor a block hash to the Polygon blockchain."""

    block_index: int
    block_hash: str


class BlockchainAnchorResponse(BaseModel):
    """Result of anchoring a block to the Polygon blockchain."""

    block_index: int
    block_hash: str
    polygon_tx_hash: str
    anchored_at: datetime
    network: Literal["polygon-amoy", "polygon-mainnet"] = "polygon-amoy"


class GenesisBlockResponse(BaseModel):
    """Response after initializing the blockchain with a genesis block."""

    block_index: int = 0
    block_hash: str
    timestamp: datetime
    message: str = "Genesis block created. Audit chain initialized."


class BlockchainListResponse(BaseModel):
    """Paginated list of blockchain audit entries."""
    items: List[BlockchainEntryResponse] = []
    total: int = 0
    chain_valid: bool = True
