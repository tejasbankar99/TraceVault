"""
TraceVault — Blockchain / Evidence Ledger Routes
Tamper-evident audit trail verification for all case evidence.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user
from app.core.database import get_db
from app.models.blockchain import BlockchainEntry
from app.models.case import Case, CaseStatus
from app.schemas.blockchain import (
    BlockchainEntryResponse,
    BlockchainListResponse,
    BlockchainVerifyResponse,
)
from app.services.blockchain_service import BlockchainService

logger = logging.getLogger(__name__)

router = APIRouter()


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────


async def _get_case_or_404(case_id: str, db: AsyncSession) -> Case:
    result = await db.execute(
        select(Case).where(Case.case_id == case_id, Case.status != CaseStatus.DELETED)
    )
    case = result.scalar_one_or_none()
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")
    return case


def _compute_file_sha256(path: str) -> str | None:
    """Read a file from *path* and return its SHA-256 hex digest, or None on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as exc:
        logger.warning("Could not read evidence file %s: %s", path, exc)
        return None


# ──────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────


@router.get(
    "",
    response_model=BlockchainListResponse,
    summary="List all blockchain ledger entries (paginated)",
)
async def list_blockchain_entries(
    current_user: Annotated[object, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    case_id: Optional[str] = Query(default=None, description="Filter to a specific case"),
    action: Optional[str] = Query(
        default=None,
        description="Filter by action type (EVIDENCE_SUBMITTED|ANALYST_ACCESSED|REPORT_GENERATED|CASE_DELETED)",
    ),
) -> BlockchainListResponse:
    """Return the full blockchain ledger, newest-first, with optional filtering."""
    from sqlalchemy import func

    query = select(BlockchainEntry)
    if case_id:
        query = query.where(BlockchainEntry.case_id == case_id)
    if action:
        query = query.where(BlockchainEntry.action == action.upper())

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total: int = count_result.scalar_one()

    offset = (page - 1) * per_page
    result = await db.execute(
        query.order_by(BlockchainEntry.block_index.desc()).offset(offset).limit(per_page)
    )
    entries = result.scalars().all()

    return BlockchainListResponse(
        total=total,
        items=[BlockchainEntryResponse.model_validate(e) for e in entries],
    )


@router.get(
    "/cases/{case_id}/blockchain",
    response_model=list[BlockchainEntryResponse],
    summary="List blockchain ledger entries for a specific case",
    tags=["Blockchain"],
)
async def get_case_blockchain(
    case_id: str,
    current_user: Annotated[object, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> list[BlockchainEntryResponse]:
    """Return every blockchain ledger entry associated with the given case,
    ordered by block index ascending."""
    await _get_case_or_404(case_id, db)

    result = await db.execute(
        select(BlockchainEntry)
        .where(BlockchainEntry.case_id == case_id)
        .order_by(BlockchainEntry.block_index.asc())
    )
    entries = result.scalars().all()
    return [BlockchainEntryResponse.model_validate(e) for e in entries]


@router.post(
    "/cases/{case_id}/blockchain/verify",
    response_model=BlockchainVerifyResponse,
    summary="Verify integrity of a case's evidence chain",
    tags=["Blockchain"],
)
async def verify_case_blockchain(
    case_id: str,
    current_user: Annotated[object, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> BlockchainVerifyResponse:
    """Perform a full integrity check on the case's evidence chain.

    The verification process:
    1. Recomputes the SHA-256 of the stored evidence file and compares it to the
       hash recorded at ingestion time.
    2. Walks every blockchain block for the case, re-hashing each one and comparing
       it to the ``previous_hash`` pointer of the next block.

    Returns ``is_valid=True`` only when **both** checks pass.
    """
    case = await _get_case_or_404(case_id, db)

    # ── Evidence file integrity ──────────────────────────────────
    computed_hash = _compute_file_sha256(case.raw_email_path)
    stored_hash: str = case.evidence_hash
    evidence_intact = computed_hash is not None and computed_hash == stored_hash

    # ── Blockchain block chain-link verification ─────────────────
    result = await db.execute(
        select(BlockchainEntry)
        .where(BlockchainEntry.case_id == case_id)
        .order_by(BlockchainEntry.block_index.asc())
    )
    entries: list[BlockchainEntry] = list(result.scalars().all())

    blockchain_svc = BlockchainService()
    verify_res = await blockchain_svc.verify_chain(db, case_id=case_id)

    is_valid = evidence_intact and verify_res.is_valid
    summary = "Evidence and blockchain integrity verified" if is_valid else (verify_res.error or "Tampering or integrity mismatch detected")

    return BlockchainVerifyResponse(
        is_valid=is_valid,
        chain_length=verify_res.total_blocks,
        verified_blocks=verify_res.verified_blocks,
        tamper_detected_at=verify_res.tamper_detected_at,
        broken_links=[],
        verification_timestamp=datetime.now(timezone.utc),
        summary=summary,
    )


@router.post(
    "/verify-all",
    summary="Verify the entire global blockchain ledger",
    response_model=dict,
)
async def verify_all_chains(
    current_user: Annotated[object, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Re-verify every block in the global ledger."""
    blockchain_svc = BlockchainService()
    verify_res = await blockchain_svc.verify_chain(db)
    return {
        "is_valid": verify_res.is_valid,
        "total_blocks": verify_res.total_blocks,
        "verified_blocks": verify_res.verified_blocks,
        "tamper_detected_at": verify_res.tamper_detected_at,
        "summary": "Ledger verified" if verify_res.is_valid else verify_res.error,
    }
