"""
TraceVault — Blockchain / Evidence Ledger Routes
Tamper-evident audit trail verification for all case evidence.
"""
from __future__ import annotations

import hashlib
import logging
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


async def _get_case_or_404(case_id: UUID, db: AsyncSession) -> Case:
    result = await db.execute(
        select(Case).where(Case.id == case_id, Case.status != CaseStatus.DELETED)
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
    case_id: Optional[UUID] = Query(default=None, description="Filter to a specific case"),
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
        page=page,
        per_page=per_page,
        pages=(total + per_page - 1) // per_page,
        entries=[BlockchainEntryResponse.model_validate(e) for e in entries],
    )


@router.get(
    "/cases/{case_id}/blockchain",
    response_model=list[BlockchainEntryResponse],
    summary="List blockchain ledger entries for a specific case",
    tags=["Blockchain"],
)
async def get_case_blockchain(
    case_id: UUID,
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
    case_id: UUID,
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

    blockchain_svc = BlockchainService(db)
    verified_blocks: list[int] = []
    tamper_detected_at: int | None = None
    chain_valid = True

    for i, entry in enumerate(entries):
        block_ok = await blockchain_svc.verify_block(entry)
        if block_ok:
            verified_blocks.append(entry.block_index)
        else:
            chain_valid = False
            if tamper_detected_at is None:
                tamper_detected_at = entry.block_index
            logger.warning(
                "Tamper detected in case %s at block %d", case_id, entry.block_index
            )

    is_valid = evidence_intact and chain_valid

    logger.info(
        "Chain verification for case %s: is_valid=%s evidence_intact=%s chain_valid=%s",
        case_id,
        is_valid,
        evidence_intact,
        chain_valid,
    )

    return BlockchainVerifyResponse(
        case_id=str(case_id),
        is_valid=is_valid,
        evidence_intact=evidence_intact,
        chain_valid=chain_valid,
        tamper_detected_at=tamper_detected_at,
        verified_blocks=verified_blocks,
        total_blocks=len(entries),
        computed_hash=computed_hash,
        stored_hash=stored_hash,
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
    """Re-verify every block in the global ledger.

    Returns a summary with counts of valid and invalid blocks and a list of
    any block indices where tampering was detected.
    """
    result = await db.execute(
        select(BlockchainEntry).order_by(BlockchainEntry.block_index.asc())
    )
    entries: list[BlockchainEntry] = list(result.scalars().all())

    blockchain_svc = BlockchainService(db)
    valid_count = 0
    invalid_count = 0
    tampered_blocks: list[int] = []

    for entry in entries:
        if await blockchain_svc.verify_block(entry):
            valid_count += 1
        else:
            invalid_count += 1
            tampered_blocks.append(entry.block_index)

    is_valid = invalid_count == 0
    logger.info(
        "Global chain verification: total=%d valid=%d invalid=%d",
        len(entries),
        valid_count,
        invalid_count,
    )

    return {
        "is_valid": is_valid,
        "total_blocks": len(entries),
        "valid_blocks": valid_count,
        "invalid_blocks": invalid_count,
        "tampered_block_indices": tampered_blocks,
    }
