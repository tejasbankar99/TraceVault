"""
TraceVault — Cases Routes
Handles email case ingestion (upload), listing, detail retrieval, and soft-deletion.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Annotated, Optional
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.auth import get_current_user, require_admin
from app.core.config import settings
from app.core.database import get_db
from app.models.case import Case, CaseStatus
from app.schemas.case import (
    CaseDetailResponse,
    CaseListResponse,
    CasePagination,
    CaseResponse,
)
from app.services.blockchain_service import BlockchainService
from app.services.evidence_service import EvidencePreservationService

logger = logging.getLogger(__name__)

router = APIRouter()

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

MAX_EMAIL_BYTES = settings.max_email_size_mb * 1024 * 1024


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


async def _get_case_or_404(case_id: str, db: AsyncSession) -> Case:
    try:
        val = UUID(case_id)
        cond = or_(Case.id == val, Case.case_id == str(case_id))
    except (ValueError, AttributeError):
        cond = (Case.case_id == str(case_id))

    result = await db.execute(
        select(Case)
        .where(cond, Case.status != CaseStatus.DELETED)
        .options(
            selectinload(Case.email_headers),
            selectinload(Case.relay_hops),
            selectinload(Case.auth_results),
            selectinload(Case.analysis_results),
            selectinload(Case.iocs),
            selectinload(Case.geo_intelligence),
            selectinload(Case.case_campaigns),
            selectinload(Case.blockchain_ledger),
        )
    )
    case = result.scalar_one_or_none()
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")
    return case


# ──────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────


@router.post(
    "/upload",
    response_model=CaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a raw .eml file or paste email text to create a new case",
)
async def upload_case(
    current_user: Annotated[object, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    file: Optional[UploadFile] = File(default=None, description=".eml email file"),
    raw_email_text: Optional[str] = Form(default=None, description="Raw RFC-2822 email text"),
    description: Optional[str] = Form(default=None, description="Optional analyst notes"),
) -> CaseResponse:
    """Ingest a new email for threat analysis.

    Accepts either:
    - A ``.eml`` file upload, **or**
    - A ``raw_email_text`` form field containing the raw RFC-2822 message.

    On success the raw evidence is immediately SHA-256 hashed, preserved via
    :class:`EvidencePreservationService`, a ``Case`` record is written to the
    database, and a ``EVIDENCE_SUBMITTED`` blockchain ledger entry is logged.
    """
    # ── Input validation ─────────────────────────────────────────
    if file is None and not raw_email_text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide either a .eml file upload or raw_email_text form field",
        )

    if file is not None:
        # Validate extension
        filename = file.filename or ""
        if not filename.lower().endswith(".eml"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Only .eml files are accepted",
            )
        raw_bytes = await file.read()
        if len(raw_bytes) > MAX_EMAIL_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File exceeds maximum allowed size of {settings.max_email_size_mb} MB",
            )
        original_filename = filename
    else:
        raw_bytes = raw_email_text.encode("utf-8")  # type: ignore[union-attr]
        if len(raw_bytes) > MAX_EMAIL_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Email text exceeds maximum allowed size of {settings.max_email_size_mb} MB",
            )
        original_filename = "raw_paste.eml"

    # ── Compute SHA-256 ──────────────────────────────────────────
    evidence_hash = _sha256(raw_bytes)
    logger.info("Evidence SHA-256: %s  file=%s  size=%d bytes", evidence_hash, original_filename, len(raw_bytes))

    # ── Preserve evidence ────────────────────────────────────────
    evidence_svc = EvidencePreservationService()
    record = await evidence_svc.preserve_email(
        raw_bytes=raw_bytes,
        created_by_id=str(current_user.id),
    )

    # ── Create Case record ───────────────────────────────────────
    case = Case(
        case_id=record.case_id,
        status="PENDING",
        evidence_hash=record.sha256,
        evidence_hash3=record.sha3_256,
        raw_email_path=record.file_path,
        file_size_bytes=record.file_size_bytes,
        created_by=current_user.id,
    )
    db.add(case)
    await db.flush()  # populate case.id before blockchain log

    # ── Blockchain ledger entry ──────────────────────────────────
    blockchain_svc = BlockchainService(db)
    await blockchain_svc.log_event(
        case_id=case.case_id,
        action="EVIDENCE_SUBMITTED",
        actor_id=current_user.id,
        actor_username=current_user.username,
        metadata={
            "filename": original_filename,
            "sha256": record.sha256,
            "sha3_256": record.sha3_256,
            "size_bytes": len(raw_bytes),
        },
    )

    await db.commit()
    await db.refresh(case)
    logger.info("Case created: %s (%s) by user %s", case.case_id, case.id, current_user.username)
    return CaseResponse.model_validate(case)


@router.get(
    "",
    response_model=CaseListResponse,
    summary="List cases with filtering, search and pagination",
)
async def list_cases(
    current_user: Annotated[object, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    page: int = Query(default=1, ge=1, description="Page number"),
    per_page: int = Query(default=20, ge=1, le=100, description="Results per page"),
    severity: Optional[str] = Query(default=None, description="Filter by severity (CRITICAL|HIGH|MEDIUM|LOW|INFO)"),
    status_filter: Optional[str] = Query(default=None, alias="status", description="Filter by case status"),
    date_from: Optional[datetime] = Query(default=None, description="Filter cases created after this ISO datetime"),
    date_to: Optional[datetime] = Query(default=None, description="Filter cases created before this ISO datetime"),
    q: Optional[str] = Query(default=None, description="Free-text search on case_id or email subject"),
) -> CaseListResponse:
    """Return a paginated, filterable list of cases.

    Excludes soft-deleted cases.  Results are ordered newest-first.
    """
    query = select(Case).where(Case.status != CaseStatus.DELETED)

    # ── Filters ──────────────────────────────────────────────────
    if severity:
        query = query.where(Case.severity == severity.upper())
    if status_filter:
        query = query.where(Case.status == status_filter.upper())
    if date_from:
        query = query.where(Case.created_at >= date_from)
    if date_to:
        query = query.where(Case.created_at <= date_to)
    if q:
        search_term = f"%{q}%"
        query = query.where(
            or_(
                Case.id.cast(str).ilike(search_term),
                Case.email_subject.ilike(search_term),
            )
        )

    # ── Count total ──────────────────────────────────────────────
    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total: int = count_result.scalar_one()

    # ── Paginate ─────────────────────────────────────────────────
    offset = (page - 1) * per_page
    result = await db.execute(
        query.order_by(Case.created_at.desc()).offset(offset).limit(per_page)
    )
    cases = result.scalars().all()

    total_pages = (total + per_page - 1) // per_page
    return CaseListResponse(
        items=[CaseResponse.model_validate(c) for c in cases],
        pagination=CasePagination(
            total=total,
            page=page,
            page_size=per_page,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_prev=page > 1,
        ),
    )


@router.get(
    "/{case_id}",
    response_model=CaseDetailResponse,
    summary="Retrieve full case details",
)
async def get_case(
    case_id: str,
    current_user: Annotated[object, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> CaseDetailResponse:
    """Return the complete case record including headers, relay hops, authentication
    results, analysis output, IOCs, geo-location data, campaign linkage, and the
    full blockchain audit trail.

    Accessing a case is itself logged as an ``ANALYST_ACCESSED`` blockchain event.
    """
    case = await _get_case_or_404(case_id, db)

    # ── Log access event ─────────────────────────────────────────
    blockchain_svc = BlockchainService(db)
    await blockchain_svc.log_event(
        case_id=case.case_id,
        action="ANALYST_ACCESSED",
        actor_id=current_user.id,
        actor_username=current_user.username,
        metadata={"case_id": str(case.case_id)},
    )
    await db.commit()

    return CaseDetailResponse.model_validate(case)


@router.delete(
    "/{case_id}",
    summary="Soft-delete a case (admin only)",
    status_code=status.HTTP_200_OK,
)
async def delete_case(
    case_id: str,
    current_user: Annotated[object, Depends(require_admin)],
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Soft-delete a case by setting its status to ``DELETED``.

    The raw evidence file is **not** removed from storage so that the chain-of-custody
    remains intact.  This action is logged to the blockchain ledger.

    Requires **admin** role.
    """
    case = await _get_case_or_404(case_id, db)
    if case.status == CaseStatus.DELETED:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Case is already deleted")

    case.status = CaseStatus.DELETED
    case.updated_at = datetime.now(timezone.utc)

    # ── Blockchain ledger entry ──────────────────────────────────
    blockchain_svc = BlockchainService(db)
    await blockchain_svc.log_event(
        case_id=case.case_id,
        action="CASE_DELETED",
        actor_id=current_user.id,
        actor_username=current_user.username,
        metadata={"case_id": str(case.case_id), "deleted_by": current_user.username},
    )

    await db.commit()
    logger.warning("Case %s soft-deleted by admin %s", case_id, current_user.username)
    return {"message": "Case deleted", "case_id": str(case_id)}
