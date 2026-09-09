"""
TraceVault — Cases Routes
Handles email case ingestion (upload), listing, detail retrieval, and soft-deletion.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Annotated, Optional

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
    result = await db.execute(
        select(Case)
        .where(Case.case_id == case_id, Case.status != CaseStatus.DELETED)
        .options(
            selectinload(Case.email_headers),
            selectinload(Case.relay_hops),
            selectinload(Case.auth_results),
            selectinload(Case.analysis_results),
            selectinload(Case.iocs),
            selectinload(Case.geo_intelligence),
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
    evidence_record = await evidence_svc.preserve_email(
        raw_bytes=raw_bytes,
        created_by_id=str(current_user.id),
    )

    # ── Create Case record ───────────────────────────────────────
    case = Case(
        case_id=evidence_record.case_id,
        created_by=current_user.id,
        raw_email_path=evidence_record.file_path,
        evidence_hash=evidence_record.sha256,
        evidence_hash3=evidence_record.sha3_256,
        file_size_bytes=evidence_record.file_size_bytes,
        status=CaseStatus.PENDING,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(case)
    await db.flush()  # populate case.id before blockchain log

    # ── Blockchain ledger entry ──────────────────────────────────
    blockchain_svc = BlockchainService()
    await blockchain_svc.add_event(
        db=db,
        case_id=case.case_id,
        action="EVIDENCE_SUBMITTED",
        actor=current_user.username,
        data={
            "original_filename": original_filename,
            "sha256": evidence_record.sha256,
            "sha3_256": evidence_record.sha3_256,
            "size_bytes": evidence_record.file_size_bytes,
        },
    )

    await db.commit()
    await db.refresh(case)
    logger.info("Case created: %s by user %s", case.case_id, current_user.username)
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
            Case.case_id.ilike(search_term)
        )

    # ── Count total ──────────────────────────────────────────────
    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total: int = count_result.scalar_one()

    # ── Paginate ─────────────────────────────────────────────────
    offset = (page - 1) * per_page
    result = await db.execute(
        query.options(selectinload(Case.email_headers))
        .order_by(Case.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    cases = result.scalars().all()

    case_responses = []
    for c in cases:
        resp = CaseResponse.model_validate(c)
        if c.email_headers:
            resp.subject = c.email_headers[0].subject
        case_responses.append(resp)

    return CaseListResponse(
        total=total,
        page=page,
        per_page=per_page,
        total_pages=(total + per_page - 1) // per_page,
        cases=case_responses,
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
    blockchain_svc = BlockchainService()
    await blockchain_svc.add_event(
        db=db,
        case_id=case.case_id,
        action="ANALYST_ACCESSED",
        actor=current_user.username,
        data={"case_id": str(case.case_id)},
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
    """Soft-delete a case by setting its status to ``DELETED``."""
    result = await db.execute(select(Case).where(Case.case_id == case_id))
    case: Case | None = result.scalar_one_or_none()
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")
    if case.status == CaseStatus.DELETED:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Case is already deleted")

    case.status = CaseStatus.DELETED
    case.updated_at = datetime.now(timezone.utc)

    # ── Blockchain ledger entry ──────────────────────────────────
    blockchain_svc = BlockchainService()
    await blockchain_svc.add_event(
        db=db,
        case_id=case.case_id,
        action="CASE_DELETED",
        actor=current_user.username,
        data={"case_id": case.case_id, "deleted_by": current_user.username},
    )

    await db.commit()
    logger.warning("Case %s soft-deleted by admin %s", case_id, current_user.username)
    return {"message": "Case deleted", "case_id": str(case_id)}
