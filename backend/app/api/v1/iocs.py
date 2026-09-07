"""
TraceVault — IOC Routes
Indicators of Compromise listing, search, per-case retrieval, and CSV export.
"""
from __future__ import annotations

import csv
import io
import logging
from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user
from app.core.database import get_db
from app.models.ioc import IOC
from app.schemas.ioc import IOCListResponse, IOCResponse

logger = logging.getLogger(__name__)

router = APIRouter()

# ──────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────


@router.get(
    "",
    response_model=IOCListResponse,
    summary="List all IOCs with filtering and pagination",
)
async def list_iocs(
    current_user: Annotated[object, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    ioc_type: Optional[str] = Query(default=None, description="Filter by type: IP|DOMAIN|URL|EMAIL|HASH|FILE"),
    severity: Optional[str] = Query(default=None, description="Filter by severity: CRITICAL|HIGH|MEDIUM|LOW|INFO"),
    case_id: Optional[UUID] = Query(default=None, description="Filter to a specific case"),
    is_lookalike: Optional[bool] = Query(default=None, description="Filter lookalike-domain IOCs"),
    q: Optional[str] = Query(default=None, description="Search within IOC value"),
) -> IOCListResponse:
    """Return a paginated list of IOCs across all cases.

    Supports filtering by type, severity, parent case, and lookalike-domain flag.
    Free-text search (``q``) performs a case-insensitive substring match on the
    IOC value field.
    """
    from sqlalchemy import func

    query = select(IOC)

    if ioc_type:
        query = query.where(IOC.ioc_type == ioc_type.upper())
    if severity:
        query = query.where(IOC.severity == severity.upper())
    if case_id:
        query = query.where(IOC.case_id == case_id)
    if is_lookalike is not None:
        query = query.where(IOC.is_lookalike == is_lookalike)
    if q:
        query = query.where(IOC.value.ilike(f"%{q}%"))

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total: int = count_result.scalar_one()

    offset = (page - 1) * per_page
    result = await db.execute(query.order_by(IOC.severity.desc(), IOC.created_at.desc()).offset(offset).limit(per_page))
    iocs = result.scalars().all()

    return IOCListResponse(
        total=total,
        page=page,
        per_page=per_page,
        pages=(total + per_page - 1) // per_page,
        iocs=[IOCResponse.model_validate(ioc) for ioc in iocs],
    )


@router.get(
    "/search",
    response_model=list[IOCResponse],
    summary="Search IOCs by value substring across all cases",
)
async def search_iocs(
    current_user: Annotated[object, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    q: str = Query(..., min_length=2, description="Search string to match against IOC value"),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[IOCResponse]:
    """Full-text substring search across the ``value`` field of all IOC records.

    Returns up to *limit* matches sorted by severity.
    """
    result = await db.execute(
        select(IOC)
        .where(IOC.value.ilike(f"%{q}%"))
        .order_by(IOC.severity.desc())
        .limit(limit)
    )
    iocs = result.scalars().all()
    return [IOCResponse.model_validate(ioc) for ioc in iocs]


@router.get(
    "/export",
    summary="Export IOCs to CSV",
    response_class=StreamingResponse,
)
async def export_iocs_csv(
    current_user: Annotated[object, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    case_id: Optional[UUID] = Query(default=None, description="Limit export to a specific case"),
    ioc_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
) -> StreamingResponse:
    """Stream all matching IOCs as a UTF-8 CSV file download.

    Optional filters: ``case_id``, ``ioc_type``, ``severity``.
    """
    query = select(IOC)
    if case_id:
        query = query.where(IOC.case_id == case_id)
    if ioc_type:
        query = query.where(IOC.ioc_type == ioc_type.upper())
    if severity:
        query = query.where(IOC.severity == severity.upper())

    result = await db.execute(query.order_by(IOC.severity.desc(), IOC.created_at.desc()))
    iocs = result.scalars().all()

    def _csv_generator():
        buf = io.StringIO()
        writer = csv.writer(buf)
        # Header row
        writer.writerow([
            "id", "case_id", "ioc_type", "value", "severity",
            "is_lookalike", "threat_intel_hits", "description",
            "first_seen", "created_at",
        ])
        yield buf.getvalue()

        for ioc in iocs:
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow([
                str(ioc.id),
                str(ioc.case_id),
                ioc.ioc_type,
                ioc.value,
                ioc.severity,
                ioc.is_lookalike,
                ioc.threat_intel_hits,
                ioc.description or "",
                ioc.first_seen.isoformat() if ioc.first_seen else "",
                ioc.created_at.isoformat() if ioc.created_at else "",
            ])
            yield buf.getvalue()

    filename = f"tracevault_iocs_{case_id or 'all'}.csv"
    return StreamingResponse(
        _csv_generator(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Case-scoped IOC endpoint (nested under /cases in router) ─────────────────
# This router is mounted at /iocs, so the case-scoped route lives in cases_ioc_router
# which is imported and re-used in the main router via the analysis prefix.

cases_ioc_router = APIRouter()


@cases_ioc_router.get(
    "/{case_id}/iocs",
    response_model=list[IOCResponse],
    summary="List all IOCs for a specific case",
    tags=["IOCs"],
)
async def get_case_iocs(
    case_id: UUID,
    current_user: Annotated[object, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    ioc_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
) -> list[IOCResponse]:
    """Return every IOC extracted from the given case, optionally filtered by
    type or severity."""
    query = select(IOC).where(IOC.case_id == case_id)
    if ioc_type:
        query = query.where(IOC.ioc_type == ioc_type.upper())
    if severity:
        query = query.where(IOC.severity == severity.upper())

    result = await db.execute(query.order_by(IOC.severity.desc()))
    iocs = result.scalars().all()

    if not iocs:
        # Verify case exists to give a meaningful 404
        from app.models.case import Case, CaseStatus
        case_result = await db.execute(
            select(Case).where(Case.id == case_id, Case.status != CaseStatus.DELETED)
        )
        if case_result.scalar_one_or_none() is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")

    return [IOCResponse.model_validate(ioc) for ioc in iocs]
