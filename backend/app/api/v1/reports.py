"""
TraceVault — Report Routes
PDF forensic report generation and HTML preview for individual cases.
"""
from __future__ import annotations

import logging
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.auth import get_current_user
from app.core.database import get_db
from app.models.case import Case, CaseStatus
from app.services.blockchain_service import BlockchainService
from app.services.report_service import ReportGeneratorService

logger = logging.getLogger(__name__)

router = APIRouter()


# ──────────────────────────────────────────────
# Helper
# ──────────────────────────────────────────────


async def _get_full_case_or_404(case_id: UUID, db: AsyncSession) -> Case:
    """Load a case with every relation needed for report generation."""
    result = await db.execute(
        select(Case)
        .where(Case.id == case_id, Case.status != CaseStatus.DELETED)
        .options(
            selectinload(Case.headers),
            selectinload(Case.relay_hops),
            selectinload(Case.auth_results),
            selectinload(Case.analysis_results),
            selectinload(Case.iocs),
            selectinload(Case.geo_data),
            selectinload(Case.campaign),
            selectinload(Case.blockchain_entries),
            selectinload(Case.submitter),
        )
    )
    case = result.scalar_one_or_none()
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")
    if case.status != CaseStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Report cannot be generated — case status is '{case.status}'. Analysis must be completed first.",
        )
    return case


def _build_report_context(case: Case) -> dict:
    """Assemble a context dictionary from all case relations for the report generator."""
    return {
        "case": case,
        "headers": case.headers,
        "relay_hops": sorted(case.relay_hops or [], key=lambda h: h.hop_index),
        "auth_results": case.auth_results,
        "analysis": case.analysis_results,
        "iocs": case.iocs or [],
        "geo_data": case.geo_data or [],
        "campaign": case.campaign,
        "blockchain_entries": sorted(case.blockchain_entries or [], key=lambda b: b.block_index),
    }


# ──────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────


@router.get(
    "/{case_id}/report",
    summary="Download the forensic report as a PDF",
    response_class=StreamingResponse,
)
async def download_report_pdf(
    case_id: UUID,
    current_user: Annotated[object, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """Generate and stream a full PDF forensic report for the given case.

    The report includes:
    - Case metadata and analyst attribution
    - Email header analysis
    - Relay chain with geo-location
    - SPF / DKIM / DMARC authentication results
    - AI threat scoring and natural-language explanation
    - SHAP feature importance breakdown
    - Full IOC table
    - Geo-location heat-map reference
    - Campaign attribution (if applicable)
    - Blockchain audit trail

    Generating a report is recorded as a ``REPORT_GENERATED`` blockchain event.
    """
    case = await _get_full_case_or_404(case_id, db)
    context = _build_report_context(case)

    report_svc = ReportGeneratorService()
    try:
        pdf_bytes: bytes = await report_svc.generate_pdf(context)
    except Exception as exc:
        logger.exception("PDF generation failed for case %s: %s", case_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate PDF report: {exc}",
        ) from exc

    # ── Blockchain ledger entry ──────────────────────────────────
    blockchain_svc = BlockchainService(db)
    await blockchain_svc.log_event(
        case_id=case.id,
        action="REPORT_GENERATED",
        actor_id=current_user.id,
        actor_username=current_user.username,
        metadata={"format": "PDF", "size_bytes": len(pdf_bytes)},
    )
    await db.commit()

    filename = f"tracevault_case_{case_id}_report.pdf"
    logger.info("PDF report generated for case %s by %s (%d bytes)", case_id, current_user.username, len(pdf_bytes))

    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/{case_id}/report/preview",
    summary="Preview the forensic report as HTML in the browser",
    response_class=HTMLResponse,
)
async def preview_report_html(
    case_id: UUID,
    current_user: Annotated[object, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    """Return an HTML-rendered version of the forensic report for in-browser preview.

    Uses the same data context and template as the PDF generator but outputs
    styled HTML instead of a PDF binary so analysts can quickly review the report
    before downloading the official PDF.
    """
    case = await _get_full_case_or_404(case_id, db)
    context = _build_report_context(case)

    report_svc = ReportGeneratorService()
    try:
        html_content: str = await report_svc.generate_html(context)
    except Exception as exc:
        logger.exception("HTML report generation failed for case %s: %s", case_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate HTML report: {exc}",
        ) from exc

    return HTMLResponse(content=html_content, status_code=200)
