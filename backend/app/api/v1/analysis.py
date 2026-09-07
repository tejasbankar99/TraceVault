"""
TraceVault — Analysis Routes
SSE-driven email threat analysis pipeline endpoints.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Annotated, AsyncGenerator
from uuid import UUID

import aiofiles
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.auth import get_current_user
from app.core.database import get_db
from app.database import async_session_maker
from app.models.case import Case, CaseStatus
from app.schemas.analysis import AnalysisResultResponse, HeaderAnalysisResponse, RelayHopResponse
from app.services.analysis_pipeline import AnalysisPipeline

logger = logging.getLogger(__name__)

router = APIRouter()

# In-memory progress queues keyed by case_id str.
_progress_queues: dict[str, asyncio.Queue] = {}


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
        )
    )
    case = result.scalar_one_or_none()
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")
    return case


async def _run_analysis_background(case_id: str, raw_email_path: str, analyst_id: str = "system") -> None:
    """Background coroutine: runs the full analysis pipeline and pushes SSE events."""
    queue: asyncio.Queue = _progress_queues.setdefault(case_id, asyncio.Queue())
    pipeline = AnalysisPipeline()

    try:
        async with aiofiles.open(raw_email_path, "rb") as fh:
            raw_bytes = await fh.read()

        async with async_session_maker() as db:
            async for sse_chunk in pipeline.run(db, case_id, raw_bytes, analyst_id):
                await queue.put(sse_chunk)
    except Exception as exc:
        logger.exception("Analysis pipeline error for case %s: %s", case_id, exc)
        err_event = {
            "step": "error",
            "progress": 100,
            "message": f"Analysis failed: {str(exc)}",
        }
        await queue.put(f"data: {json.dumps(err_event)}\n\n")
    finally:
        await queue.put(None)


async def _sse_event_generator(case_id: str) -> AsyncGenerator[str, None]:
    """Yield SSE-formatted strings from the progress queue for *case_id*."""
    queue: asyncio.Queue = _progress_queues.setdefault(case_id, asyncio.Queue())

    # Send an initial "connected" heartbeat
    yield f"data: {json.dumps({'type': 'connected', 'case_id': case_id})}\n\n"

    while True:
        try:
            item = await asyncio.wait_for(queue.get(), timeout=30.0)
        except asyncio.TimeoutError:
            yield ": keepalive\n\n"
            continue

        if item is None:
            break

        if isinstance(item, str) and item.startswith("data:"):
            yield item
        else:
            yield f"data: {json.dumps(item)}\n\n"

    _progress_queues.pop(case_id, None)


# ──────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────


@router.post(
    "/{case_id}/analyze",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger threat analysis for a case",
)
async def start_analysis(
    case_id: str,
    background_tasks: BackgroundTasks,
    current_user: Annotated[object, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Start the asynchronous analysis pipeline for the given case."""
    case = await _get_case_or_404(case_id, db)

    if case.status not in (CaseStatus.PENDING, CaseStatus.FAILED):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Case is in '{case.status}' status — only PENDING or FAILED cases can be analysed",
        )

    # Pre-create queue
    case_id_str = case.case_id
    _progress_queues[case_id_str] = asyncio.Queue()

    # Mark as ANALYZING
    case.status = CaseStatus.ANALYZING
    await db.commit()

    # Schedule pipeline in background
    background_tasks.add_task(
        _run_analysis_background,
        case_id_str,
        case.raw_email_path,
        str(current_user.id),
    )

    sse_url = f"/api/v1/cases/{case_id_str}/analysis/stream"
    logger.info("Analysis started for case %s by %s", case_id_str, current_user.username)
    return {
        "message": "Analysis started",
        "case_id": case_id_str,
        "sse_url": sse_url,
    }


@router.get(
    "/{case_id}/analysis/stream",
    summary="SSE stream of real-time analysis progress",
    response_class=StreamingResponse,
)
async def analysis_stream(
    case_id: str,
    current_user: Annotated[object, Depends(get_current_user)],
) -> StreamingResponse:
    """Server-Sent Events stream that delivers live progress updates from the
    analysis pipeline.
    """
    case_id_str = str(case_id)

    return StreamingResponse(
        _sse_event_generator(case_id_str),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
            "Access-Control-Allow-Origin": "*",
        },
    )


@router.get(
    "/{case_id}/analysis",
    response_model=AnalysisResultResponse,
    summary="Retrieve completed analysis results",
)
async def get_analysis_results(
    case_id: str,
    current_user: Annotated[object, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> AnalysisResultResponse:
    """Return the full analysis output for a completed case."""
    case = await _get_case_or_404(case_id, db)

    if not case.analysis_results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No analysis results found for this case",
        )

    return AnalysisResultResponse.model_validate(case.analysis_results[0])


@router.get(
    "/{case_id}/headers",
    response_model=HeaderAnalysisResponse,
    summary="Retrieve parsed email header analysis",
)
async def get_headers(
    case_id: str,
    current_user: Annotated[object, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> HeaderAnalysisResponse:
    """Return structured email header data including all relay hops and
    SPF / DKIM / DMARC authentication results."""
    case = await _get_case_or_404(case_id, db)

    if not case.email_headers:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Header data not yet available — run analysis first",
        )

    return HeaderAnalysisResponse.model_validate(case.email_headers[0])


@router.get(
    "/{case_id}/relay-path",
    response_model=list[RelayHopResponse],
    summary="Retrieve ordered email relay chain",
)
async def get_relay_path(
    case_id: str,
    current_user: Annotated[object, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> list[RelayHopResponse]:
    """Return the ordered list of ``Received:`` header hops extracted from the email."""
    case = await _get_case_or_404(case_id, db)

    if not case.relay_hops:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Relay path not yet available — run analysis first",
        )

    return [RelayHopResponse.model_validate(hop) for hop in sorted(case.relay_hops, key=lambda h: h.hop_index)]
