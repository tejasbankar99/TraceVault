"""
TraceVault — Analysis Routes
SSE-driven email threat analysis pipeline endpoints.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Annotated, AsyncGenerator

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.auth import get_current_user
from app.core.database import get_db
from app.models.case import Case, CaseStatus
from app.schemas.analysis import AnalysisResultResponse, HeaderAnalysisResponse, RelayHopResponse
from app.services.analysis_pipeline import AnalysisPipeline

logger = logging.getLogger(__name__)

router = APIRouter()

# In-memory progress queues keyed by case_id str.
# A production deployment would use Redis pub/sub instead.
_progress_queues: dict[str, asyncio.Queue] = {}


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
        )
    )
    case = result.scalar_one_or_none()
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")
    return case


async def _run_analysis_background(case_id: str, raw_email_path: str) -> None:
    """Background coroutine: runs the full analysis pipeline and pushes SSE events."""
    from app.core.database import AsyncSessionLocal  # local import to avoid circular deps

    queue: asyncio.Queue = _progress_queues.setdefault(case_id, asyncio.Queue())

    try:
        # Read the raw email bytes from disk
        import aiofiles
        async with aiofiles.open(raw_email_path, "rb") as f:
            raw_bytes = await f.read()

        # Run pipeline with its own DB session
        async with AsyncSessionLocal() as db:
            pipeline = AnalysisPipeline()
            async for sse_str in pipeline.run(
                db=db,
                case_id=case_id,
                raw_bytes=raw_bytes,
                analyst_id="system",
            ):
                # sse_str is already "data: {...}\n\n" — parse to dict for queue
                try:
                    payload = json.loads(sse_str.removeprefix("data: ").strip())
                    await queue.put({"type": "progress", "payload": payload})
                except Exception:
                    pass

        await queue.put({"type": "complete", "payload": {"case_id": case_id}})
    except Exception as exc:
        logger.exception("Analysis pipeline error for case %s: %s", case_id, exc)
        await queue.put({"type": "error", "payload": {"case_id": case_id, "error": str(exc)}})
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
            # Keepalive comment to prevent proxy/browser from closing the connection
            yield ": keepalive\n\n"
            continue

        if item is None:
            # Sentinel: pipeline finished
            yield f"data: {json.dumps({'type': 'done', 'case_id': case_id})}\n\n"
            break

        yield f"data: {json.dumps(item)}\n\n"

    # Clean up queue
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
    """Start the asynchronous analysis pipeline for the given case.

    The case must be in ``PENDING`` or ``FAILED`` status.  Analysis runs in a
    FastAPI ``BackgroundTasks`` coroutine and streams progress via SSE at the
    URL returned in ``sse_url``.
    """
    case = await _get_case_or_404(case_id, db)

    if case.status not in (CaseStatus.PENDING, CaseStatus.FAILED):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Case is in '{case.status}' status — only PENDING or FAILED cases can be analysed",
        )

    # Pre-create the queue so the SSE endpoint can connect immediately
    _progress_queues[case_id] = asyncio.Queue()

    # Mark as ANALYZING
    case.status = CaseStatus.ANALYZING
    await db.commit()

    # Schedule pipeline in background (FastAPI handles the async execution)
    background_tasks.add_task(_run_analysis_background, case_id, case.raw_email_path)

    sse_url = f"/api/v1/analysis/{case_id}/analysis/stream"
    logger.info("Analysis started for case %s by %s", case_id, current_user.username)
    return {
        "message": "Analysis started",
        "case_id": case_id,
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

    Connect with ``EventSource`` in the browser or ``curl -N`` in the terminal.
    Events are JSON-encoded and carry a ``type`` field (``progress`` | ``complete``
    | ``error`` | ``done`` | ``connected``).
    """
    return StreamingResponse(
        _sse_event_generator(case_id),
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
    """Return the full analysis output for a completed case.

    Includes threat score, detected categories, natural-language explanation, and
    the top SHAP feature contributions that drove the model's decision.
    """
    case = await _get_case_or_404(case_id, db)

    if case.status not in (CaseStatus.COMPLETED, CaseStatus.FAILED):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Analysis results not yet available — case status is '{case.status}'",
        )
    if not case.analysis_results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No analysis results found for this case",
        )

    first_result = case.analysis_results[0] if isinstance(case.analysis_results, list) else case.analysis_results
    return AnalysisResultResponse.model_validate(first_result)


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

    return HeaderAnalysisResponse.model_validate(case.email_headers[0] if isinstance(case.email_headers, list) else case.email_headers)


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
    """Return the ordered list of ``Received:`` header hops extracted from the
    email, enriched with geo-location and threat intelligence lookups."""
    case = await _get_case_or_404(case_id, db)

    if not case.relay_hops:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Relay path not yet available — run analysis first",
        )

    return [RelayHopResponse.model_validate(hop) for hop in sorted(case.relay_hops, key=lambda h: h.hop_index)]
