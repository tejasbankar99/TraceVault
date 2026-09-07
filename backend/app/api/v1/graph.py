"""
TraceVault — Threat Graph Routes
Cytoscape.js-compatible IOC relationship graphs for global and case-scoped views.
"""
from __future__ import annotations

import logging
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.auth import get_current_user
from app.core.database import get_db
from app.models.case import Case, CaseStatus
from app.models.ioc import IOC

logger = logging.getLogger(__name__)

router = APIRouter()


# ──────────────────────────────────────────────
# Graph-building helpers
# ──────────────────────────────────────────────

_SEVERITY_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#22c55e",
    "INFO": "#64748b",
}

_IOC_SHAPE = {
    "IP": "ellipse",
    "DOMAIN": "round-rectangle",
    "URL": "hexagon",
    "EMAIL": "diamond",
    "HASH": "triangle",
    "FILE": "pentagon",
}


def _case_node(case: Case) -> dict:
    return {
        "data": {
            "id": f"case:{case.case_id}",
            "label": str(case.case_id),
            "type": "CASE",
            "severity": case.severity,
            "status": case.status,
            "case_id": str(case.case_id),
        },
        "classes": f"case severity-{(case.severity or 'INFO').lower()}",
    }


def _ioc_node(ioc: IOC) -> dict:
    val = ioc.ioc_value or ""
    return {
        "data": {
            "id": f"ioc:{ioc.id}",
            "label": val if len(val) <= 40 else val[:37] + "…",
            "full_value": val,
            "type": ioc.ioc_type,
            "severity": ioc.severity,
            "ioc_id": str(ioc.id),
            "case_id": str(ioc.case_id),
            "is_lookalike": ioc.is_lookalike,
        },
        "classes": f"ioc ioc-{ioc.ioc_type.lower()} severity-{(ioc.severity or 'INFO').lower()}",
        "style": {
            "background-color": _SEVERITY_COLOR.get(ioc.severity or "INFO", "#64748b"),
            "shape": _IOC_SHAPE.get(ioc.ioc_type, "ellipse"),
        },
    }


def _case_ioc_edge(case: Case, ioc: IOC) -> dict:
    return {
        "data": {
            "id": f"edge:case:{case.case_id}:ioc:{ioc.id}",
            "source": f"case:{case.case_id}",
            "target": f"ioc:{ioc.id}",
            "relation": "CONTAINS",
        },
    }


def _shared_ioc_edges(iocs: list[IOC]) -> list[dict]:
    """Create edges between IOC nodes that share identical values across different cases."""
    value_map: dict[str, list[IOC]] = {}
    for ioc in iocs:
        value_map.setdefault(ioc.ioc_value, []).append(ioc)

    edges: list[dict] = []
    for value, group in value_map.items():
        if len(group) < 2:
            continue
        for i in range(len(group) - 1):
            src = group[i]
            tgt = group[i + 1]
            edges.append({
                "data": {
                    "id": f"edge:shared:{src.id}:{tgt.id}",
                    "source": f"ioc:{src.id}",
                    "target": f"ioc:{tgt.id}",
                    "relation": "SHARED_IOC",
                    "shared_value": value,
                }
            })
    return edges


# ──────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────


@router.get(
    "",
    summary="Global IOC relationship graph (Cytoscape.js format)",
    response_model=dict,
)
async def get_global_graph(
    current_user: Annotated[object, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Return the complete threat graph across **all** cases and IOCs.

    The response is structured for direct consumption by Cytoscape.js:
    ``{nodes: [...], edges: [...]}``.

    - **Case nodes** are shaped as circles, coloured by severity.
    - **IOC nodes** are shaped by IOC type, coloured by severity.
    - **CONTAINS** edges link each case to its extracted IOCs.
    - **SHARED_IOC** edges link IOC nodes with identical values across cases,
      revealing cross-case infrastructure reuse.
    """
    # Load all non-deleted cases with their IOCs
    result = await db.execute(
        select(Case)
        .where(Case.status != CaseStatus.DELETED)
        .options(selectinload(Case.iocs))
    )
    cases: list[Case] = list(result.scalars().all())

    nodes: list[dict] = []
    edges: list[dict] = []
    all_iocs: list[IOC] = []

    for case in cases:
        nodes.append(_case_node(case))
        for ioc in (case.iocs or []):
            nodes.append(_ioc_node(ioc))
            edges.append(_case_ioc_edge(case, ioc))
            all_iocs.append(ioc)

    # Cross-case shared-IOC edges
    edges.extend(_shared_ioc_edges(all_iocs))

    logger.debug("Global graph: %d nodes, %d edges", len(nodes), len(edges))
    return {"nodes": nodes, "edges": edges}


@router.get(
    "/{case_id}",
    summary="Case-centred IOC relationship graph",
    response_model=dict,
)
async def get_case_graph(
    case_id: str,
    current_user: Annotated[object, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Return a graph centred on *case_id*."""
    # Load focal case
    focal_result = await db.execute(
        select(Case)
        .where(Case.case_id == case_id, Case.status != CaseStatus.DELETED)
        .options(selectinload(Case.iocs))
    )
    focal_case: Case | None = focal_result.scalar_one_or_none()
    if focal_case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case {case_id} not found")

    focal_ioc_values = {ioc.ioc_value for ioc in (focal_case.iocs or [])}

    nodes: list[dict] = [_case_node(focal_case)]
    edges: list[dict] = []
    all_iocs: list[IOC] = list(focal_case.iocs or [])

    for ioc in focal_case.iocs or []:
        nodes.append(_ioc_node(ioc))
        edges.append(_case_ioc_edge(focal_case, ioc))

    # Find related cases via shared IOC values
    if focal_ioc_values:
        related_result = await db.execute(
            select(Case)
            .where(Case.status != CaseStatus.DELETED, Case.case_id != case_id)
            .options(selectinload(Case.iocs))
        )
        related_cases: list[Case] = list(related_result.scalars().all())

        for rcase in related_cases:
            rcase_values = {ioc.ioc_value for ioc in (rcase.iocs or [])}
            if not rcase_values.intersection(focal_ioc_values):
                continue  # No shared IOCs — skip

            nodes.append(_case_node(rcase))
            for ioc in (rcase.iocs or []):
                nodes.append(_ioc_node(ioc))
                edges.append(_case_ioc_edge(rcase, ioc))
                all_iocs.append(ioc)

    # Deduplicate nodes by id
    seen_ids: set[str] = set()
    unique_nodes: list[dict] = []
    for node in nodes:
        nid = node["data"]["id"]
        if nid not in seen_ids:
            seen_ids.add(nid)
            unique_nodes.append(node)

    edges.extend(_shared_ioc_edges(all_iocs))

    logger.debug("Case graph for %s: %d nodes, %d edges", case_id, len(unique_nodes), len(edges))
    return {"nodes": unique_nodes, "edges": edges}
