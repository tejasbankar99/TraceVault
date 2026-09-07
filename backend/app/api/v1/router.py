"""
TraceVault API v1 — Main Router
Aggregates all sub-routers under the /api/v1 prefix.
"""
from fastapi import APIRouter

from app.api.v1 import auth, cases, analysis, iocs, blockchain, reports, graph, campaigns, stats

api_router = APIRouter()

# ── Authentication ────────────────────────────────────────────────────────────
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])

# ── Cases management ──────────────────────────────────────────────────────────
api_router.include_router(cases.router, prefix="/cases", tags=["Cases"])

# ── Analysis (nested under /cases/{case_id}/) ─────────────────────────────────
api_router.include_router(analysis.router, prefix="/cases", tags=["Analysis"])

# ── IOCs (global endpoints at /iocs/…) ───────────────────────────────────────
api_router.include_router(iocs.router, prefix="/iocs", tags=["IOCs"])

# ── IOCs (case-scoped at /cases/{case_id}/iocs) ───────────────────────────────
api_router.include_router(iocs.cases_ioc_router, prefix="/cases", tags=["IOCs"])

# ── Blockchain (global at /blockchain/…, case-scoped paths inside module) ─────
api_router.include_router(blockchain.router, prefix="/blockchain", tags=["Blockchain"])

# ── Reports (nested under /cases/{case_id}/report) ───────────────────────────
api_router.include_router(reports.router, prefix="/cases", tags=["Reports"])

# ── Threat Graph ──────────────────────────────────────────────────────────────
api_router.include_router(graph.router, prefix="/graph", tags=["Threat Graph"])

# ── Campaign Intelligence ─────────────────────────────────────────────────────
api_router.include_router(campaigns.router, prefix="/campaigns", tags=["Campaigns"])

# ── Dashboard Statistics ──────────────────────────────────────────────────────
api_router.include_router(stats.router, prefix="/stats", tags=["Statistics"])
