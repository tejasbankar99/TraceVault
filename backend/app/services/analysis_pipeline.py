"""
analysis_pipeline.py
====================
Main analysis orchestrator for TraceVault.

Runs all eight analysis stages in sequence and streams real-time progress
to the client via Server-Sent Events (SSE).

SSE event format::

    data: {"step": "...", "progress": 0-100, "message": "...", "data": {...}}

Pipeline stages
---------------
1.  parse        (10%)  — MIME parsing, attachment extraction
2.  header_forensics (20%) — Relay chain analysis, anomaly detection
3.  auth_validation  (30%) — SPF / DKIM / DMARC verification
4.  ioc_extraction   (45%) — URL / IP / domain / hash IOC extraction
5.  ai_analysis      (60%) — Rule engine + ML + Gemini LLM
6.  geo_intelligence (75%) — IP geolocation + infrastructure profiling
7.  correlation      (88%) — Cross-case IOC correlation, campaign detection
8.  finalizing       (95%) — Persist final threat score to case record
9.  blockchain       (98%) — Immutable audit log entry + Polygon anchoring
10. complete         (100%) — Done
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.case import Case, AnalysisResult, CaseStatus
from app.models.email_data import EmailHeader, RelayHop, AuthResult
from app.models.ioc import IOC
from app.models.geo import GeoIntelligence
from app.services.ai_threat_engine import AIThreatEngine, ThreatAnalysisResult
from app.services.blockchain_ledger import BlockchainLedgerService
from app.services.geo_intelligence import GeoIntelligenceService, IPIntelligenceResult
from app.services.threat_correlator import ThreatCorrelatorService


# ---------------------------------------------------------------------------
# Lazy imports of sibling services (avoids circular imports at module load)
# These services are expected to exist in the same services package.
# ---------------------------------------------------------------------------

def _import_email_parser():
    from app.services.email_parser import EmailParserService
    return EmailParserService


def _import_evidence_preservation():
    from app.services.evidence_preservation import EvidencePreservationService
    return EvidencePreservationService


def _import_header_forensics():
    from app.services.header_forensics import HeaderForensicsService
    return HeaderForensicsService


def _import_auth_validator():
    from app.services.auth_validator import AuthValidatorService
    return AuthValidatorService


def _import_ioc_extractor():
    from app.services.ioc_extractor import IOCExtractorService
    return IOCExtractorService


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class AnalysisPipeline:
    """
    Orchestrates all TraceVault analysis services for a single email case.

    Yields SSE-formatted strings that the FastAPI endpoint can forward
    directly to the browser.

    Usage::

        pipeline = AnalysisPipeline()
        async for event in pipeline.run(db, case_id, raw_bytes, analyst_id):
            yield event   # FastAPI SSE response
    """

    def __init__(self) -> None:
        # Instantiate services that have no circular dependencies at load time.
        self.ai_engine = AIThreatEngine()
        self.geo = GeoIntelligenceService()
        self.correlator = ThreatCorrelatorService()
        self.blockchain = BlockchainLedgerService()

        # Lazy-loaded service instances (populated on first run).
        self._parser = None
        self._evidence = None
        self._forensics = None
        self._auth = None
        self._ioc = None

    # ------------------------------------------------------------------
    # Service accessors (lazy init)
    # ------------------------------------------------------------------

    @property
    def parser(self):
        if self._parser is None:
            self._parser = _import_email_parser()()
        return self._parser

    @property
    def evidence(self):
        if self._evidence is None:
            self._evidence = _import_evidence_preservation()()
        return self._evidence

    @property
    def forensics(self):
        if self._forensics is None:
            self._forensics = _import_header_forensics()()
        return self._forensics

    @property
    def auth(self):
        if self._auth is None:
            self._auth = _import_auth_validator()()
        return self._auth

    @property
    def ioc(self):
        if self._ioc is None:
            self._ioc = _import_ioc_extractor()()
        return self._ioc

    # ------------------------------------------------------------------
    # Main pipeline
    # ------------------------------------------------------------------

    async def run(
        self,
        db: AsyncSession,
        case_id: str,
        raw_bytes: bytes,
        analyst_id: str,
    ) -> AsyncGenerator[str, None]:
        """
        Execute the full analysis pipeline, yielding SSE event strings.

        All exceptions are caught; a terminal "error" event is yielded and
        the case is marked FAILED so the UI can surface the error.
        """

        def sse_event(
            step: str,
            progress: int,
            message: str,
            data: Optional[dict] = None,
        ) -> str:
            payload: dict[str, Any] = {
                "step": step,
                "progress": progress,
                "message": message,
            }
            if data:
                payload["data"] = data
            return f"data: {json.dumps(payload)}\n\n"

        try:
            yield sse_event("start", 0, "Analysis pipeline started")
            await self.blockchain.add_event(
                db,
                case_id,
                "ANALYSIS_STARTED",
                analyst_id,
                {"case_id": case_id, "analyst_id": analyst_id},
            )

            # ----------------------------------------------------------------
            # Stage 1 — Parse email (10 %)
            # ----------------------------------------------------------------
            yield sse_event("parsing", 10, "Parsing email structure and MIME parts…")
            parsed = await self.parser.parse_eml_bytes(raw_bytes)

            # ----------------------------------------------------------------
            # Stage 2 — Header forensics (20 %)
            # ----------------------------------------------------------------
            yield sse_event(
                "header_forensics", 20, "Analysing email headers and relay chain…"
            )
            header_result = self.forensics.analyze_headers(parsed)
            await self._save_relay_hops(db, case_id, header_result.relay_chain)
            await self._save_email_headers(db, case_id, parsed, header_result)

            # ----------------------------------------------------------------
            # Stage 3 — Auth validation (30 %)
            # ----------------------------------------------------------------
            yield sse_event(
                "auth_validation", 30, "Validating SPF, DKIM, and DMARC authentication…"
            )
            first_hop = header_result.first_public_hop
            sender_ip: Optional[str] = (
                first_hop.ip_address if first_hop else None
            )
            auth_result = await self.auth.validate_all(parsed, sender_ip, raw_bytes)
            await self._save_auth_result(db, case_id, auth_result)

            # ----------------------------------------------------------------
            # Stage 4 — IOC extraction (45 %)
            # ----------------------------------------------------------------
            yield sse_event(
                "ioc_extraction", 45, "Extracting Indicators of Compromise…"
            )
            iocs = self.ioc.extract_all_iocs(parsed, header_result.relay_chain)
            await self._save_iocs(db, case_id, iocs)

            # ----------------------------------------------------------------
            # Stage 5 — AI threat analysis (60 %)
            # ----------------------------------------------------------------
            yield sse_event(
                "ai_analysis", 60, "Running AI threat detection (Gemini + ML)…"
            )
            threat_result = await self.ai_engine.analyze(
                parsed, header_result, auth_result, iocs
            )
            await self._save_analysis_result(db, case_id, threat_result)

            # ----------------------------------------------------------------
            # Stage 6 — Geo intelligence (75 %)
            # ----------------------------------------------------------------
            yield sse_event(
                "geo_intelligence",
                75,
                "Gathering geolocation and infrastructure intelligence…",
            )
            geo_result: Optional[IPIntelligenceResult] = None
            if sender_ip:
                geo_result = await self.geo.analyze_ip(sender_ip)
                await self._save_geo_result(db, case_id, sender_ip, geo_result)

            # ----------------------------------------------------------------
            # Stage 7 — Threat correlation (88 %)
            # ----------------------------------------------------------------
            yield sse_event(
                "correlation",
                88,
                "Correlating IOCs with threat intelligence database…",
            )
            correlation = await self.correlator.correlate_case(db, case_id, iocs)

            # ----------------------------------------------------------------
            # Stage 8 — Update case record (95 %)
            # ----------------------------------------------------------------
            yield sse_event(
                "finalizing", 95, "Updating case record with final threat assessment…"
            )
            await self._update_case_score(db, case_id, threat_result)

            # ----------------------------------------------------------------
            # Stage 9 — Blockchain logging (98 %)
            # ----------------------------------------------------------------
            yield sse_event(
                "blockchain", 98, "Recording analysis completion in evidence ledger…"
            )
            final_block = await self.blockchain.add_event(
                db,
                case_id,
                "ANALYSIS_COMPLETED",
                "system",
                {
                    "case_id": case_id,
                    "threat_score": threat_result.threat_score,
                    "severity": threat_result.severity,
                    "ioc_count": len(iocs),
                    "campaign_id": correlation.campaign_id,
                    "is_part_of_campaign": correlation.is_part_of_campaign,
                },
            )

            # Optional Polygon Amoy anchoring (non-blocking; failure is silent).
            await self.blockchain.anchor_to_polygon(db, final_block)

            # ----------------------------------------------------------------
            # Stage 10 — Complete (100 %)
            # ----------------------------------------------------------------
            yield sse_event(
                "complete",
                100,
                "Analysis complete",
                {
                    "threat_score": threat_result.threat_score,
                    "severity": threat_result.severity,
                    "ioc_count": len(iocs),
                    "campaign_id": correlation.campaign_id,
                    "is_part_of_campaign": correlation.is_part_of_campaign,
                    "geo_country": (
                        geo_result.country if geo_result else None
                    ),
                },
            )

        except Exception as exc:
            yield sse_event("error", 0, f"Analysis failed: {exc!s}")
            await self._mark_case_failed(db, case_id, str(exc))

    # ------------------------------------------------------------------
    # Persistence helpers — fully implemented
    # ------------------------------------------------------------------

    async def _save_relay_hops(
        self,
        db: AsyncSession,
        case_id: str,
        relay_chain: list,
    ) -> None:
        """Persist each hop in the relay chain as a RelayHop record."""
        for hop in (relay_chain or []):
            record = RelayHop(
                id=uuid.uuid4(),
                case_id=case_id,
                hop_index=getattr(hop, "hop_index", 0),
                by_server=getattr(hop, "by_server", None) or "",
                from_server=getattr(hop, "from_server", None) or "",
                ip_address=getattr(hop, "ip_address", None) or "",
                protocol=getattr(hop, "protocol", None) or "SMTP",
                timestamp=getattr(hop, "timestamp", None),
                is_public_ip=getattr(hop, "is_public_ip", True),
                is_suspicious=getattr(hop, "is_suspicious", False),
                raw_header=getattr(hop, "raw_header", None) or "",
            )
            db.add(record)
        await db.commit()

    async def _save_email_headers(
        self,
        db: AsyncSession,
        case_id: str,
        parsed,
        header_result,
    ) -> None:
        """Persist the parsed email header metadata as an EmailHeader record."""
        anomalies_data = [
            {
                "type": getattr(anomaly, "anomaly_type", ""),
                "description": getattr(anomaly, "description", ""),
                "severity": getattr(anomaly, "severity", "MEDIUM"),
            }
            for anomaly in (getattr(header_result, "anomalies", None) or [])
        ]

        reply_to_val = getattr(parsed, "reply_to", None)
        if isinstance(reply_to_val, list):
            reply_to_str = ", ".join(reply_to_val)
        else:
            reply_to_str = str(reply_to_val) if reply_to_val else None

        record = EmailHeader(
            id=uuid.uuid4(),
            case_id=case_id,
            from_addr=getattr(parsed, "from_addr", None),
            from_name=getattr(parsed, "from_name", None),
            from_domain=getattr(parsed, "from_domain", None),
            reply_to=reply_to_str,
            reply_to_domain=None,
            return_path=getattr(parsed, "return_path", None),
            return_path_domain=None,
            message_id=getattr(parsed, "message_id", None),
            subject=getattr(parsed, "subject", None),
            date_sent=getattr(parsed, "date", None),
            x_mailer=getattr(parsed, "x_mailer", None),
            x_originating_ip=getattr(parsed, "x_originating_ip", None),
            content_type=getattr(parsed, "content_type", None),
            raw_headers=getattr(parsed, "headers", {}) or {},
            rfc_violations=getattr(parsed, "rfc_violations", []) or anomalies_data,
            spoofing_indicators=getattr(header_result, "spoofing_indicators", []) or [],
        )
        db.add(record)
        await db.commit()

    async def _save_auth_result(
        self,
        db: AsyncSession,
        case_id: str,
        auth_result,
    ) -> None:
        """Persist SPF / DKIM / DMARC authentication results as an AuthResult record."""
        spf_obj = getattr(auth_result, "spf", None)
        dkim_obj = getattr(auth_result, "dkim", None)
        dmarc_obj = getattr(auth_result, "dmarc", None)

        record = AuthResult(
            id=uuid.uuid4(),
            case_id=case_id,
            spf_result=getattr(spf_obj, "result", "none") if spf_obj else "none",
            spf_domain=getattr(spf_obj, "domain", None) if spf_obj else None,
            spf_explanation=getattr(spf_obj, "explanation", None) if spf_obj else None,
            dkim_result="pass" if (dkim_obj and getattr(dkim_obj, "is_valid", False)) else (getattr(dkim_obj, "result", "fail") if dkim_obj else "none"),
            dkim_domain=getattr(dkim_obj, "domain", None) if dkim_obj else None,
            dkim_selector=getattr(dkim_obj, "selector", None) if dkim_obj else None,
            dmarc_result=getattr(dmarc_obj, "result", "none") if dmarc_obj else "none",
            dmarc_policy=getattr(dmarc_obj, "policy", None) if dmarc_obj else None,
            dmarc_subdomain_policy=getattr(dmarc_obj, "subdomain_policy", None) if dmarc_obj else None,
            overall_verdict=getattr(auth_result, "overall_verdict", "WARN") if auth_result else "WARN",
            spoofing_risk=getattr(auth_result, "spoofing_risk", "UNKNOWN") if auth_result else "UNKNOWN",
            raw_auth_header=None,
        )
        db.add(record)
        await db.commit()

    async def _save_iocs(
        self,
        db: AsyncSession,
        case_id: str,
        iocs: list,
    ) -> None:
        """Persist all extracted IOC objects as app.models.ioc.IOC records."""
        for ioc in (iocs or []):
            record = IOC(
                id=uuid.uuid4(),
                case_id=case_id,
                ioc_type=getattr(ioc, "ioc_type", "UNKNOWN"),
                ioc_value=str(getattr(ioc, "ioc_value", "")),
                defanged_value=getattr(ioc, "defanged_value", str(getattr(ioc, "ioc_value", ""))),
                severity=getattr(ioc, "severity", "LOW"),
                context=str(getattr(ioc, "context", "") or ""),
                is_lookalike=bool(getattr(ioc, "is_lookalike", False)),
                lookalike_target=getattr(ioc, "lookalike_target", None),
                is_shortened_url=bool(getattr(ioc, "is_shortened_url", False)),
                redirect_target=None,
                metadata_=getattr(ioc, "metadata", {}) or {},
            )
            db.add(record)
        await db.commit()

    async def _save_analysis_result(
        self,
        db: AsyncSession,
        case_id: str,
        threat_result: ThreatAnalysisResult,
    ) -> None:
        """Persist the final ThreatAnalysisResult as an AnalysisResult record."""
        record = AnalysisResult(
            id=uuid.uuid4(),
            case_id=case_id,
            threat_score=threat_result.threat_score,
            severity=threat_result.severity,
            threat_categories=threat_result.threat_categories if isinstance(threat_result.threat_categories, (dict, list)) else [],
            rule_score=threat_result.rule_score,
            ml_score=float(threat_result.ml_score) if threat_result.ml_score is not None else None,
            gemini_score=threat_result.gemini_score,
            ai_explanation=threat_result.ai_explanation,
            urgency_phrases=threat_result.urgency_indicators if isinstance(threat_result.urgency_indicators, (dict, list)) else [],
            impersonation_details=threat_result.impersonation_analysis if isinstance(threat_result.impersonation_analysis, dict) else {},
            social_engineering_patterns=threat_result.social_engineering_patterns if isinstance(threat_result.social_engineering_patterns, (dict, list)) else [],
            shap_features=threat_result.shap_features if isinstance(threat_result.shap_features, dict) else {},
            recommended_actions=threat_result.recommended_actions if isinstance(threat_result.recommended_actions, (dict, list)) else [],
            analyzed_at=datetime.now(timezone.utc),
            analysis_duration_ms=None,
        )
        db.add(record)
        await db.commit()

    async def _save_geo_result(
        self,
        db: AsyncSession,
        case_id: str,
        ip: str,
        geo_result: IPIntelligenceResult,
    ) -> None:
        """Persist IP geolocation and infrastructure intelligence as a GeoIntelligence record."""
        if not geo_result:
            return
        record = GeoIntelligence(
            id=uuid.uuid4(),
            case_id=case_id,
            ip_address=ip,
            country=geo_result.country,
            country_code=geo_result.country_code,
            city=geo_result.city,
            region=geo_result.region,
            latitude=geo_result.latitude,
            longitude=geo_result.longitude,
            isp=geo_result.isp,
            org=geo_result.org,
            asn=geo_result.asn,
            hostname=geo_result.hostname,
            is_vpn=bool(geo_result.is_vpn),
            is_tor=bool(geo_result.is_tor),
            is_hosting=bool(geo_result.is_hosting),
            is_proxy=bool(geo_result.is_proxy),
            ptr_record=geo_result.ptr_record,
            whois_data=geo_result.whois_data if isinstance(geo_result.whois_data, dict) else {},
            dns_records={},
            enrichment_source=geo_result.enrichment_source,
        )
        db.add(record)
        await db.commit()

    async def _update_case_score(
        self,
        db: AsyncSession,
        case_id: str,
        threat_result: ThreatAnalysisResult,
    ) -> None:
        """Update the Case record with the final threat score, severity, and COMPLETED status."""
        stmt = (
            update(Case)
            .where(Case.case_id == case_id)
            .values(
                threat_score=threat_result.threat_score,
                severity=threat_result.severity,
                status=CaseStatus.COMPLETED,
                updated_at=datetime.now(timezone.utc),
            )
        )
        await db.execute(stmt)
        await db.commit()

    async def _mark_case_failed(
        self,
        db: AsyncSession,
        case_id: str,
        error: str,
    ) -> None:
        """Mark the Case record as FAILED and record in blockchain ledger."""
        try:
            stmt = (
                update(Case)
                .where(Case.case_id == case_id)
                .values(
                    status=CaseStatus.FAILED,
                    updated_at=datetime.now(timezone.utc),
                )
            )
            await db.execute(stmt)
            await db.commit()

            await self.blockchain.add_event(
                db,
                case_id,
                "ANALYSIS_FAILED",
                "system",
                {"case_id": case_id, "error": str(error)[:500]},
            )
        except Exception:
            pass
