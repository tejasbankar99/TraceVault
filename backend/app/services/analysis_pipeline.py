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

from app.models.analysis import (
    AnalysisResult,
    AuthResult,
    EmailHeader,
    GeoIntelligence,
    RelayHop,
)
from app.models.case import Case
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
        """
        Persist each hop in the relay chain as a RelayHop record.

        Expects each hop to expose at minimum:
          hop_index, ip_address, hostname, timestamp, protocol,
          delay_seconds, is_public, raw_header
        """
        for hop in (relay_chain or []):
            record = RelayHop(
                id=uuid.uuid4(),
                case_id=case_id,
                hop_index=getattr(hop, "hop_index", 0),
                ip_address=getattr(hop, "ip_address", None),
                hostname=getattr(hop, "hostname", None),
                timestamp=getattr(hop, "timestamp", None),
                protocol=getattr(hop, "protocol", None),
                delay_seconds=getattr(hop, "delay_seconds", None),
                is_public=getattr(hop, "is_public", True),
                raw_header=getattr(hop, "raw_header", None),
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
        """
        Persist the parsed email header metadata and detected anomalies
        as a single EmailHeader record.
        """
        anomalies_data = []
        for anomaly in (getattr(header_result, "anomalies", None) or []):
            anomalies_data.append(
                {
                    "type": getattr(anomaly, "anomaly_type", ""),
                    "description": getattr(anomaly, "description", ""),
                    "severity": getattr(anomaly, "severity", "MEDIUM"),
                }
            )

        record = EmailHeader(
            id=uuid.uuid4(),
            case_id=case_id,
            message_id=getattr(parsed, "message_id", None),
            subject=getattr(parsed, "subject", None),
            from_addr=getattr(parsed, "from_addr", None),
            to_addr=getattr(parsed, "to_addr", None),
            reply_to=getattr(parsed, "reply_to", None),
            return_path=getattr(parsed, "return_path", None),
            date_header=getattr(parsed, "date", None),
            x_mailer=getattr(parsed, "x_mailer", None),
            x_originating_ip=getattr(parsed, "x_originating_ip", None),
            anomalies=anomalies_data,
            all_headers=getattr(parsed, "all_headers", {}),
        )
        db.add(record)
        await db.commit()

    async def _save_auth_result(
        self,
        db: AsyncSession,
        case_id: str,
        auth_result,
    ) -> None:
        """
        Persist SPF / DKIM / DMARC / ARC authentication results as an
        AuthResult record. Gracefully handles a None auth_result.
        """
        if auth_result is None:
            record = AuthResult(
                id=uuid.uuid4(),
                case_id=case_id,
                spf_result="none",
                dkim_result="none",
                dmarc_result="none",
            )
        else:
            record = AuthResult(
                id=uuid.uuid4(),
                case_id=case_id,
                spf_result=getattr(auth_result, "spf_result", "none"),
                spf_domain=getattr(auth_result, "spf_domain", None),
                spf_details=getattr(auth_result, "spf_details", {}),
                dkim_result=getattr(auth_result, "dkim_result", "none"),
                dkim_domain=getattr(auth_result, "dkim_domain", None),
                dkim_selector=getattr(auth_result, "dkim_selector", None),
                dkim_details=getattr(auth_result, "dkim_details", {}),
                dmarc_result=getattr(auth_result, "dmarc_result", "none"),
                dmarc_domain=getattr(auth_result, "dmarc_domain", None),
                dmarc_policy=getattr(auth_result, "dmarc_policy", None),
                dmarc_details=getattr(auth_result, "dmarc_details", {}),
                arc_result=getattr(auth_result, "arc_result", None),
                authentication_results_header=getattr(
                    auth_result, "authentication_results_header", None
                ),
            )
        db.add(record)
        await db.commit()

    async def _save_iocs(
        self,
        db: AsyncSession,
        case_id: str,
        iocs: list,
    ) -> None:
        """
        Persist all extracted IOC objects as app.models.ioc.IOC records.

        Expects each IOC object to expose the standard IOC dataclass fields.
        A single bulk-add is used for efficiency.
        """
        from app.models.ioc import IOC as IOCModel

        for ioc in (iocs or []):
            record = IOCModel(
                id=uuid.uuid4(),
                case_id=case_id,
                ioc_type=getattr(ioc, "ioc_type", "UNKNOWN"),
                ioc_value=str(getattr(ioc, "ioc_value", "")),
                severity=getattr(ioc, "severity", "MEDIUM"),
                is_lookalike=getattr(ioc, "is_lookalike", False),
                lookalike_target=getattr(ioc, "lookalike_target", None),
                is_shortened_url=getattr(ioc, "is_shortened_url", False),
                is_malicious=getattr(ioc, "is_malicious", False),
                confidence=getattr(ioc, "confidence", 0.5),
                context=getattr(ioc, "context", {}),
            )
            db.add(record)
        await db.commit()

    async def _save_analysis_result(
        self,
        db: AsyncSession,
        case_id: str,
        threat_result: ThreatAnalysisResult,
    ) -> None:
        """
        Persist the final ThreatAnalysisResult from the AI engine as an
        AnalysisResult record.
        """
        record = AnalysisResult(
            id=uuid.uuid4(),
            case_id=case_id,
            threat_score=threat_result.threat_score,
            severity=threat_result.severity,
            rule_score=threat_result.rule_score,
            ml_score=threat_result.ml_score,
            gemini_score=threat_result.gemini_score,
            threat_categories=threat_result.threat_categories,
            triggered_rules=threat_result.triggered_rules,
            ai_explanation=threat_result.ai_explanation,
            urgency_indicators=threat_result.urgency_indicators,
            impersonation_analysis=threat_result.impersonation_analysis,
            social_engineering_patterns=threat_result.social_engineering_patterns,
            bec_indicators=threat_result.bec_indicators,
            shap_features=threat_result.shap_features,
            recommended_actions=threat_result.recommended_actions,
            confidence=threat_result.confidence,
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
        """
        Persist the IP geolocation and infrastructure intelligence as a
        GeoIntelligence record.
        """
        record = GeoIntelligence(
            id=uuid.uuid4(),
            case_id=case_id,
            ip_address=ip,
            is_private=geo_result.is_private,
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
            ptr_record=geo_result.ptr_record,
            is_vpn=geo_result.is_vpn,
            is_tor=geo_result.is_tor,
            is_hosting=geo_result.is_hosting,
            is_proxy=geo_result.is_proxy,
            whois_data=geo_result.whois_data,
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
        """
        Update the Case record with the final threat score, severity, status,
        threat categories, and AI explanation.
        """
        stmt = (
            update(Case)
            .where(Case.case_id == case_id)
            .values(
                threat_score=threat_result.threat_score,
                severity=threat_result.severity,
                status="COMPLETE",
                threat_categories=threat_result.threat_categories,
                ai_explanation=threat_result.ai_explanation,
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
        """
        Mark the Case record as FAILED with the error message and record
        the failure event in the blockchain ledger.
        """
        try:
            stmt = (
                update(Case)
                .where(Case.case_id == case_id)
                .values(
                    status="FAILED",
                    error_message=error[:1000],
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
                {"case_id": case_id, "error": error[:500]},
            )
        except Exception:
            # Best-effort — do not raise so the caller's error event is sent.
            pass
