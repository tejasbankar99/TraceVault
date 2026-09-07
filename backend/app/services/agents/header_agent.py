"""
TraceVault – Header & Authentication Forensic Agent
Specialist Agent for deep inspection of email headers, relay hops, and SPF/DKIM/DMARC.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional

try:
    from google import genai
    _HAS_GENAI = True
except ImportError:
    _HAS_GENAI = False

from app.config import settings
from app.services.agents import AgentResult

logger = logging.getLogger(__name__)

HEADER_SYSTEM_PROMPT = """You are HeaderAgent, an elite cybersecurity email forensics specialist focusing exclusively on email routing headers and authentication standards (RFC 5322, RFC 7208, RFC 6376, RFC 7489).

Your sole responsibility is to evaluate:
1. SPF, DKIM, and DMARC results and domain alignment.
2. The Received: relay hop chain, hop delays, MTA anomalies, and originating IP addresses.
3. Header inconsistencies, such as mismatches between From, Reply-To, and Return-Path.
4. Client/Mailer indicators (X-Mailer, X-Originating-IP, missing Message-ID).

Input Data will include parsed headers, relay hops, and authentication checks.

Evaluate the forensic risk and return STRICT JSON with this exact schema:
{
  "score": <integer from 0 to 100, where 0 is pristine/legitimate and 100 is definite forgery/spoofing>,
  "confidence": <float from 0.0 to 1.0 representing your certainty>,
  "findings": [
    "<concise bullet point forensic observation 1>",
    "<concise bullet point forensic observation 2>",
    "<concise bullet point forensic observation 3>"
  ]
}

Only output the raw JSON object. Do not include markdown quotes, explanations, or prologue.
"""


class HeaderAgent:
    """Specialist agent analyzing email headers and cryptographic authentication."""

    def __init__(self) -> None:
        self.api_key = settings.google_api_key
        self.gemini_client: Optional[genai.Client] = None

        if _HAS_GENAI and self.api_key:
            try:
                self.gemini_client = genai.Client(api_key=self.api_key)
            except Exception as exc:
                logger.warning("HeaderAgent could not initialize Gemini client: %s", exc)

    async def analyze(self, header_data: dict[str, Any]) -> AgentResult:
        """
        Analyze header forensics and authentication data.
        
        Parameters
        ----------
        header_data : dict
            Dictionary containing:
            - from_addr, from_name, from_domain, reply_to, return_path, subject, date
            - spf_result, dkim_result, dmarc_result, dmarc_policy, overall_verdict
            - relay_hops: list of {hop_index, from_server, by_server, ip_address, is_public_ip, delay_seconds}
            - anomalies: list of detected anomalies
            
        Returns
        -------
        AgentResult
            Standardized threat assessment from the HeaderAgent.
        """
        if self.gemini_client:
            try:
                return await self._analyze_with_gemini(header_data)
            except Exception as exc:
                logger.warning("HeaderAgent Gemini analysis failed (%s); falling back to rule heuristic", exc)

        return self._heuristic_analysis(header_data)

    async def _analyze_with_gemini(self, header_data: dict[str, Any]) -> AgentResult:
        """Query Google Gemini 2.0 Flash in a non-blocking thread."""
        prompt = (
            f"{HEADER_SYSTEM_PROMPT}\n\n"
            f"Analyze the following email header forensic profile:\n"
            f"{json.dumps(header_data, default=str, indent=2)}"
        )

        def _call_gemini():
            return self.gemini_client.models.generate_content(
                model="gemini-2.0-flash",
                contents=prompt,
            )

        response = await asyncio.to_thread(_call_gemini)
        raw_text = (response.text or "").strip()

        # Clean markdown code blocks if returned
        if raw_text.startswith("```json"):
            raw_text = raw_text[7:]
        if raw_text.startswith("```"):
            raw_text = raw_text[3:]
        if raw_text.endswith("```"):
            raw_text = raw_text[:-3]

        parsed = json.loads(raw_text.strip())

        score = max(0, min(100, int(parsed.get("score", 0))))
        confidence = max(0.0, min(1.0, float(parsed.get("confidence", 0.85))))
        findings = [str(f) for f in parsed.get("findings", [])]

        return AgentResult(
            agent_name="HeaderAgent",
            score=score,
            confidence=confidence,
            findings=findings or ["Header analysis completed with Gemini 2.0 Flash"],
        )

    def _heuristic_analysis(self, header_data: dict[str, Any]) -> AgentResult:
        """Deterministic fallback when LLM is unavailable."""
        score = 0
        findings: list[str] = []

        spf = str(header_data.get("spf_result", "")).lower()
        dkim = str(header_data.get("dkim_result", "")).lower()
        dmarc = str(header_data.get("dmarc_result", "")).lower()

        if spf in ("fail", "permerror"):
            score += 30
            findings.append(f"SPF validation failed ({spf}) for domain")
        elif spf == "softfail":
            score += 15
            findings.append("SPF softfail detected")

        if dkim in ("fail", "none"):
            score += 25
            findings.append(f"DKIM signature verification returned '{dkim}'")

        if dmarc in ("fail", "none"):
            score += 20
            findings.append(f"DMARC policy enforcement status: {dmarc}")

        # Check From vs Return-Path mismatch
        from_domain = header_data.get("from_domain") or ""
        return_path = header_data.get("return_path") or ""
        if from_domain and return_path and from_domain not in return_path:
            score += 20
            findings.append(f"Mismatch between sender domain ({from_domain}) and Return-Path ({return_path})")

        # Relay hop anomalies
        relay_hops = header_data.get("relay_hops", [])
        if len(relay_hops) > 1:
            findings.append(f"Analyzed {len(relay_hops)} SMTP relay hops in transmission path")

        if not findings:
            findings.append("No significant header spoofing or authentication anomalies detected")

        score = min(100, score)
        return AgentResult(
            agent_name="HeaderAgent",
            score=score,
            confidence=0.75,
            findings=findings,
        )
