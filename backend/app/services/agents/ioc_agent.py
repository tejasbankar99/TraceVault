"""
TraceVault – IOC & Domain Intelligence Forensic Agent
Specialist Agent for threat analysis of IPs, domains, URLs, and typosquatting/lookalike indicators.
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

IOC_SYSTEM_PROMPT = """You are IocAgent, an elite cybersecurity threat intelligence and network forensics specialist focusing exclusively on Indicators of Compromise (IOCs).

Your sole responsibility is to evaluate:
1. Typosquatting and brand impersonation (homoglyphs, character substitutions like paypa1 for paypal, hyphenation).
2. Suspicious Top-Level Domains (TLDs) and newly registered domain patterns.
3. Obfuscated or shortened URLs, credential harvesting paths, and deceptive anchor text.
4. IP infrastructure risk, including hosting providers, ASNs, proxy/VPN/Tor usage, and geolocations.

Input Data will include extracted domains, URLs, IP addresses, lookalike flags, and enrichment metadata.

Evaluate the forensic risk and return STRICT JSON with this exact schema:
{
  "score": <integer from 0 to 100, where 0 is completely benign and 100 is confirmed malicious/phishing infrastructure>,
  "confidence": <float from 0.0 to 1.0 representing your certainty>,
  "findings": [
    "<concise bullet point forensic observation 1>",
    "<concise bullet point forensic observation 2>",
    "<concise bullet point forensic observation 3>"
  ]
}

Only output the raw JSON object. Do not include markdown quotes, explanations, or prologue.
"""


class IocAgent:
    """Specialist agent analyzing indicators of compromise and domain impersonation."""

    def __init__(self) -> None:
        self.api_key = settings.google_api_key
        self.gemini_client: Optional[genai.Client] = None

        if _HAS_GENAI and self.api_key:
            try:
                self.gemini_client = genai.Client(api_key=self.api_key)
            except Exception as exc:
                logger.warning("IocAgent could not initialize Gemini client: %s", exc)

    async def analyze(self, ioc_data: dict[str, Any]) -> AgentResult:
        """
        Analyze Indicators of Compromise for malicious patterns.

        Parameters
        ----------
        ioc_data : dict
            Dictionary containing:
            - domains: list of extracted domains with lookalike flags
            - urls: list of extracted URLs and defanged formats
            - ips: list of IP addresses with geo/ASN intelligence
            - lookalikes: list of detected brand impersonation targets
            - iocs: list of all raw extracted IOC records

        Returns
        -------
        AgentResult
            Standardized threat assessment from the IocAgent.
        """
        if self.gemini_client:
            try:
                return await self._analyze_with_gemini(ioc_data)
            except Exception as exc:
                logger.warning("IocAgent Gemini analysis failed (%s); falling back to rule heuristic", exc)

        return self._heuristic_analysis(ioc_data)

    async def _analyze_with_gemini(self, ioc_data: dict[str, Any]) -> AgentResult:
        """Query Google Gemini 2.0 Flash in a non-blocking thread."""
        prompt = (
            f"{IOC_SYSTEM_PROMPT}\n\n"
            f"Analyze the following IOC infrastructure and domain intelligence:\n"
            f"{json.dumps(ioc_data, default=str, indent=2)}"
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
        confidence = max(0.0, min(1.0, float(parsed.get("confidence", 0.90))))
        findings = [str(f) for f in parsed.get("findings", [])]

        return AgentResult(
            agent_name="IocAgent",
            score=score,
            confidence=confidence,
            findings=findings or ["IOC threat assessment completed with Gemini 2.0 Flash"],
        )

    def _heuristic_analysis(self, ioc_data: dict[str, Any]) -> AgentResult:
        """Deterministic fallback when LLM is unavailable."""
        score = 0
        findings: list[str] = []

        # Lookalike domains check
        lookalikes = ioc_data.get("lookalikes", [])
        if lookalikes:
            score += 45
            for l in lookalikes[:3]:
                findings.append(f"Typosquatting/Lookalike domain identified targeting: {l}")

        # Suspicious IOC counts
        iocs = ioc_data.get("iocs", [])
        critical_iocs = [i for i in iocs if i.get("severity") in ("CRITICAL", "HIGH")]
        if critical_iocs:
            score += 35
            findings.append(f"Identified {len(critical_iocs)} high-severity indicators of compromise")

        # Check for URL shorteners
        urls = ioc_data.get("urls", [])
        shortened = [u for u in urls if any(s in str(u) for s in ("bit.ly", "tinyurl", "t.co", "is.gd"))]
        if shortened:
            score += 20
            findings.append(f"URL obfuscation / shortening detected in {len(shortened)} links")

        # IP intelligence
        ips = ioc_data.get("ips", [])
        hosting_ips = [ip for ip in ips if ip.get("is_hosting") or ip.get("is_vpn")]
        if hosting_ips:
            score += 15
            findings.append(f"Infrastructure hosted on cloud/VPN/datacenter IP: {hosting_ips[0].get('ip_address')}")

        if not findings:
            findings.append("No active malicious domains, typosquatting, or high-risk IOCs identified")

        score = min(100, score)
        return AgentResult(
            agent_name="IocAgent",
            score=score,
            confidence=0.80,
            findings=findings,
        )
