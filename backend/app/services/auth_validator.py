"""
TraceVault — auth_validator.py
Validates SPF, DKIM, and DMARC for an analysed email.

Primary strategy : parse the Authentication-Results header (set by the
                   receiving MTA — most reliable for forensics).
Secondary strategy: live DNS-based validation using pyspf, dkimpy, checkdmarc.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

# Optional live validation dependencies
try:
    import spf as pyspf          # pyspf package  (pip install pyspf)
    _HAS_SPF = True
except ImportError:
    _HAS_SPF = False

try:
    import dkim as dkimpy        # dkimpy package (pip install dkimpy)
    _HAS_DKIM = True
except ImportError:
    _HAS_DKIM = False

try:
    import checkdmarc            # checkdmarc package
    _HAS_CHECKDMARC = True
except ImportError:
    _HAS_CHECKDMARC = False

if TYPE_CHECKING:
    from app.services.email_parser import ParsedEmailData

from app.utils.constants import AUTH_VERDICTS


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SPFResult:
    """Result of an SPF check (either parsed or live)."""
    result: str                          # pass / fail / softfail / neutral / none / error
    explanation: str = ""
    domain: str = ""
    source: str = "header"              # "header" | "live"


@dataclass
class DKIMResult:
    """Result of a DKIM verification."""
    is_valid: bool
    domain: str = ""
    selector: str = ""
    error: str = ""
    source: str = "header"              # "header" | "live"


@dataclass
class DMARCResult:
    """Result of a DMARC policy lookup / evaluation."""
    result: str                          # pass / fail / none / error
    policy: str = "none"                 # none / quarantine / reject
    subdomain_policy: str = "none"
    pct: int = 100                       # percentage of messages to apply policy to
    domain: str = ""
    error: str = ""
    source: str = "header"              # "header" | "live"


@dataclass
class ParsedAuthResults:
    """Parsed values extracted from a raw Authentication-Results header."""
    spf_result: str = "none"
    spf_domain: str = ""
    dkim_result: str = "none"
    dkim_domain: str = ""
    dkim_selector: str = ""
    dmarc_result: str = "none"
    dmarc_domain: str = ""
    raw: str = ""


@dataclass
class AuthValidationResult:
    """Complete authentication validation result for a single email."""
    spf: SPFResult = field(default_factory=lambda: SPFResult(result="none"))
    dkim: DKIMResult = field(default_factory=lambda: DKIMResult(is_valid=False))
    dmarc: DMARCResult = field(default_factory=lambda: DMARCResult(result="none"))
    overall_verdict: str = AUTH_VERDICTS.WARN   # PASS / WARN / FAIL / CRITICAL
    spoofing_risk: str = "UNKNOWN"               # LOW / MEDIUM / HIGH / CRITICAL
    analysis_notes: list[str] = field(default_factory=list)

    @property
    def spf_result(self) -> str:
        return self.spf.result if self.spf else "none"

    @property
    def spf_domain(self) -> str:
        return self.spf.domain if self.spf else ""

    @property
    def dkim_result(self) -> str:
        if not self.dkim:
            return "none"
        return "pass" if self.dkim.is_valid else "fail"

    @property
    def dkim_domain(self) -> str:
        return self.dkim.domain if self.dkim else ""

    @property
    def dmarc_result(self) -> str:
        return self.dmarc.result if self.dmarc else "none"

    @property
    def dmarc_policy(self) -> str:
        return self.dmarc.policy if self.dmarc else "none"


# ---------------------------------------------------------------------------
# Regex helpers for Authentication-Results header parsing
# ---------------------------------------------------------------------------

# Matches: spf=<result> [(...)] [smtp.mailfrom=<domain>]
_RE_SPF = re.compile(
    r"spf=(?P<result>[a-z]+)"
    r"(?:\s+\([^)]*\))?"
    r"(?:\s+smtp\.(?:mailfrom|helo)=(?P<domain>[^\s;]+))?",
    re.IGNORECASE,
)

# Matches: dkim=<result> [header.i=@<domain>] [header.s=<selector>]
_RE_DKIM = re.compile(
    r"dkim=(?P<result>[a-z]+)"
    r"(?:\s+\([^)]*\))?"
    r"(?:\s+header\.i=@?(?P<domain>[^\s;]+))?"
    r"(?:\s+header\.s=(?P<selector>[^\s;]+))?",
    re.IGNORECASE,
)

# Matches: dmarc=<result> [(...)] [header.from=<domain>]
_RE_DMARC = re.compile(
    r"dmarc=(?P<result>[a-z]+)"
    r"(?:\s+\([^)]*\))?"
    r"(?:\s+header\.from=(?P<domain>[^\s;]+))?",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class AuthValidatorService:
    """
    Validates SPF, DKIM, and DMARC authentication for an email.

    Workflow:
    1. If an Authentication-Results header is present, parse it for immediate
       verdicts (reliable — set by the receiving MTA).
    2. Attempt live DNS-based validation for each protocol using pyspf,
       dkimpy, and checkdmarc when available.
    3. Prefer live results over header-parsed results when both are available.
    4. Compute an overall verdict and spoofing risk level.
    """

    # ------------------------------------------------------------------
    # Main entry-point
    # ------------------------------------------------------------------

    async def validate_all(
        self,
        parsed_email: "ParsedEmailData",
        sender_ip: str | None,
        raw_bytes: bytes,
    ) -> AuthValidationResult:
        """
        Run all three validations and compute an overall verdict.

        Args:
            parsed_email: Structured email data from EmailParserService.
            sender_ip:    IP of the SMTP sender (from relay chain or X-Originating-IP).
            raw_bytes:    Raw .eml bytes (needed for live DKIM verification).

        Returns:
            An ``AuthValidationResult`` with SPF, DKIM, DMARC, and overall verdict.
        """
        notes: list[str] = []

        # --- Parse Authentication-Results header (primary) ---
        parsed_auth: ParsedAuthResults | None = None
        if parsed_email.authentication_results:
            parsed_auth = self.parse_auth_results_header(parsed_email.authentication_results)

        # --- Build initial results from header ---
        spf_result = self._spf_from_parsed(parsed_auth)
        dkim_result = self._dkim_from_parsed(parsed_auth)
        dmarc_result = self._dmarc_from_parsed(parsed_auth)

        # --- Live SPF ---
        if _HAS_SPF and sender_ip and parsed_email.from_addr:
            try:
                live_spf = await self.check_spf_live(
                    sender_ip=sender_ip,
                    from_email=parsed_email.from_addr,
                    helo_domain=parsed_email.from_domain or parsed_email.from_addr.split("@")[-1],
                )
                live_spf.source = "live"
                spf_result = live_spf
                notes.append(f"Live SPF check: {live_spf.result} ({live_spf.explanation})")
            except Exception as exc:
                notes.append(f"Live SPF check failed: {exc}")

        # --- Live DKIM ---
        if _HAS_DKIM and raw_bytes:
            try:
                live_dkim = await self.verify_dkim(raw_bytes)
                live_dkim.source = "live"
                dkim_result = live_dkim
                if live_dkim.is_valid:
                    notes.append(f"Live DKIM verification: PASS (domain={live_dkim.domain})")
                else:
                    notes.append(f"Live DKIM verification: FAIL — {live_dkim.error}")
            except Exception as exc:
                notes.append(f"Live DKIM verification failed: {exc}")

        # --- Live DMARC ---
        if _HAS_CHECKDMARC and parsed_email.from_domain:
            try:
                live_dmarc = await self.check_dmarc_policy(parsed_email.from_domain)
                live_dmarc.source = "live"
                dmarc_result = live_dmarc
                notes.append(
                    f"Live DMARC lookup: policy={live_dmarc.policy}, "
                    f"result={live_dmarc.result}"
                )
            except Exception as exc:
                notes.append(f"Live DMARC lookup failed: {exc}")

        # --- No Authentication-Results and no live ---
        if not parsed_email.authentication_results and not _HAS_SPF:
            notes.append(
                "No Authentication-Results header present; "
                "live validation libraries not installed. "
                "Authentication status cannot be determined."
            )

        # --- Overall verdict ---
        verdict, risk = self.compute_overall_verdict(spf_result, dkim_result, dmarc_result)

        return AuthValidationResult(
            spf=spf_result,
            dkim=dkim_result,
            dmarc=dmarc_result,
            overall_verdict=verdict,
            spoofing_risk=risk,
            analysis_notes=notes,
        )

    # ------------------------------------------------------------------
    # Header parsing
    # ------------------------------------------------------------------

    def parse_auth_results_header(self, auth_results_header: str) -> ParsedAuthResults:
        """
        Parse the ``Authentication-Results`` header value into structured data.

        Example input::

            dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
            dkim=pass header.i=@google.com header.s=20210112;
            spf=pass smtp.mailfrom=google.com

        Returns:
            A ``ParsedAuthResults`` with extracted fields for SPF, DKIM, DMARC.
        """
        raw = auth_results_header.strip()
        result = ParsedAuthResults(raw=raw)

        # SPF
        m_spf = _RE_SPF.search(raw)
        if m_spf:
            result.spf_result = m_spf.group("result").lower()
            result.spf_domain = (m_spf.group("domain") or "").lower()

        # DKIM
        m_dkim = _RE_DKIM.search(raw)
        if m_dkim:
            result.dkim_result = m_dkim.group("result").lower()
            result.dkim_domain = (m_dkim.group("domain") or "").lower()
            result.dkim_selector = (m_dkim.group("selector") or "").lower()

        # DMARC
        m_dmarc = _RE_DMARC.search(raw)
        if m_dmarc:
            result.dmarc_result = m_dmarc.group("result").lower()
            result.dmarc_domain = (m_dmarc.group("domain") or "").lower()

        return result

    # ------------------------------------------------------------------
    # Live validation methods
    # ------------------------------------------------------------------

    async def check_spf_live(
        self,
        sender_ip: str,
        from_email: str,
        helo_domain: str,
    ) -> SPFResult:
        """
        Perform a live SPF DNS lookup using pyspf.

        Args:
            sender_ip:   The IP address of the sending SMTP server.
            from_email:  The MAIL FROM (envelope sender) address.
            helo_domain: The HELO/EHLO domain used in the SMTP session.

        Returns:
            An ``SPFResult`` with the lookup result and explanation.
        """
        if not _HAS_SPF:
            return SPFResult(
                result="none",
                explanation="pyspf not installed",
                source="live",
            )
        try:
            result, explanation = pyspf.check2(
                i=sender_ip,
                s=from_email,
                h=helo_domain,
            )
            domain = from_email.split("@")[-1] if "@" in from_email else ""
            return SPFResult(
                result=result.lower(),
                explanation=explanation or "",
                domain=domain,
                source="live",
            )
        except Exception as exc:
            return SPFResult(
                result="error",
                explanation=str(exc),
                source="live",
            )

    async def verify_dkim(self, raw_bytes: bytes) -> DKIMResult:
        """
        Verify the DKIM signature in *raw_bytes* using dkimpy.

        dkimpy performs a live DNS lookup for the public key.

        Args:
            raw_bytes: The complete raw email bytes (RFC 5322).

        Returns:
            A ``DKIMResult`` with ``is_valid=True`` when the signature verifies.
        """
        if not _HAS_DKIM:
            return DKIMResult(
                is_valid=False,
                error="dkimpy not installed",
                source="live",
            )
        try:
            d = dkimpy.DKIM(raw_bytes)
            is_valid = d.verify()

            # Extract domain / selector from the parsed signature
            domain = ""
            selector = ""
            if hasattr(d, "domain") and d.domain:
                domain = d.domain.decode("utf-8") if isinstance(d.domain, bytes) else d.domain
            if hasattr(d, "selector") and d.selector:
                selector = d.selector.decode("utf-8") if isinstance(d.selector, bytes) else d.selector

            return DKIMResult(
                is_valid=bool(is_valid),
                domain=domain,
                selector=selector,
                error="" if is_valid else "Signature verification failed",
                source="live",
            )
        except Exception as exc:
            return DKIMResult(
                is_valid=False,
                error=str(exc),
                source="live",
            )

    async def check_dmarc_policy(self, domain: str) -> DMARCResult:
        """
        Look up the DMARC policy for *domain* using checkdmarc.

        Args:
            domain: The organisational domain to check (e.g. ``"google.com"``).

        Returns:
            A ``DMARCResult`` with policy, subdomain_policy, and pct.
        """
        if not _HAS_CHECKDMARC:
            return DMARCResult(
                result="none",
                error="checkdmarc not installed",
                source="live",
            )
        try:
            report = checkdmarc.check_dmarc(domain)
            dmarc_data = report.get("dmarc") if (isinstance(report, dict) and "dmarc" in report) else report
            tags = dmarc_data.get("tags", {}) if isinstance(dmarc_data, dict) else {}

            policy = tags.get("p", {}).get("value", "none") if isinstance(tags.get("p"), dict) else tags.get("p", "none")
            sp = tags.get("sp", {}).get("value", policy) if isinstance(tags.get("sp"), dict) else tags.get("sp", policy)
            pct = int(tags.get("pct", {}).get("value", 100)) if isinstance(tags.get("pct"), dict) else 100
            valid = dmarc_data.get("valid", False) if isinstance(dmarc_data, dict) else False
            error = "" if valid else (dmarc_data.get("error", "Invalid DMARC record") if isinstance(dmarc_data, dict) else "Invalid DMARC record")

            return DMARCResult(
                result="pass" if valid else "fail",
                policy=policy,
                subdomain_policy=sp,
                pct=pct,
                domain=domain,
                error=error,
                source="live",
            )
        except Exception as exc:
            return DMARCResult(
                result="error",
                domain=domain,
                error=str(exc),
                source="live",
            )

    # ------------------------------------------------------------------
    # Overall verdict computation
    # ------------------------------------------------------------------

    def compute_overall_verdict(
        self,
        spf: SPFResult,
        dkim: DKIMResult,
        dmarc: DMARCResult,
    ) -> tuple[str, str]:
        """
        Compute the overall authentication verdict and spoofing risk level.

        Verdict logic:
        - ``CRITICAL``: SPF fail/error **and** DKIM invalid → high confidence spoof.
        - ``FAIL``    : SPF fail/error **or** DKIM invalid.
        - ``WARN``    : SPF softfail, or DMARC not set/fail with at least one pass.
        - ``PASS``    : SPF pass and DKIM valid.

        Spoofing risk levels:
        - ``CRITICAL`` → "CRITICAL"
        - ``FAIL``     → "HIGH"
        - ``WARN``     → "MEDIUM"
        - ``PASS``     → "LOW"

        Returns:
            ``(verdict, spoofing_risk_level)`` as strings.
        """
        spf_fail = spf.result in ("fail", "error", "permerror", "temperror")
        spf_soft = spf.result == "softfail"
        spf_pass = spf.result == "pass"
        dkim_fail = not dkim.is_valid
        dkim_pass = dkim.is_valid
        dmarc_fail = dmarc.result in ("fail", "error")

        # CRITICAL: both SPF and DKIM fail
        if spf_fail and dkim_fail:
            return AUTH_VERDICTS.CRITICAL, "CRITICAL"

        # FAIL: one of SPF or DKIM fails
        if spf_fail or dkim_fail:
            return AUTH_VERDICTS.FAIL, "HIGH"

        # WARN: softfail or DMARC issues
        if spf_soft or dmarc_fail:
            return AUTH_VERDICTS.WARN, "MEDIUM"

        # Partial data: neither confirmed pass nor confirmed fail
        if not spf_pass and not dkim_pass:
            return AUTH_VERDICTS.WARN, "MEDIUM"

        # PASS: all good
        return AUTH_VERDICTS.PASS, "LOW"

    # ------------------------------------------------------------------
    # Helpers to build result objects from parsed header data
    # ------------------------------------------------------------------

    def _spf_from_parsed(self, parsed: ParsedAuthResults | None) -> SPFResult:
        if parsed is None:
            return SPFResult(result="none", source="header")
        return SPFResult(
            result=parsed.spf_result,
            domain=parsed.spf_domain,
            source="header",
        )

    def _dkim_from_parsed(self, parsed: ParsedAuthResults | None) -> DKIMResult:
        if parsed is None:
            return DKIMResult(is_valid=False, source="header")
        is_valid = parsed.dkim_result == "pass"
        return DKIMResult(
            is_valid=is_valid,
            domain=parsed.dkim_domain,
            selector=parsed.dkim_selector,
            error="" if is_valid else f"DKIM result: {parsed.dkim_result}",
            source="header",
        )

    def _dmarc_from_parsed(self, parsed: ParsedAuthResults | None) -> DMARCResult:
        if parsed is None:
            return DMARCResult(result="none", source="header")
        return DMARCResult(
            result=parsed.dmarc_result,
            domain=parsed.dmarc_domain,
            source="header",
        )
