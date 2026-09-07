"""
TraceVault — header_forensics.py
Full forensic analysis of email headers: relay-chain reconstruction, anomaly
detection, spoofing indicators, and risk scoring.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING

from app.utils.ioc_patterns import is_private_ip, IPV4_PATTERN

if TYPE_CHECKING:
    from app.services.email_parser import ParsedEmailData


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RelayHopData:
    """Structured representation of a single SMTP relay hop."""
    hop_index: int                       # 0 = earliest (originating)
    from_server: str = ""
    by_server: str = ""
    ip_address: str = ""
    protocol: str = ""
    hop_id: str = ""
    for_address: str = ""
    timestamp: datetime | None = None
    is_public_ip: bool = False
    is_suspicious: bool = False
    raw_header: str = ""


@dataclass
class HeaderAnomaly:
    """A single detected header anomaly or red flag."""
    anomaly_type: str
    description: str
    severity: str                        # CRITICAL / HIGH / MEDIUM / LOW
    field_name: str = ""


@dataclass
class HeaderForensicsResult:
    """Aggregated result of full header forensic analysis."""
    relay_chain: list[RelayHopData] = field(default_factory=list)
    first_public_hop: RelayHopData | None = None
    anomalies: list[HeaderAnomaly] = field(default_factory=list)
    spoofing_indicators: list[str] = field(default_factory=list)
    risk_score: int = 0


# ---------------------------------------------------------------------------
# Received header parsing regexes
# ---------------------------------------------------------------------------

# Captures "from <name> ([ip])" patterns
_RE_FROM = re.compile(
    r"from\s+"
    r"(?P<from_server>[^\s\(\[]+)"
    r"(?:\s+\((?P<from_extra>[^\)]+)\))?"
    ,
    re.IGNORECASE,
)

# Captures "by <server>" pattern
_RE_BY = re.compile(r"by\s+(?P<by_server>[^\s]+)", re.IGNORECASE)

# Captures "with <protocol>" pattern
_RE_WITH = re.compile(r"with\s+(?P<protocol>[^\s;]+)", re.IGNORECASE)

# Captures "id <message-id>" pattern
_RE_ID = re.compile(r"\bid\s+(?P<hop_id>[^\s;]+)", re.IGNORECASE)

# Captures "for <email>" pattern
_RE_FOR = re.compile(r"for\s+<(?P<for_addr>[^>]+)>", re.IGNORECASE)

# Captures timestamp at the end: "; Weekday, DD Mon YYYY HH:MM:SS ±HHMM"
_RE_TIMESTAMP = re.compile(
    r";\s*(?P<timestamp>"
    r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+\d{1,2}\s+"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"\d{4}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4}"
    r"(?:\s+\([A-Z]+\))?)"
    ,
    re.IGNORECASE,
)

# Extract bracketed IP: (1.2.3.4) or [1.2.3.4]
_RE_BRACKETED_IP = re.compile(r"[\[\(](" + IPV4_PATTERN.pattern + r")[\]\)]")

# Lookalike IP in from_server string
_RE_IP_IN_STRING = re.compile(IPV4_PATTERN.pattern)


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class HeaderForensicsService:
    """
    Performs deep forensic analysis of email headers.

    Usage::

        service = HeaderForensicsService()
        result = service.analyze_headers(parsed_email)
    """

    # ------------------------------------------------------------------
    # Main entry-point
    # ------------------------------------------------------------------

    def analyze_headers(self, parsed_email: "ParsedEmailData") -> HeaderForensicsResult:
        """
        Execute the full header analysis pipeline.

        1. Build relay chain from Received headers.
        2. Identify the first public (infrastructure-originating) hop.
        3. Detect header anomalies.
        4. Collect spoofing indicators.
        5. Compute an aggregate risk score.

        Returns:
            A ``HeaderForensicsResult`` with all findings.
        """
        relay_chain = self.build_relay_chain(parsed_email.received_headers)
        first_public = self.find_first_public_hop(relay_chain)
        anomalies = self.detect_header_anomalies(parsed_email)
        spoofing_indicators = self.detect_spoofing_indicators(parsed_email)

        # Risk score: weighted anomaly severity
        severity_weights = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
        risk_score = min(
            sum(severity_weights.get(a.severity, 5) for a in anomalies)
            + len(spoofing_indicators) * 10,
            100,
        )

        return HeaderForensicsResult(
            relay_chain=relay_chain,
            first_public_hop=first_public,
            anomalies=anomalies,
            spoofing_indicators=spoofing_indicators,
            risk_score=risk_score,
        )

    # ------------------------------------------------------------------
    # Relay chain
    # ------------------------------------------------------------------

    def build_relay_chain(self, received_headers: list[str]) -> list[RelayHopData]:
        """
        Parse Received headers into an ordered list of ``RelayHopData`` objects.

        Standard email stores Received headers newest-first (last hop at top).
        We reverse so that index 0 = earliest originating hop.

        Args:
            received_headers: Raw Received header string values, newest first.

        Returns:
            List of ``RelayHopData``, index 0 = originating server.
        """
        # Input is newest-first; reverse to get oldest-first
        ordered = list(reversed(received_headers))
        chain: list[RelayHopData] = []

        for idx, raw in enumerate(ordered):
            hop = self._parse_single_received(raw)
            if hop is None:
                # Still create a minimal hop so we don't lose positional info
                hop = RelayHopData(hop_index=idx, raw_header=raw)
            else:
                hop.hop_index = idx

            # Determine if public IP
            if hop.ip_address:
                hop.is_public_ip = not is_private_ip(hop.ip_address)
            else:
                hop.is_public_ip = False

            chain.append(hop)

        return chain

    def find_first_public_hop(
        self,
        relay_chain: list[RelayHopData],
    ) -> RelayHopData | None:
        """
        Find the earliest relay hop that has a public (routable) IP address.

        This hop represents the first infrastructure server that touched the
        email outside of RFC 1918 address space — i.e. the true sending
        infrastructure origin.

        Returns:
            The earliest ``RelayHopData`` with ``is_public_ip=True``, or None.
        """
        for hop in relay_chain:  # already ordered oldest→newest
            if hop.is_public_ip and hop.ip_address:
                return hop
        return None

    # ------------------------------------------------------------------
    # Anomaly detection
    # ------------------------------------------------------------------

    def detect_header_anomalies(
        self,
        parsed_email: "ParsedEmailData",
    ) -> list[HeaderAnomaly]:
        """
        Systematically check for header red flags and anomalies.

        Returns a list of ``HeaderAnomaly`` objects, each with a type,
        human-readable description, severity, and the offending field name.
        """
        anomalies: list[HeaderAnomaly] = []

        # 1. From domain vs Return-Path domain mismatch
        from_domain = parsed_email.from_domain.lower()
        rp = parsed_email.return_path.lower()
        rp_domain = rp.split("@")[-1].strip("<> ") if "@" in rp else ""
        if from_domain and rp_domain and from_domain != rp_domain:
            anomalies.append(HeaderAnomaly(
                anomaly_type="MISMATCH_FROM_RETURN_PATH",
                description=(
                    f"From domain '{from_domain}' does not match "
                    f"Return-Path domain '{rp_domain}' — common spoofing indicator."
                ),
                severity="HIGH",
                field_name="Return-Path",
            ))

        # 2. From domain vs Reply-To domain mismatch (reply hijacking)
        for rt in parsed_email.reply_to:
            rt_domain = rt.split("@")[-1].lower() if "@" in rt else ""
            if from_domain and rt_domain and from_domain != rt_domain:
                anomalies.append(HeaderAnomaly(
                    anomaly_type="REPLY_HIJACKING",
                    description=(
                        f"Reply-To address '{rt}' uses domain '{rt_domain}' "
                        f"which differs from From domain '{from_domain}'. "
                        f"Replies will be directed to a different domain."
                    ),
                    severity="HIGH",
                    field_name="Reply-To",
                ))
                break

        # 3. Message-ID domain mismatch
        mid = parsed_email.message_id or ""
        mid_domain = mid.split("@")[-1].strip(">").lower() if "@" in mid else ""
        if from_domain and mid_domain and mid_domain != from_domain:
            anomalies.append(HeaderAnomaly(
                anomaly_type="SUSPICIOUS_MESSAGE_ID",
                description=(
                    f"Message-ID domain '{mid_domain}' does not match "
                    f"From domain '{from_domain}'. May indicate a forged header."
                ),
                severity="MEDIUM",
                field_name="Message-ID",
            ))

        # 4. Missing Date header
        if not parsed_email.date:
            anomalies.append(HeaderAnomaly(
                anomaly_type="RFC_VIOLATION_MISSING_DATE",
                description="Required 'Date' header is absent or unparseable.",
                severity="MEDIUM",
                field_name="Date",
            ))

        # 5. Future timestamps in Received headers
        now = datetime.now(tz=timezone.utc)
        relay_chain = self.build_relay_chain(parsed_email.received_headers)
        for hop in relay_chain:
            if hop.timestamp and hop.timestamp > now:
                anomalies.append(HeaderAnomaly(
                    anomaly_type="TIMESTAMP_ANOMALY",
                    description=(
                        f"Received header hop {hop.hop_index} has a future timestamp "
                        f"({hop.timestamp.isoformat()}). Possible clock skew or forgery."
                    ),
                    severity="MEDIUM",
                    field_name="Received",
                ))

        # 6. Received header timestamps out of order
        timestamps = [h.timestamp for h in relay_chain if h.timestamp]
        for i in range(1, len(timestamps)):
            if timestamps[i] < timestamps[i - 1]:
                anomalies.append(HeaderAnomaly(
                    anomaly_type="RELAY_ANOMALY",
                    description=(
                        f"Received header timestamps are out of order at hop {i}. "
                        f"Expected ascending order; found {timestamps[i]} < {timestamps[i-1]}."
                    ),
                    severity="MEDIUM",
                    field_name="Received",
                ))
                break  # report once

        # 7. RFC 1918 IP in a position suggesting external relay
        for hop in relay_chain:
            if hop.ip_address and is_private_ip(hop.ip_address):
                if hop.hop_index == 0 and len(relay_chain) > 1:
                    anomalies.append(HeaderAnomaly(
                        anomaly_type="RFC1918_IN_EXTERNAL_HOP",
                        description=(
                            f"Originating Received hop contains a private IP "
                            f"({hop.ip_address}) but email traversed external relays. "
                            f"The private IP in Received headers may have been injected."
                        ),
                        severity="LOW",
                        field_name="Received",
                    ))

        # 8. Very short relay chain for claimed enterprise sender
        if from_domain and len(relay_chain) < 2:
            # Legitimate enterprise mail always passes through at least 2 hops
            anomalies.append(HeaderAnomaly(
                anomaly_type="SHORT_RELAY_CHAIN",
                description=(
                    f"Only {len(relay_chain)} Received hop(s) found for claimed sender "
                    f"'{from_domain}'. Legitimate enterprise mail typically traverses 2+ hops."
                ),
                severity="LOW",
                field_name="Received",
            ))

        # 9. X-Originating-IP present (webmail / cloud sending)
        if parsed_email.x_originating_ip:
            anomalies.append(HeaderAnomaly(
                anomaly_type="WEBMAIL_ORIGIN",
                description=(
                    f"X-Originating-IP header present ({parsed_email.x_originating_ip}). "
                    f"Email was composed via webmail or a cloud sending service."
                ),
                severity="LOW",
                field_name="X-Originating-IP",
            ))

        # 10. Missing Message-ID
        if not parsed_email.message_id:
            anomalies.append(HeaderAnomaly(
                anomaly_type="MISSING_MESSAGE_ID",
                description=(
                    "'Message-ID' header is absent. Legitimate MUAs always add one; "
                    "its absence suggests a scripted or forged email."
                ),
                severity="MEDIUM",
                field_name="Message-ID",
            ))

        return anomalies

    def detect_spoofing_indicators(
        self,
        parsed_email: "ParsedEmailData",
    ) -> list[str]:
        """
        Return a list of human-readable spoofing indicator descriptions.

        Each string is a concise analyst-facing statement of a single
        spoofing signal (suitable for display in a findings list).
        """
        indicators: list[str] = []

        from_domain = parsed_email.from_domain.lower()

        # From ≠ Return-Path
        rp = parsed_email.return_path.lower()
        rp_domain = rp.split("@")[-1].strip("<> ") if "@" in rp else ""
        if from_domain and rp_domain and from_domain != rp_domain:
            indicators.append(
                f"From domain ({from_domain}) differs from Return-Path domain ({rp_domain})"
            )

        # Reply-To hijacking
        for rt in parsed_email.reply_to:
            rt_domain = rt.split("@")[-1].lower() if "@" in rt else ""
            if from_domain and rt_domain and from_domain != rt_domain:
                indicators.append(
                    f"Reply-To ({rt}) points to a different domain than From ({from_domain})"
                )

        # No authentication results
        if not parsed_email.authentication_results:
            indicators.append(
                "No Authentication-Results header — SPF/DKIM/DMARC status unknown"
            )
        else:
            auth = parsed_email.authentication_results.lower()
            if "spf=fail" in auth or "spf=softfail" in auth:
                indicators.append("SPF check failed or soft-failed per Authentication-Results")
            if "dkim=fail" in auth or "dkim=none" in auth:
                indicators.append("DKIM check failed or no DKIM signature per Authentication-Results")
            if "dmarc=fail" in auth:
                indicators.append("DMARC check failed per Authentication-Results")

        # No DKIM signature at all
        if not parsed_email.dkim_signature:
            indicators.append("No DKIM-Signature header — message is unsigned")

        # Message-ID domain mismatch
        mid = parsed_email.message_id or ""
        mid_domain = mid.split("@")[-1].strip(">").lower() if "@" in mid else ""
        if from_domain and mid_domain and mid_domain != from_domain:
            indicators.append(
                f"Message-ID domain ({mid_domain}) does not match From domain ({from_domain})"
            )

        return indicators

    # ------------------------------------------------------------------
    # Message-ID analysis
    # ------------------------------------------------------------------

    def analyze_message_id(self, message_id: str) -> dict:
        """
        Analyse the Message-ID for signs of bulk / template-based sending.

        Returns a dict with:
        - ``is_suspicious``     bool
        - ``reasons``           list[str]
        - ``local_part``        str
        - ``domain_part``       str
        """
        reasons: list[str] = []
        local, _, domain = message_id.partition("@")

        # Very short local part
        if len(local) < 6:
            reasons.append(f"Unusually short local part: '{local}'")

        # All numeric local part (common in spam tools)
        if re.match(r"^\d+$", local):
            reasons.append("Local part is entirely numeric (common in bulk mailers)")

        # No domain in Message-ID
        if not domain:
            reasons.append("Message-ID has no domain part (malformed)")

        # Domain doesn't look like a valid FQDN
        if domain and not re.match(r"^[a-z0-9.\-]+\.[a-z]{2,}$", domain, re.IGNORECASE):
            reasons.append(f"Message-ID domain '{domain}' does not look like a valid FQDN")

        # Bulk mailer fingerprints
        bulk_patterns = [
            (r"\d{10,}", "Long numeric sequence (timestamp or counter)"),
            (r"[a-f0-9]{32}", "MD5-like hash in local part"),
            (r"\.bulk\.", "Contains '.bulk.' marker"),
            (r"mailchimp|sendgrid|constantcontact|campaign", "Known bulk ESP pattern"),
        ]
        for pattern, description in bulk_patterns:
            if re.search(pattern, local, re.IGNORECASE):
                reasons.append(description)

        return {
            "is_suspicious": len(reasons) > 0,
            "reasons": reasons,
            "local_part": local,
            "domain_part": domain,
        }

    # ------------------------------------------------------------------
    # Single Received header parser
    # ------------------------------------------------------------------

    def _parse_single_received(self, header: str) -> RelayHopData | None:
        """
        Parse a single raw Received header string into a ``RelayHopData``.

        The Received header format is loosely defined (RFC 5321 §4.4), so
        we use targeted regex extraction rather than strict grammar.

        Returns ``None`` if the header cannot be meaningfully parsed.
        """
        if not header or not header.strip():
            return None

        hop = RelayHopData(hop_index=0, raw_header=header)

        # from <server>
        m_from = _RE_FROM.search(header)
        if m_from:
            hop.from_server = m_from.group("from_server").strip()
            extra = m_from.group("from_extra") or ""
            # Try to extract IP from the parenthetical extra part
            ip_m = _RE_BRACKETED_IP.search(f"[{extra}]")
            if not ip_m:
                ip_m = _RE_IP_IN_STRING.search(extra)
            if ip_m:
                hop.ip_address = ip_m.group(0).strip("[]() ")

        # If IP not found in from's parenthetical, try the whole header
        if not hop.ip_address:
            all_ips = _RE_BRACKETED_IP.findall(header)
            if all_ips:
                hop.ip_address = all_ips[0]

        # by <server>
        m_by = _RE_BY.search(header)
        if m_by:
            hop.by_server = m_by.group("by_server").strip(";")

        # with <protocol>
        m_with = _RE_WITH.search(header)
        if m_with:
            hop.protocol = m_with.group("protocol").strip(";")

        # id <message-id>
        m_id = _RE_ID.search(header)
        if m_id:
            hop.hop_id = m_id.group("hop_id").strip(";")

        # for <email>
        m_for = _RE_FOR.search(header)
        if m_for:
            hop.for_address = m_for.group("for_addr")

        # timestamp
        m_ts = _RE_TIMESTAMP.search(header)
        if m_ts:
            try:
                hop.timestamp = parsedate_to_datetime(m_ts.group("timestamp").strip())
            except Exception:
                hop.timestamp = None

        # Nothing useful extracted
        if not hop.from_server and not hop.by_server and not hop.ip_address:
            return None

        return hop
